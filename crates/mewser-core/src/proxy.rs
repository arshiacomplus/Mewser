use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::error::CoreError;
use crate::policy::is_restricted_ip;
use crate::router::RoutingPolicy;
use crate::tunnel::socks5::{connect_and_handshake, Socks5Auth, Socks5Config, Socks5Target};

#[derive(Debug, Clone)]
pub struct PolicyProxyConfig {
    pub bind_addr: SocketAddr,
    pub routing_policy: RoutingPolicy,
    pub socks5_endpoint: SocketAddr,
    pub socks5_endpoint_dynamic: Option<Arc<std::sync::RwLock<Option<SocketAddr>>>>,
    pub socks5_auth: Option<Socks5Auth>,
    pub connect_timeout: Duration,
    pub allow_loopback_for_testing: bool,
}

impl PolicyProxyConfig {
    pub fn new(
        bind_addr: SocketAddr,
        routing_policy: RoutingPolicy,
        socks5_endpoint: SocketAddr,
    ) -> Self {
        Self {
            bind_addr,
            routing_policy,
            socks5_endpoint,
            socks5_endpoint_dynamic: None,
            socks5_auth: None,
            connect_timeout: Duration::from_secs(10),
            allow_loopback_for_testing: false,
        }
    }

    pub fn with_dynamic_socks5_endpoint(
        mut self,
        dynamic: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    ) -> Self {
        self.socks5_endpoint_dynamic = Some(dynamic);
        self
    }

    pub fn resolved_socks5_endpoint(&self) -> Option<SocketAddr> {
        if let Some(ref dyn_ep) = self.socks5_endpoint_dynamic {
            if let Ok(guard) = dyn_ep.read() {
                return *guard;
            }
        }
        Some(self.socks5_endpoint)
    }

    pub fn with_auth(mut self, auth: Option<Socks5Auth>) -> Self {
        self.socks5_auth = auth;
        self
    }

    pub fn with_allow_loopback_for_testing(mut self, allow: bool) -> Self {
        self.allow_loopback_for_testing = allow;
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct PolicyProxyStats {
    pub total_requests: Arc<AtomicUsize>,
    pub direct_requests: Arc<AtomicUsize>,
    pub tunnel_requests: Arc<AtomicUsize>,
    pub blocked_requests: Arc<AtomicUsize>,
    pub failed_tunnel_requests: Arc<AtomicUsize>,
    pub subresource_requests: Arc<AtomicUsize>,
}

pub struct PolicyProxyHandle {
    bound_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    stats: PolicyProxyStats,
    dynamic_endpoint: Option<Arc<std::sync::RwLock<Option<SocketAddr>>>>,
}

impl PolicyProxyHandle {
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    pub fn stats(&self) -> &PolicyProxyStats {
        &self.stats
    }

    pub fn set_socks5_endpoint(&self, addr: Option<SocketAddr>) {
        if let Some(ref dyn_ep) = self.dynamic_endpoint {
            if let Ok(mut guard) = dyn_ep.write() {
                *guard = addr;
            }
        }
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.bound_addr, Duration::from_millis(100));
    }
}

impl Drop for PolicyProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct PolicyProxy;

impl PolicyProxy {
    pub fn start(config: PolicyProxyConfig) -> Result<PolicyProxyHandle, CoreError> {
        if !config.bind_addr.ip().is_loopback() {
            return Err(CoreError::Configuration(
                "Policy proxy must bind to a loopback address (e.g. 127.0.0.1)".into(),
            ));
        }

        let listener = TcpListener::bind(config.bind_addr).map_err(|e| {
            CoreError::Configuration(format!(
                "Failed to bind policy proxy on {}: {e}",
                config.bind_addr
            ))
        })?;

        let bound_addr = listener.local_addr().map_err(|e| {
            CoreError::Configuration(format!("Failed to read policy proxy bound address: {e}"))
        })?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = PolicyProxyStats::default();

        let shutdown_clone = Arc::clone(&shutdown);
        let stats_clone = stats.clone();
        let config_clone = config.clone();

        thread::spawn(move || {
            let _ = listener.set_nonblocking(false);
            for stream_res in listener.incoming() {
                if shutdown_clone.load(Ordering::SeqCst) {
                    break;
                }

                match stream_res {
                    Ok(client_stream) => {
                        let cfg = config_clone.clone();
                        let st = stats_clone.clone();
                        thread::spawn(move || {
                            let _ = handle_client(client_stream, cfg, st);
                        });
                    }
                    Err(_) => {
                        if shutdown_clone.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                }
            }
        });

        let dynamic_endpoint = config.socks5_endpoint_dynamic.clone();

        Ok(PolicyProxyHandle {
            bound_addr,
            shutdown,
            stats,
            dynamic_endpoint,
        })
    }
}

fn handle_client(
    mut client_stream: TcpStream,
    config: PolicyProxyConfig,
    stats: PolicyProxyStats,
) -> Result<(), std::io::Error> {
    let _ = client_stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = client_stream.set_write_timeout(Some(Duration::from_secs(15)));

    let mut buf = vec![0u8; 16384];
    let mut total_read = 0;

    let (headers_end, request_line_end) = loop {
        let n = client_stream.read(&mut buf[total_read..])?;
        if n == 0 {
            return Ok(());
        }
        total_read += n;

        let slice = &buf[..total_read];
        if let Some(pos) = find_subsequence(slice, b"\r\n\r\n") {
            let line_end = find_subsequence(slice, b"\r\n").unwrap_or(pos);
            break (pos + 4, line_end);
        }

        if total_read >= buf.len() {
            return send_response(
                &mut client_stream,
                400,
                "Bad Request",
                "Request header too large\r\n",
            );
        }
    };

    stats.total_requests.fetch_add(1, Ordering::SeqCst);

    let req_line_bytes = &buf[..request_line_end];
    let req_line = String::from_utf8_lossy(req_line_bytes);
    let mut parts = req_line.split_whitespace();

    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let raw_target = parts.next().unwrap_or("");
    let _version = parts.next().unwrap_or("HTTP/1.1");

    let header_text = String::from_utf8_lossy(&buf[..headers_end]).to_ascii_lowercase();
    if is_subresource_request(raw_target, &header_text) {
        stats.subresource_requests.fetch_add(1, Ordering::SeqCst);
        if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
            eprintln!("[PolicyProxy] -> Subresource detected: {method} {raw_target}");
        }
    }

    if method == "CONNECT" {
        handle_connect(
            client_stream,
            raw_target,
            &buf[headers_end..total_read],
            &config,
            &stats,
        )
    } else {
        handle_http_request(
            client_stream,
            &method,
            raw_target,
            &buf[..headers_end],
            &buf[headers_end..total_read],
            &config,
            &stats,
        )
    }
}

fn handle_connect(
    mut client_stream: TcpStream,
    target: &str,
    initial_data: &[u8],
    config: &PolicyProxyConfig,
    stats: &PolicyProxyStats,
) -> Result<(), std::io::Error> {
    let (host, port) = parse_host_and_port(target, 443);

    if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
        eprintln!("[PolicyProxy] CONNECT {target} (Host: {host}, Port: {port})");
    }

    if is_ssrf_blocked(&host, config.allow_loopback_for_testing) {
        stats.blocked_requests.fetch_add(1, Ordering::SeqCst);
        if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
            eprintln!("[PolicyProxy] -> SSRF blocked destination: {host}");
        }
        return send_response(
            &mut client_stream,
            403,
            "Forbidden",
            "SSRF defense: Target host or IP is restricted by policy\r\n",
        );
    }

    if config.routing_policy.is_direct_target(&host) {
        if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
            eprintln!("[PolicyProxy] -> Route: DIRECT for {host}:{port}");
        }
        handle_direct_connect(client_stream, &host, port, initial_data, config, stats)
    } else {
        if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
            eprintln!(
                "[PolicyProxy] -> Route: TUNNEL (SOCKS5 domain addressing) for {host}:{port}"
            );
        }
        handle_tunnel_connect(client_stream, &host, port, initial_data, config, stats)
    }
}

fn handle_direct_connect(
    mut client_stream: TcpStream,
    host: &str,
    port: u16,
    initial_data: &[u8],
    config: &PolicyProxyConfig,
    stats: &PolicyProxyStats,
) -> Result<(), std::io::Error> {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => {
            return send_response(
                &mut client_stream,
                502,
                "Bad Gateway",
                &format!("Direct DNS resolution failed for {host}: {e}\r\n"),
            );
        }
    };

    if !config.allow_loopback_for_testing {
        for sa in &addrs {
            if is_restricted_ip(sa.ip()) {
                stats.blocked_requests.fetch_add(1, Ordering::SeqCst);
                return send_response(
                    &mut client_stream,
                    403,
                    "Forbidden",
                    "SSRF defense: Resolved IP is restricted\r\n",
                );
            }
        }
    }

    let mut upstream_stream = None;
    for sa in addrs {
        if let Ok(stream) = TcpStream::connect_timeout(&sa, config.connect_timeout) {
            upstream_stream = Some(stream);
            break;
        }
    }

    let upstream = match upstream_stream {
        Some(s) => s,
        None => {
            return send_response(
                &mut client_stream,
                502,
                "Bad Gateway",
                &format!("Direct connection failed for {host}:{port}\r\n"),
            );
        }
    };

    stats.direct_requests.fetch_add(1, Ordering::SeqCst);
    if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
        eprintln!(
            "[PolicyProxy] -> DIRECT connected for {host}:{port} (HTTP 200 Connection Established)"
        );
    }

    client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    client_stream.flush()?;

    if !initial_data.is_empty() {
        let mut up = upstream.try_clone()?;
        up.write_all(initial_data)?;
        up.flush()?;
    }

    relay_bidirectional(client_stream, upstream)
}

fn handle_tunnel_connect(
    mut client_stream: TcpStream,
    host: &str,
    port: u16,
    initial_data: &[u8],
    config: &PolicyProxyConfig,
    stats: &PolicyProxyStats,
) -> Result<(), std::io::Error> {
    let proxy_addr = match config.resolved_socks5_endpoint() {
        Some(addr) => addr,
        None => {
            stats.failed_tunnel_requests.fetch_add(1, Ordering::SeqCst);
            if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
                eprintln!("[PolicyProxy] -> TUNNEL failed for {host}:{port}: MasterDNS tunnel is disconnected (HTTP 502 Bad Gateway - FAIL-CLOSED)");
            }
            return send_response(
                &mut client_stream,
                502,
                "Bad Gateway",
                "Tunnel transmission failed (fail-closed): MasterDNS tunnel is disconnected\r\n",
            );
        }
    };

    let socks5_cfg = Socks5Config {
        proxy_addr,
        auth: config.socks5_auth.clone(),
        connect_timeout: config.connect_timeout.max(Duration::from_secs(30)),
        read_timeout: Duration::from_secs(60),
        write_timeout: Duration::from_secs(60),
        max_response_bytes: 32 * 1024 * 1024,
    };

    let target = Socks5Target::Domain(host.to_string(), port);
    let upstream = match connect_and_handshake(&socks5_cfg, &target) {
        Ok(stream) => {
            if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
                eprintln!("[PolicyProxy] -> TUNNEL established for {host}:{port} (HTTP 200 Connection Established)");
            }
            stream
        }
        Err(e) => {
            stats.failed_tunnel_requests.fetch_add(1, Ordering::SeqCst);
            if std::env::var_os("MEWSER_LOG_PROXY_REQUESTS").is_some() {
                eprintln!("[PolicyProxy] -> TUNNEL failed for {host}:{port}: {e} (HTTP 502 Bad Gateway - FAIL-CLOSED)");
            }
            return send_response(
                &mut client_stream,
                502,
                "Bad Gateway",
                &format!("Tunnel transmission failed (fail-closed): {e}\r\n"),
            );
        }
    };

    stats.tunnel_requests.fetch_add(1, Ordering::SeqCst);

    client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    client_stream.flush()?;

    if !initial_data.is_empty() {
        let mut up = upstream.try_clone()?;
        up.write_all(initial_data)?;
        up.flush()?;
    }

    relay_bidirectional(client_stream, upstream)
}

fn handle_http_request(
    mut client_stream: TcpStream,
    method: &str,
    raw_target: &str,
    headers: &[u8],
    body_prefix: &[u8],
    config: &PolicyProxyConfig,
    stats: &PolicyProxyStats,
) -> Result<(), std::io::Error> {
    let (host, port, path) = parse_http_target(raw_target, headers);

    if is_ssrf_blocked(&host, config.allow_loopback_for_testing) {
        stats.blocked_requests.fetch_add(1, Ordering::SeqCst);
        return send_response(
            &mut client_stream,
            403,
            "Forbidden",
            "SSRF defense: Target host or IP is restricted by policy\r\n",
        );
    }

    let is_direct = config.routing_policy.is_direct_target(&host);

    let mut upstream = if is_direct {
        let addr_str = format!("{host}:{port}");
        let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(e) => {
                return send_response(
                    &mut client_stream,
                    502,
                    "Bad Gateway",
                    &format!("Direct DNS resolution failed for {host}: {e}\r\n"),
                );
            }
        };

        if !config.allow_loopback_for_testing {
            for sa in &addrs {
                if is_restricted_ip(sa.ip()) {
                    stats.blocked_requests.fetch_add(1, Ordering::SeqCst);
                    return send_response(
                        &mut client_stream,
                        403,
                        "Forbidden",
                        "SSRF defense: Resolved IP is restricted\r\n",
                    );
                }
            }
        }

        let mut connected = None;
        for sa in addrs {
            if let Ok(stream) = TcpStream::connect_timeout(&sa, config.connect_timeout) {
                connected = Some(stream);
                break;
            }
        }

        match connected {
            Some(s) => {
                stats.direct_requests.fetch_add(1, Ordering::SeqCst);
                s
            }
            None => {
                return send_response(
                    &mut client_stream,
                    502,
                    "Bad Gateway",
                    &format!("Direct connection failed for {host}:{port}\r\n"),
                );
            }
        }
    } else {
        let proxy_addr = match config.resolved_socks5_endpoint() {
            Some(addr) => addr,
            None => {
                stats.failed_tunnel_requests.fetch_add(1, Ordering::SeqCst);
                return send_response(
                    &mut client_stream,
                    502,
                    "Bad Gateway",
                    "Tunnel transmission failed (fail-closed): MasterDNS tunnel is disconnected\r\n",
                );
            }
        };

        let socks5_cfg = Socks5Config {
            proxy_addr,
            auth: config.socks5_auth.clone(),
            connect_timeout: config.connect_timeout,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_response_bytes: 32 * 1024 * 1024,
        };

        let target = Socks5Target::Domain(host.to_string(), port);
        match connect_and_handshake(&socks5_cfg, &target) {
            Ok(stream) => {
                stats.tunnel_requests.fetch_add(1, Ordering::SeqCst);
                stream
            }
            Err(e) => {
                stats.failed_tunnel_requests.fetch_add(1, Ordering::SeqCst);
                return send_response(
                    &mut client_stream,
                    502,
                    "Bad Gateway",
                    &format!("Tunnel transmission failed (fail-closed): {e}\r\n"),
                );
            }
        }
    };

    let rewritten_req = rewrite_request_headers(method, &path, headers);
    upstream.write_all(&rewritten_req)?;
    if !body_prefix.is_empty() {
        upstream.write_all(body_prefix)?;
    }

    relay_bidirectional(client_stream, upstream)
}

fn rewrite_request_headers(method: &str, path: &str, headers: &[u8]) -> Vec<u8> {
    let header_str = String::from_utf8_lossy(headers);
    let mut lines = header_str.split("\r\n");
    let _old_req_line = lines.next().unwrap_or("");

    let mut out = format!("{method} {path} HTTP/1.1\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("proxy-connection:") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn parse_host_and_port(target: &str, default_port: u16) -> (String, u16) {
    let target = target.trim();
    if target.starts_with('[') {
        if let Some(end_bracket) = target.find(']') {
            let host = &target[1..end_bracket];
            let rest = &target[end_bracket + 1..];
            let port = if let Some(p_str) = rest.strip_prefix(':') {
                p_str.parse::<u16>().unwrap_or(default_port)
            } else {
                default_port
            };
            return (host.to_string(), port);
        }
    }

    if let Some((h, p)) = target.split_once(':') {
        let port = p.parse::<u16>().unwrap_or(default_port);
        (h.to_string(), port)
    } else {
        (target.to_string(), default_port)
    }
}

fn parse_http_target(raw_target: &str, headers: &[u8]) -> (String, u16, String) {
    if raw_target.starts_with("http://") || raw_target.starts_with("https://") {
        if let Some(after_scheme) = raw_target.split("://").nth(1) {
            let (host_port, path) = match after_scheme.find('/') {
                Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
                None => (after_scheme, "/"),
            };
            let (host, port) = parse_host_and_port(host_port, 80);
            return (host, port, path.to_string());
        }
    }

    let header_str = String::from_utf8_lossy(headers);
    let mut host = String::new();
    let mut port = 80;

    for line in header_str.lines() {
        if let Some(val) = line.strip_prefix("Host: ") {
            let (h, p) = parse_host_and_port(val.trim(), 80);
            host = h;
            port = p;
            break;
        } else if let Some(val) = line.strip_prefix("host: ") {
            let (h, p) = parse_host_and_port(val.trim(), 80);
            host = h;
            port = p;
            break;
        }
    }

    let path = if raw_target.starts_with('/') {
        raw_target.to_string()
    } else {
        "/".to_string()
    };

    (host, port, path)
}

fn is_ssrf_blocked(host: &str, allow_loopback: bool) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" {
        return !allow_loopback;
    }

    if let Ok(ip) = lower.parse::<IpAddr>() {
        if ip.is_loopback() {
            return !allow_loopback;
        }
        return is_restricted_ip(ip);
    }

    false
}

fn is_subresource_request(target: &str, header_text: &str) -> bool {
    let target_lower = target.to_ascii_lowercase();
    let exts = [
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        "frame.html",
    ];

    if exts.iter().any(|ext| target_lower.contains(ext)) {
        return true;
    }

    if header_text.contains("sec-fetch-dest: image")
        || header_text.contains("sec-fetch-dest: script")
        || header_text.contains("sec-fetch-dest: style")
        || header_text.contains("sec-fetch-dest: font")
        || header_text.contains("sec-fetch-dest: iframe")
    {
        return true;
    }

    false
}

fn relay_bidirectional(
    mut client: TcpStream,
    mut upstream: TcpStream,
) -> Result<(), std::io::Error> {
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let _ = upstream.set_write_timeout(None);

    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;

    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(std::net::Shutdown::Write);
    });

    let _ = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = t1.join();

    Ok(())
}

fn send_response(
    stream: &mut TcpStream,
    status: u16,
    phrase: &str,
    body: &str,
) -> Result<(), std::io::Error> {
    let resp = format!(
        "HTTP/1.1 {status} {phrase}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
