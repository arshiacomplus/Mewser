use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mewser_core::tunnel::{
    Socks5Auth, Socks5Config, Socks5Target, Socks5TunnelAdapter, TunnelAdapter,
};
use mewser_core::{CoreError, RoutingPolicy};
use mewser_gateway::{ExtractedPage, Gateway, GatewayConfig, GatewayServer};

struct TestSocks5Proxy {
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    auth: Option<Socks5Auth>,
    force_reject_code: Option<u8>,
    hang: bool,
}

impl TestSocks5Proxy {
    fn bind(
        auth: Option<Socks5Auth>,
        force_reject_code: Option<u8>,
        hang: bool,
    ) -> std::io::Result<(SocketAddr, Self)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let proxy = Self {
            listener,
            shutdown: Arc::new(AtomicBool::new(false)),
            auth,
            force_reject_code,
            hang,
        };
        Ok((addr, proxy))
    }

    fn spawn(self) -> (Arc<AtomicBool>, JoinHandle<()>) {
        let shutdown_thread = Arc::clone(&self.shutdown);
        let shutdown_ret = Arc::clone(&self.shutdown);
        let listener = self.listener;
        let auth = self.auth;
        let reject_code = self.force_reject_code;
        let hang = self.hang;

        let handle = thread::spawn(move || {
            while !shutdown_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let auth_clone = auth.clone();
                        thread::spawn(move || {
                            let _ = handle_socks5_client(stream, auth_clone, reject_code, hang);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        (shutdown_ret, handle)
    }
}

fn handle_socks5_client(
    mut client: TcpStream,
    auth: Option<Socks5Auth>,
    reject_code: Option<u8>,
    hang: bool,
) -> std::io::Result<()> {
    if hang {
        thread::sleep(Duration::from_secs(10));
        return Ok(());
    }

    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    client.set_write_timeout(Some(Duration::from_secs(3)))?;

    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting)?;
    let num_methods = greeting[1] as usize;
    let mut methods = vec![0u8; num_methods];
    client.read_exact(&mut methods)?;

    if let Some(expected_auth) = auth {
        if !methods.contains(&0x02) {
            client.write_all(&[0x05, 0xFF])?;
            return Ok(());
        }
        client.write_all(&[0x05, 0x02])?;

        let mut sub_ver = [0u8; 1];
        client.read_exact(&mut sub_ver)?;
        let mut ulen = [0u8; 1];
        client.read_exact(&mut ulen)?;
        let mut ubuf = vec![0u8; ulen[0] as usize];
        client.read_exact(&mut ubuf)?;

        let mut plen = [0u8; 1];
        client.read_exact(&mut plen)?;
        let mut pbuf = vec![0u8; plen[0] as usize];
        client.read_exact(&mut pbuf)?;

        let username = String::from_utf8_lossy(&ubuf);
        let password = String::from_utf8_lossy(&pbuf);

        if username == expected_auth.username && password == expected_auth.password {
            client.write_all(&[0x01, 0x00])?;
        } else {
            client.write_all(&[0x01, 0x01])?;
            return Ok(());
        }
    } else {
        client.write_all(&[0x05, 0x00])?;
    }

    let mut connect_hdr = [0u8; 4];
    client.read_exact(&mut connect_hdr)?;

    let target_addr: SocketAddr = match connect_hdr[3] {
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            client.read_exact(&mut ip_bytes)?;
            let mut port_bytes = [0u8; 2];
            client.read_exact(&mut port_bytes)?;
            let port = u16::from_be_bytes(port_bytes);
            SocketAddr::from((ip_bytes, port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut domain_buf = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain_buf)?;
            let mut port_bytes = [0u8; 2];
            client.read_exact(&mut port_bytes)?;
            let port = u16::from_be_bytes(port_bytes);
            let domain = String::from_utf8_lossy(&domain_buf);
            format!("{domain}:{port}")
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], port)))
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Ok(());
        }
    };

    if let Some(code) = reject_code {
        client.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect_timeout(&target_addr, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(_) => {
            client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Ok(());
        }
    };

    client.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])?;

    upstream.set_read_timeout(Some(Duration::from_secs(3)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = client_read.read(&mut buf) {
            if n == 0 || upstream_write.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let mut buf = [0u8; 8192];
    while let Ok(n) = upstream.read(&mut buf) {
        if n == 0 || client.write_all(&buf[..n]).is_err() {
            break;
        }
    }

    let _ = t1.join();
    Ok(())
}

#[test]
fn test_socks5_gateway_extraction_end_to_end() {
    let mock_web = TcpListener::bind("127.0.0.1:0").unwrap();
    let web_addr = mock_web.local_addr().unwrap();
    let web_stop = Arc::new(AtomicBool::new(false));
    let web_stop_clone = Arc::clone(&web_stop);

    let web_thread = thread::spawn(move || {
        mock_web.set_nonblocking(true).unwrap();
        while !web_stop_clone.load(Ordering::Relaxed) {
            match mock_web.accept() {
                Ok((mut stream, _)) => {
                    let mut req_buf = [0u8; 1024];
                    let _ = stream.read(&mut req_buf);
                    let body = r#"
                        <!DOCTYPE html>
                        <html>
                        <head><title>Remote Tunneled Page</title></head>
                        <body>
                            <article>
                                <h1>Article Via DNS Tunnel</h1>
                                <p>Successfully extracted across local SOCKS5 tunnel over TCP.</p>
                            </article>
                        </body>
                        </html>
                    "#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let gw_config = GatewayConfig {
        allow_loopback_for_testing: true,
        ..Default::default()
    };
    let gateway = Gateway::new(gw_config);
    let gw_server = GatewayServer::bind("127.0.0.1:0".parse().unwrap(), gateway).unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_thread) = gw_server.spawn();

    let (proxy_addr, proxy) = TestSocks5Proxy::bind(None, None, false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let adapter = Socks5TunnelAdapter::new(
        Socks5Config {
            proxy_addr,
            auth: None,
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(3),
            max_response_bytes: 1024 * 1024,
        },
        Socks5Target::Ip(gw_addr),
    );

    assert!(adapter.is_connected());

    let target_page_url = format!("http://{}/article", web_addr);
    let post_body = serde_json::json!({ "url": target_page_url }).to_string();
    let http_request = format!(
        "POST /extract HTTP/1.1\r\nHost: gateway.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        post_body.len(),
        post_body
    );

    let raw_response = adapter.send_request(http_request.as_bytes()).unwrap();
    let response_str = String::from_utf8_lossy(&raw_response);

    assert!(response_str.starts_with("HTTP/1.1 200 OK"));
    let json_start = response_str.find("\r\n\r\n").unwrap() + 4;
    let page: ExtractedPage = serde_json::from_str(&response_str[json_start..]).unwrap();

    assert_eq!(page.title, "Remote Tunneled Page");
    assert_eq!(page.headings.len(), 1);
    assert_eq!(page.headings[0].text, "Article Via DNS Tunnel");

    web_stop.store(true, Ordering::Relaxed);
    proxy_shutdown.store(true, Ordering::Relaxed);
    gw_handle.stop();

    let _ = web_thread.join();
    let _ = proxy_thread.join();
    let _ = gw_thread.join();
}

#[test]
fn test_socks5_with_masterdns_credentials() {
    let gw_server = GatewayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Gateway::new(GatewayConfig::default()),
    )
    .unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_thread) = gw_server.spawn();

    let masterdns_auth = Socks5Auth {
        username: "master_dns_vpn".to_string(),
        password: "test_secret_pass".to_string(),
    };

    let (proxy_addr, proxy) =
        TestSocks5Proxy::bind(Some(masterdns_auth.clone()), None, false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let good_adapter = Socks5TunnelAdapter::new(
        Socks5Config {
            proxy_addr,
            auth: Some(masterdns_auth),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );

    let health_check = b"GET /health HTTP/1.1\r\nHost: gateway.local\r\nConnection: close\r\n\r\n";
    let resp = good_adapter.send_request(health_check).unwrap();
    assert!(String::from_utf8_lossy(&resp).contains(r#"{"status":"ok"}"#));

    let bad_adapter = Socks5TunnelAdapter::new(
        Socks5Config {
            proxy_addr,
            auth: Some(Socks5Auth {
                username: "master_dns_vpn".into(),
                password: "wrong_password".into(),
            }),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );

    let bad_res = bad_adapter.send_request(health_check);
    assert!(matches!(bad_res, Err(CoreError::TunnelFailed(_))));

    proxy_shutdown.store(true, Ordering::Relaxed);
    gw_handle.stop();
    let _ = proxy_thread.join();
    let _ = gw_thread.join();
}

#[test]
fn test_socks5_failures_and_non_fallback_invariant() {
    let offline_addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();
    let offline_adapter = Socks5TunnelAdapter::new(
        Socks5Config {
            proxy_addr: offline_addr,
            connect_timeout: Duration::from_millis(100),
            ..Default::default()
        },
        Socks5Target::Ip("127.0.0.1:4040".parse().unwrap()),
    );

    assert!(!offline_adapter.is_connected());
    let err = offline_adapter.send_request(b"test").unwrap_err();
    assert!(matches!(err, CoreError::TunnelFailed(_)));

    let policy = RoutingPolicy::new();
    let dummy_target =
        mewser_core::ParsedTarget::parse("https://blocked-foreign.example/").unwrap();
    let fallback_res = policy.handle_tunnel_failure(&dummy_target, err);
    assert_eq!(fallback_res, Err(CoreError::DirectFallbackForbidden));
}

#[test]
fn test_socks5_rejected_connection_and_timeout() {
    let (proxy_addr, proxy) = TestSocks5Proxy::bind(None, Some(0x05), false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let adapter = Socks5TunnelAdapter::new(
        Socks5Config {
            proxy_addr,
            ..Default::default()
        },
        Socks5Target::Domain("127.0.0.1".into(), 4040),
    );

    let err = adapter.send_request(b"test").unwrap_err();
    assert!(matches!(err, CoreError::TunnelFailed(ref msg) if msg.contains("Connection refused")));

    proxy_shutdown.store(true, Ordering::Relaxed);
    let _ = proxy_thread.join();

    let (hang_addr, hang_proxy) = TestSocks5Proxy::bind(None, None, true).unwrap();
    let (hang_shutdown, hang_thread) = hang_proxy.spawn();

    let timeout_adapter = Socks5TunnelAdapter::new(
        Socks5Config {
            proxy_addr: hang_addr,
            read_timeout: Duration::from_millis(200),
            ..Default::default()
        },
        Socks5Target::Domain("127.0.0.1".into(), 4040),
    );

    let timeout_err = timeout_adapter.send_request(b"test").unwrap_err();
    assert!(matches!(timeout_err, CoreError::TunnelFailed(_)));

    hang_shutdown.store(true, Ordering::Relaxed);
    let _ = hang_thread.join();
}

#[test]
fn test_socks5_response_size_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = listener.local_addr().unwrap();

    let srv_thread = thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut req = [0u8; 64];
            let _ = s.read(&mut req);
            let big = vec![b'A'; 20_000];
            let _ = s.write_all(&big);
        }
    });

    let (proxy_addr, proxy) = TestSocks5Proxy::bind(None, None, false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let adapter = Socks5TunnelAdapter::new(
        Socks5Config {
            proxy_addr,
            max_response_bytes: 4096,
            ..Default::default()
        },
        Socks5Target::Ip(target_addr),
    );

    let err = adapter.send_request(b"ping").unwrap_err();
    assert!(matches!(err, CoreError::TunnelFailed(ref msg) if msg.contains("exceeded limit")));

    proxy_shutdown.store(true, Ordering::Relaxed);
    let _ = proxy_thread.join();
    let _ = srv_thread.join();
}
