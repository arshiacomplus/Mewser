use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::thread;

use mewser_core::error::CoreError;
use mewser_core::proxy::{PolicyProxy, PolicyProxyConfig};
use mewser_core::router::RoutingPolicy;

#[test]
fn test_policy_proxy_rejects_non_loopback_bind() {
    let external_addr: SocketAddr = "192.168.1.50:8080".parse().unwrap();
    let config = PolicyProxyConfig::new(
        external_addr,
        RoutingPolicy::new(),
        "127.0.0.1:1080".parse().unwrap(),
    );

    let res = PolicyProxy::start(config);
    match res {
        Err(CoreError::Configuration(msg)) => {
            assert!(msg.contains("must bind to a loopback address"));
        }
        _ => panic!("Expected configuration error for non-loopback bind"),
    }
}

#[test]
fn test_policy_proxy_direct_routing_and_subresource_tracking() {
    // 1. Mock upstream HTTP server for a "direct" target
    let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let upstream_handle = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("GET /main.html") {
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello direct!";
                stream.write_all(resp.as_bytes()).unwrap();
            } else if req.contains("GET /app.js") {
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nconsole.log(1);";
                stream.write_all(resp.as_bytes()).unwrap();
            }
        }
    });

    // 2. Configure routing policy to route "127.0.0.1" directly
    let mut policy = RoutingPolicy::new();
    policy.add_direct_domain("127.0.0.1");

    // 3. Start PolicyProxy on loopback with allow_loopback_for_testing = true
    let proxy_cfg = PolicyProxyConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        policy,
        "127.0.0.1:1080".parse().unwrap(),
    )
    .with_allow_loopback_for_testing(true);

    let proxy = PolicyProxy::start(proxy_cfg).unwrap();
    let proxy_addr = proxy.bound_addr();

    // 4. Client requests main document
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    let req = format!(
        "GET http://127.0.0.1:{}/main.html HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    client.write_all(req.as_bytes()).unwrap();

    let mut resp = String::new();
    client.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("Hello direct!"));

    // 5. Client requests subresource /app.js
    let mut client2 = TcpStream::connect(proxy_addr).unwrap();
    let req2 = format!(
        "GET http://127.0.0.1:{}/app.js HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    client2.write_all(req2.as_bytes()).unwrap();

    let mut resp2 = String::new();
    client2.read_to_string(&mut resp2).unwrap();
    assert!(resp2.starts_with("HTTP/1.1 200 OK"));
    assert!(resp2.contains("console.log(1);"));

    // Check statistics
    assert_eq!(proxy.stats().total_requests.load(Ordering::SeqCst), 2);
    assert_eq!(proxy.stats().direct_requests.load(Ordering::SeqCst), 2);
    assert_eq!(proxy.stats().subresource_requests.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.stats().tunnel_requests.load(Ordering::SeqCst), 0);

    upstream_handle.join().unwrap();
}

#[test]
fn test_policy_proxy_tunnel_fail_closed_when_socks5_offline() {
    // SOCKS5 endpoint is closed / offline
    let closed_socks5: SocketAddr = "127.0.0.1:19999".parse().unwrap();

    // Policy routes "blocked.tunnel" over tunnel (not in direct list)
    let policy = RoutingPolicy::new();

    let proxy_cfg = PolicyProxyConfig::new("127.0.0.1:0".parse().unwrap(), policy, closed_socks5)
        .with_allow_loopback_for_testing(true);

    let proxy = PolicyProxy::start(proxy_cfg).unwrap();
    let proxy_addr = proxy.bound_addr();

    // Client sends CONNECT for tunnel-designated destination
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"CONNECT secret.tunnel:443 HTTP/1.1\r\nHost: secret.tunnel:443\r\n\r\n")
        .unwrap();

    let mut resp = String::new();
    client.read_to_string(&mut resp).unwrap();

    // Must return 502 Bad Gateway and fail-closed
    assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"));
    assert!(resp.contains("fail-closed"));

    // Verify stats
    assert_eq!(proxy.stats().total_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        proxy.stats().failed_tunnel_requests.load(Ordering::SeqCst),
        1
    );
    assert_eq!(proxy.stats().direct_requests.load(Ordering::SeqCst), 0);
}

#[test]
fn test_policy_proxy_blocks_ssrf_destinations() {
    let policy = RoutingPolicy::new();
    // allow_loopback_for_testing is false by default -> SSRF strictly blocked
    let proxy_cfg = PolicyProxyConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        policy,
        "127.0.0.1:1080".parse().unwrap(),
    );

    let proxy = PolicyProxy::start(proxy_cfg).unwrap();
    let proxy_addr = proxy.bound_addr();

    // Requesting loopback 127.0.0.1:8080 must return 403 Forbidden
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
        .unwrap();

    let mut resp = String::new();
    client.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"));
    assert!(resp.contains("SSRF defense"));

    assert_eq!(proxy.stats().blocked_requests.load(Ordering::SeqCst), 1);
}

#[test]
fn test_policy_proxy_connect_tunnel_to_mock_socks5() {
    // 1. Mock SOCKS5 server that accepts handshake and CONNECT for a domain
    let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    let socks_handle = thread::spawn(move || {
        let (mut stream, _) = socks_listener.accept().unwrap();
        // Read greeting
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        // Send greeting reply
        stream.write_all(&[0x05, 0x00]).unwrap();

        // Read CONNECT request: 0x05, 0x01, 0x00, 0x03, len, domain, port
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 0x05); // VER
        assert_eq!(header[1], 0x01); // CMD = CONNECT
        assert_eq!(header[3], 0x03); // ATYP = Domain

        let mut len = [0u8; 1];
        stream.read_exact(&mut len).unwrap();
        let mut domain_bytes = vec![0u8; len[0] as usize];
        stream.read_exact(&mut domain_bytes).unwrap();
        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).unwrap();

        let domain = String::from_utf8(domain_bytes).unwrap();
        assert_eq!(domain, "tunneled.example");

        // Send SOCKS5 success reply
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .unwrap();

        // Now mock TLS/data transfer over established tunnel
        let mut client_data = [0u8; 4];
        stream.read_exact(&mut client_data).unwrap();
        assert_eq!(&client_data, b"PING");
        stream.write_all(b"PONG").unwrap();
    });

    let policy = RoutingPolicy::new(); // unlisted domain -> routed via tunnel
    let proxy_cfg = PolicyProxyConfig::new("127.0.0.1:0".parse().unwrap(), policy, socks_addr)
        .with_allow_loopback_for_testing(true);

    let proxy = PolicyProxy::start(proxy_cfg).unwrap();
    let proxy_addr = proxy.bound_addr();

    // Client sends CONNECT for tunneled.example:443
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"CONNECT tunneled.example:443 HTTP/1.1\r\nHost: tunneled.example:443\r\n\r\n")
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 Connection Established"));

    // Send payload through tunnel
    client.write_all(b"PING").unwrap();
    let mut pong_buf = [0u8; 4];
    client.read_exact(&mut pong_buf).unwrap();
    assert_eq!(&pong_buf, b"PONG");

    assert_eq!(proxy.stats().tunnel_requests.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.stats().direct_requests.load(Ordering::SeqCst), 0);

    socks_handle.join().unwrap();
}
