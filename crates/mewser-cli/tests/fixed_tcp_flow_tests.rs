use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mewser_cli::{BrowsingMode, ClientEngine, ClientError, NavigationResult};
use mewser_core::tunnel::FixedTcpConfig;
use mewser_gateway::{Gateway, GatewayConfig, GatewayServer};

/// Mock TCP proxy that simulates a local MasterDNS TCP tunnel listener
/// forwarding raw streams to a statically configured remote Gateway address.
struct MockMasterDnsTcpTunnel {
    listener: TcpListener,
    target_gateway: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl MockMasterDnsTcpTunnel {
    fn bind(target_gateway: SocketAddr) -> std::io::Result<(SocketAddr, Self)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        Ok((
            addr,
            Self {
                listener,
                target_gateway,
                shutdown: Arc::new(AtomicBool::new(false)),
            },
        ))
    }

    fn spawn(self) -> (Arc<AtomicBool>, JoinHandle<()>) {
        let shutdown = Arc::clone(&self.shutdown);
        let shutdown_ret = Arc::clone(&self.shutdown);
        let listener = self.listener;
        let target = self.target_gateway;

        let handle = thread::spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((client_stream, _)) => {
                        thread::spawn(move || {
                            let _ = forward_stream(client_stream, target);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        (shutdown_ret, handle)
    }
}

fn forward_stream(mut client: TcpStream, target: SocketAddr) -> std::io::Result<()> {
    let mut server = TcpStream::connect(target)?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    server.set_read_timeout(Some(Duration::from_secs(3)))?;

    let mut client_clone = client.try_clone()?;
    let mut server_clone = server.try_clone()?;

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match client_clone.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if server.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = server.shutdown(std::net::Shutdown::Write);
    });

    let t2 = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match server_clone.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if client.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client.shutdown(std::net::Shutdown::Write);
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn spawn_test_origin_server() -> (SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_thread = Arc::clone(&shutdown);

    let handle = thread::spawn(move || {
        while !shutdown_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut req = [0u8; 1024];
                    let _ = stream.read(&mut req);

                    let html_body = r#"<!DOCTYPE html>
<html>
<head><title>Fixed TCP Article</title></head>
<body>
    <article>
        <h1>Welcome to Fixed TCP</h1>
        <p>This content arrived through a simulated raw MasterDNS TCP tunnel.</p>
        <a href="/next-page">Next Article</a>
    </article>
</body>
</html>"#;

                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/html; charset=utf-8\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n\
                         {html_body}",
                        html_body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    (addr, shutdown, handle)
}

#[test]
fn test_successful_fixed_tcp_flow_to_gateway() {
    let (origin_addr, origin_sd, origin_th) = spawn_test_origin_server();

    let gw_cfg = GatewayConfig {
        allow_loopback_for_testing: true,
        ..Default::default()
    };
    let gateway = Gateway::new(gw_cfg);

    let gw_server = GatewayServer::bind("127.0.0.1:0".parse().unwrap(), gateway).unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_th) = gw_server.spawn();

    let (tunnel_addr, tunnel) = MockMasterDnsTcpTunnel::bind(gw_addr).unwrap();
    let (tunnel_sd, tunnel_th) = tunnel.spawn();

    let client_config = FixedTcpConfig {
        endpoint: tunnel_addr,
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(10),
        write_timeout: Duration::from_secs(5),
        max_response_bytes: 2 * 1024 * 1024,
    };

    let engine = ClientEngine::with_fixed_tcp(client_config);
    let target_url = format!("http://{origin_addr}/article");

    let result = engine
        .navigate(&target_url, BrowsingMode::ResilientText)
        .expect("Navigation via fixed-TCP tunnel must succeed");

    match result {
        NavigationResult::TextPage(page) => {
            assert_eq!(page.title, "Fixed TCP Article");
            assert_eq!(page.headings.len(), 1);
            assert_eq!(page.headings[0].text, "Welcome to Fixed TCP");
            assert_eq!(page.links.len(), 1);
            assert_eq!(page.links[0].text, "Next Article");
        }
    }

    tunnel_sd.store(true, Ordering::Relaxed);
    gw_handle.stop();
    origin_sd.store(true, Ordering::Relaxed);
    let _ = tunnel_th.join();
    let _ = gw_th.join();
    let _ = origin_th.join();
}

#[test]
fn test_malformed_and_error_responses_via_fixed_tcp() {
    // 1. Malformed non-HTTP response
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"GARBAGE NON-HTTP RESPONSE");
            }
        });

        let config = FixedTcpConfig {
            endpoint: addr,
            ..Default::default()
        };
        let engine = ClientEngine::with_fixed_tcp(config);
        let res = engine.navigate("https://example.com/", BrowsingMode::ResilientText);

        assert!(matches!(res, Err(ClientError::MalformedResponse(_))));
        let _ = handle.join();
    }

    // 2. Gateway error status (e.g. 403 Forbidden)
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let resp = "HTTP/1.1 403 Forbidden\r\n\
                            Content-Type: application/json\r\n\
                            Content-Length: 35\r\n\
                            Connection: close\r\n\r\n\
                            {\"error\":\"Target blocked by SSRF\"}";
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let config = FixedTcpConfig {
            endpoint: addr,
            ..Default::default()
        };
        let engine = ClientEngine::with_fixed_tcp(config);
        let res = engine.navigate("https://example.com/", BrowsingMode::ResilientText);

        match res {
            Err(ClientError::Gateway { status, message }) => {
                assert_eq!(status, 403);
                assert_eq!(message, "Target blocked by SSRF");
            }
            other => panic!("Expected Gateway error 403, got: {other:?}"),
        }
        let _ = handle.join();
    }
}

#[test]
fn test_fixed_tcp_timeouts_and_size_limits() {
    // 1. Timeout handling
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                // Hang without responding
                thread::sleep(Duration::from_millis(600));
            }
        });

        let config = FixedTcpConfig {
            endpoint: addr,
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_millis(200),
            write_timeout: Duration::from_millis(200),
            max_response_bytes: 2 * 1024 * 1024,
        };
        let engine = ClientEngine::with_fixed_tcp(config);
        let res = engine.navigate("https://example.com/", BrowsingMode::ResilientText);

        match res {
            Err(ClientError::Tunnel(msg)) => {
                assert!(msg.to_lowercase().contains("timed out"));
            }
            other => panic!("Expected Tunnel timeout error, got: {other:?}"),
        }
        let _ = handle.join();
    }

    // 2. Response size limit exceeded
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let huge_body = vec![b'A'; 5000];
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    huge_body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&huge_body);
            }
        });

        let config = FixedTcpConfig {
            endpoint: addr,
            max_response_bytes: 500, // Small limit
            ..Default::default()
        };
        let engine = ClientEngine::with_fixed_tcp(config);
        let res = engine.navigate("https://example.com/", BrowsingMode::ResilientText);

        assert!(matches!(res, Err(ClientError::ResponseTooLarge { .. })));
        let _ = handle.join();
    }
}

#[test]
fn test_closed_connection_and_offline_handling() {
    // 1. Connection immediately closed by remote listener without sending data
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                // Immediately drop stream to trigger EOF
            }
        });

        let config = FixedTcpConfig {
            endpoint: addr,
            ..Default::default()
        };
        let engine = ClientEngine::with_fixed_tcp(config);
        let res = engine.navigate("https://example.com/", BrowsingMode::ResilientText);

        assert!(matches!(res, Err(ClientError::MalformedResponse(_))));
        let _ = handle.join();
    }

    // 2. Offline endpoint
    {
        let unused_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = FixedTcpConfig {
            endpoint: unused_addr,
            connect_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let engine = ClientEngine::with_fixed_tcp(config);
        let res = engine.navigate("https://example.com/", BrowsingMode::ResilientText);

        assert!(matches!(res, Err(ClientError::Tunnel(_))));
    }
}

#[test]
fn test_explicit_mode_and_fail_closed_invariants() {
    let dummy_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let config = FixedTcpConfig {
        endpoint: dummy_addr,
        ..Default::default()
    };
    let engine = ClientEngine::with_fixed_tcp(config);

    // Standard web mode must be rejected explicitly without network activity
    let res = engine.navigate("https://example.com/", BrowsingMode::StandardWeb);
    assert_eq!(res, Err(ClientError::StandardWebNotImplemented));
}

#[test]
fn test_cli_binary_fixed_tcp_flags() {
    let cargo_bin = env!("CARGO_BIN_EXE_mewser");

    // 1. --gateway forbidden in fixed-tcp mode
    let out = std::process::Command::new(cargo_bin)
        .args([
            "--mode",
            "resilient-text",
            "--url",
            "https://example.com/",
            "--transport",
            "fixed-tcp",
            "--gateway",
            "127.0.0.1:4040",
        ])
        .output()
        .expect("Failed to execute binary");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--gateway cannot be configured in fixed-tcp transport mode"));

    // 2. --proxy-user forbidden in fixed-tcp mode
    let out_user = std::process::Command::new(cargo_bin)
        .args([
            "--mode",
            "resilient-text",
            "--url",
            "https://example.com/",
            "--transport",
            "fixed-tcp",
            "--proxy-user",
            "admin",
        ])
        .output()
        .expect("Failed to execute binary");

    assert!(!out_user.status.success());
    let stderr_user = String::from_utf8_lossy(&out_user.stderr);
    assert!(stderr_user.contains("Proxy authentication is only applicable to SOCKS5 transport"));

    // 3. invalid transport rejected
    let out_bad = std::process::Command::new(cargo_bin)
        .args([
            "--mode",
            "resilient-text",
            "--url",
            "https://example.com/",
            "--transport",
            "unknown-proto",
        ])
        .output()
        .expect("Failed to execute binary");

    assert!(!out_bad.status.success());
    let stderr_bad = String::from_utf8_lossy(&out_bad.stderr);
    assert!(stderr_bad.contains("Unsupported transport 'unknown-proto'"));
}
