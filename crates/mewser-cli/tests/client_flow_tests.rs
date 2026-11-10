use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mewser_cli::{
    format_page_for_terminal, resolve_proxy_auth, BrowsingMode, ClientEngine, ClientError,
    NavigationResult, ENV_SOCKS5_PASSWORD,
};
use mewser_core::tunnel::{Socks5Auth, Socks5Config, Socks5Target};
use mewser_core::{CoreError, RoutingPolicy};
use mewser_gateway::{Gateway, GatewayConfig, GatewayServer};

struct TestSocksProxy {
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    auth: Option<Socks5Auth>,
    hang: bool,
}

impl TestSocksProxy {
    fn bind(auth: Option<Socks5Auth>, hang: bool) -> std::io::Result<(SocketAddr, Self)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let proxy = Self {
            listener,
            shutdown: Arc::new(AtomicBool::new(false)),
            auth,
            hang,
        };
        Ok((addr, proxy))
    }

    fn spawn(self) -> (Arc<AtomicBool>, JoinHandle<()>) {
        let shutdown_thread = Arc::clone(&self.shutdown);
        let shutdown_ret = Arc::clone(&self.shutdown);
        let listener = self.listener;
        let auth = self.auth;
        let hang = self.hang;

        let handle = thread::spawn(move || {
            while !shutdown_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let auth_clone = auth.clone();
                        thread::spawn(move || {
                            let _ = run_socks_connection(stream, auth_clone, hang);
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

fn run_socks_connection(
    mut client: TcpStream,
    auth: Option<Socks5Auth>,
    hang: bool,
) -> std::io::Result<()> {
    if hang {
        thread::sleep(Duration::from_secs(5));
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
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip)?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port)?;
            SocketAddr::from((ip, u16::from_be_bytes(port)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut domain_buf = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain_buf)?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port)?;
            let domain = String::from_utf8_lossy(&domain_buf);
            let p = u16::from_be_bytes(port);
            format!("{domain}:{p}")
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], p)))
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Ok(());
        }
    };

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
fn test_explicit_mode_requirement() {
    let dummy_cfg = Socks5Config::default();
    let engine = ClientEngine::with_socks5(
        dummy_cfg,
        Socks5Target::Ip(SocketAddr::from(([127, 0, 0, 1], 4040))),
    );

    let res = engine.navigate("https://example.com/page", BrowsingMode::StandardWeb);
    assert_eq!(res, Err(ClientError::StandardWebNotImplemented));

    let invalid_mode = "unknown-mode".parse::<BrowsingMode>();
    assert!(matches!(invalid_mode, Err(ClientError::InvalidMode(_))));
}

#[test]
fn test_successful_client_flow_through_socks5_to_gateway() {
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
                        <head><title>Mewser Test Article</title></head>
                        <body>
                            <article>
                                <h1>Client Flow Verified</h1>
                                <p>This page was requested in Resilient Text mode over SOCKS5.</p>
                                <img src="/cat.png" alt="Mewser Mascot">
                                <ul>
                                    <li>Feature A</li>
                                    <li>Feature B</li>
                                </ul>
                                <a href="/next">Next Link</a>
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

    let gw_server = GatewayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Gateway::new(GatewayConfig {
            allow_loopback_for_testing: true,
            ..Default::default()
        }),
    )
    .unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_thread) = gw_server.spawn();

    let (proxy_addr, proxy) = TestSocksProxy::bind(None, false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(3),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );

    let destination_url = format!("http://{web_addr}/test-article");
    let nav_result = client
        .navigate(&destination_url, BrowsingMode::ResilientText)
        .unwrap();

    match nav_result {
        NavigationResult::TextPage(page) => {
            assert_eq!(page.title, "Mewser Test Article");
            assert_eq!(page.headings.len(), 1);
            assert_eq!(page.headings[0].text, "Client Flow Verified");
            assert_eq!(page.images.len(), 1);
            assert_eq!(page.images[0].alt.as_deref(), Some("Mewser Mascot"));

            let output = format_page_for_terminal(&page);
            assert!(output.contains("Title: Mewser Test Article"));
            assert!(output.contains("# Client Flow Verified"));
            assert!(output.contains("This page was requested in Resilient Text mode"));
            assert!(output.contains("[Image #1: Mewser Mascot | Source:"));
            assert!(output.contains("[1] Next Link ->"));
        }
    }

    web_stop.store(true, Ordering::Relaxed);
    proxy_shutdown.store(true, Ordering::Relaxed);
    gw_handle.stop();

    let _ = web_thread.join();
    let _ = proxy_thread.join();
    let _ = gw_thread.join();
}

#[test]
fn test_socks5_authentication_and_offline_failures() {
    let gw_server = GatewayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Gateway::new(GatewayConfig::default()),
    )
    .unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_thread) = gw_server.spawn();

    let expected_auth = Socks5Auth {
        username: "master_dns_vpn".to_string(),
        password: "real_password".to_string(),
    };

    let (proxy_addr, proxy) = TestSocksProxy::bind(Some(expected_auth), false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let bad_client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            auth: Some(Socks5Auth {
                username: "master_dns_vpn".to_string(),
                password: "wrong_password".to_string(),
            }),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );

    let err = bad_client
        .navigate("https://example.com/", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(err, ClientError::Tunnel(ref msg) if msg.contains("rejected by proxy")));

    let offline_client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr: "127.0.0.1:19998".parse().unwrap(),
            connect_timeout: Duration::from_millis(100),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );

    let offline_err = offline_client
        .navigate("https://example.com/", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(offline_err, ClientError::Tunnel(_)));

    let policy = RoutingPolicy::new();
    let target = mewser_core::ParsedTarget::parse("https://blocked-foreign.example/").unwrap();
    let fallback =
        policy.handle_tunnel_failure(&target, CoreError::TunnelFailed("Proxy offline".into()));
    assert_eq!(fallback, Err(CoreError::DirectFallbackForbidden));

    proxy_shutdown.store(true, Ordering::Relaxed);
    gw_handle.stop();
    let _ = proxy_thread.join();
    let _ = gw_thread.join();
}

#[test]
fn test_gateway_errors_and_malformed_responses_handled_safely() {
    let gw_server = GatewayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Gateway::new(GatewayConfig::default()),
    )
    .unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_thread) = gw_server.spawn();

    let (proxy_addr, proxy) = TestSocksProxy::bind(None, false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );

    let ssrf_err = client
        .navigate("http://127.0.0.1:8080/admin", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(ssrf_err, ClientError::Gateway { status: 403, .. }));

    let bad_scheme = client
        .navigate("ftp://example.com/file", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(bad_scheme, ClientError::InvalidUrl(_)));

    let creds_err = client
        .navigate("http://user:pass@example.com/", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(creds_err, ClientError::InvalidUrl(_)));

    proxy_shutdown.store(true, Ordering::Relaxed);
    gw_handle.stop();
    let _ = proxy_thread.join();
    let _ = gw_thread.join();

    let bogus_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let bogus_addr = bogus_server.local_addr().unwrap();

    let bogus_thread = thread::spawn(move || {
        if let Ok((mut s, _)) = bogus_server.accept() {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"NOT_VALID_HTTP_RESPONSE\r\n\r\n");
        }
    });

    let (proxy_addr2, proxy2) = TestSocksProxy::bind(None, false).unwrap();
    let (proxy_shutdown2, proxy_thread2) = proxy2.spawn();

    let bogus_client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr: proxy_addr2,
            ..Default::default()
        },
        Socks5Target::Ip(bogus_addr),
    );

    let malformed_err = bogus_client
        .navigate("https://example.com/", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(malformed_err, ClientError::MalformedResponse(_)));

    proxy_shutdown2.store(true, Ordering::Relaxed);
    let _ = proxy_thread2.join();
    let _ = bogus_thread.join();
}

#[test]
fn test_timeouts_and_response_size_limits() {
    let (hang_proxy_addr, hang_proxy) = TestSocksProxy::bind(None, true).unwrap();
    let (hang_shutdown, hang_thread) = hang_proxy.spawn();

    let client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr: hang_proxy_addr,
            read_timeout: Duration::from_millis(200),
            ..Default::default()
        },
        Socks5Target::Ip(SocketAddr::from(([127, 0, 0, 1], 4040))),
    );

    let timeout_err = client
        .navigate("https://example.com/", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(timeout_err, ClientError::Tunnel(_)));

    hang_shutdown.store(true, Ordering::Relaxed);
    let _ = hang_thread.join();

    let huge_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let huge_addr = huge_server.local_addr().unwrap();

    let huge_thread = thread::spawn(move || {
        if let Ok((mut s, _)) = huge_server.accept() {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let huge_body = vec![b'X'; 10_000];
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            let _ = s.write_all(&huge_body);
        }
    });

    let (proxy_addr, proxy) = TestSocksProxy::bind(None, false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    let size_limited_client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            max_response_bytes: 2048,
            ..Default::default()
        },
        Socks5Target::Ip(huge_addr),
    );

    let size_err = size_limited_client
        .navigate("https://example.com/", BrowsingMode::ResilientText)
        .unwrap_err();
    assert!(matches!(size_err, ClientError::ResponseTooLarge { .. }));

    proxy_shutdown.store(true, Ordering::Relaxed);
    let _ = proxy_thread.join();
    let _ = huge_thread.join();
}

#[test]
fn test_credentials_handling_via_env_var() {
    let gw_server = GatewayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Gateway::new(GatewayConfig::default()),
    )
    .unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_thread) = gw_server.spawn();

    let proxy_user = "test_env_user".to_string();
    let proxy_pass = "secret_env_pass_789".to_string();

    let expected_auth = Socks5Auth {
        username: proxy_user.clone(),
        password: proxy_pass.clone(),
    };

    let (proxy_addr, proxy) = TestSocksProxy::bind(Some(expected_auth), false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    // 1. Set environment variable MEWSER_SOCKS5_PASSWORD
    env::set_var(ENV_SOCKS5_PASSWORD, &proxy_pass);
    let resolved_auth = resolve_proxy_auth(Some(proxy_user)).unwrap();
    env::remove_var(ENV_SOCKS5_PASSWORD);

    assert!(resolved_auth.is_some());

    // 2. Client engine successfully connects using the resolved auth
    let client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            auth: resolved_auth,
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(3),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );

    // Should authenticate successfully and reach gateway
    let health_check = client.navigate("http://127.0.0.1:8080/admin", BrowsingMode::ResilientText);
    // Gateway responds with 403 SSRF blocked, proving authentication through SOCKS5 succeeded
    assert!(matches!(
        health_check,
        Err(ClientError::Gateway { status: 403, .. })
    ));

    // 3. Verify that passwords are never included in error messages
    let err_str = format!("{:?}", health_check);
    assert!(!err_str.contains(&proxy_pass));

    proxy_shutdown.store(true, Ordering::Relaxed);
    gw_handle.stop();
    let _ = proxy_thread.join();
    let _ = gw_thread.join();
}

#[test]
fn test_client_gateway_token_authentication() {
    let auth_token = "mewser-test-secret-token-1234567890abcdef";

    let gw_server = GatewayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Gateway::new(GatewayConfig {
            allow_loopback_for_testing: false,
            auth_token: Some(auth_token.to_string()),
            ..Default::default()
        }),
    )
    .unwrap();
    let gw_addr = gw_server.local_addr().unwrap();
    let (gw_handle, gw_thread) = gw_server.spawn();

    let (proxy_addr, proxy) = TestSocksProxy::bind(None, false).unwrap();
    let (proxy_shutdown, proxy_thread) = proxy.spawn();

    // 1. Client without auth token -> 401
    let unauth_client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(3),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    );
    let res1 = unauth_client.navigate("http://127.0.0.1:8080/admin", BrowsingMode::ResilientText);
    assert!(
        matches!(res1, Err(ClientError::Gateway { status: 401, .. })),
        "Expected 401, got {:?}",
        res1
    );

    // 2. Client with wrong auth token -> 401
    let bad_client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(3),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    )
    .with_auth_token(Some("wrong-secret-value".to_string()));
    let res2 = bad_client.navigate("http://127.0.0.1:8080/admin", BrowsingMode::ResilientText);
    assert!(
        matches!(res2, Err(ClientError::Gateway { status: 401, .. })),
        "Expected 401, got {:?}",
        res2
    );

    // 3. Client with valid auth token -> passes auth (SSRF destination gives 403, proving auth succeeded)
    let good_client = ClientEngine::with_socks5(
        Socks5Config {
            proxy_addr,
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(3),
            ..Default::default()
        },
        Socks5Target::Ip(gw_addr),
    )
    .with_auth_token(Some(auth_token.to_string()));
    let res3 = good_client.navigate("http://127.0.0.1:8080/admin", BrowsingMode::ResilientText);
    assert!(
        matches!(res3, Err(ClientError::Gateway { status: 403, .. })),
        "Expected 403 SSRF blocked after valid auth, got {:?}",
        res3
    );

    // 4. Verify secrets are never in errors or Display output
    let err_msg = format!("{}", res2.unwrap_err());
    assert!(!err_msg.contains("wrong-secret-value"));
    assert!(!err_msg.contains(auth_token));

    proxy_shutdown.store(true, Ordering::Relaxed);
    gw_handle.stop();
    let _ = proxy_thread.join();
    let _ = gw_thread.join();
}
