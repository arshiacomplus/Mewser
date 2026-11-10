use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mewser_gateway::{
    extract_page, ContentBlock, Gateway, GatewayConfig, GatewayError, GatewayServer,
};
use url::Url;

#[test]
fn test_ssrf_blocks_private_and_cloud_metadata_targets() {
    let config = GatewayConfig::default();
    let gateway = Gateway::new(config);

    let blocked_targets = [
        "http://127.0.0.1:8080/",
        "http://127.0.0.2:9000/",
        "http://10.0.0.1/",
        "http://10.254.254.254/secret",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost:3000/",
        "http://sub.localhost/",
        "http://[::1]:8080/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://metadata.google.internal/",
        "http://instance-data/",
    ];

    for target in blocked_targets {
        let res = gateway.extract(target);
        assert!(
            matches!(res, Err(GatewayError::SsrfBlocked { .. })),
            "Expected SSRF block for target: {target}, got: {:?}",
            res
        );
    }
}

#[test]
fn test_cgnat_shared_address_space_rejection() {
    let config = GatewayConfig::default();
    let gateway = Gateway::new(config);

    let blocked_cgnat = [
        "http://100.64.0.0/",
        "http://100.64.0.1/",
        "http://100.100.0.1:8080/data",
        "http://100.127.255.255/",
    ];

    for target in blocked_cgnat {
        let res = gateway.extract(target);
        assert!(
            matches!(res, Err(GatewayError::SsrfBlocked { .. })),
            "Expected SSRF block for CGNAT target {target}, got: {:?}",
            res
        );
    }
}

#[test]
fn test_scheme_and_credential_rejections() {
    let config = GatewayConfig::default();
    let gateway = Gateway::new(config);

    assert!(matches!(
        gateway.extract("file:///etc/passwd"),
        Err(GatewayError::UnsupportedScheme(_))
    ));
    assert!(matches!(
        gateway.extract("ftp://files.example.com/doc"),
        Err(GatewayError::UnsupportedScheme(_))
    ));
    assert!(matches!(
        gateway.extract("gopher://old.example.com/"),
        Err(GatewayError::UnsupportedScheme(_))
    ));
    assert!(matches!(
        gateway.extract("javascript:alert(1)"),
        Err(GatewayError::UnsupportedScheme(_))
    ));
    assert!(matches!(
        gateway.extract("http://admin:secret@example.com/login"),
        Err(GatewayError::CredentialsNotAllowed)
    ));
}

#[test]
fn test_html_extraction_prioritization_and_cleaning() {
    let html = r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>   Page Title - News Site   </title>
            <meta name="description" content="Detailed article summary.">
        </head>
        <body>
            <header>
                <nav><a href="/menu">Menu</a></nav>
            </header>
            <article>
                <h1>Headline Story</h1>
                <p>Opening paragraph with informative analysis.</p>
                <img src="/images/chart.png" alt="Market trends">
                <h2>Key Findings</h2>
                <ol>
                    <li>First finding</li>
                    <li>Second finding</li>
                </ol>
                <p>Read the reference at <a href="https://external.example/report">Full Report</a>.</p>
            </article>
            <aside>
                <p>Sidebar advertisement</p>
                <a href="/ad">Buy now</a>
            </aside>
            <footer>
                <p>Site footer text</p>
            </footer>
            <script>let tracking = true;</script>
            <style>body { color: red; }</style>
        </body>
        </html>
    "#;

    let base_url = Url::parse("https://news.example.com/article/101").unwrap();
    let page = extract_page(html, &base_url);

    assert_eq!(page.title, "Page Title - News Site");
    assert_eq!(
        page.description.as_deref(),
        Some("Detailed article summary.")
    );

    assert_eq!(page.headings.len(), 2);
    assert_eq!(page.headings[0].level, 1);
    assert_eq!(page.headings[0].text, "Headline Story");
    assert_eq!(page.headings[1].level, 2);
    assert_eq!(page.headings[1].text, "Key Findings");

    assert_eq!(page.images.len(), 1);
    assert_eq!(page.images[0].id, 1);
    assert_eq!(
        page.images[0].src,
        "https://news.example.com/images/chart.png"
    );
    assert_eq!(page.images[0].alt.as_deref(), Some("Market trends"));

    assert_eq!(page.links.len(), 1);
    assert_eq!(page.links[0].text, "Full Report");
    assert_eq!(page.links[0].href, "https://external.example/report");

    let text_blocks: Vec<&str> = page
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Paragraph { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(text_blocks.len(), 2);
    assert!(text_blocks[0].contains("Opening paragraph"));
    assert!(text_blocks[1].contains("Read the reference"));

    let json = serde_json::to_string(&page).unwrap();
    assert!(json.contains("headline_story") || json.contains("Headline Story"));
}

#[test]
fn test_response_size_limit_aborts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let server_thread = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            listener.set_nonblocking(true).unwrap();
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let large_body = "A".repeat(20_000);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        large_body.len(),
                        large_body
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

    let config = GatewayConfig {
        max_response_bytes: 4096, // 4KB limit
        allow_loopback_for_testing: true,
        ..Default::default()
    };
    let gateway = Gateway::new(config);

    let result = gateway.extract(&format!("http://127.0.0.1:{port}/large"));
    stop.store(true, Ordering::Relaxed);
    let _ = server_thread.join();

    assert!(
        matches!(
            result,
            Err(GatewayError::ResponseTooLarge { limit: 4096, .. })
        ),
        "Expected ResponseTooLarge, got: {:?}",
        result
    );
}

#[test]
fn test_redirect_limit_exceeded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let server_thread = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            listener.set_nonblocking(true).unwrap();
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/loop\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let config = GatewayConfig {
        max_redirects: 3,
        allow_loopback_for_testing: true,
        ..Default::default()
    };
    let gateway = Gateway::new(config);

    let result = gateway.extract(&format!("http://127.0.0.1:{port}/loop"));
    stop.store(true, Ordering::Relaxed);
    let _ = server_thread.join();

    assert!(
        matches!(result, Err(GatewayError::RedirectLimitExceeded(3))),
        "Expected RedirectLimitExceeded(3), got: {:?}",
        result
    );
}

#[test]
fn test_redirect_to_ssrf_target_is_blocked() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let server_thread = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            listener.set_nonblocking(true).unwrap();
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    // Redirects to cloud metadata endpoint
                    let resp = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/secret\r\nConnection: close\r\n\r\n";
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

    let config = GatewayConfig {
        allow_loopback_for_testing: true,
        ..Default::default()
    };
    let gateway = Gateway::new(config);

    let result = gateway.extract(&format!("http://127.0.0.1:{port}/trigger-ssrf"));
    stop.store(true, Ordering::Relaxed);
    let _ = server_thread.join();

    assert!(
        matches!(result, Err(GatewayError::SsrfBlocked { .. })),
        "Expected SsrfBlocked upon redirect, got: {:?}",
        result
    );
}

#[test]
fn test_loopback_gateway_server_api() {
    let config = GatewayConfig::default();
    let gateway = Gateway::new(config);

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = GatewayServer::bind(server_addr, gateway).unwrap();
    let actual_addr = server.local_addr().unwrap();
    let (handle, join_handle) = server.spawn();

    // 1. Test GET /health
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains(r#"{"status":"ok"}"#));

    // 2. Test GET /extract with bad scheme
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    stream
        .write_all(b"GET /extract?url=file:///etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));

    // 3. Test POST /extract with SSRF destination
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    let post_body = r#"{"url":"http://169.254.169.254/latest/meta-data"}"#;
    let post_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        post_body.len(),
        post_body
    );
    stream.write_all(post_req.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"));

    // Stop server
    handle.stop();
    let _ = join_handle.join();
}

#[test]
fn test_authenticated_gateway_server_api() {
    let secret_token = "secure-test-token-0123456789abcdef0123456789abcdef";
    let config = GatewayConfig {
        auth_token: Some(secret_token.to_string()),
        ..Default::default()
    };
    let gateway = Gateway::new(config);

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = GatewayServer::bind(server_addr, gateway).unwrap();
    let actual_addr = server.local_addr().unwrap();
    let (handle, join_handle) = server.spawn();

    // 1. GET /health should remain public and unauthenticated
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains(r#"{"status":"ok"}"#));

    // 2. GET /extract without credentials should return 401
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    stream
        .write_all(b"GET /extract?url=https://example.com/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));

    // 3. POST /extract without credentials should return 401
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    let post_body = r#"{"url":"https://example.com/"}"#;
    let post_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        post_body.len(),
        post_body
    );
    stream.write_all(post_req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));

    // 4. GET /extract with invalid credentials should return 401
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    stream
        .write_all(b"GET /extract?url=https://example.com/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));

    // 5. POST /extract with malformed authorization header should return 401
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    let post_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dXNlcjpwYXNz\r\nContent-Length: {}\r\n\r\n{}",
        post_body.len(),
        post_body
    );
    stream.write_all(post_req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));

    // 6. POST /extract with valid credentials should pass auth (SSRF target gives 403 Forbidden, not 401)
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    let ssrf_body = r#"{"url":"http://127.0.0.1:8080/admin"}"#;
    let auth_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}",
        secret_token,
        ssrf_body.len(),
        ssrf_body
    );
    stream.write_all(auth_req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"));

    // 7. GET /extract with valid credentials should pass auth (bad scheme gives 400 Bad Request, not 401)
    let mut stream = TcpStream::connect(actual_addr).unwrap();
    let get_req = format!(
        "GET /extract?url=file:///etc/passwd HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
        secret_token
    );
    stream.write_all(get_req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request"));

    handle.stop();
    let _ = join_handle.join();
}
