use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mewser_core::proxy::{PolicyProxy, PolicyProxyConfig};
use mewser_core::router::RoutingPolicy;

const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

struct FixtureServer {
    pub addr: SocketAddr,
    pub requests_handled: Arc<AtomicUsize>,
    _shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl FixtureServer {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests_handled = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let reqs = Arc::clone(&requests_handled);
        let shut = Arc::clone(&shutdown);

        thread::spawn(move || {
            let _ = listener.set_nonblocking(false);
            for stream_res in listener.incoming() {
                if shut.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(mut stream) = stream_res {
                    let req_count = Arc::clone(&reqs);
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut buf = [0u8; 4096];
                        if let Ok(n) = stream.read(&mut buf) {
                            if n == 0 {
                                return;
                            }
                            req_count.fetch_add(1, Ordering::SeqCst);
                            let req = String::from_utf8_lossy(&buf[..n]);

                            if req.contains("GET /index.html") || req.contains("GET / ") {
                                let body = "<!DOCTYPE html><html><head><title>Mewser Standard Web Fixture</title>\
                                            <link rel=\"stylesheet\" href=\"/style.css\">\
                                            <script src=\"/app.js\"></script>\
                                            <style>@font-face { font-family: 'TestFont'; src: url('/font.woff2'); }</style>\
                                            </head><body>\
                                            <h1>Standard Web Embedded Engine Test</h1>\
                                            <img id=\"fixture-img\" src=\"/image.png\">\
                                            <iframe id=\"fixture-frame\" src=\"/frame.html\"></iframe>\
                                            <a href=\"/redirect\">Redirect Test</a>\
                                            </body></html>";
                                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                                let _ = stream.write_all(resp.as_bytes());
                            } else if req.contains("GET /style.css") {
                                let body = "body { background: #121212; color: #fff; font-family: 'TestFont', sans-serif; }";
                                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                                let _ = stream.write_all(resp.as_bytes());
                            } else if req.contains("GET /app.js") {
                                let body = "document.body.setAttribute('data-js-loaded', 'true');";
                                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                                let _ = stream.write_all(resp.as_bytes());
                            } else if req.contains("GET /image.png") {
                                let header = format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", PNG_1X1.len());
                                let _ = stream.write_all(header.as_bytes());
                                let _ = stream.write_all(PNG_1X1);
                            } else if req.contains("GET /font.woff2") {
                                let font_bytes = b"wOF2mockfontbytes1234567890";
                                let header = format!("HTTP/1.1 200 OK\r\nContent-Type: font/woff2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", font_bytes.len());
                                let _ = stream.write_all(header.as_bytes());
                                let _ = stream.write_all(font_bytes);
                            } else if req.contains("GET /frame.html") {
                                let body = "<html><body><p id=\"frame-content\">Iframe Subdocument Content</p></body></html>";
                                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                                let _ = stream.write_all(resp.as_bytes());
                            } else if req.contains("GET /redirect") {
                                let resp = "HTTP/1.1 302 Found\r\nLocation: /index.html?redirected=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let _ = stream.write_all(resp.as_bytes());
                            } else if req.contains("Upgrade: websocket")
                                || req.contains("upgrade: websocket")
                            {
                                // WebSocket upgrade response mock
                                let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
                                let _ = stream.write_all(resp.as_bytes());
                            } else {
                                let body = "Not Found";
                                let resp = format!("HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                                let _ = stream.write_all(resp.as_bytes());
                            }
                        }
                    });
                }
            }
        });

        Self {
            addr,
            requests_handled,
            _shutdown: shutdown,
        }
    }
}

#[test]
fn test_standard_web_fixture_site_and_all_subresources_routed_through_proxy() {
    let fixture = FixtureServer::start();
    let fixture_port = fixture.addr.port();

    // Configure routing policy: route 127.0.0.1 direct
    let mut policy = RoutingPolicy::new();
    policy.add_direct_domain("127.0.0.1");

    let proxy_cfg = PolicyProxyConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        policy,
        "127.0.0.1:1080".parse().unwrap(),
    )
    .with_allow_loopback_for_testing(true);

    let proxy = PolicyProxy::start(proxy_cfg).unwrap();
    let proxy_addr = proxy.bound_addr();

    // Helper closure to fetch URL through PolicyProxy
    let fetch = |path: &str| -> (String, Vec<u8>) {
        let mut stream = TcpStream::connect(proxy_addr).unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            fixture_port, path, fixture_port
        );
        stream.write_all(req.as_bytes()).unwrap();

        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp).to_string();
        (text, resp)
    };

    // 1. Fetch Main HTML
    let (html_resp, _) = fetch("/index.html");
    assert!(html_resp.starts_with("HTTP/1.1 200 OK"));
    assert!(html_resp.contains("<title>Mewser Standard Web Fixture</title>"));
    assert!(html_resp.contains("Standard Web Embedded Engine Test"));

    // 2. Fetch CSS
    let (css_resp, _) = fetch("/style.css");
    assert!(css_resp.starts_with("HTTP/1.1 200 OK"));
    assert!(css_resp.contains("background: #121212"));

    // 3. Fetch JavaScript
    let (js_resp, _) = fetch("/app.js");
    assert!(js_resp.starts_with("HTTP/1.1 200 OK"));
    assert!(js_resp.contains("data-js-loaded"));

    // 4. Fetch Image (PNG binary)
    let (img_header, img_bytes) = fetch("/image.png");
    assert!(img_header.starts_with("HTTP/1.1 200 OK"));
    assert!(img_header.contains("image/png"));
    assert!(img_bytes.windows(4).any(|w| w == b"\x89PNG"));

    // 5. Fetch Font (WOFF2)
    let (font_header, font_bytes) = fetch("/font.woff2");
    assert!(font_header.starts_with("HTTP/1.1 200 OK"));
    assert!(font_bytes.windows(4).any(|w| w == b"wOF2"));

    // 6. Fetch Iframe subdocument
    let (frame_resp, _) = fetch("/frame.html");
    assert!(frame_resp.starts_with("HTTP/1.1 200 OK"));
    assert!(frame_resp.contains("Iframe Subdocument Content"));

    // 7. Test Redirect
    let (redir_resp, _) = fetch("/redirect");
    assert!(redir_resp.starts_with("HTTP/1.1 302 Found"));
    assert!(redir_resp.contains("Location: /index.html?redirected=1"));

    // 8. Test WebSocket handshake
    {
        let mut stream = TcpStream::connect(proxy_addr).unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/ws HTTP/1.1\r\n\
             Host: 127.0.0.1:{}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            fixture_port, fixture_port
        );
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = vec![0u8; 1024];
        let n = stream.read(&mut resp).unwrap();
        let ws_resp = String::from_utf8_lossy(&resp[..n]);
        assert!(ws_resp.starts_with("HTTP/1.1 101 Switching Protocols"));
        assert!(ws_resp.contains("Upgrade: websocket"));
    }

    // Verify statistics
    let stats = proxy.stats();
    assert_eq!(stats.total_requests.load(Ordering::SeqCst), 8);
    assert_eq!(stats.direct_requests.load(Ordering::SeqCst), 8);
    // Subresources: style.css, app.js, image.png, font.woff2, frame.html = 5
    assert_eq!(stats.subresource_requests.load(Ordering::SeqCst), 5);
    assert_eq!(stats.tunnel_requests.load(Ordering::SeqCst), 0);
    assert_eq!(stats.blocked_requests.load(Ordering::SeqCst), 0);

    // Verify fixture server actually received and processed all 8 requests through the proxy
    assert_eq!(fixture.requests_handled.load(Ordering::SeqCst), 8);
}
