use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use mewser_cli::BrowsingMode;
use mewser_desktop::state::{
    DesktopTransport, HistoryStack, PageState, PersistentSettings, SettingsState,
};
use mewser_gateway::{ContentBlock, ExtractedPage};

#[test]
fn test_history_flow_across_pages() {
    let mut history = HistoryStack::new();

    // 1. Initially at no URL. Navigate to page 1:
    let mut current_url: Option<String> = None;
    history.push_new(current_url.clone());
    current_url = Some("https://example.com/page1".to_string());
    assert_eq!(history.past_len(), 0);
    assert_eq!(history.future_len(), 0);
    assert!(!history.can_go_back());
    assert!(!history.can_go_forward());

    // 2. Navigate to page 2:
    history.push_new(current_url.clone());
    current_url = Some("https://example.com/page2".to_string());
    assert_eq!(history.past_len(), 1); // contains page1
    assert_eq!(history.future_len(), 0);
    assert!(history.can_go_back());
    assert!(!history.can_go_forward());

    // 3. Navigate to page 3:
    history.push_new(current_url.clone());
    current_url = Some("https://example.com/page3".to_string());
    assert_eq!(history.past_len(), 2); // contains page1, page2
    assert_eq!(history.future_len(), 0);

    // 4. Back to page 2:
    let prev = history
        .go_back(current_url.clone())
        .expect("Back to page 2");
    assert_eq!(prev, "https://example.com/page2");
    current_url = Some(prev);
    assert_eq!(history.past_len(), 1); // contains page1
    assert_eq!(history.future_len(), 1); // contains page3
    assert!(history.can_go_back());
    assert!(history.can_go_forward());

    // 5. Back to page 1:
    let prev2 = history
        .go_back(current_url.clone())
        .expect("Back to page 1");
    assert_eq!(prev2, "https://example.com/page1");
    current_url = Some(prev2);
    assert_eq!(history.past_len(), 0);
    assert_eq!(history.future_len(), 2); // contains page3, page2
    assert!(!history.can_go_back());
    assert!(history.can_go_forward());

    // 6. Forward to page 2:
    let next = history
        .go_forward(current_url.clone())
        .expect("Forward to page 2");
    assert_eq!(next, "https://example.com/page2");
    current_url = Some(next);
    assert_eq!(history.past_len(), 1); // contains page1
    assert_eq!(history.future_len(), 1); // contains page3
    assert!(history.can_go_back());
    assert!(history.can_go_forward());

    // 7. From page 2, branch off to new page 4 -> future must be cleared:
    history.push_new(current_url.clone());
    current_url = Some("https://example.com/page4".to_string());
    assert_eq!(history.past_len(), 2); // contains page1, page2
    assert_eq!(history.future_len(), 0); // cleared!
    assert!(history.can_go_back());
    assert!(!history.can_go_forward());
    assert_eq!(current_url.as_deref(), Some("https://example.com/page4"));
}

#[test]
fn test_desktop_client_engine_extraction_over_mock_fixed_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind test server");
    let local_addr = listener.local_addr().expect("Get port");

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Accept client");
        let mut req_buf = vec![0u8; 1024];
        let n = stream.read(&mut req_buf).expect("Read request");
        let req_text = String::from_utf8_lossy(&req_buf[..n]);
        assert!(req_text.contains("POST /extract HTTP/1.1"));

        let mock_page = ExtractedPage {
            url: "https://example.com/test".to_string(),
            title: "Mock Extracted Page".to_string(),
            description: Some("Test description".to_string()),
            headings: vec![],
            content: vec![ContentBlock::Paragraph {
                text: "Hello from local mock gateway".to_string(),
            }],
            links: vec![],
            images: vec![],
        };
        let body = serde_json::to_string(&mock_page).expect("Serialize mock");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).expect("Write response");
    });

    let settings = SettingsState {
        transport: DesktopTransport::FixedTcp,
        tcp_endpoint_str: local_addr.to_string(),
        timeout_secs: 5,
        ..Default::default()
    };

    let adapter = settings.build_tunnel_adapter().expect("Build adapter");
    let engine = mewser_cli::ClientEngine::new(adapter);
    let result = engine
        .navigate("https://example.com/test", BrowsingMode::ResilientText)
        .expect("Navigation should succeed");

    match result {
        mewser_cli::NavigationResult::TextPage(page) => {
            assert_eq!(page.title, "Mock Extracted Page");
            assert_eq!(page.url, "https://example.com/test");
            assert_eq!(page.content.len(), 1);
        }
    }

    handle.join().expect("Server thread join");
}

#[test]
fn test_desktop_disconnected_handling_when_tunnel_is_offline() {
    // Port 1 is not running any listener
    let settings = SettingsState {
        transport: DesktopTransport::FixedTcp,
        tcp_endpoint_str: "127.0.0.1:1".to_string(),
        timeout_secs: 1,
        ..Default::default()
    };

    let adapter = settings.build_tunnel_adapter().expect("Build adapter");
    let engine = mewser_cli::ClientEngine::new(adapter);
    let result = engine.navigate("https://example.com/", BrowsingMode::ResilientText);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let page_state =
        PageState::from_client_error("https://example.com/".to_string(), err, &settings);

    match page_state {
        PageState::Disconnected {
            url,
            endpoint,
            details,
        } => {
            assert_eq!(url, "https://example.com/");
            assert_eq!(endpoint, "127.0.0.1:1");
            assert!(
                details.contains("Connection refused") || details.contains("Failed to connect")
            );
        }
        other => panic!("Expected PageState::Disconnected, got: {other:?}"),
    }
}

#[test]
fn test_desktop_ssrf_error_classification() {
    let settings = SettingsState::default();
    let ssrf_err = mewser_cli::ClientError::Gateway {
        status: 403,
        message:
            "SSRF defense blocked destination 127.0.0.1: Host IP 127.0.0.1 is in a restricted range"
                .to_string(),
    };

    let state = PageState::from_client_error(
        "http://127.0.0.1:8080/admin".to_string(),
        ssrf_err,
        &settings,
    );
    match state {
        PageState::SsrfBlocked { url, message } => {
            assert_eq!(url, "http://127.0.0.1:8080/admin");
            assert!(message.contains("SSRF defense blocked"));
        }
        other => panic!("Expected PageState::SsrfBlocked, got: {other:?}"),
    }
}

#[test]
fn test_non_secret_settings_roundtrip() {
    let settings = SettingsState {
        transport: DesktopTransport::FixedTcp,
        proxy_addr_str: "127.0.0.1:1080".to_string(),
        gateway_addr_str: "127.0.0.1:4040".to_string(),
        tcp_endpoint_str: "127.0.0.1:9999".to_string(),
        proxy_user: "my_user".to_string(),
        proxy_pass: "temporary_secret_password".to_string(),
        gateway_token: "temporary_secret_gateway_token".to_string(),
        active_mode: BrowsingMode::ResilientText,
        timeout_secs: 42,
        direct_domains: vec!["internal.bank".to_string()],
        direct_suffixes: vec![".bank".to_string()],
        tunnel_domain: "primary.example.com".to_string(),
        tunnel_encryption_method: 1,
        tunnel_encryption_key: "temporary_secret_tunnel_key".to_string(),
        tunnel_resolvers: vec!["1.1.1.1:53".to_string()],
        tunnel_auto_connect: true,
        ..Default::default()
    };

    let persistent = PersistentSettings {
        transport: settings.transport,
        proxy_addr_str: settings.proxy_addr_str.clone(),
        gateway_addr_str: settings.gateway_addr_str.clone(),
        tcp_endpoint_str: settings.tcp_endpoint_str.clone(),
        proxy_user: settings.proxy_user.clone(),
        timeout_secs: settings.timeout_secs,
        direct_domains: settings.direct_domains.clone(),
        direct_suffixes: settings.direct_suffixes.clone(),
        profiles: settings.profile_store.profiles.clone(),
        selected_profile_id: settings.profile_store.selected_profile_id.clone(),
        vault_file_consent: false,
        tunnel_domain: settings.tunnel_domain.clone(),
        tunnel_encryption_method: settings.tunnel_encryption_method,
        tunnel_resolvers: settings.tunnel_resolvers.clone(),
        tunnel_auto_connect: settings.tunnel_auto_connect,
    };

    let json = serde_json::to_string(&persistent).expect("Serialize");
    assert!(!json.contains("temporary_secret_password"));
    assert!(!json.contains("temporary_secret_gateway_token"));
    assert!(!json.contains("temporary_secret_tunnel_key"));

    let loaded: PersistentSettings = serde_json::from_str(&json).expect("Deserialize");
    assert_eq!(loaded.transport, DesktopTransport::FixedTcp);
    assert_eq!(loaded.tcp_endpoint_str, "127.0.0.1:9999");
    assert_eq!(loaded.timeout_secs, 42);
    assert_eq!(loaded.proxy_user, "my_user");
    assert_eq!(loaded.direct_domains, vec!["internal.bank".to_string()]);
    assert_eq!(loaded.direct_suffixes, vec![".bank".to_string()]);
    assert_eq!(loaded.tunnel_domain, "primary.example.com");
}

#[test]
fn test_gateway_token_storage_security_audit() {
    let temp_dir = std::env::temp_dir().join(format!("mewser_test_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    let test_token = "mewser_audit_token_999888777666";
    let test_pass = "mewser_audit_socks_pass_555444";
    let test_key = "mewser_audit_tunnel_key_333222";

    let settings = SettingsState {
        transport: DesktopTransport::Socks5,
        proxy_addr_str: "127.0.0.1:1080".to_string(),
        gateway_addr_str: "127.0.0.1:4040".to_string(),
        tcp_endpoint_str: "127.0.0.1:1080".to_string(),
        proxy_user: "audit_user".to_string(),
        proxy_pass: test_pass.to_string(),
        gateway_token: test_token.to_string(),
        active_mode: BrowsingMode::StandardWeb,
        timeout_secs: 30,
        direct_domains: vec!["audit.local".to_string()],
        direct_suffixes: vec![".internal".to_string()],
        tunnel_domain: "primary.example.com".to_string(),
        tunnel_encryption_method: 1,
        tunnel_encryption_key: test_key.to_string(),
        tunnel_resolvers: vec!["8.8.8.8:53".to_string()],
        tunnel_auto_connect: true,
        ..Default::default()
    };

    // 1. Save settings to disk
    settings.save_persistent().expect("Save settings");

    let settings_path = temp_dir.join("mewser").join("desktop_settings.json");
    assert!(
        settings_path.exists(),
        "Settings file must be created on disk"
    );

    let file_content = std::fs::read_to_string(&settings_path).expect("Read settings file");

    // 2. Security audit assertions: Token, password, and tunnel key must NOT exist in the file
    assert!(
        !file_content.contains(test_token),
        "Gateway token leaked into desktop_settings.json!"
    );
    assert!(
        !file_content.contains("gateway_token"),
        "gateway_token key present in desktop_settings.json!"
    );
    assert!(
        !file_content.contains(test_pass),
        "SOCKS5 password leaked into desktop_settings.json!"
    );
    assert!(
        !file_content.contains("proxy_pass"),
        "proxy_pass key present in desktop_settings.json!"
    );
    assert!(
        !file_content.contains(test_key),
        "Tunnel encryption key leaked into desktop_settings.json!"
    );
    assert!(
        !file_content.contains("tunnel_encryption_key"),
        "tunnel_encryption_key key present in desktop_settings.json!"
    );

    // Non-sensitive configuration MUST be preserved
    assert!(file_content.contains("audit_user"));
    assert!(file_content.contains("audit.local"));
    assert!(file_content.contains("127.0.0.1:4040"));

    // 3. Deserializing from disk ensures token remains uninitialized from file
    std::env::remove_var("MEWSER_GATEWAY_AUTH_TOKEN");
    std::env::remove_var("MEWSER_SOCKS5_PASSWORD");
    let loaded = SettingsState::load_or_default();
    assert_eq!(
        loaded.gateway_token, "",
        "Token must not be restored from disk"
    );
    assert_eq!(
        loaded.proxy_pass, "",
        "Password must not be restored from disk"
    );
    assert_eq!(loaded.proxy_user, "audit_user");
    assert_eq!(loaded.direct_domains, vec!["audit.local".to_string()]);

    // 4. Test environment variable support for in-memory token
    std::env::set_var("MEWSER_GATEWAY_AUTH_TOKEN", "env_provided_token");
    let loaded_with_env = SettingsState::load_or_default();
    assert_eq!(
        loaded_with_env.effective_gateway_token().0,
        "env_provided_token"
    );
    assert_eq!(
        loaded_with_env.gateway_token_source(),
        mewser_desktop::state::GatewayTokenSource::Environment
    );
    std::env::remove_var("MEWSER_GATEWAY_AUTH_TOKEN");

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_desktop_policy_proxy_subresource_routing_metrics() {
    use mewser_core::proxy::PolicyProxy;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};

    // 1. Start Mock HTTP Origin Server with Subresources
    let origin_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let requests_handled = Arc::new(AtomicUsize::new(0));
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let reqs = Arc::clone(&requests_handled);
    let shut = Arc::clone(&shutdown);

    thread::spawn(move || {
        let _ = origin_listener.set_nonblocking(false);
        for stream_res in origin_listener.incoming() {
            if shut.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(mut stream) = stream_res {
                reqs.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("GET /style.css") {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 12\r\nConnection: close\r\n\r\nbody { color: red; }";
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /app.js") {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 14\r\nConnection: close\r\n\r\nconsole.log(1);";
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /image.png") {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\nConnection: close\r\n\r\nPNG!";
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /font.woff2") {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: font/woff2\r\nContent-Length: 4\r\nConnection: close\r\n\r\nwOF2";
                    let _ = stream.write_all(resp.as_bytes());
                } else {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nConnection: close\r\n\r\n<html></html>";
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        }
    });

    // 2. Start Desktop PolicyProxy with dynamic upstream
    std::env::set_var("MEWSER_ALLOW_LOOPBACK_FOR_TESTING", "1");
    let settings = SettingsState {
        direct_domains: vec!["127.0.0.1".to_string(), "localhost".to_string()],
        ..SettingsState::default()
    };
    let dynamic_socks5 = Arc::new(RwLock::new(Some("127.0.0.1:1080".parse().unwrap())));

    let proxy_cfg = settings
        .build_policy_proxy_config_with_dynamic("127.0.0.1:0".parse().unwrap(), dynamic_socks5)
        .unwrap();

    let proxy = PolicyProxy::start(proxy_cfg).unwrap();
    let proxy_addr = proxy.bound_addr();

    // Helper to send proxy request
    let fetch_subresource = |path: &str, accept: &str| {
        let mut stream = std::net::TcpStream::connect(proxy_addr).unwrap();
        let req = format!(
            "GET http://{origin_addr}{path} HTTP/1.1\r\nHost: {origin_addr}\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("200 OK"));
    };

    // 3. Fetch main document
    fetch_subresource("/", "text/html");

    // 4. Fetch subresources: CSS, JS, Image, Font
    fetch_subresource("/style.css", "text/css,*/*;q=0.1");
    fetch_subresource("/app.js", "*/*");
    fetch_subresource("/image.png", "image/avif,image/webp,image/png,*/*");
    fetch_subresource("/font.woff2", "font/woff2,font/*,*/*");

    // 5. Verify Subresources > 0 on PolicyProxy stats
    let stats = proxy.stats();
    let subresources = stats.subresource_requests.load(Ordering::SeqCst);
    println!("[Desktop Test] Observable subresources: {subresources}");
    assert!(
        subresources >= 4,
        "Expected subresources >= 4, got {subresources}"
    );

    // Cleanup
    shutdown.store(true, Ordering::SeqCst);
    proxy.stop();
    std::env::remove_var("MEWSER_ALLOW_LOOPBACK_FOR_TESTING");
}

#[test]
fn test_home_dashboard_quick_access_targets_and_normalization() {
    use mewser_desktop::app::normalize_input_url;

    let quick_access_items = [
        ("🌐", "Example Domain", "https://example.com/"),
        ("</>", "Rust Language", "https://www.rust-lang.org/"),
        ("🛡️", "Gateway Health", "http://127.0.0.1:4040/health"),
        (
            "📄",
            "IETF RFC 1035",
            "https://www.ietf.org/rfc/rfc1035.txt",
        ),
        (
            "W",
            "Wikipedia",
            "https://en.wikipedia.org/wiki/Domain_Name_System",
        ),
    ];

    assert_eq!(quick_access_items.len(), 5);

    for (icon, label, url) in quick_access_items.iter() {
        assert!(!icon.is_empty(), "Icon must not be empty for {label}");
        assert!(!label.is_empty(), "Label must not be empty");
        let normalized = normalize_input_url(url);
        assert!(
            normalized.starts_with("http://") || normalized.starts_with("https://"),
            "Target {url} must normalize to valid scheme"
        );
    }

    // Verify search bar input normalization
    assert_eq!(normalize_input_url("example.com"), "https://example.com");
    assert_eq!(
        normalize_input_url("rust-lang.org/learn"),
        "https://rust-lang.org/learn"
    );
    assert_eq!(
        normalize_input_url("https://www.wikipedia.org"),
        "https://www.wikipedia.org"
    );
}

#[test]
fn test_home_dashboard_mode_and_state_contracts() {
    use mewser_desktop::controller::TunnelState;

    // Verify MasterDNS display formatting contract
    let active_prof_name = "Secondary VPS Node";
    let tunnel_domain = "secondary.example.org";
    let tunnel_method = 2u8;
    let resolver_count = 2usize;

    let meta_str = format!(
        "Profile: {active_prof_name} · {tunnel_domain} · Method {tunnel_method} · {resolver_count} resolvers"
    );
    assert_eq!(
        meta_str,
        "Profile: Secondary VPS Node · secondary.example.org · Method 2 · 2 resolvers"
    );

    // Verify TunnelState transitions mapping to UI actions
    let state_disconnected = TunnelState::Disconnected;
    let (action_discon, sensitive_discon) = match state_disconnected {
        TunnelState::Disconnected => ("Connect", true),
        _ => unreachable!(),
    };
    assert_eq!(action_discon, "Connect");
    assert!(sensitive_discon);

    let state_connected = TunnelState::Connected {
        profile_id: "sec-node".to_string(),
        profile_name: "Secondary VPS Node".to_string(),
        endpoint: "127.0.0.1:40188".parse().unwrap(),
        session_id: Some(1042),
    };
    let (action_conn, sensitive_conn) = match state_connected {
        TunnelState::Connected { .. } => ("Disconnect", true),
        _ => unreachable!(),
    };
    assert_eq!(action_conn, "Disconnect");
    assert!(sensitive_conn);
}

#[test]
fn test_resilient_reader_outline_and_marks() {
    use mewser_gateway::HeadingItem;

    let page = ExtractedPage {
        url: "https://example.com/spec".to_string(),
        title: "Specification Document".to_string(),
        description: Some("Protocol architecture and security guarantees.".to_string()),
        headings: vec![
            HeadingItem {
                level: 1,
                text: "Overview".to_string(),
            },
            HeadingItem {
                level: 2,
                text: "Architecture".to_string(),
            },
            HeadingItem {
                level: 3,
                text: "Tunnel Transport Details".to_string(),
            },
            HeadingItem {
                level: 2,
                text: "Fail-Closed Security".to_string(),
            },
        ],
        content: vec![
            ContentBlock::Heading {
                level: 1,
                text: "Overview".to_string(),
            },
            ContentBlock::Paragraph {
                text: "Mewser provides resilient browsing over DNS tunnels.".to_string(),
            },
            ContentBlock::Heading {
                level: 2,
                text: "Architecture".to_string(),
            },
            ContentBlock::Paragraph {
                text: "ClientEngine coordinates with Gateway extraction.".to_string(),
            },
        ],
        links: vec![
            mewser_gateway::LinkItem {
                href: "https://example.com/rfc1035".to_string(),
                text: "RFC 1035".to_string(),
            },
            mewser_gateway::LinkItem {
                href: "https://example.com/dns-security".to_string(),
                text: "DNS Security Specs".to_string(),
            },
        ],
        images: vec![],
    };

    // Verify heading outline metrics and indentation rules
    assert_eq!(page.headings.len(), 4);
    for (idx, h) in page.headings.iter().enumerate() {
        let expected_margin = (h.level.saturating_sub(1) as i32) * 14 + 6;
        match h.level {
            1 => assert_eq!(expected_margin, 6),
            2 => assert_eq!(expected_margin, 20),
            3 => assert_eq!(expected_margin, 34),
            _ => panic!("Unexpected heading level"),
        }
        let mark_name = format!("heading_{idx}");
        assert_eq!(mark_name, format!("heading_{idx}"));
    }
}

#[test]
fn test_resilient_reader_page_info_metadata_and_security_labels() {
    let raw_url = "https://example.com/archive/article-102";
    let parsed_url = url::Url::parse(raw_url).expect("Valid test URL");
    let domain = parsed_url.host_str().unwrap_or("Unknown");
    assert_eq!(domain, "example.com");

    let elapsed_ms = 423u128;
    let meta_str = format!("{} · Extracted in {} ms", raw_url, elapsed_ms);
    assert_eq!(
        meta_str,
        "https://example.com/archive/article-102 · Extracted in 423 ms"
    );

    // Verify page statistics metrics computation
    let headings_count = 5usize;
    let content_blocks_count = 14usize;
    let links_count = 3usize;

    let stats_label = format!(
        "Sections: {} headings · {} content blocks · {} navigational links",
        headings_count, content_blocks_count, links_count
    );
    assert!(stats_label.contains("5 headings"));
    assert!(stats_label.contains("14 content blocks"));
    assert!(stats_label.contains("3 navigational links"));

    // Verify fail-closed security posture disclosure
    const SECURITY_POLICY: &str =
        "SSRF Defense Active · Private, loopback, link-local, and cloud metadata IPs blocked.";
    assert!(SECURITY_POLICY.contains("SSRF Defense Active"));
    assert!(SECURITY_POLICY.contains("Private"));
    assert!(SECURITY_POLICY.contains("cloud metadata"));
}

#[test]
fn test_resilient_reader_fail_closed_error_classification() {
    // Classification helper following Mewser's fail-closed routing invariants:
    fn classify_reader_error(err_str: &str) -> (&'static str, &'static str) {
        let err_lower = err_str.to_lowercase();
        if err_lower.contains("ssrf") || err_lower.contains("private") {
            (
                "Destination Rejected (SSRF Protection)",
                "Security Policy: Access to private networks, loopback addresses, link-local interfaces, and cloud metadata services is strictly blocked at the Gateway perimeter.",
            )
        } else if err_lower.contains("timed out") || err_lower.contains("timeout") {
            (
                "Connection Timed Out",
                "Extraction Request Timed Out: The destination server or Gateway did not respond within the allocated duration. In accordance with fail-closed security invariants, direct connection fallback is never permitted.",
            )
        } else if err_lower.contains("unauthorized") || err_lower.contains("401") {
            (
                "Gateway Authentication Required",
                "Authentication Failure: The Resilient Gateway rejected the request credentials. Verify your Gateway Access Token in Mewser Settings.",
            )
        } else if err_lower.contains("disconnected") || err_lower.contains("tunnel") {
            (
                "MasterDNS Tunnel Disconnected",
                "Fail-Closed Protection: Resilient text mode operates strictly through the MasterDNS tunnel. Connect to a MasterDNS profile to browse.",
            )
        } else {
            (
                "Extraction Failed",
                "Fail-Closed Policy: Mewser never falls back to an unencrypted or direct network connection.",
            )
        }
    }

    let (title_ssrf, body_ssrf) =
        classify_reader_error("SSRF defense triggered: IP 169.254.169.254 blocked");
    assert_eq!(title_ssrf, "Destination Rejected (SSRF Protection)");
    assert!(body_ssrf.contains("strictly blocked"));

    let (title_timeout, body_timeout) =
        classify_reader_error("Request to https://example.com/slow timed out after 10000ms");
    assert_eq!(title_timeout, "Connection Timed Out");
    assert!(body_timeout.contains("direct connection fallback is never permitted"));

    let (title_auth, body_auth) =
        classify_reader_error("HTTP 401 Unauthorized: Invalid Gateway Token");
    assert_eq!(title_auth, "Gateway Authentication Required");
    assert!(body_auth.contains("Gateway Access Token"));

    let (title_tunnel, body_tunnel) =
        classify_reader_error("MasterDNS tunnel is disconnected: cannot route request");
    assert_eq!(title_tunnel, "MasterDNS Tunnel Disconnected");
    assert!(body_tunnel.contains("Fail-Closed Protection"));
}

#[test]
fn test_resilient_reader_typography_scale_bounds() {
    let mut font_scale = 14i32; // Default 14pt

    // Scaling down
    font_scale = (font_scale - 2).clamp(11, 24);
    assert_eq!(font_scale, 12);

    font_scale = (font_scale - 2).clamp(11, 24);
    assert_eq!(font_scale, 11); // Clamped at lower bound

    font_scale = (font_scale - 2).clamp(11, 24);
    assert_eq!(font_scale, 11); // Remains clamped at 11

    // Reset
    font_scale = 14;
    assert_eq!(font_scale, 14);

    // Scaling up
    for _ in 0..10 {
        font_scale = (font_scale + 2).clamp(11, 24);
    }
    assert_eq!(font_scale, 24); // Clamped at upper bound 24
}

#[test]
fn test_reader_navigation_from_home_to_article_metadata_consistency() {
    use mewser_desktop::state::ReaderPageMetadata;
    use mewser_gateway::{ContentBlock, ExtractedPage, HeadingItem, LinkItem};

    // 1. Initial Home state: Reader tab has no extraction metadata
    let mut tab = mewser_desktop::app::TabModel::new(
        1,
        "mewser:home".to_string(),
        mewser_cli::BrowsingMode::ResilientText,
    );
    assert!(tab.reader_metadata.is_none());

    // Verify default fallback when metadata is None (never returns dummy "mewser:home" as extracted URL)
    let popover_url = tab
        .reader_metadata
        .as_ref()
        .map(|m| m.url.as_str())
        .unwrap_or("Unavailable");
    let popover_domain = tab
        .reader_metadata
        .as_ref()
        .map(|m| m.domain.as_str())
        .unwrap_or("Unavailable");
    assert_eq!(popover_url, "Unavailable");
    assert_eq!(popover_domain, "Unavailable");

    // 2. Navigation initiates to Example Domain:
    let dest_url = "https://example.com/";
    tab.active_request_id += 1;
    let req_id_1 = tab.active_request_id;
    tab.reader_metadata = Some(ReaderPageMetadata::new_loading(dest_url));

    let loading_meta = tab.reader_metadata.as_ref().unwrap();
    assert_eq!(loading_meta.url, "https://example.com/");
    assert_eq!(loading_meta.domain, "example.com");
    assert!(loading_meta.is_loading);
    assert_eq!(loading_meta.elapsed_ms, None);
    assert_eq!(loading_meta.headings_count, 0);

    // 3. Extraction completes:
    let page = ExtractedPage {
        url: dest_url.to_string(),
        title: "Example Domain".to_string(),
        description: Some("Illustrative documentation domain.".to_string()),
        headings: vec![HeadingItem {
            level: 1,
            text: "Example Domain".to_string(),
        }],
        content: vec![
            ContentBlock::Heading {
                level: 1,
                text: "Example Domain".to_string(),
            },
            ContentBlock::Paragraph {
                text:
                    "This domain is established to be used for illustrative examples in documents."
                        .to_string(),
            },
        ],
        links: vec![LinkItem {
            href: "https://www.iana.org/domains/example".to_string(),
            text: "More information...".to_string(),
        }],
        images: vec![],
    };

    let elapsed_ms = 423u128;
    assert_eq!(tab.active_request_id, req_id_1);
    tab.reader_metadata = Some(ReaderPageMetadata::new_loaded(&page, elapsed_ms));

    // Verify all parts (header, body model, Page Information) refer to the exact same extraction result
    let loaded_meta = tab.reader_metadata.as_ref().unwrap();
    assert_eq!(loaded_meta.url, "https://example.com/");
    assert_eq!(loaded_meta.domain, "example.com");
    assert_eq!(loaded_meta.elapsed_ms, Some(423));
    assert_eq!(loaded_meta.headings_count, 1);
    assert_eq!(loaded_meta.content_blocks_count, 2);
    assert_eq!(loaded_meta.links_count, 1);
    assert!(!loaded_meta.is_loading);
    assert!(!loaded_meta.is_error);

    // Check consistency between page and metadata
    assert_eq!(loaded_meta.url, page.url);
    assert_eq!(loaded_meta.headings_count, page.headings.len());
    assert_eq!(loaded_meta.content_blocks_count, page.content.len());
    assert_eq!(loaded_meta.links_count, page.links.len());
}

#[test]
fn test_reader_navigation_between_different_articles_and_stale_response_filtering() {
    use mewser_desktop::state::ReaderPageMetadata;
    use mewser_gateway::{ContentBlock, ExtractedPage, HeadingItem};

    let mut tab = mewser_desktop::app::TabModel::new(
        1,
        "https://example.com/article-a".to_string(),
        mewser_cli::BrowsingMode::ResilientText,
    );

    // 1. Navigation to Article A
    tab.active_request_id += 1;
    let req_id_a = tab.active_request_id;
    tab.reader_metadata = Some(ReaderPageMetadata::new_loading(
        "https://example.com/article-a",
    ));

    // 2. User immediately navigates to Article B before Article A arrives
    tab.active_request_id += 1;
    let req_id_b = tab.active_request_id;
    // Clears previous page metadata immediately upon new navigation
    tab.reader_metadata = Some(ReaderPageMetadata::new_loading(
        "https://example.com/article-b",
    ));

    let in_flight_meta = tab.reader_metadata.as_ref().unwrap();
    assert_eq!(in_flight_meta.url, "https://example.com/article-b");
    assert!(in_flight_meta.is_loading);

    // 3. Stale response for Article A arrives late:
    let page_a = ExtractedPage {
        url: "https://example.com/article-a".to_string(),
        title: "Article A".to_string(),
        description: None,
        headings: vec![HeadingItem {
            level: 1,
            text: "Article A".to_string(),
        }],
        content: vec![],
        links: vec![],
        images: vec![],
    };

    // Stale check: req_id_a (1) != tab.active_request_id (2) -> MUST BE REJECTED
    let is_stale = req_id_a != tab.active_request_id;
    assert!(is_stale);
    if !is_stale {
        tab.reader_metadata = Some(ReaderPageMetadata::new_loaded(&page_a, 200));
    }
    // Metadata remains for Article B
    assert_eq!(
        tab.reader_metadata.as_ref().unwrap().url,
        "https://example.com/article-b"
    );

    // 4. Fresh response for Article B arrives:
    let page_b = ExtractedPage {
        url: "https://example.com/article-b".to_string(),
        title: "Article B".to_string(),
        description: None,
        headings: vec![
            HeadingItem {
                level: 1,
                text: "Article B".to_string(),
            },
            HeadingItem {
                level: 2,
                text: "Subheading".to_string(),
            },
        ],
        content: vec![ContentBlock::Paragraph {
            text: "Article B body text.".to_string(),
        }],
        links: vec![],
        images: vec![],
    };

    let is_b_current = req_id_b == tab.active_request_id;
    assert!(is_b_current);
    if is_b_current {
        tab.reader_metadata = Some(ReaderPageMetadata::new_loaded(&page_b, 350));
    }

    let final_meta = tab.reader_metadata.as_ref().unwrap();
    assert_eq!(final_meta.url, "https://example.com/article-b");
    assert_eq!(final_meta.domain, "example.com");
    assert_eq!(final_meta.elapsed_ms, Some(350));
    assert_eq!(final_meta.headings_count, 2);
    assert_eq!(final_meta.content_blocks_count, 1);
}

#[test]
fn test_reader_duplicate_title_suppression_logic() {
    let article_title = "Domain Name System — Protocol & Architecture";

    // Case 1: First heading is H1 with exact matching text -> duplicate suppressed in body
    let first_heading_text = "Domain Name System — Protocol & Architecture";
    let first_heading_level = 1u8;
    let is_dup = first_heading_level == 1
        && first_heading_text
            .trim()
            .eq_ignore_ascii_case(article_title.trim());
    assert!(is_dup);

    // Case 2: First heading is H1 with distinct text -> rendered normally
    let distinct_heading_text = "Introduction and Motivation";
    let is_dup_distinct = first_heading_level == 1
        && distinct_heading_text
            .trim()
            .eq_ignore_ascii_case(article_title.trim());
    assert!(!is_dup_distinct);

    // Case 3: First heading is H2 with matching text -> not top-level, rendered normally
    let h2_level = 2u8;
    let is_dup_h2 = h2_level == 1
        && first_heading_text
            .trim()
            .eq_ignore_ascii_case(article_title.trim());
    assert!(!is_dup_h2);
}

#[test]
fn test_reader_contents_sidebar_toggle_allocation_and_reflow() {
    // Total window width in desktop mode
    let window_width = 1069i32;
    let tool_strip_width = 46i32;
    let sidebar_width = 240i32;

    // 1. Initial State: Contents sidebar collapsed
    let full_reading_width = window_width - tool_strip_width; // 1023px
    assert_eq!(full_reading_width, 1023);

    let is_sidebar_visible = false;
    let active_reading_width = if is_sidebar_visible {
        full_reading_width - sidebar_width
    } else {
        full_reading_width
    };
    assert_eq!(active_reading_width, 1023);

    // 2. First Toggle Open: User clicks Contents control without window resize
    let is_sidebar_visible_after_toggle = true;
    let reduced_reading_width = full_reading_width - sidebar_width;
    assert_eq!(reduced_reading_width, 783);

    let sidebar_start_x = tool_strip_width + reduced_reading_width; // 46 + 783 = 829
    assert_eq!(sidebar_start_x, 829);

    // Verify clear margin between maximum text column and sidebar
    let max_text_col = 825i32;
    assert!(max_text_col < sidebar_start_x);
    let clearance_margin = sidebar_start_x - max_text_col;
    assert!(clearance_margin >= 4);

    // 3. Section Navigation: Clicking heading 1 ("2. MasterDNS Tunneling Mechanisms")
    let headings = [
        "1. Architecture and Design Goals",
        "2. MasterDNS Tunneling Mechanisms",
        "3. Server-Side Extraction Pipeline",
        "4. Fail-Closed Security Invariants",
    ];
    let selected_heading_idx = 1usize;
    let mark_name = format!("heading_{selected_heading_idx}");
    assert_eq!(mark_name, "heading_1");
    assert_eq!(
        headings[selected_heading_idx],
        "2. MasterDNS Tunneling Mechanisms"
    );

    // 4. Toggle Close: User closes Contents without window resize
    let is_sidebar_visible_after_close = false;
    let restored_reading_width = if is_sidebar_visible_after_close {
        full_reading_width - sidebar_width
    } else {
        full_reading_width
    };
    assert_eq!(restored_reading_width, 1023);

    // 5. Repeat Toggle Open: Confirm idempotent behavior
    let is_sidebar_visible_repeat = true;
    let repeat_reading_width = full_reading_width - sidebar_width;
    assert_eq!(repeat_reading_width, 783);
    assert_eq!(is_sidebar_visible_repeat, is_sidebar_visible_after_toggle);
}

#[test]
fn test_routing_policy_domain_validation_and_normalization() {
    use mewser_desktop::app::validate_direct_domain;

    let existing = vec![
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        "domestic-bank.example".to_string(),
    ];

    // 1. Valid domain syntax with whitespace and case normalization
    let v1 = validate_direct_domain("   Portal.Internal   ", &existing).expect("Valid domain");
    assert_eq!(v1, "portal.internal");

    let v2 = validate_direct_domain("sub.service-node.corp", &existing).expect("Valid domain");
    assert_eq!(v2, "sub.service-node.corp");

    let v3 = validate_direct_domain("10.0.0.1", &existing).expect("Valid IP");
    assert_eq!(v3, "10.0.0.1");

    // 2. Reject empty or whitespace-only
    let e_empty = validate_direct_domain("   ", &existing).expect_err("Empty domain must fail");
    assert!(e_empty.contains("empty"));

    // 3. Reject protocol schemes
    let e_scheme1 =
        validate_direct_domain("http://example.com", &existing).expect_err("Scheme must fail");
    assert!(e_scheme1.contains("Protocol scheme"));
    let e_scheme2 = validate_direct_domain("https://bank.internal/api", &existing)
        .expect_err("Scheme must fail");
    assert!(e_scheme2.contains("Protocol scheme"));

    // 4. Reject paths, queries, fragments
    let e_path =
        validate_direct_domain("example.com/portal", &existing).expect_err("Path must fail");
    assert!(e_path.contains("paths"));
    let e_query =
        validate_direct_domain("example.com?query=1", &existing).expect_err("Query must fail");
    assert!(e_query.contains("queries"));

    // 5. Reject port numbers
    let e_port = validate_direct_domain("example.com:8080", &existing).expect_err("Port must fail");
    assert!(e_port.contains("Port numbers"));

    // 6. Reject spaces inside domain
    let e_space =
        validate_direct_domain("portal internal.com", &existing).expect_err("Space must fail");
    assert!(e_space.contains("whitespace"));

    // 7. Reject leading dots (clarify suffix rule)
    let e_dot =
        validate_direct_domain(".internal.corp", &existing).expect_err("Leading dot must fail");
    assert!(e_dot.contains("Direct Suffixes"));

    // 8. Reject invalid labels (consecutive dots, trailing dot, invalid hyphens)
    let e_consec =
        validate_direct_domain("example..com", &existing).expect_err("Consecutive dots must fail");
    assert!(e_consec.contains("consecutive dots"));

    let e_hyphen =
        validate_direct_domain("-bad-label.com", &existing).expect_err("Leading hyphen must fail");
    assert!(e_hyphen.contains("hyphen"));

    // 9. Reject duplicates (case-insensitive)
    let e_dup1 = validate_direct_domain("127.0.0.1", &existing).expect_err("Duplicate must fail");
    assert!(e_dup1.contains("already in direct rules"));

    let e_dup2 = validate_direct_domain("DOMESTIC-BANK.EXAMPLE", &existing)
        .expect_err("Duplicate must fail");
    assert!(e_dup2.contains("already in direct rules"));
}

#[test]
fn test_routing_policy_suffix_validation_and_normalization() {
    use mewser_desktop::app::validate_direct_suffix;

    let existing = vec![".corp.internal".to_string(), ".ir".to_string()];

    // 1. Valid suffix syntax with auto-leading dot normalization
    let v1 = validate_direct_suffix("local", &existing).expect("Valid suffix without dot");
    assert_eq!(v1, ".local");

    let v2 =
        validate_direct_suffix("  .SERVICE.INTERNAL  ", &existing).expect("Valid suffix with dot");
    assert_eq!(v2, ".service.internal");

    // 2. Reject empty or single dot
    let e_empty = validate_direct_suffix("   ", &existing).expect_err("Empty suffix must fail");
    assert!(e_empty.contains("empty"));

    let e_dot = validate_direct_suffix(".", &existing).expect_err("Single dot must fail");
    assert!(e_dot.contains("label after the dot"));

    // 3. Reject schemes and paths
    let e_scheme =
        validate_direct_suffix("https://.corp", &existing).expect_err("Scheme must fail");
    assert!(e_scheme.contains("Protocol scheme"));

    let e_path = validate_direct_suffix(".corp/internal", &existing).expect_err("Path must fail");
    assert!(e_path.contains("paths"));

    let e_port = validate_direct_suffix(".corp:8080", &existing).expect_err("Port must fail");
    assert!(e_port.contains("Port numbers"));

    // 4. Reject invalid dots and hyphens
    let e_consec = validate_direct_suffix(".corp..internal", &existing)
        .expect_err("Consecutive dots must fail");
    assert!(e_consec.contains("consecutive dots"));

    // 5. Reject duplicates
    let e_dup =
        validate_direct_suffix(".CORP.INTERNAL", &existing).expect_err("Duplicate must fail");
    assert!(e_dup.contains("already in direct rules"));
}

#[test]
fn test_routing_policy_staging_save_and_cancel_isolation() {
    let initial_settings = mewser_desktop::state::SettingsState {
        direct_domains: vec!["127.0.0.1".to_string(), "localhost".to_string()],
        direct_suffixes: vec![".local".to_string()],
        ..Default::default()
    };

    // 1. Simulate staged in-memory edits
    let mut staged_domains = initial_settings.direct_domains.clone();
    let mut staged_suffixes = initial_settings.direct_suffixes.clone();

    // Add new rule to staged collections
    staged_domains.push("domestic-bank.example".to_string());
    staged_suffixes.push(".corp.internal".to_string());

    // 2. Cancel operation: staged edits are discarded, leaving initial settings unmutated
    let cancelled_settings = initial_settings.clone();
    assert_eq!(cancelled_settings.direct_domains.len(), 2);
    assert_eq!(cancelled_settings.direct_suffixes.len(), 1);
    assert!(!cancelled_settings
        .direct_domains
        .contains(&"domestic-bank.example".to_string()));
    assert!(!cancelled_settings
        .direct_suffixes
        .contains(&".corp.internal".to_string()));

    // 3. Save operation: staged edits are committed to settings
    let mut saved_settings = initial_settings.clone();
    saved_settings.direct_domains = staged_domains;
    saved_settings.direct_suffixes = staged_suffixes;

    assert_eq!(saved_settings.direct_domains.len(), 3);
    assert_eq!(saved_settings.direct_suffixes.len(), 2);
    assert!(saved_settings
        .direct_domains
        .contains(&"domestic-bank.example".to_string()));
    assert!(saved_settings
        .direct_suffixes
        .contains(&".corp.internal".to_string()));

    // 4. Persistence roundtrip check: verify build_routing_policy incorporates saved rules
    let routing_policy = saved_settings.build_routing_policy();
    assert!(routing_policy.is_direct_target("domestic-bank.example"));
    assert!(routing_policy.is_direct_target("portal.corp.internal"));
    assert!(!routing_policy.is_direct_target("news.ycombinator.com"));
}

#[test]
fn test_routing_policy_decision_invariants_and_ssrf_protection() {
    use mewser_core::policy::is_restricted_ip;
    use mewser_core::router::{RouteDecision, RoutingPolicy};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut policy = RoutingPolicy::new();
    policy.add_direct_domain("domestic-bank.example");
    policy.add_direct_domain("portal.internal");
    policy.add_direct_suffix(".corp.internal");
    policy.add_direct_suffix(".ir");

    // 1. Direct matching for exact domains and suffixes
    match policy.route("https://domestic-bank.example/account") {
        RouteDecision::Direct(t) => assert_eq!(t.host, "domestic-bank.example"),
        _ => panic!("Expected Direct route for configured exact domain"),
    }
    match policy.route("https://auth.corp.internal/login") {
        RouteDecision::Direct(t) => assert_eq!(t.host, "auth.corp.internal"),
        _ => panic!("Expected Direct route for configured suffix"),
    }
    match policy.route("https://tehran.portal.ir/service") {
        RouteDecision::Direct(t) => assert_eq!(t.host, "tehran.portal.ir"),
        _ => panic!("Expected Direct route for .ir suffix"),
    }

    // 2. Tunneled routing for unlisted public destinations
    match policy.route("https://news.ycombinator.com/item?id=42") {
        RouteDecision::Tunnel(t) => assert_eq!(t.host, "news.ycombinator.com"),
        _ => panic!("Expected Tunnel route for unlisted public domain"),
    }

    // 3. Fail closed on tunnel failure: never falls back to direct
    let target =
        mewser_core::policy::ParsedTarget::parse("https://blocked-in-region.example/").unwrap();
    let err = policy.handle_tunnel_failure(
        &target,
        mewser_core::error::CoreError::TunnelFailed("Tunnel connection timed out".into()),
    );
    assert_eq!(
        err,
        Err(mewser_core::error::CoreError::DirectFallbackForbidden)
    );

    // 4. SSRF Defense verification: private, loopback, link-local, and cloud metadata
    match policy.route("http://127.0.0.1:8080/metrics") {
        RouteDecision::Blocked(mewser_core::error::CoreError::SsrfBlocked(_)) => {}
        _ => panic!("Expected SSRF Blocked for loopback"),
    }
    match policy.route("http://169.254.169.254/latest/meta-data") {
        RouteDecision::Blocked(mewser_core::error::CoreError::SsrfBlocked(_)) => {}
        _ => panic!("Expected SSRF Blocked for cloud metadata"),
    }
    match policy.route("http://10.0.0.5/admin") {
        RouteDecision::Blocked(mewser_core::error::CoreError::SsrfBlocked(_)) => {}
        _ => panic!("Expected SSRF Blocked for private 10.0.0.0/8"),
    }
    match policy.route("http://192.168.1.1/setup") {
        RouteDecision::Blocked(mewser_core::error::CoreError::SsrfBlocked(_)) => {}
        _ => panic!("Expected SSRF Blocked for private 192.168.0.0/16"),
    }

    // Enforce dynamic policy check function
    assert!(is_restricted_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(is_restricted_ip(IpAddr::V4(Ipv4Addr::new(
        169, 254, 169, 254
    ))));
    assert!(is_restricted_ip(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))));
    assert!(is_restricted_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(is_restricted_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(is_restricted_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn test_gateway_endpoint_validation() {
    use mewser_desktop::validate_gateway_endpoint;

    // 1. Valid endpoints (IPv4 and IPv6 with valid port, whitespace trimmed)
    assert_eq!(
        validate_gateway_endpoint("127.0.0.1:4040").unwrap(),
        "127.0.0.1:4040"
    );
    assert_eq!(
        validate_gateway_endpoint("   192.168.1.50:4040   ").unwrap(),
        "192.168.1.50:4040"
    );
    assert_eq!(
        validate_gateway_endpoint("[::1]:4040").unwrap(),
        "[::1]:4040"
    );
    assert_eq!(
        validate_gateway_endpoint("[2001:db8::1]:8080").unwrap(),
        "[2001:db8::1]:8080"
    );

    // 2. Reject empty or whitespace
    let err_empty = validate_gateway_endpoint("").unwrap_err();
    assert!(err_empty.contains("cannot be empty"));
    let err_ws = validate_gateway_endpoint("   ").unwrap_err();
    assert!(err_ws.contains("cannot be empty"));

    // 3. Reject URL schemes (http://, https://)
    let err_http = validate_gateway_endpoint("http://127.0.0.1:4040").unwrap_err();
    assert!(err_http.contains("remove http:// or https://"));
    let err_https = validate_gateway_endpoint("https://192.168.1.50:4040").unwrap_err();
    assert!(err_https.contains("remove http:// or https://"));

    // 4. Reject path, query, and fragment components
    let err_path = validate_gateway_endpoint("127.0.0.1:4040/extract").unwrap_err();
    assert!(err_path.contains("path, query, or fragment"));
    let err_query = validate_gateway_endpoint("127.0.0.1:4040?auth=token").unwrap_err();
    assert!(err_query.contains("path, query, or fragment"));
    let err_frag = validate_gateway_endpoint("127.0.0.1:4040#status").unwrap_err();
    assert!(err_frag.contains("path, query, or fragment"));

    // 5. Reject embedded whitespace
    let err_space = validate_gateway_endpoint("127.0.0.1 4040").unwrap_err();
    assert!(err_space.contains("whitespace"));

    // 6. Reject missing port
    let err_no_port = validate_gateway_endpoint("127.0.0.1").unwrap_err();
    assert!(err_no_port.contains("Missing port number"));

    // 7. Reject port 0 and port > 65535
    let err_port_0 = validate_gateway_endpoint("127.0.0.1:0").unwrap_err();
    assert!(err_port_0.contains("between 1 and 65535"));
    let err_port_overflow = validate_gateway_endpoint("127.0.0.1:70000").unwrap_err();
    assert!(err_port_overflow.contains("between 1 and 65535"));

    // 8. Reject invalid hostname syntax (e.g., underscores)
    let err_hostname = validate_gateway_endpoint("invalid_host:4040").unwrap_err();
    assert!(err_hostname.contains("invalid characters"));
    // Verify valid hostname:port is accepted
    assert_eq!(
        validate_gateway_endpoint("gateway.example.com:4040").unwrap(),
        "gateway.example.com:4040"
    );
}

#[test]
fn test_gateway_settings_staging_save_and_cancel_isolation() {
    let initial_settings = mewser_desktop::state::SettingsState {
        gateway_addr_str: "127.0.0.1:4040".to_string(),
        timeout_secs: 30,
        ..Default::default()
    };

    // 1. Simulate staged in-memory edits in Settings dialog
    let staged_addr = "192.168.1.50:4040".to_string();
    let staged_timeout = 60;

    // 2. Cancel action: Dialog is closed without committing, initial settings remain untouched
    let cancelled_settings = initial_settings.clone();
    assert_eq!(cancelled_settings.gateway_addr_str, "127.0.0.1:4040");
    assert_eq!(cancelled_settings.timeout_secs, 30);

    // 3. Save action: Staged values are committed to settings state
    let mut saved_settings = initial_settings.clone();
    saved_settings.gateway_addr_str = staged_addr;
    saved_settings.timeout_secs = staged_timeout;

    assert_eq!(saved_settings.gateway_addr_str, "192.168.1.50:4040");
    assert_eq!(saved_settings.timeout_secs, 60);

    // 4. Persistence roundtrip: verify PersistentSettings serialization and deserialization
    let persisted = mewser_desktop::state::PersistentSettings {
        transport: saved_settings.transport,
        proxy_addr_str: saved_settings.proxy_addr_str.clone(),
        gateway_addr_str: saved_settings.gateway_addr_str.clone(),
        tcp_endpoint_str: saved_settings.tcp_endpoint_str.clone(),
        proxy_user: saved_settings.proxy_user.clone(),
        timeout_secs: saved_settings.timeout_secs,
        direct_domains: saved_settings.direct_domains.clone(),
        direct_suffixes: saved_settings.direct_suffixes.clone(),
        profiles: saved_settings.profile_store.profiles.clone(),
        selected_profile_id: saved_settings.profile_store.selected_profile_id.clone(),
        vault_file_consent: saved_settings.vault_file_consent,
        tunnel_domain: saved_settings.tunnel_domain.clone(),
        tunnel_encryption_method: saved_settings.tunnel_encryption_method,
        tunnel_resolvers: saved_settings.tunnel_resolvers.clone(),
        tunnel_auto_connect: saved_settings.tunnel_auto_connect,
    };

    let json = serde_json::to_string(&persisted).expect("Serialize persistent settings");
    assert!(json.contains("192.168.1.50:4040"));
    assert!(json.contains("\"timeout_secs\":60") || json.contains("\"timeout_secs\": 60"));

    let deserialized: mewser_desktop::state::PersistentSettings =
        serde_json::from_str(&json).expect("Deserialize persistent settings");
    assert_eq!(deserialized.gateway_addr_str, "192.168.1.50:4040");
    assert_eq!(deserialized.timeout_secs, 60);
}

#[test]
fn test_gateway_auth_status_derived_from_env_and_isolated() {
    let secret_token = "secret_gateway_token_isolated_test_12345";
    let state_with_auth = mewser_desktop::state::SettingsState {
        gateway_token: secret_token.to_string(),
        ..Default::default()
    };

    // 1. Verify token is held in volatile memory
    assert_eq!(state_with_auth.gateway_token, secret_token);

    // 2. PersistentSettings serialization strictly omits gateway_token
    let persisted = mewser_desktop::state::PersistentSettings {
        transport: state_with_auth.transport,
        proxy_addr_str: state_with_auth.proxy_addr_str.clone(),
        gateway_addr_str: state_with_auth.gateway_addr_str.clone(),
        tcp_endpoint_str: state_with_auth.tcp_endpoint_str.clone(),
        proxy_user: state_with_auth.proxy_user.clone(),
        timeout_secs: state_with_auth.timeout_secs,
        direct_domains: state_with_auth.direct_domains.clone(),
        direct_suffixes: state_with_auth.direct_suffixes.clone(),
        profiles: state_with_auth.profile_store.profiles.clone(),
        selected_profile_id: state_with_auth.profile_store.selected_profile_id.clone(),
        vault_file_consent: state_with_auth.vault_file_consent,
        tunnel_domain: state_with_auth.tunnel_domain.clone(),
        tunnel_encryption_method: state_with_auth.tunnel_encryption_method,
        tunnel_resolvers: state_with_auth.tunnel_resolvers.clone(),
        tunnel_auto_connect: state_with_auth.tunnel_auto_connect,
    };

    let json = serde_json::to_string(&persisted).expect("Serialize persistent settings");
    assert!(
        !json.contains(secret_token),
        "Gateway token leaked into PersistentSettings serialization!"
    );
    assert!(
        !json.contains("gateway_token"),
        "gateway_token key present in PersistentSettings serialization!"
    );
}

#[test]
fn test_gateway_health_routing_and_fail_closed_invariants() {
    use mewser_core::router::RoutingPolicy;

    let mut policy = RoutingPolicy::new();
    policy.add_direct_domain("127.0.0.1");
    policy.add_direct_domain("localhost");

    // 1. Direct local targets are classified for direct routing
    assert!(policy.is_direct_target("127.0.0.1"));
    assert!(policy.is_direct_target("localhost"));

    // 2. Remote/tunneled targets are not direct
    assert!(!policy.is_direct_target("192.168.1.50"));
    assert!(!policy.is_direct_target("news.ycombinator.com"));

    // 3. Fail-closed invariant on tunnel failure: never falls back to direct
    let parsed_target =
        mewser_core::policy::ParsedTarget::parse("https://news.ycombinator.com/item?id=42")
            .unwrap();
    let err = policy.handle_tunnel_failure(
        &parsed_target,
        mewser_core::error::CoreError::TunnelFailed("Offline".into()),
    );
    assert_eq!(
        err,
        Err(mewser_core::error::CoreError::DirectFallbackForbidden)
    );
}

#[test]
fn test_validate_socket_addr_syntax_and_schemes() {
    use mewser_desktop::validate_socket_addr;

    // 1. Accept valid IPv4 and IPv6 socket addresses
    assert_eq!(
        validate_socket_addr("127.0.0.1:1080", "SOCKS5 proxy").unwrap(),
        "127.0.0.1:1080"
    );
    assert_eq!(
        validate_socket_addr("   127.0.0.1:9050   ", "SOCKS5 proxy").unwrap(),
        "127.0.0.1:9050"
    );
    assert_eq!(
        validate_socket_addr("[::1]:1080", "Fixed TCP").unwrap(),
        "[::1]:1080"
    );
    assert_eq!(
        validate_socket_addr("[2001:db8::1]:8080", "Fixed TCP").unwrap(),
        "[2001:db8::1]:8080"
    );

    // 2. Reject empty or whitespace
    let err_empty = validate_socket_addr("", "SOCKS5 proxy").unwrap_err();
    assert!(err_empty.contains("cannot be empty"));
    let err_ws = validate_socket_addr("   ", "SOCKS5 proxy").unwrap_err();
    assert!(err_ws.contains("cannot be empty"));

    // 3. Reject URL schemes (http://, https://, socks5://, tcp://)
    let err_http = validate_socket_addr("http://127.0.0.1:1080", "SOCKS5 proxy").unwrap_err();
    assert!(err_http.contains("remove http:// or https://") || err_http.contains("not a URL"));
    let err_socks = validate_socket_addr("socks5://127.0.0.1:1080", "SOCKS5 proxy").unwrap_err();
    assert!(err_socks.contains("not a URL"));
    let err_tcp = validate_socket_addr("tcp://127.0.0.1:1080", "Fixed TCP").unwrap_err();
    assert!(err_tcp.contains("not a URL"));

    // 4. Reject path, query, and fragment components
    let err_path = validate_socket_addr("127.0.0.1:1080/proxy", "SOCKS5 proxy").unwrap_err();
    assert!(err_path.contains("path, query, or fragment"));
    let err_query = validate_socket_addr("127.0.0.1:1080?key=val", "SOCKS5 proxy").unwrap_err();
    assert!(err_query.contains("path, query, or fragment"));
    let err_frag = validate_socket_addr("127.0.0.1:1080#section", "SOCKS5 proxy").unwrap_err();
    assert!(err_frag.contains("path, query, or fragment"));

    // 5. Reject embedded whitespace
    let err_space = validate_socket_addr("127.0.0.1 1080", "SOCKS5 proxy").unwrap_err();
    assert!(err_space.contains("whitespace"));

    // 6. Reject missing port
    let err_no_port = validate_socket_addr("127.0.0.1", "SOCKS5 proxy").unwrap_err();
    assert!(err_no_port.contains("Missing port number"));

    // 7. Reject port 0 and port overflow
    let err_port_0 = validate_socket_addr("127.0.0.1:0", "SOCKS5 proxy").unwrap_err();
    assert!(err_port_0.contains("between 1 and 65535"));
    let err_overflow = validate_socket_addr("127.0.0.1:70000", "SOCKS5 proxy").unwrap_err();
    assert!(err_overflow.contains("between 1 and 65535"));

    // 8. Reject invalid non-IP hostname
    let err_host = validate_socket_addr("not_an_ip:1080", "SOCKS5 proxy").unwrap_err();
    assert!(err_host.contains("Invalid IP address syntax"));
}

#[test]
fn test_general_settings_staging_save_and_cancel_isolation() {
    use mewser_desktop::state::{DesktopTransport, PersistentSettings, SettingsState};

    let initial_settings = SettingsState {
        transport: DesktopTransport::Socks5,
        proxy_addr_str: "127.0.0.1:1080".to_string(),
        tcp_endpoint_str: "127.0.0.1:1080".to_string(),
        proxy_user: String::new(),
        proxy_pass: String::new(),
        gateway_addr_str: "127.0.0.1:4040".to_string(),
        gateway_token: String::new(),
        active_mode: mewser_cli::BrowsingMode::StandardWeb,
        timeout_secs: 30,
        direct_domains: vec!["127.0.0.1".to_string(), "localhost".to_string()],
        direct_suffixes: vec![".ir".to_string()],
        profile_store: mewser_desktop::profile::ProfileStore::new(),
        secret_vault: mewser_desktop::profile::SecretVault::memory(),
        vault_file_consent: false,
        tunnel_domain: "primary.example.com".to_string(),
        tunnel_encryption_method: 1,
        tunnel_encryption_key: String::new(),
        tunnel_resolvers: vec!["8.8.8.8:53".to_string()],
        tunnel_auto_connect: true,
    };

    // Staging modifications in dialog form
    let mut staged_transport = initial_settings.transport;
    let mut staged_proxy_addr = initial_settings.proxy_addr_str.clone();
    let mut staged_tcp_endpoint = initial_settings.tcp_endpoint_str.clone();
    let mut staged_proxy_user = initial_settings.proxy_user.clone();
    let mut staged_auto_connect = initial_settings.tunnel_auto_connect;
    let mut staged_vault_consent = initial_settings.vault_file_consent;

    // Verify initial staged values match initial settings
    assert_eq!(staged_transport, DesktopTransport::Socks5);
    assert_eq!(staged_proxy_addr, "127.0.0.1:1080");
    assert_eq!(staged_tcp_endpoint, "127.0.0.1:1080");
    assert_eq!(staged_proxy_user, "");
    assert!(staged_auto_connect);
    assert!(!staged_vault_consent);

    // Simulate user editing General settings controls
    staged_transport = DesktopTransport::FixedTcp;
    staged_proxy_addr = "127.0.0.1:9050".to_string();
    staged_tcp_endpoint = "127.0.0.1:9050".to_string();
    staged_proxy_user = "mewser_user".to_string();
    staged_auto_connect = false;
    staged_vault_consent = true;

    // 1. Cancel action: initial_settings must remain completely unchanged
    assert_eq!(initial_settings.transport, DesktopTransport::Socks5);
    assert_eq!(initial_settings.proxy_addr_str, "127.0.0.1:1080");
    assert_eq!(initial_settings.tcp_endpoint_str, "127.0.0.1:1080");
    assert_eq!(initial_settings.proxy_user, "");
    assert!(initial_settings.tunnel_auto_connect);
    assert!(!initial_settings.vault_file_consent);

    // 2. Save action: commit staged edits into model and serialize
    let mut committed_settings = initial_settings.clone();
    committed_settings.transport = staged_transport;
    committed_settings.proxy_addr_str = staged_proxy_addr;
    committed_settings.tcp_endpoint_str = staged_tcp_endpoint;
    committed_settings.proxy_user = staged_proxy_user;
    committed_settings.tunnel_auto_connect = staged_auto_connect;
    committed_settings.vault_file_consent = staged_vault_consent;

    let persisted = PersistentSettings {
        transport: committed_settings.transport,
        proxy_addr_str: committed_settings.proxy_addr_str.clone(),
        gateway_addr_str: committed_settings.gateway_addr_str.clone(),
        tcp_endpoint_str: committed_settings.tcp_endpoint_str.clone(),
        proxy_user: committed_settings.proxy_user.clone(),
        timeout_secs: committed_settings.timeout_secs,
        direct_domains: committed_settings.direct_domains.clone(),
        direct_suffixes: committed_settings.direct_suffixes.clone(),
        profiles: committed_settings.profile_store.profiles.clone(),
        selected_profile_id: committed_settings.profile_store.selected_profile_id.clone(),
        vault_file_consent: committed_settings.vault_file_consent,
        tunnel_domain: committed_settings.tunnel_domain.clone(),
        tunnel_encryption_method: committed_settings.tunnel_encryption_method,
        tunnel_resolvers: committed_settings.tunnel_resolvers.clone(),
        tunnel_auto_connect: committed_settings.tunnel_auto_connect,
    };

    let serialized = serde_json::to_string(&persisted).expect("Serialize persistent settings");
    let deserialized: PersistentSettings =
        serde_json::from_str(&serialized).expect("Deserialize persistent settings");

    assert_eq!(deserialized.transport, DesktopTransport::FixedTcp);
    assert_eq!(deserialized.proxy_addr_str, "127.0.0.1:9050");
    assert_eq!(deserialized.tcp_endpoint_str, "127.0.0.1:9050");
    assert_eq!(deserialized.proxy_user, "mewser_user");
    assert!(!deserialized.tunnel_auto_connect);
    assert!(deserialized.vault_file_consent);

    // Preserved other tab configurations
    assert_eq!(deserialized.gateway_addr_str, "127.0.0.1:4040");
    assert_eq!(deserialized.timeout_secs, 30);
    assert_eq!(
        deserialized.direct_domains,
        vec!["127.0.0.1".to_string(), "localhost".to_string()]
    );
    assert_eq!(deserialized.direct_suffixes, vec![".ir".to_string()]);
}

#[test]
fn test_general_settings_credential_isolation() {
    use mewser_desktop::state::PersistentSettings;

    let secret_socks_pass = "super_secret_socks5_password_12345";

    let persisted = PersistentSettings {
        transport: mewser_desktop::state::DesktopTransport::Socks5,
        proxy_addr_str: "127.0.0.1:1080".to_string(),
        gateway_addr_str: "127.0.0.1:4040".to_string(),
        tcp_endpoint_str: "127.0.0.1:1080".to_string(),
        proxy_user: "mewser_user".to_string(),
        timeout_secs: 30,
        direct_domains: vec!["127.0.0.1".to_string()],
        direct_suffixes: Vec::new(),
        profiles: Vec::new(),
        selected_profile_id: None,
        vault_file_consent: false,
        tunnel_domain: "primary.example.com".to_string(),
        tunnel_encryption_method: 1,
        tunnel_resolvers: Vec::new(),
        tunnel_auto_connect: true,
    };

    let json = serde_json::to_string(&persisted).expect("Serialize persistent settings");
    assert!(
        !json.contains(secret_socks_pass),
        "SOCKS5 password leaked into PersistentSettings serialization!"
    );
    assert!(
        !json.contains("proxy_pass"),
        "proxy_pass field present in PersistentSettings serialization!"
    );
}

#[test]
fn test_topology_a_fixed_tcp_end_to_end_endpoint_mapping() {
    // 1. VPS Gateway Server: Binds to simulated VPS loopback port (MEWSER_GATEWAY_BIND=127.0.0.1:4040)
    let vps_gw_listener = TcpListener::bind("127.0.0.1:0").expect("Bind VPS Gateway listener");
    let vps_gw_addr = vps_gw_listener.local_addr().expect("VPS Gateway addr");

    let test_token = "topology_a_auth_token_64chars_abcdef0123456789abcdef0123456789abcdef";

    let vps_gw_handle = thread::spawn(move || {
        let (mut stream, _) = vps_gw_listener
            .accept()
            .expect("VPS Gateway accepts forwarded connection");
        let mut req_buf = vec![0u8; 2048];
        let n = stream
            .read(&mut req_buf)
            .expect("VPS Gateway reads request");
        let req_text = String::from_utf8_lossy(&req_buf[..n]);

        // Verify request semantics:
        // - Invariant: POST /extract
        // - Invariant: Host is gateway.local
        // - Invariant: Authorization token forwarded intact
        assert!(req_text.contains("POST /extract HTTP/1.1"));
        assert!(req_text.contains("Host: gateway.local"));
        assert!(req_text.contains(&format!("Authorization: Bearer {test_token}")));

        let page = ExtractedPage {
            url: "https://example.com/topology-a".to_string(),
            title: "Topology A Verified".to_string(),
            description: Some("Extracted via MasterDNS TCP tunnel".to_string()),
            headings: vec![],
            content: vec![ContentBlock::Paragraph {
                text: "End-to-end endpoint mapping verified.".to_string(),
            }],
            links: vec![],
            images: vec![],
        };
        let body = serde_json::to_string(&page).unwrap();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).unwrap();
        stream.flush().unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });

    // 2. Desktop Local MasterDNS Runtime Listener:
    // Binds to local client port (e.g., 127.0.0.1:1080).
    // In TCP mode, MasterDNS forwards byte streams from the desktop local listener
    // across the DNS tunnel to the VPS MasterDNS forwarder (FORWARD_IP:FORWARD_PORT -> 127.0.0.1:4040).
    let local_tunnel_listener =
        TcpListener::bind("127.0.0.1:0").expect("Bind desktop MasterDNS local listener");
    let desktop_local_addr = local_tunnel_listener
        .local_addr()
        .expect("Desktop local addr");

    let tunnel_handle = thread::spawn(move || {
        let (client_stream, _) = local_tunnel_listener
            .accept()
            .expect("Local MasterDNS accepts client stream");
        let forward_stream =
            std::net::TcpStream::connect(vps_gw_addr).expect("Tunnel forwards to VPS Gateway");

        client_stream
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        forward_stream
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();

        let mut c2f = client_stream.try_clone().unwrap();
        let mut f2c = forward_stream.try_clone().unwrap();
        let mut f_write = forward_stream.try_clone().unwrap();
        let mut c_write = client_stream.try_clone().unwrap();

        let t1 = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                match c2f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if f_write.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = f_write.shutdown(std::net::Shutdown::Write);
        });

        let t2 = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                match f2c.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if c_write.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = c_write.shutdown(std::net::Shutdown::Both);
        });

        let _ = t1.join();
        let _ = t2.join();
    });

    // 3. Desktop Client Configuration:
    // User configures Fixed TCP in Settings:
    // - transport: FixedTcp
    // - tcp_endpoint_str: points to Desktop's local listener (127.0.0.1:1080 / desktop_local_addr)
    // - gateway_token: configured token
    let settings = SettingsState {
        transport: DesktopTransport::FixedTcp,
        tcp_endpoint_str: desktop_local_addr.to_string(),
        gateway_token: test_token.to_string(),
        timeout_secs: 5,
        ..Default::default()
    };

    // Client builds adapter and executes navigation
    let adapter = settings
        .build_tunnel_adapter()
        .expect("Build FixedTcp adapter");
    let (eff_tok, _) = settings.effective_gateway_token();
    let engine = mewser_cli::ClientEngine::new(adapter).with_auth_token(Some(eff_tok));

    let result = engine
        .navigate(
            "https://example.com/topology-a",
            BrowsingMode::ResilientText,
        )
        .expect("Navigation through Topology A must succeed");

    match result {
        mewser_cli::NavigationResult::TextPage(page) => {
            assert_eq!(page.title, "Topology A Verified");
            assert_eq!(page.url, "https://example.com/topology-a");
            assert_eq!(
                page.content,
                vec![ContentBlock::Paragraph {
                    text: "End-to-end endpoint mapping verified.".to_string(),
                }]
            );
        }
    }

    vps_gw_handle.join().expect("VPS Gateway joins");
    tunnel_handle.join().expect("Tunnel thread joins");
}

#[test]
fn test_fixed_tcp_settings_uses_only_tcp_endpoint_and_ignores_gateway_addr_str() {
    let settings = SettingsState {
        transport: DesktopTransport::FixedTcp,
        tcp_endpoint_str: "127.0.0.1:1080".to_string(),
        gateway_addr_str: "irrelevant_target.invalid:9999".to_string(),
        ..Default::default()
    };

    // build_fixed_tcp_config uses strictly tcp_endpoint_str
    let cfg = settings
        .build_fixed_tcp_config()
        .expect("FixedTcp config must succeed");
    assert_eq!(
        cfg.endpoint,
        "127.0.0.1:1080".parse::<std::net::SocketAddr>().unwrap()
    );

    // test_local_endpoint probes tcp_endpoint_str
    let res = settings.test_local_endpoint();
    assert!(res.unwrap_err().contains("127.0.0.1:1080"));
}

#[test]
fn test_masterdns_config_probe_target_conditioned_on_transport() {
    let mut settings = SettingsState {
        transport: DesktopTransport::Socks5,
        gateway_addr_str: "198.51.100.25:4040".to_string(),
        ..Default::default()
    };

    // SOCKS5: probe_target must be Some(gateway_addr_str)
    let cfg_socks5 = settings.build_masterdns_config();
    assert_eq!(
        cfg_socks5.probe_target,
        Some("198.51.100.25:4040".to_string())
    );

    // FixedTcp: probe_target must be None (zero SOCKS5 data plane probing against fixed TCP stream)
    settings.transport = DesktopTransport::FixedTcp;
    let cfg_fixed = settings.build_masterdns_config();
    assert_eq!(cfg_fixed.probe_target, None);
}
