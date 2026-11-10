use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn get_release_binary_path() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let bin = root
        .join("target")
        .join("x86_64-unknown-linux-gnu")
        .join("release")
        .join("mewser-gateway");
    if bin.is_file() {
        return bin;
    }
    // Fallback to debug or host release target
    let fallback = root.join("target").join("release").join("mewser-gateway");
    if fallback.is_file() {
        return fallback;
    }
    root.join("target").join("debug").join("mewser-gateway")
}

fn find_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().unwrap().port()
}

struct TestGatewayProcess {
    child: Child,
    addr: SocketAddr,
    token: String,
}

impl TestGatewayProcess {
    fn spawn(token: Option<&str>, bind_addr: Option<SocketAddr>, allow_non_loopback: bool) -> Self {
        let bin = get_release_binary_path();
        assert!(
            bin.is_file(),
            "mewser-gateway binary must exist at {:?}",
            bin
        );

        let port = find_free_port();
        let addr = bind_addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)));
        let tok = token.unwrap_or("test-secret-token-abcdef1234567890abcdef1234567890");

        let mut cmd = Command::new(&bin);
        cmd.env("MEWSER_GATEWAY_BIND", addr.to_string());
        cmd.env("MEWSER_GATEWAY_AUTH_TOKEN", tok);
        if allow_non_loopback {
            cmd.env("MEWSER_GATEWAY_ALLOW_NON_LOOPBACK", "1");
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn().expect("failed to spawn mewser-gateway");

        // Wait for server to bind and accept connections
        let start = Instant::now();
        let mut ready = false;
        while start.elapsed() < Duration::from_secs(3) {
            if TcpStream::connect(addr).is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(
            ready,
            "Gateway failed to start within 3 seconds on {}",
            addr
        );

        Self {
            child,
            addr,
            token: tok.to_string(),
        }
    }
}

impl Drop for TestGatewayProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let pid = self.child.id() as i32;
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(1500) {
                if let Ok(Some(_)) = self.child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_gateway_binary_starts_and_health_check() {
    let gw = TestGatewayProcess::spawn(None, None, false);

    let mut stream = TcpStream::connect(gw.addr).unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains(r#"{"status":"ok"}"#));
}

#[test]
fn test_gateway_binary_fails_on_missing_token_by_default() {
    let bin = get_release_binary_path();
    let port = find_free_port();

    let mut cmd = Command::new(&bin);
    cmd.env("MEWSER_GATEWAY_BIND", format!("127.0.0.1:{port}"));
    cmd.env_remove("MEWSER_GATEWAY_AUTH_TOKEN");
    cmd.env_remove("MEWSER_GATEWAY_REQUIRE_AUTH");

    let output = cmd.output().expect("failed to run command");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Authentication token is required"),
        "Expected missing token fatal error, got: {}",
        stderr
    );
}

#[test]
fn test_gateway_binary_rejects_non_loopback_without_allow_flag() {
    let bin = get_release_binary_path();

    let mut cmd = Command::new(&bin);
    cmd.env("MEWSER_GATEWAY_BIND", "192.168.1.100:4040");
    cmd.env("MEWSER_GATEWAY_AUTH_TOKEN", "valid-token-12345");
    cmd.env_remove("MEWSER_GATEWAY_ALLOW_NON_LOOPBACK");

    let output = cmd.output().expect("failed to run command");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Gateway must bind exclusively to a loopback address"),
        "Expected non-loopback rejection, got: {}",
        stderr
    );
}

#[test]
fn test_gateway_binary_authentication_and_extraction_flow() {
    let gw = TestGatewayProcess::spawn(Some("valid-secret-bearer-tok-999"), None, false);

    // 1. Unauthenticated request to /extract returns 401
    let mut s1 = TcpStream::connect(gw.addr).unwrap();
    let unauth_body = r#"{"url":"https://example.com/"}"#;
    let unauth_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        unauth_body.len(),
        unauth_body
    );
    s1.write_all(unauth_req.as_bytes()).unwrap();
    let mut resp1 = String::new();
    s1.read_to_string(&mut resp1).unwrap();
    assert!(resp1.starts_with("HTTP/1.1 401 Unauthorized"));

    // 2. Invalid token returns 401
    let mut s2 = TcpStream::connect(gw.addr).unwrap();
    let wrong_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\nContent-Length: {}\r\n\r\n{}",
        unauth_body.len(),
        unauth_body
    );
    s2.write_all(wrong_req.as_bytes()).unwrap();
    let mut resp2 = String::new();
    s2.read_to_string(&mut resp2).unwrap();
    assert!(resp2.starts_with("HTTP/1.1 401 Unauthorized"));

    // 3. Valid token on SSRF target (loopback IP) returns 403 Forbidden
    let mut s3 = TcpStream::connect(gw.addr).unwrap();
    let ssrf_body = r#"{"url":"http://127.0.0.1:9999/admin"}"#;
    let ssrf_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}",
        gw.token,
        ssrf_body.len(),
        ssrf_body
    );
    s3.write_all(ssrf_req.as_bytes()).unwrap();
    let mut resp3 = String::new();
    s3.read_to_string(&mut resp3).unwrap();
    assert!(
        resp3.starts_with("HTTP/1.1 403 Forbidden"),
        "Expected 403 Forbidden for SSRF target, got: {}",
        resp3
    );
    assert!(resp3.contains("restricted range") || resp3.contains("SSRF"));

    // 4. Valid token on CGNAT target (RFC 6598 100.64.0.1) returns 403 Forbidden
    let mut s4 = TcpStream::connect(gw.addr).unwrap();
    let cgnat_body = r#"{"url":"http://100.64.0.1/admin"}"#;
    let cgnat_req = format!(
        "POST /extract HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}",
        gw.token,
        cgnat_body.len(),
        cgnat_body
    );
    s4.write_all(cgnat_req.as_bytes()).unwrap();
    let mut resp4 = String::new();
    s4.read_to_string(&mut resp4).unwrap();
    assert!(
        resp4.starts_with("HTTP/1.1 403 Forbidden"),
        "Expected 403 Forbidden for CGNAT SSRF target, got: {}",
        resp4
    );
    assert!(resp4.contains("restricted range") || resp4.contains("SSRF"));
}

#[cfg(unix)]
#[test]
fn test_gateway_binary_graceful_sigterm_shutdown() {
    let mut gw = TestGatewayProcess::spawn(None, None, false);
    let pid = gw.child.id() as i32;

    // Send SIGTERM
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    let start = Instant::now();
    let mut exited = false;
    while start.elapsed() < Duration::from_secs(3) {
        if let Ok(Some(status)) = gw.child.try_wait() {
            assert!(
                status.success() || status.code() == Some(0),
                "Process should exit cleanly on SIGTERM, got: {:?}",
                status
            );
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(
        exited,
        "Gateway did not gracefully shut down within 3s on SIGTERM"
    );
}

#[cfg(unix)]
#[test]
fn test_gateway_binary_environment_secrets_not_in_cmdline() {
    let secret = "very-confidential-secret-key-do-not-leak";
    let gw = TestGatewayProcess::spawn(Some(secret), None, false);
    let pid = gw.child.id();

    let cmdline_path = format!("/proc/{pid}/cmdline");
    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
        assert!(
            !cmdline.contains(secret),
            "Secret token leaked into /proc/{pid}/cmdline!"
        );
    }
}

#[test]
fn test_packaged_distribution_checksums_match() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let dist_dir = root.join("dist").join("gateway").join("linux-x86_64");

    let sums_path = dist_dir.join("SHA256SUMS");
    assert!(sums_path.is_file(), "SHA256SUMS file must exist in package");

    let output = Command::new("sha256sum")
        .arg("-c")
        .arg("SHA256SUMS")
        .current_dir(&dist_dir)
        .output()
        .expect("run sha256sum -c");

    assert!(
        output.status.success(),
        "sha256sum -c failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
