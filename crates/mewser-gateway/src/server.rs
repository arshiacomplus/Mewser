use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Deserialize;

use crate::error::GatewayError;
use crate::Gateway;

#[derive(Deserialize)]
struct ExtractRequest {
    url: String,
}

pub struct GatewayServer {
    listener: TcpListener,
    gateway: Arc<Gateway>,
    shutdown: Arc<AtomicBool>,
}

impl GatewayServer {
    pub fn bind(addr: SocketAddr, gateway: Gateway) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;

        Ok(Self {
            listener,
            gateway: Arc::new(gateway),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn spawn(self) -> (GatewayServerHandle, JoinHandle<()>) {
        let shutdown_thread = Arc::clone(&self.shutdown);
        let shutdown_handle = Arc::clone(&self.shutdown);
        let listener = self.listener;
        let gateway = self.gateway;

        let thread_handle = thread::spawn(move || {
            while !shutdown_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let gw = Arc::clone(&gateway);
                        thread::spawn(move || {
                            let _ = handle_connection(stream, &gw);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let handle = GatewayServerHandle {
            shutdown: shutdown_handle,
        };
        (handle, thread_handle)
    }
}

pub struct GatewayServerHandle {
    shutdown: Arc<AtomicBool>,
}

impl GatewayServerHandle {
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn handle_connection(mut stream: TcpStream, gateway: &Gateway) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut stream, 400, r#"{"error":"Malformed HTTP request"}"#)?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    let mut content_length = 0usize;
    let mut auth_header: Option<String> = None;
    loop {
        let mut header_line = String::new();
        if reader.read_line(&mut header_line)? == 0 || header_line == "\r\n" || header_line == "\n"
        {
            break;
        }
        if let Some((name, val)) = header_line.split_once(':') {
            let name_trim = name.trim();
            if name_trim.eq_ignore_ascii_case("content-length") {
                if let Ok(len) = val.trim().parse::<usize>() {
                    content_length = len;
                }
            } else if name_trim.eq_ignore_ascii_case("authorization") {
                auth_header = Some(val.trim().to_string());
            }
        }
    }

    if method == "GET" && path == "/health" {
        send_response(&mut stream, 200, r#"{"status":"ok"}"#)?;
        return Ok(());
    }

    if let Some(expected_token) = &gateway.config().auth_token {
        let is_valid = match auth_header.as_deref() {
            Some(header_val) => {
                let parts: Vec<&str> = header_val.split_whitespace().collect();
                if parts.len() == 2 && parts[0].eq_ignore_ascii_case("Bearer") {
                    constant_time_eq(parts[1].as_bytes(), expected_token.as_bytes())
                } else {
                    false
                }
            }
            None => false,
        };

        if !is_valid {
            send_response(&mut stream, 401, r#"{"error":"Unauthorized"}"#)?;
            return Ok(());
        }
    }

    let target_url = if method == "GET" && path.starts_with("/extract") {
        match extract_url_from_query(path) {
            Some(u) => u,
            None => {
                send_response(
                    &mut stream,
                    400,
                    r#"{"error":"Missing or invalid 'url' query parameter"}"#,
                )?;
                return Ok(());
            }
        }
    } else if method == "POST" && path == "/extract" {
        if content_length == 0 || content_length > 1024 * 64 {
            send_response(
                &mut stream,
                400,
                r#"{"error":"Invalid request payload size"}"#,
            )?;
            return Ok(());
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;

        match serde_json::from_slice::<ExtractRequest>(&body) {
            Ok(req) => req.url,
            Err(_) => {
                send_response(
                    &mut stream,
                    400,
                    r#"{"error":"Invalid JSON body; expected {\"url\":\"...\"}"}"#,
                )?;
                return Ok(());
            }
        }
    } else {
        send_response(&mut stream, 404, r#"{"error":"Endpoint not found"}"#)?;
        return Ok(());
    };

    match gateway.extract(&target_url) {
        Ok(page) => {
            let json = serde_json::to_string(&page).unwrap_or_else(|_| "{}".to_string());
            send_response(&mut stream, 200, &json)?;
        }
        Err(err) => {
            let (status, msg) = error_to_response(&err);
            let resp = serde_json::json!({ "error": msg }).to_string();
            send_response(&mut stream, status, &resp)?;
        }
    }

    Ok(())
}

fn extract_url_from_query(path: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        if k == "url" && !v.trim().is_empty() {
            return Some(v.into_owned());
        }
    }
    None
}

fn error_to_response(err: &GatewayError) -> (u16, String) {
    match err {
        GatewayError::InvalidUrl(_)
        | GatewayError::UnsupportedScheme(_)
        | GatewayError::CredentialsNotAllowed => (400, err.to_string()),
        GatewayError::SsrfBlocked { .. } => (403, err.to_string()),
        GatewayError::ResponseTooLarge { .. } => (413, err.to_string()),
        GatewayError::Timeout(_) => (504, err.to_string()),
        _ => (502, err.to_string()),
    }
}

fn send_response(stream: &mut TcpStream, status_code: u16, body: &str) -> std::io::Result<()> {
    let status_text = match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Internal Server Error",
    };

    let response = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );

    stream.write_all(response.as_bytes())?;
    stream.flush()
}
