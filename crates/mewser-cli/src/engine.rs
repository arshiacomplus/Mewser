use mewser_core::tunnel::{
    FixedTcpConfig, FixedTcpTunnelAdapter, Socks5Config, Socks5Target, Socks5TunnelAdapter,
    TunnelAdapter,
};
use mewser_gateway::ExtractedPage;
use url::Url;

use crate::error::{sanitize_url_for_display, ClientError};
use crate::mode::BrowsingMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationResult {
    TextPage(ExtractedPage),
}

pub struct ClientEngine {
    adapter: Box<dyn TunnelAdapter + Send + Sync>,
    auth_token: Option<String>,
}

impl ClientEngine {
    pub fn new(adapter: Box<dyn TunnelAdapter + Send + Sync>) -> Self {
        Self {
            adapter,
            auth_token: None,
        }
    }

    pub fn with_auth_token(mut self, auth_token: Option<String>) -> Self {
        self.auth_token = auth_token.filter(|t| !t.trim().is_empty());
        self
    }

    pub fn set_auth_token(&mut self, auth_token: Option<String>) {
        self.auth_token = auth_token.filter(|t| !t.trim().is_empty());
    }

    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }

    pub fn with_socks5(config: Socks5Config, gateway_target: Socks5Target) -> Self {
        let adapter = Socks5TunnelAdapter::new(config, gateway_target);
        Self {
            adapter: Box::new(adapter),
            auth_token: None,
        }
    }

    pub fn with_fixed_tcp(config: FixedTcpConfig) -> Self {
        let adapter = FixedTcpTunnelAdapter::new(config);
        Self {
            adapter: Box::new(adapter),
            auth_token: None,
        }
    }

    pub fn navigate(
        &self,
        raw_url: &str,
        mode: BrowsingMode,
    ) -> Result<NavigationResult, ClientError> {
        match mode {
            BrowsingMode::StandardWeb => Err(ClientError::StandardWebNotImplemented),
            BrowsingMode::ResilientText => self.extract_via_gateway(raw_url),
        }
    }

    fn extract_via_gateway(&self, raw_url: &str) -> Result<NavigationResult, ClientError> {
        let parsed = Url::parse(raw_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ClientError::InvalidUrl(format!(
                "Unsupported scheme '{scheme}'. Only http and https are allowed"
            )));
        }

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ClientError::InvalidUrl(
                "Credentials are not permitted in destination URLs".into(),
            ));
        }

        let post_json = serde_json::json!({ "url": raw_url });
        let body_bytes = serde_json::to_vec(&post_json).map_err(|e| {
            ClientError::MalformedResponse(format!("Failed to serialize request: {e}"))
        })?;

        let mut http_request = format!(
            "POST /extract HTTP/1.1\r\n\
             Host: gateway.local\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n",
            body_bytes.len()
        );

        if let Some(ref token) = self.auth_token {
            http_request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }

        http_request.push_str("Connection: close\r\n\r\n");

        let mut payload = http_request.into_bytes();
        payload.extend_from_slice(&body_bytes);

        let response_bytes = self.adapter.send_request(&payload).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("exceeded limit") {
                ClientError::ResponseTooLarge {
                    limit: self.adapter.max_payload_size(),
                    received: 0,
                }
            } else {
                ClientError::Tunnel(msg)
            }
        })?;

        self.parse_gateway_http_response(&response_bytes, raw_url)
    }

    fn parse_gateway_http_response(
        &self,
        bytes: &[u8],
        raw_url: &str,
    ) -> Result<NavigationResult, ClientError> {
        let text = String::from_utf8_lossy(bytes);

        let header_end = text
            .find("\r\n\r\n")
            .or_else(|| text.find("\n\n"))
            .ok_or_else(|| {
                ClientError::MalformedResponse("Incomplete HTTP response from Gateway".into())
            })?;

        let delimiter_len = if text.contains("\r\n\r\n") { 4 } else { 2 };
        let headers_part = &text[..header_end];
        let body_part = &text[header_end + delimiter_len..];

        let status_line = headers_part.lines().next().ok_or_else(|| {
            ClientError::MalformedResponse("Missing HTTP status line from Gateway".into())
        })?;

        let status_code = parse_status_code(status_line)?;

        if status_code != 200 {
            if status_code == 401 {
                return Err(ClientError::Gateway {
                    status: 401,
                    message: "Authentication failed: Missing or invalid Gateway authorization token (MEWSER_GATEWAY_AUTH_TOKEN)".to_string(),
                });
            }

            let error_msg = if let Ok(val) = serde_json::from_str::<serde_json::Value>(body_part) {
                val.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or(body_part.trim())
                    .to_string()
            } else {
                body_part.trim().to_string()
            };

            return Err(ClientError::Gateway {
                status: status_code,
                message: if error_msg.is_empty() {
                    format!("Gateway returned error status {status_code}")
                } else {
                    error_msg
                },
            });
        }

        let page: ExtractedPage = serde_json::from_str(body_part).map_err(|e| {
            let safe_url = sanitize_url_for_display(raw_url);
            ClientError::MalformedResponse(format!(
                "Failed to parse Gateway JSON for destination {safe_url}: {e}"
            ))
        })?;

        Ok(NavigationResult::TextPage(page))
    }
}

fn parse_status_code(status_line: &str) -> Result<u16, ClientError> {
    let mut parts = status_line.split_whitespace();
    parts.next(); // Skip HTTP/1.1
    let code_str = parts.next().ok_or_else(|| {
        ClientError::MalformedResponse(format!("Invalid status line: {status_line}"))
    })?;

    code_str.parse::<u16>().map_err(|_| {
        ClientError::MalformedResponse(format!("Invalid status code in line: {status_line}"))
    })
}
