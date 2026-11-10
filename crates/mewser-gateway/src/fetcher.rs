use std::io::Read;
use url::Url;

use crate::config::GatewayConfig;
use crate::error::GatewayError;
use crate::ssrf::validate_destination_url;

pub struct SafeFetcher {
    agent: ureq::Agent,
    config: GatewayConfig,
}

impl SafeFetcher {
    pub fn new(config: GatewayConfig) -> Self {
        let allow_loopback = config.allow_loopback_for_testing;

        let agent = ureq::builder()
            .timeout_connect(config.connect_timeout)
            .timeout_read(config.read_timeout)
            .redirects(0)
            .resolver(
                move |netloc: &str| -> std::io::Result<Vec<std::net::SocketAddr>> {
                    let (host, port_str) = netloc.rsplit_once(':').ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Missing port in resolver address",
                        )
                    })?;

                    let port: u16 = port_str
                        .parse()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

                    let host_clean = if host.starts_with('[') && host.ends_with(']') {
                        &host[1..host.len() - 1]
                    } else {
                        host
                    };

                    crate::ssrf::resolve_and_validate(host_clean, port, allow_loopback).map_err(
                        |e| {
                            std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string())
                        },
                    )
                },
            )
            .build();

        Self { agent, config }
    }

    pub fn fetch(&self, raw_url: &str) -> Result<(String, Url), GatewayError> {
        let allow_loopback = self.config.allow_loopback_for_testing;
        let mut current_url = validate_destination_url(raw_url, allow_loopback)?;
        let mut redirect_count = 0usize;

        loop {
            let resp = match self
                .agent
                .get(current_url.as_str())
                .set("User-Agent", &self.config.user_agent)
                .set(
                    "Accept",
                    "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
                )
                .call()
            {
                Ok(r) => r,
                Err(ureq::Error::Status(code, r)) => {
                    if (300..=399).contains(&code) {
                        r
                    } else {
                        return Err(GatewayError::HttpError {
                            status: code,
                            message: format!("HTTP request failed with status {code}"),
                        });
                    }
                }
                Err(ureq::Error::Transport(t)) => {
                    let msg = t.to_string();
                    if msg.contains("SSRF defense blocked") || msg.contains("PermissionDenied") {
                        return Err(GatewayError::SsrfBlocked {
                            target: current_url.to_string(),
                            reason: msg,
                        });
                    }
                    if t.kind() == ureq::ErrorKind::Io && msg.contains("timed out") {
                        return Err(GatewayError::Timeout("connection or read".to_string()));
                    }
                    return Err(GatewayError::Network(msg));
                }
            };

            let status = resp.status();
            if (300..=399).contains(&status) {
                redirect_count += 1;
                if redirect_count > self.config.max_redirects {
                    return Err(GatewayError::RedirectLimitExceeded(
                        self.config.max_redirects,
                    ));
                }

                let location = resp
                    .header("Location")
                    .ok_or_else(|| GatewayError::HttpError {
                        status,
                        message: "Redirect response missing Location header".to_string(),
                    })?;

                let next_url = current_url.join(location).map_err(|e| {
                    GatewayError::InvalidUrl(format!("Invalid redirect Location header: {e}"))
                })?;

                current_url = validate_destination_url(next_url.as_str(), allow_loopback)?;
                continue;
            }

            if let Some(cl_str) = resp.header("Content-Length") {
                if let Ok(cl) = cl_str.parse::<usize>() {
                    if cl > self.config.max_response_bytes {
                        return Err(GatewayError::ResponseTooLarge {
                            limit: self.config.max_response_bytes,
                            received: cl,
                        });
                    }
                }
            }

            let mut reader = resp.into_reader();
            let mut body = Vec::new();
            let mut chunk = [0u8; 8192];

            loop {
                let n = reader.read(&mut chunk).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        GatewayError::Timeout("reading response body".to_string())
                    } else {
                        GatewayError::Network(format!("Failed reading response: {e}"))
                    }
                })?;

                if n == 0 {
                    break;
                }

                body.extend_from_slice(&chunk[..n]);
                if body.len() > self.config.max_response_bytes {
                    return Err(GatewayError::ResponseTooLarge {
                        limit: self.config.max_response_bytes,
                        received: body.len(),
                    });
                }
            }

            let html = String::from_utf8_lossy(&body).into_owned();
            return Ok((html, current_url));
        }
    }
}
