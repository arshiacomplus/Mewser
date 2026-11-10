use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::CoreError;
use crate::tunnel::TunnelAdapter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedTcpConfig {
    pub endpoint: SocketAddr,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for FixedTcpConfig {
    fn default() -> Self {
        Self {
            endpoint: SocketAddr::from(([127, 0, 0, 1], 1080)),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(5),
            max_response_bytes: 2 * 1024 * 1024,
        }
    }
}

pub struct FixedTcpTunnelAdapter {
    config: FixedTcpConfig,
}

impl FixedTcpTunnelAdapter {
    pub fn new(config: FixedTcpConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &FixedTcpConfig {
        &self.config
    }
}

impl TunnelAdapter for FixedTcpTunnelAdapter {
    fn send_request(&self, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
        if payload.len() > self.max_payload_size() {
            return Err(CoreError::TunnelFailed(format!(
                "Payload size {} exceeds maximum tunnel limit {}",
                payload.len(),
                self.max_payload_size()
            )));
        }

        let mut stream =
            TcpStream::connect_timeout(&self.config.endpoint, self.config.connect_timeout)
                .map_err(|e| {
                    CoreError::TunnelFailed(format!(
                        "Failed to connect to fixed TCP endpoint at {}: {e}",
                        self.config.endpoint
                    ))
                })?;

        stream
            .set_read_timeout(Some(self.config.read_timeout))
            .map_err(|e| {
                CoreError::TunnelFailed(format!("Failed to configure read timeout: {e}"))
            })?;
        stream
            .set_write_timeout(Some(self.config.write_timeout))
            .map_err(|e| {
                CoreError::TunnelFailed(format!("Failed to configure write timeout: {e}"))
            })?;

        stream.write_all(payload).map_err(|e| {
            CoreError::TunnelFailed(format!("Failed sending payload over fixed TCP tunnel: {e}"))
        })?;

        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];

        loop {
            let n = match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    return Err(CoreError::TunnelFailed(
                        "Timed out reading tunnel response".into(),
                    ));
                }
                Err(e) => {
                    return Err(CoreError::TunnelFailed(format!(
                        "Failed reading from fixed TCP stream: {e}"
                    )));
                }
            };

            response.extend_from_slice(&buffer[..n]);
            if response.len() > self.config.max_response_bytes {
                return Err(CoreError::TunnelFailed(format!(
                    "Tunnel response size {} exceeded limit of {}",
                    response.len(),
                    self.config.max_response_bytes
                )));
            }
        }

        Ok(response)
    }

    fn is_connected(&self) -> bool {
        TcpStream::connect_timeout(&self.config.endpoint, Duration::from_millis(200)).is_ok()
    }

    fn max_payload_size(&self) -> usize {
        self.config.max_response_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_tcp_config_default() {
        let config = FixedTcpConfig::default();
        assert_eq!(config.endpoint, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.max_response_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn fixed_tcp_adapter_rejects_oversized_payload() {
        let config = FixedTcpConfig {
            max_response_bytes: 10,
            ..Default::default()
        };
        let adapter = FixedTcpTunnelAdapter::new(config);
        let result = adapter.send_request(b"this is longer than 10 bytes");
        assert!(matches!(result, Err(CoreError::TunnelFailed(_))));
    }
}
