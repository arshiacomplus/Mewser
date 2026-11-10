pub mod fixed_tcp;
pub mod socks5;

use crate::error::CoreError;

pub trait TunnelAdapter {
    fn send_request(&self, payload: &[u8]) -> Result<Vec<u8>, CoreError>;
    fn is_connected(&self) -> bool;
    fn max_payload_size(&self) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelTransport {
    Socks5,
    FixedTcp,
}

pub use fixed_tcp::{FixedTcpConfig, FixedTcpTunnelAdapter};
pub use socks5::{Socks5Auth, Socks5Config, Socks5Target, Socks5TunnelAdapter};

#[derive(Debug, Default)]
pub struct MockTunnelAdapter {
    pub connected: bool,
    pub max_size: usize,
}

impl MockTunnelAdapter {
    pub fn new(connected: bool, max_size: usize) -> Self {
        Self {
            connected,
            max_size,
        }
    }
}

impl TunnelAdapter for MockTunnelAdapter {
    fn send_request(&self, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
        if !self.connected {
            return Err(CoreError::TunnelFailed("Tunnel adapter is offline".into()));
        }
        if payload.len() > self.max_size {
            return Err(CoreError::TunnelFailed(format!(
                "Payload size {} exceeds maximum tunnel MTU {}",
                payload.len(),
                self.max_size
            )));
        }

        let mut echo = b"ACK:".to_vec();
        echo.extend_from_slice(payload);
        Ok(echo)
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn max_payload_size(&self) -> usize {
        self.max_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_adapter_transfers_within_bounds() {
        let adapter = MockTunnelAdapter::new(true, 512);
        let resp = adapter.send_request(b"ping").unwrap();
        assert_eq!(resp, b"ACK:ping");
    }

    #[test]
    fn mock_adapter_rejects_disconnected_or_oversized() {
        let offline = MockTunnelAdapter::new(false, 512);
        assert!(matches!(
            offline.send_request(b"data"),
            Err(CoreError::TunnelFailed(_))
        ));

        let small_mtu = MockTunnelAdapter::new(true, 4);
        assert!(matches!(
            small_mtu.send_request(b"too large"),
            Err(CoreError::TunnelFailed(_))
        ));
    }
}
