use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::CoreError;
use crate::tunnel::TunnelAdapter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Auth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Debug, Clone)]
pub struct Socks5Config {
    pub proxy_addr: SocketAddr,
    pub auth: Option<Socks5Auth>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            proxy_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            auth: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(5),
            max_response_bytes: 2 * 1024 * 1024,
        }
    }
}

pub struct Socks5TunnelAdapter {
    config: Socks5Config,
    target: Socks5Target,
}

impl Socks5TunnelAdapter {
    pub fn new(config: Socks5Config, target: Socks5Target) -> Self {
        Self { config, target }
    }

    pub fn config(&self) -> &Socks5Config {
        &self.config
    }

    pub fn target(&self) -> &Socks5Target {
        &self.target
    }
}

impl TunnelAdapter for Socks5TunnelAdapter {
    fn send_request(&self, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
        if payload.len() > self.max_payload_size() {
            return Err(CoreError::TunnelFailed(format!(
                "Payload size {} exceeds maximum tunnel limit {}",
                payload.len(),
                self.max_payload_size()
            )));
        }

        let mut stream = connect_and_handshake(&self.config, &self.target)?;

        stream.write_all(payload).map_err(|e| {
            CoreError::TunnelFailed(format!("Failed sending payload over tunnel: {e}"))
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
                        "Failed reading from tunnel stream: {e}"
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
        TcpStream::connect_timeout(&self.config.proxy_addr, Duration::from_millis(200)).is_ok()
    }

    fn max_payload_size(&self) -> usize {
        self.config.max_response_bytes
    }
}

pub fn connect_and_handshake(
    config: &Socks5Config,
    target: &Socks5Target,
) -> Result<TcpStream, CoreError> {
    let mut stream = TcpStream::connect_timeout(&config.proxy_addr, config.connect_timeout)
        .map_err(|e| {
            CoreError::TunnelFailed(format!(
                "Failed to connect to SOCKS5 proxy at {}: {e}",
                config.proxy_addr
            ))
        })?;

    stream
        .set_read_timeout(Some(config.read_timeout))
        .map_err(|e| CoreError::TunnelFailed(format!("Failed to configure read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(config.write_timeout))
        .map_err(|e| CoreError::TunnelFailed(format!("Failed to configure write timeout: {e}")))?;

    if config.auth.is_some() {
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .map_err(|e| CoreError::TunnelFailed(format!("Failed sending SOCKS5 greeting: {e}")))?;
    } else {
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .map_err(|e| CoreError::TunnelFailed(format!("Failed sending SOCKS5 greeting: {e}")))?;
    }

    let mut greeting_reply = [0u8; 2];
    stream.read_exact(&mut greeting_reply).map_err(|e| {
        CoreError::TunnelFailed(format!("Failed reading SOCKS5 greeting reply: {e}"))
    })?;

    if greeting_reply[0] != 0x05 {
        return Err(CoreError::TunnelFailed(format!(
            "Unsupported SOCKS version in handshake: 0x{:02x}",
            greeting_reply[0]
        )));
    }

    match greeting_reply[1] {
        0x00 => {}
        0x02 => {
            let auth = config.auth.as_ref().ok_or_else(|| {
                CoreError::TunnelFailed(
                    "Proxy requested username/password auth unexpectedly".into(),
                )
            })?;

            let mut auth_req = Vec::new();
            auth_req.push(0x01);
            let u_bytes = auth.username.as_bytes();
            if u_bytes.len() > 255 {
                return Err(CoreError::TunnelFailed("Username exceeds 255 bytes".into()));
            }
            auth_req.push(u_bytes.len() as u8);
            auth_req.extend_from_slice(u_bytes);

            let p_bytes = auth.password.as_bytes();
            if p_bytes.len() > 255 {
                return Err(CoreError::TunnelFailed("Password exceeds 255 bytes".into()));
            }
            auth_req.push(p_bytes.len() as u8);
            auth_req.extend_from_slice(p_bytes);

            stream.write_all(&auth_req).map_err(|e| {
                CoreError::TunnelFailed(format!("Failed sending SOCKS5 auth request: {e}"))
            })?;

            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).map_err(|e| {
                CoreError::TunnelFailed(format!("Failed reading SOCKS5 auth reply: {e}"))
            })?;

            if auth_reply[1] != 0x00 {
                return Err(CoreError::TunnelFailed(
                    "SOCKS5 authentication rejected by proxy (bad credentials)".into(),
                ));
            }
        }
        0xFF => {
            return Err(CoreError::TunnelFailed(
                "SOCKS5 proxy rejected authentication methods".into(),
            ));
        }
        other => {
            return Err(CoreError::TunnelFailed(format!(
                "Unsupported SOCKS5 auth method selected by proxy: 0x{other:02x}"
            )));
        }
    }

    let mut connect_req = Vec::new();
    connect_req.extend_from_slice(&[0x05, 0x01, 0x00]);

    match target {
        Socks5Target::Ip(SocketAddr::V4(v4)) => {
            connect_req.push(0x01);
            connect_req.extend_from_slice(&v4.ip().octets());
            connect_req.extend_from_slice(&v4.port().to_be_bytes());
        }
        Socks5Target::Ip(SocketAddr::V6(v6)) => {
            connect_req.push(0x04);
            connect_req.extend_from_slice(&v6.ip().octets());
            connect_req.extend_from_slice(&v6.port().to_be_bytes());
        }
        Socks5Target::Domain(domain, port) => {
            if let Ok(ip) = domain.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        connect_req.push(0x01);
                        connect_req.extend_from_slice(&v4.octets());
                        connect_req.extend_from_slice(&port.to_be_bytes());
                    }
                    IpAddr::V6(v6) => {
                        connect_req.push(0x04);
                        connect_req.extend_from_slice(&v6.octets());
                        connect_req.extend_from_slice(&port.to_be_bytes());
                    }
                }
            } else {
                let d_bytes = domain.as_bytes();
                if d_bytes.len() > 255 {
                    return Err(CoreError::TunnelFailed(
                        "Target domain exceeds 255 bytes".into(),
                    ));
                }
                connect_req.push(0x03);
                connect_req.push(d_bytes.len() as u8);
                connect_req.extend_from_slice(d_bytes);
                connect_req.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    stream.write_all(&connect_req).map_err(|e| {
        CoreError::TunnelFailed(format!("Failed sending SOCKS5 CONNECT command: {e}"))
    })?;

    let mut connect_header = [0u8; 4];
    stream.read_exact(&mut connect_header).map_err(|e| {
        CoreError::TunnelFailed(format!("Failed reading SOCKS5 CONNECT reply header: {e}"))
    })?;

    if connect_header[0] != 0x05 {
        return Err(CoreError::TunnelFailed(format!(
            "Invalid SOCKS version in CONNECT reply: 0x{:02x}",
            connect_header[0]
        )));
    }

    if connect_header[1] != 0x00 {
        let reason = match connect_header[1] {
            0x01 => "General SOCKS server failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused",
            0x06 => "TTL expired",
            0x07 => "Command not supported",
            0x08 => "Address type not supported",
            _ => "Unknown SOCKS5 error",
        };
        return Err(CoreError::TunnelFailed(format!(
            "SOCKS5 connection rejected by proxy: {reason} (code 0x{:02x})",
            connect_header[1]
        )));
    }

    match connect_header[3] {
        0x01 => {
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port).map_err(|e| {
                CoreError::TunnelFailed(format!("Failed reading SOCKS5 IPv4 bound address: {e}"))
            })?;
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).map_err(|e| {
                CoreError::TunnelFailed(format!("Failed reading SOCKS5 domain bound length: {e}"))
            })?;
            let len = len_byte[0] as usize;
            let mut buf = vec![0u8; len + 2];
            stream.read_exact(&mut buf).map_err(|e| {
                CoreError::TunnelFailed(format!("Failed reading SOCKS5 domain bound address: {e}"))
            })?;
        }
        0x04 => {
            let mut addr_port = [0u8; 18];
            stream.read_exact(&mut addr_port).map_err(|e| {
                CoreError::TunnelFailed(format!("Failed reading SOCKS5 IPv6 bound address: {e}"))
            })?;
        }
        other => {
            return Err(CoreError::TunnelFailed(format!(
                "Unknown address type in SOCKS5 CONNECT reply: 0x{other:02x}"
            )));
        }
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_config_default_matches_masterdns_parameters() {
        let cfg = Socks5Config::default();
        assert_eq!(cfg.proxy_addr.port(), 1080);
        assert_eq!(cfg.proxy_addr.ip(), IpAddr::from([127, 0, 0, 1]));
        assert_eq!(cfg.auth, None);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
    }
}
