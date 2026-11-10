use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_redirects: usize,
    pub user_agent: String,
    pub listen_addr: SocketAddr,
    pub allow_loopback_for_testing: bool,
    pub auth_token: Option<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            max_response_bytes: 2 * 1024 * 1024,
            max_redirects: 5,
            user_agent: "MewserGateway/0.1".to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 4040)),
            allow_loopback_for_testing: false,
            auth_token: None,
        }
    }
}
