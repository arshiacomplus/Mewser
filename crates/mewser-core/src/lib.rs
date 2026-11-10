pub mod error;
pub mod policy;
pub mod proxy;
pub mod router;
pub mod tunnel;

pub use error::CoreError;
pub use policy::ParsedTarget;
pub use proxy::{PolicyProxy, PolicyProxyConfig, PolicyProxyHandle, PolicyProxyStats};
pub use router::{RouteDecision, RouteMode, RoutingPolicy};
pub use tunnel::{
    FixedTcpConfig, FixedTcpTunnelAdapter, MockTunnelAdapter, Socks5Auth, Socks5Config,
    Socks5Target, Socks5TunnelAdapter, TunnelAdapter, TunnelTransport,
};
