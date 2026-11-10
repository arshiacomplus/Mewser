use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CoreError {
    InvalidUrl(String),
    UnsupportedScheme(String),
    SsrfBlocked(String),
    HostMissing,
    TunnelFailed(String),
    DirectFallbackForbidden,
    Configuration(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "Invalid URL format: {url}"),
            Self::UnsupportedScheme(s) => write!(f, "Unsupported URL scheme: {s}"),
            Self::SsrfBlocked(target) => write!(f, "Target blocked by SSRF defense: {target}"),
            Self::HostMissing => write!(f, "URL host component missing"),
            Self::TunnelFailed(reason) => write!(f, "Tunnel transmission failed: {reason}"),
            Self::DirectFallbackForbidden => write!(
                f,
                "Tunnel-designated request failed; direct network fallback is forbidden"
            ),
            Self::Configuration(msg) => write!(f, "Configuration error: {msg}"),
        }
    }
}

impl std::error::Error for CoreError {}
