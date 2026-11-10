use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum GatewayError {
    InvalidUrl(String),
    UnsupportedScheme(String),
    CredentialsNotAllowed,
    SsrfBlocked { target: String, reason: String },
    RedirectLimitExceeded(usize),
    ResponseTooLarge { limit: usize, received: usize },
    Timeout(String),
    HttpError { status: u16, message: String },
    Network(String),
    Extraction(String),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
            Self::UnsupportedScheme(scheme) => write!(f, "Unsupported scheme: {scheme}"),
            Self::CredentialsNotAllowed => {
                write!(f, "Credentials are not allowed in destination URLs")
            }
            Self::SsrfBlocked { target, reason } => {
                write!(f, "SSRF defense blocked destination {target}: {reason}")
            }
            Self::RedirectLimitExceeded(max) => {
                write!(f, "Redirect limit of {max} exceeded")
            }
            Self::ResponseTooLarge { limit, received } => {
                write!(
                    f,
                    "Response body size ({received} bytes) exceeded maximum limit ({limit} bytes)"
                )
            }
            Self::Timeout(op) => write!(f, "Operation timed out during {op}"),
            Self::HttpError { status, message } => {
                write!(f, "HTTP error {status}: {message}")
            }
            Self::Network(msg) => write!(f, "Network error: {msg}"),
            Self::Extraction(msg) => write!(f, "Extraction error: {msg}"),
        }
    }
}

impl std::error::Error for GatewayError {}
