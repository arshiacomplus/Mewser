use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ClientError {
    MissingMode,
    MissingUrl,
    InvalidMode(String),
    InvalidUrl(String),
    StandardWebNotImplemented,
    Tunnel(String),
    Gateway { status: u16, message: String },
    MalformedResponse(String),
    ResponseTooLarge { limit: usize, received: usize },
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMode => write!(
                f,
                "Explicit browsing mode selection is required for privacy. Use '--mode resilient-text' or '--mode standard-web'"
            ),
            Self::MissingUrl => write!(f, "Missing destination URL. Use '--url <URL>'"),
            Self::InvalidMode(msg) => write!(f, "{msg}"),
            Self::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
            Self::StandardWebNotImplemented => write!(
                f,
                "Standard Web mode is not implemented yet (requires native browser engine integration). No network request was performed."
            ),
            Self::Tunnel(msg) => write!(f, "Tunnel transmission error: {msg}"),
            Self::Gateway { status, message } => {
                write!(f, "Gateway returned HTTP {status}: {message}")
            }
            Self::MalformedResponse(msg) => write!(f, "Malformed Gateway response: {msg}"),
            Self::ResponseTooLarge { limit, received } => write!(
                f,
                "Response size ({received} bytes) exceeded maximum allowed limit ({limit} bytes)"
            ),
        }
    }
}

impl std::error::Error for ClientError {}

pub fn sanitize_url_for_display(raw_url: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(raw_url) {
        if parsed.query().is_some() {
            parsed.set_query(Some("[REDACTED]"));
        }
        parsed.to_string()
    } else if let Some((base, _)) = raw_url.split_once('?') {
        format!("{base}?[REDACTED]")
    } else {
        raw_url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_url_redacts_query() {
        let clean = sanitize_url_for_display("https://example.com/search?q=secret&token=12345");
        assert_eq!(clean, "https://example.com/search?[REDACTED]");

        let no_query = sanitize_url_for_display("https://example.com/article/10");
        assert_eq!(no_query, "https://example.com/article/10");
    }
}
