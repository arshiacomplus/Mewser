use std::fmt;
use std::str::FromStr;

use crate::error::ClientError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowsingMode {
    ResilientText,
    StandardWeb,
}

impl FromStr for BrowsingMode {
    type Err = ClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "resilient-text" | "text" | "resilient" => Ok(Self::ResilientText),
            "standard-web" | "web" | "standard" => Ok(Self::StandardWeb),
            other => Err(ClientError::InvalidMode(format!(
                "Unknown browsing mode '{other}'. Must be 'resilient-text' or 'standard-web'"
            ))),
        }
    }
}

impl fmt::Display for BrowsingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResilientText => write!(f, "resilient-text"),
            Self::StandardWeb => write!(f, "standard-web"),
        }
    }
}
