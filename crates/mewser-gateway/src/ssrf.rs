use std::net::{SocketAddr, ToSocketAddrs};
use url::Url;

use crate::error::GatewayError;

pub fn validate_destination_url(raw_url: &str, allow_loopback: bool) -> Result<Url, GatewayError> {
    let url = Url::parse(raw_url).map_err(|e| GatewayError::InvalidUrl(e.to_string()))?;

    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(GatewayError::UnsupportedScheme(scheme.to_string()));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(GatewayError::CredentialsNotAllowed);
    }

    let host = url
        .host_str()
        .ok_or_else(|| GatewayError::InvalidUrl("Missing host in destination URL".to_string()))?;

    validate_host_string(host, allow_loopback)?;

    Ok(url)
}

pub fn validate_host_string(host: &str, allow_loopback: bool) -> Result<(), GatewayError> {
    let lower = host.to_ascii_lowercase();
    if lower == "metadata.google.internal" || lower == "instance-data" {
        return Err(GatewayError::SsrfBlocked {
            target: host.to_string(),
            reason: "Target hostname is reserved cloud metadata".to_string(),
        });
    }

    if lower == "localhost" || lower.ends_with(".localhost") {
        if allow_loopback {
            return Ok(());
        }
        return Err(GatewayError::SsrfBlocked {
            target: host.to_string(),
            reason: "Target hostname is reserved or internal".to_string(),
        });
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if allow_loopback && ip.is_loopback() {
            return Ok(());
        }
        if mewser_core::policy::is_restricted_ip(ip) {
            return Err(GatewayError::SsrfBlocked {
                target: host.to_string(),
                reason: format!("Host IP {ip} is in a restricted range"),
            });
        }
    }

    Ok(())
}

pub fn resolve_and_validate(
    host: &str,
    port: u16,
    allow_loopback: bool,
) -> Result<Vec<SocketAddr>, GatewayError> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            GatewayError::Network(format!("DNS resolution failed for {host}:{port}: {e}"))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(GatewayError::Network(format!(
            "No IP addresses resolved for {host}"
        )));
    }

    for addr in &addrs {
        let ip = addr.ip();
        if allow_loopback && ip.is_loopback() {
            continue;
        }

        if mewser_core::policy::is_restricted_ip(ip) {
            return Err(GatewayError::SsrfBlocked {
                target: host.to_string(),
                reason: format!("Resolved address {ip} is restricted"),
            });
        }
    }

    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_invalid_schemes_and_credentials() {
        assert!(matches!(
            validate_destination_url("file:///etc/shadow", false),
            Err(GatewayError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            validate_destination_url("gopher://example.com/1", false),
            Err(GatewayError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            validate_destination_url("http://admin:secret@example.com/", false),
            Err(GatewayError::CredentialsNotAllowed)
        ));
    }

    #[test]
    fn reject_literal_ssrf_hostnames() {
        assert!(matches!(
            validate_destination_url("http://127.0.0.1:8080/", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_destination_url("https://169.254.169.254/latest/meta-data", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_destination_url("http://localhost:3000/", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_destination_url("http://sub.localhost/", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));
    }

    #[test]
    fn accept_valid_destination_urls() {
        let url =
            validate_destination_url("https://example.com/articles/1?ref=home", false).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/articles/1");
    }

    #[test]
    fn reject_restricted_dns_resolution() {
        let res = resolve_and_validate("localhost", 80, false);
        assert!(matches!(res, Err(GatewayError::SsrfBlocked { .. })));
    }

    #[test]
    fn allow_loopback_when_test_flag_enabled() {
        let res = resolve_and_validate("127.0.0.1", 8080, true);
        assert!(res.is_ok());
    }

    #[test]
    fn reject_cgnat_shared_address_space_boundaries() {
        // Below boundary: allowed
        assert!(validate_destination_url("http://100.63.255.255/", false).is_ok());

        // Exact CGNAT range boundaries (100.64.0.0/10): rejected
        assert!(matches!(
            validate_destination_url("http://100.64.0.0/", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_destination_url("http://100.64.0.1/", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_destination_url("http://100.100.0.1/", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_destination_url("http://100.127.255.255/", false),
            Err(GatewayError::SsrfBlocked { .. })
        ));

        // Above boundary: allowed
        assert!(validate_destination_url("http://100.128.0.0/", false).is_ok());
    }
}
