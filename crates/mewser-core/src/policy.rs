use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::CoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarget {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path_and_query: String,
}

impl ParsedTarget {
    pub fn parse(raw_url: &str) -> Result<Self, CoreError> {
        let trimmed = raw_url.trim();

        let (scheme, rest) = trimmed
            .split_once("://")
            .ok_or_else(|| CoreError::InvalidUrl(trimmed.to_string()))?;

        let scheme_lower = scheme.to_ascii_lowercase();
        if scheme_lower != "http" && scheme_lower != "https" {
            return Err(CoreError::UnsupportedScheme(scheme_lower));
        }

        let (authority, path_and_query) = match rest.find(['/', '?', '#']) {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/".to_string()),
        };

        let host_port_part = match authority.rfind('@') {
            Some(idx) => &authority[idx + 1..],
            None => authority,
        };

        if host_port_part.is_empty() {
            return Err(CoreError::HostMissing);
        }

        let (host, port) = if host_port_part.starts_with('[') {
            let closing_bracket = host_port_part
                .find(']')
                .ok_or_else(|| CoreError::InvalidUrl(trimmed.to_string()))?;
            let ipv6_str = &host_port_part[1..closing_bracket];
            let after_bracket = &host_port_part[closing_bracket + 1..];

            let port = if let Some(port_str) = after_bracket.strip_prefix(':') {
                Some(
                    port_str
                        .parse::<u16>()
                        .map_err(|_| CoreError::InvalidUrl(trimmed.to_string()))?,
                )
            } else if after_bracket.is_empty() {
                None
            } else {
                return Err(CoreError::InvalidUrl(trimmed.to_string()));
            };

            (ipv6_str.to_ascii_lowercase(), port)
        } else {
            match host_port_part.split_once(':') {
                Some((h, p)) => {
                    let port = p
                        .parse::<u16>()
                        .map_err(|_| CoreError::InvalidUrl(trimmed.to_string()))?;
                    (h.to_ascii_lowercase(), Some(port))
                }
                None => (host_port_part.to_ascii_lowercase(), None),
            }
        };

        if host.is_empty() {
            return Err(CoreError::HostMissing);
        }

        validate_ssrf_safety(&host)?;

        Ok(Self {
            scheme: scheme_lower,
            host,
            port,
            path_and_query,
        })
    }
}

pub fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_restricted_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4_mapped) = v6.to_ipv4_mapped() {
                is_restricted_ipv4(v4_mapped)
            } else {
                is_restricted_ipv6(v6)
            }
        }
    }
}

fn is_restricted_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || octets[0] == 10
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224
}

fn is_restricted_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();

    ip.is_loopback()
        || ip.is_unspecified()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xff00) == 0xff00
}

fn validate_ssrf_safety(host: &str) -> Result<(), CoreError> {
    if host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.eq_ignore_ascii_case("metadata.google.internal")
    {
        return Err(CoreError::SsrfBlocked(host.to_string()));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_restricted_ip(ip) {
            return Err(CoreError::SsrfBlocked(host.to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_http_and_https_urls() {
        let p1 = ParsedTarget::parse("https://example.com/index.html?q=test").unwrap();
        assert_eq!(p1.scheme, "https");
        assert_eq!(p1.host, "example.com");
        assert_eq!(p1.port, None);
        assert_eq!(p1.path_and_query, "/index.html?q=test");

        let p2 = ParsedTarget::parse("http://example.org:8080/").unwrap();
        assert_eq!(p2.scheme, "http");
        assert_eq!(p2.host, "example.org");
        assert_eq!(p2.port, Some(8080));
        assert_eq!(p2.path_and_query, "/");
    }

    #[test]
    fn reject_unsupported_schemes() {
        assert_eq!(
            ParsedTarget::parse("file:///etc/passwd"),
            Err(CoreError::UnsupportedScheme("file".to_string()))
        );
        assert_eq!(
            ParsedTarget::parse("javascript:alert(1)"),
            Err(CoreError::InvalidUrl("javascript:alert(1)".to_string()))
        );
        assert_eq!(
            ParsedTarget::parse("ftp://example.com"),
            Err(CoreError::UnsupportedScheme("ftp".to_string()))
        );
    }

    #[test]
    fn reject_ssrf_targets() {
        assert!(matches!(
            ParsedTarget::parse("http://127.0.0.1/admin"),
            Err(CoreError::SsrfBlocked(_))
        ));
        assert!(matches!(
            ParsedTarget::parse("http://localhost:8000"),
            Err(CoreError::SsrfBlocked(_))
        ));
        assert!(matches!(
            ParsedTarget::parse("http://169.254.169.254/latest/meta-data"),
            Err(CoreError::SsrfBlocked(_))
        ));
        assert!(matches!(
            ParsedTarget::parse("http://10.0.0.1"),
            Err(CoreError::SsrfBlocked(_))
        ));
        assert!(matches!(
            ParsedTarget::parse("http://192.168.1.1"),
            Err(CoreError::SsrfBlocked(_))
        ));
        assert!(matches!(
            ParsedTarget::parse("http://172.16.0.5"),
            Err(CoreError::SsrfBlocked(_))
        ));
        assert!(matches!(
            ParsedTarget::parse("http://[::1]:8080"),
            Err(CoreError::SsrfBlocked(_))
        ));
    }

    #[test]
    fn allow_valid_public_ip() {
        let parsed = ParsedTarget::parse("https://93.184.216.34/").unwrap();
        assert_eq!(parsed.host, "93.184.216.34");
    }

    #[test]
    fn cgnat_shared_address_space_boundaries() {
        // 100.63.255.255: Just below CGNAT range -> not restricted
        let ip_below: IpAddr = "100.63.255.255".parse().unwrap();
        assert!(!is_restricted_ip(ip_below));
        assert!(ParsedTarget::parse("http://100.63.255.255/").is_ok());

        // 100.64.0.0: Network base of 100.64.0.0/10 -> rejected
        let ip_base: IpAddr = "100.64.0.0".parse().unwrap();
        assert!(is_restricted_ip(ip_base));
        assert!(matches!(
            ParsedTarget::parse("http://100.64.0.0/"),
            Err(CoreError::SsrfBlocked(_))
        ));

        // 100.64.0.1: First usable host -> rejected
        let ip_first: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(is_restricted_ip(ip_first));
        assert!(matches!(
            ParsedTarget::parse("http://100.64.0.1/"),
            Err(CoreError::SsrfBlocked(_))
        ));

        // 100.100.0.1: Mid-range host -> rejected
        let ip_mid: IpAddr = "100.100.0.1".parse().unwrap();
        assert!(is_restricted_ip(ip_mid));
        assert!(matches!(
            ParsedTarget::parse("http://100.100.0.1/"),
            Err(CoreError::SsrfBlocked(_))
        ));

        // 100.127.255.255: Upper bound of 100.64.0.0/10 -> rejected
        let ip_top: IpAddr = "100.127.255.255".parse().unwrap();
        assert!(is_restricted_ip(ip_top));
        assert!(matches!(
            ParsedTarget::parse("http://100.127.255.255/"),
            Err(CoreError::SsrfBlocked(_))
        ));

        // 100.128.0.0: Just above CGNAT range -> not restricted
        let ip_above: IpAddr = "100.128.0.0".parse().unwrap();
        assert!(!is_restricted_ip(ip_above));
        assert!(ParsedTarget::parse("http://100.128.0.0/").is_ok());
    }
}
