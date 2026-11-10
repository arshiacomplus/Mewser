use std::collections::HashSet;

use crate::error::CoreError;
use crate::policy::ParsedTarget;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RouteMode {
    Direct,
    Tunnel,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouteDecision {
    Direct(ParsedTarget),
    Tunnel(ParsedTarget),
    Blocked(CoreError),
}

#[derive(Debug, Clone, Default)]
pub struct RoutingPolicy {
    direct_domains: HashSet<String>,
    direct_suffixes: Vec<String>,
}

impl RoutingPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_direct_domain(&mut self, domain: impl Into<String>) {
        self.direct_domains
            .insert(domain.into().to_ascii_lowercase());
    }

    pub fn add_direct_suffix(&mut self, suffix: impl Into<String>) {
        let mut s = suffix.into().to_ascii_lowercase();
        if !s.starts_with('.') {
            s.insert(0, '.');
        }
        self.direct_suffixes.push(s);
    }

    pub fn route(&self, raw_url: &str) -> RouteDecision {
        let target = match ParsedTarget::parse(raw_url) {
            Ok(t) => t,
            Err(e) => return RouteDecision::Blocked(e),
        };

        if self.is_direct_target(&target.host) {
            RouteDecision::Direct(target)
        } else {
            RouteDecision::Tunnel(target)
        }
    }

    pub fn is_direct_target(&self, host: &str) -> bool {
        let lower = host.to_ascii_lowercase();
        if self.direct_domains.contains(&lower) {
            return true;
        }

        self.direct_suffixes
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    }

    pub fn handle_tunnel_failure(
        &self,
        _target: &ParsedTarget,
        _cause: CoreError,
    ) -> Result<RouteMode, CoreError> {
        Err(CoreError::DirectFallbackForbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_direct_for_whitelisted_domain_and_suffix() {
        let mut policy = RoutingPolicy::new();
        policy.add_direct_domain("domestic-bank.example");
        policy.add_direct_suffix(".ir");

        match policy.route("https://domestic-bank.example/portal") {
            RouteDecision::Direct(t) => assert_eq!(t.host, "domestic-bank.example"),
            _ => panic!("Expected Direct route"),
        }

        match policy.route("https://sub.portal.ir/service") {
            RouteDecision::Direct(t) => assert_eq!(t.host, "sub.portal.ir"),
            _ => panic!("Expected Direct route"),
        }
    }

    #[test]
    fn routes_tunnel_for_unlisted_domains() {
        let mut policy = RoutingPolicy::new();
        policy.add_direct_domain("domestic.example");

        match policy.route("https://news.ycombinator.com/item?id=1") {
            RouteDecision::Tunnel(t) => assert_eq!(t.host, "news.ycombinator.com"),
            _ => panic!("Expected Tunnel route"),
        }
    }

    #[test]
    fn blocks_ssrf_destinations() {
        let policy = RoutingPolicy::new();
        match policy.route("http://127.0.0.1:8080/") {
            RouteDecision::Blocked(CoreError::SsrfBlocked(_)) => {}
            _ => panic!("Expected SSRF Blocked route"),
        }
    }

    #[test]
    fn tunnel_failure_never_falls_back_to_direct() {
        let policy = RoutingPolicy::new();
        let target = ParsedTarget::parse("https://blocked-in-region.example/").unwrap();
        let failure_result = policy.handle_tunnel_failure(
            &target,
            CoreError::TunnelFailed("Timeout in MasterDNS transport".into()),
        );

        assert_eq!(failure_result, Err(CoreError::DirectFallbackForbidden));
    }
}
