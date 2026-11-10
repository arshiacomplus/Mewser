#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelMilestone {
    Starting,
    ResolverTesting { completed: usize, total: usize },
    SessionInitialized { session_id: u64 },
    Socks5Listening { address: String },
    SessionLost,
    MtuFailed,
    ProcessExited { code: Option<i32> },
    Unrecognized,
}

pub struct LogSanitizer {
    secrets: Vec<String>,
}

impl LogSanitizer {
    pub fn new(secrets: Vec<String>) -> Self {
        let filtered = secrets
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= 6) // avoid matching tiny substrings
            .collect();
        Self { secrets: filtered }
    }

    /// Redacts all configured secret tokens or passwords from the input line.
    pub fn sanitize(&self, line: &str) -> String {
        let mut result = line.to_string();
        for secret in &self.secrets {
            if result.contains(secret) {
                result = result.replace(secret, "[REDACTED]");
            }
        }
        result
    }

    /// Parses milestone signals from MasterDNS client output.
    pub fn parse_milestone(&self, raw_line: &str) -> TunnelMilestone {
        let line = raw_line.trim();

        if line.contains("Starting MasterDnsVPN Client")
            || line.contains("MasterDnsVPN Client Started")
        {
            return TunnelMilestone::Starting;
        }

        if line.contains("Rejected (") || line.contains("Validated (") {
            if let Some(start_idx) = line.find('(') {
                if let Some(end_idx) = line[start_idx..].find(')') {
                    let sub = &line[start_idx + 1..start_idx + end_idx];
                    let mut parts = sub.split('/');
                    if let (Some(cur_s), Some(tot_s)) = (parts.next(), parts.next()) {
                        if let (Ok(cur), Ok(tot)) = (cur_s.parse::<usize>(), tot_s.parse::<usize>())
                        {
                            return TunnelMilestone::ResolverTesting {
                                completed: cur,
                                total: tot,
                            };
                        }
                    }
                }
            }
        }

        if line.contains("Session Initialized Successfully") {
            if let Some(idx) = line.find("ID:") {
                let rest = line[idx + 3..].trim();
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(id) = digits.parse::<u64>() {
                    return TunnelMilestone::SessionInitialized { session_id: id };
                }
            }
            return TunnelMilestone::SessionInitialized { session_id: 0 };
        }

        if line.contains("SOCKS5 Proxy server is listening on") {
            if let Some(idx) = line.find("listening on") {
                let addr = line[idx + 12..].trim().to_string();
                return TunnelMilestone::Socks5Listening { address: addr };
            }
        }

        if line.contains("Session lost")
            || line.contains("Session Lost")
            || line.contains("Session closed")
            || line.contains("Session Terminated")
            || line.contains("Connection to server lost")
            || line.contains("Session was closed")
        {
            return TunnelMilestone::SessionLost;
        }

        if line.contains("No valid connections found after MTU testing")
            || line.contains("no valid connections after mtu testing")
        {
            return TunnelMilestone::MtuFailed;
        }

        TunnelMilestone::Unrecognized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitizer_redacts_keys_and_passwords() {
        let sanitizer = LogSanitizer::new(vec![
            "my_super_secret_key_12345".to_string(),
            "secret_pass_67890".to_string(),
        ]);

        let raw = "Client loaded key my_super_secret_key_12345 and pass secret_pass_67890 securely";
        let clean = sanitizer.sanitize(raw);
        assert_eq!(
            clean,
            "Client loaded key [REDACTED] and pass [REDACTED] securely"
        );
        assert!(!clean.contains("my_super_secret_key_12345"));
        assert!(!clean.contains("secret_pass_67890"));
    }

    #[test]
    fn test_milestone_parsing() {
        let sanitizer = LogSanitizer::new(Vec::new());

        let m1 = sanitizer
            .parse_milestone("❌ Rejected (14/34): tunnel.example.com via 185.252.30.130:53");
        assert_eq!(
            m1,
            TunnelMilestone::ResolverTesting {
                completed: 14,
                total: 34
            }
        );

        let m2 = sanitizer.parse_milestone("✅ Session Initialized Successfully (ID: 9)");
        assert_eq!(m2, TunnelMilestone::SessionInitialized { session_id: 9 });

        let m3 =
            sanitizer.parse_milestone("🚀 SOCKS5 Proxy server is listening on 127.0.0.1:40157");
        assert_eq!(
            m3,
            TunnelMilestone::Socks5Listening {
                address: "127.0.0.1:40157".to_string()
            }
        );

        let m4 = sanitizer.parse_milestone("⚠️ Connection to server lost, Session closed");
        assert_eq!(m4, TunnelMilestone::SessionLost);
    }
}
