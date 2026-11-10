use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mewser_cli::BrowsingMode;
use mewser_core::tunnel::{
    FixedTcpConfig, FixedTcpTunnelAdapter, Socks5Auth, Socks5Config, Socks5Target,
    Socks5TunnelAdapter, TunnelAdapter,
};
use mewser_gateway::ExtractedPage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DesktopTransport {
    Socks5,
    FixedTcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageState {
    Idle,
    Loading {
        url: String,
        started_at: Instant,
    },
    Loaded {
        page: ExtractedPage,
    },
    Disconnected {
        url: String,
        endpoint: String,
        details: String,
    },
    SsrfBlocked {
        url: String,
        message: String,
    },
    Error {
        url: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderPageMetadata {
    pub url: String,
    pub domain: String,
    pub elapsed_ms: Option<u128>,
    pub headings_count: usize,
    pub content_blocks_count: usize,
    pub links_count: usize,
    pub is_loading: bool,
    pub is_error: bool,
    pub error_summary: Option<String>,
}

impl ReaderPageMetadata {
    pub fn new_loading(url: &str) -> Self {
        let domain = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "Unavailable".into());
        Self {
            url: url.to_string(),
            domain,
            elapsed_ms: None,
            headings_count: 0,
            content_blocks_count: 0,
            links_count: 0,
            is_loading: true,
            is_error: false,
            error_summary: None,
        }
    }

    pub fn new_loaded(page: &mewser_gateway::ExtractedPage, elapsed_ms: u128) -> Self {
        let domain = url::Url::parse(&page.url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "Unavailable".into());
        Self {
            url: page.url.clone(),
            domain,
            elapsed_ms: Some(elapsed_ms),
            headings_count: page.headings.len(),
            content_blocks_count: page.content.len(),
            links_count: page.links.len(),
            is_loading: false,
            is_error: false,
            error_summary: None,
        }
    }

    pub fn new_error(url: &str, error_msg: &str) -> Self {
        let domain = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "Unavailable".into());
        Self {
            url: url.to_string(),
            domain,
            elapsed_ms: None,
            headings_count: 0,
            content_blocks_count: 0,
            links_count: 0,
            is_loading: false,
            is_error: true,
            error_summary: Some(error_msg.to_string()),
        }
    }
}

impl PageState {
    pub fn from_client_error(
        url: String,
        err: mewser_cli::ClientError,
        settings: &SettingsState,
    ) -> Self {
        match err {
            mewser_cli::ClientError::Tunnel(ref msg)
                if msg.contains("Connection refused")
                    || msg.contains("Failed to connect")
                    || msg.contains("os error 111") =>
            {
                let endpoint = match settings.transport {
                    DesktopTransport::Socks5 => settings.proxy_addr_str.clone(),
                    DesktopTransport::FixedTcp => settings.tcp_endpoint_str.clone(),
                };
                PageState::Disconnected {
                    url,
                    endpoint,
                    details: msg.clone(),
                }
            }
            mewser_cli::ClientError::Gateway {
                status: 403,
                ref message,
            } if message.contains("SSRF") || message.contains("restricted range") => {
                PageState::SsrfBlocked {
                    url,
                    message: message.clone(),
                }
            }
            _ => PageState::Error {
                url,
                message: err.to_string(),
            },
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HistoryStack {
    past: Vec<String>,
    future: Vec<String>,
}

impl HistoryStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn can_go_back(&self) -> bool {
        !self.past.is_empty()
    }

    pub fn can_go_forward(&self) -> bool {
        !self.future.is_empty()
    }

    pub fn past_len(&self) -> usize {
        self.past.len()
    }

    pub fn future_len(&self) -> usize {
        self.future.len()
    }

    pub fn push_new(&mut self, current_url: Option<String>) {
        if let Some(curr) = current_url {
            let trimmed = curr.trim();
            if !trimmed.is_empty() {
                self.past.push(trimmed.to_string());
            }
        }
        self.future.clear();
    }

    pub fn go_back(&mut self, current_url: Option<String>) -> Option<String> {
        let prev = self.past.pop()?;
        if let Some(curr) = current_url {
            let trimmed = curr.trim();
            if !trimmed.is_empty() {
                self.future.push(trimmed.to_string());
            }
        }
        Some(prev)
    }

    pub fn go_forward(&mut self, current_url: Option<String>) -> Option<String> {
        let next = self.future.pop()?;
        if let Some(curr) = current_url {
            let trimmed = curr.trim();
            if !trimmed.is_empty() {
                self.past.push(trimmed.to_string());
            }
        }
        Some(next)
    }
}

use crate::controller::MasterDnsConfig;
use crate::profile::{MasterDnsProfile, ProfileStore, SecretVault};
use mewser_core::proxy::PolicyProxyConfig;
use mewser_core::router::RoutingPolicy;

use crate::controller::manifest::compute_sha256;

// SHA-256 hashes of legacy developer-owned domain names and IP addresses.
// Stored strictly as cryptographic hashes to ensure zero plaintext developer infrastructure
// strings exist in release binaries while fully preserving migration and purge safeguards.
const DEVELOPER_EXACT_HASHES: &[[u8; 32]] = &[
    // SHA-256 of "blue-boy.sbs"
    [
        0xc1, 0xc0, 0xcd, 0xd0, 0x30, 0xf4, 0xad, 0x39, 0x51, 0x0a, 0x28, 0x7d, 0xdd, 0x52, 0xc4,
        0x4f, 0x9e, 0x43, 0x82, 0x81, 0x6c, 0x87, 0xde, 0x38, 0x27, 0x68, 0xeb, 0xa6, 0x3b, 0x24,
        0x3a, 0x10,
    ],
    // SHA-256 of "z8.blue-boy.sbs"
    [
        0x04, 0xaa, 0xc8, 0x01, 0xb8, 0xe8, 0x5b, 0x21, 0x9c, 0x69, 0x62, 0x3c, 0x3f, 0xa0, 0xe7,
        0x54, 0xad, 0x9b, 0x3e, 0x66, 0x41, 0x26, 0xd9, 0x46, 0x67, 0x61, 0x6a, 0x18, 0xa3, 0xa9,
        0xe3, 0x79,
    ],
    // SHA-256 of "vpn2.blue-boy.sbs"
    [
        0xb7, 0x30, 0xf4, 0x82, 0x28, 0x3d, 0x32, 0x2a, 0x14, 0x9f, 0x43, 0xae, 0xff, 0x94, 0x34,
        0x63, 0xa7, 0x76, 0x65, 0x1d, 0xcf, 0x63, 0x7c, 0x9f, 0x45, 0x6f, 0xe2, 0x49, 0x90, 0x84,
        0x52, 0x15,
    ],
    // SHA-256 of "vpn3.blue-boy.sbs"
    [
        0x77, 0x01, 0xfa, 0x0a, 0xc4, 0xfb, 0x4b, 0xa1, 0x80, 0x8e, 0x1c, 0xfb, 0x0f, 0x16, 0x9c,
        0x64, 0x4f, 0x69, 0x8d, 0x0c, 0x8a, 0x4f, 0x1f, 0x5f, 0xc3, 0x4f, 0x08, 0xae, 0x3c, 0x3a,
        0xd6, 0x45,
    ],
    // SHA-256 of "45.154.96.6"
    [
        0x5c, 0x5a, 0x4d, 0x9b, 0x2f, 0xde, 0xac, 0xf9, 0x94, 0xcd, 0x7b, 0xd1, 0xbf, 0x7f, 0x1b,
        0x03, 0xe0, 0xae, 0x4d, 0x16, 0x32, 0xaa, 0x4b, 0x89, 0x1e, 0x3e, 0x81, 0x41, 0x16, 0xa3,
        0x19, 0x4e,
    ],
];

// SHA-256 of "blue-boy.sbs" for subdomain suffix matching
const DEVELOPER_SUFFIX_HASH: [u8; 32] = [
    0xc1, 0xc0, 0xcd, 0xd0, 0x30, 0xf4, 0xad, 0x39, 0x51, 0x0a, 0x28, 0x7d, 0xdd, 0x52, 0xc4, 0x4f,
    0x9e, 0x43, 0x82, 0x81, 0x6c, 0x87, 0xde, 0x38, 0x27, 0x68, 0xeb, 0xa6, 0x3b, 0x24, 0x3a, 0x10,
];

pub fn is_developer_domain(domain: &str) -> bool {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    let lower_bytes = lower.as_bytes();
    let exact_hash = compute_sha256(lower_bytes);
    if DEVELOPER_EXACT_HASHES.contains(&exact_hash) {
        return true;
    }

    // Check every dot-separated suffix (e.g. for "node.example.org", checks "example.org" and "org")
    for (idx, b) in lower_bytes.iter().enumerate() {
        if *b == b'.' && idx + 1 < lower_bytes.len() {
            let suffix_hash = compute_sha256(&lower_bytes[idx + 1..]);
            if suffix_hash == DEVELOPER_SUFFIX_HASH {
                return true;
            }
        }
    }

    false
}

pub const GATEWAY_TOKEN_SECRET_REF: &str = "gateway_auth_token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayTokenSource {
    Vault,
    Memory,
    Environment,
    None,
}

pub fn default_tunnel_domain() -> String {
    String::new()
}

fn default_encryption_method() -> u8 {
    1
}

fn default_auto_connect() -> bool {
    false
}

pub fn default_masterdns_resolvers() -> Vec<String> {
    vec![
        "109.125.169.20:53".to_string(),
        "109.230.91.227:53".to_string(),
        "109.232.1.153:53".to_string(),
        "109.232.1.154:53".to_string(),
        "109.232.1.155:53".to_string(),
        "109.232.4.58:53".to_string(),
        "188.213.65.54:53".to_string(),
        "46.245.90.90:53".to_string(),
        "78.157.41.60:53".to_string(),
        "85.185.157.181:53".to_string(),
        "94.182.154.105:53".to_string(),
        "95.38.102.86:53".to_string(),
        "8.8.8.8:53".to_string(),
        "1.1.1.1:53".to_string(),
        "2.188.21.130:53".to_string(),
        "212.86.72.72:53".to_string(),
        "185.49.84.2:53".to_string(),
        "102.22.83.142:53".to_string(),
        "91.92.209.6:53".to_string(),
        "185.208.77.178:53".to_string(),
        "185.252.30.130:53".to_string(),
        "102.22.254.232:53".to_string(),
        "102.22.207.86:53".to_string(),
        "102.22.72.90:53".to_string(),
        "102.22.72.24:53".to_string(),
        "102.22.124.233:53".to_string(),
        "195.245.70.210:53".to_string(),
        "185.213.11.85:53".to_string(),
        "46.38.143.236:53".to_string(),
        "2.188.210.13:53".to_string(),
        "31.24.234.37:53".to_string(),
        "45.81.18.141:53".to_string(),
        "45.81.19.13:53".to_string(),
        "81.12.31.48:53".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistentSettings {
    pub transport: DesktopTransport,
    pub proxy_addr_str: String,
    pub gateway_addr_str: String,
    pub tcp_endpoint_str: String,
    pub proxy_user: String,
    pub timeout_secs: u64,
    #[serde(default)]
    pub direct_domains: Vec<String>,
    #[serde(default)]
    pub direct_suffixes: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<MasterDnsProfile>,
    #[serde(default)]
    pub selected_profile_id: Option<String>,
    #[serde(default)]
    pub vault_file_consent: bool,
    #[serde(default = "default_tunnel_domain")]
    pub tunnel_domain: String,
    #[serde(default = "default_encryption_method")]
    pub tunnel_encryption_method: u8,
    #[serde(default = "default_masterdns_resolvers")]
    pub tunnel_resolvers: Vec<String>,
    #[serde(default = "default_auto_connect")]
    pub tunnel_auto_connect: bool,
}

pub fn get_settings_file_path() -> Option<PathBuf> {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        return Some(
            PathBuf::from(config_home)
                .join("mewser")
                .join("desktop_settings.json"),
        );
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(
            PathBuf::from(home)
                .join(".config")
                .join("mewser")
                .join("desktop_settings.json"),
        );
    }
    None
}

pub fn get_secrets_file_path() -> Option<PathBuf> {
    get_settings_file_path().map(|p| {
        p.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".vault.json")
    })
}

#[derive(Debug, Clone)]
pub struct SettingsState {
    pub transport: DesktopTransport,
    pub proxy_addr_str: String,
    pub gateway_addr_str: String,
    pub tcp_endpoint_str: String,
    pub proxy_user: String,
    pub proxy_pass: String,
    pub gateway_token: String,
    pub active_mode: BrowsingMode,
    pub timeout_secs: u64,
    pub direct_domains: Vec<String>,
    pub direct_suffixes: Vec<String>,
    pub profile_store: ProfileStore,
    pub secret_vault: SecretVault,
    pub vault_file_consent: bool,
    pub tunnel_domain: String,
    pub tunnel_encryption_method: u8,
    pub tunnel_encryption_key: String,
    pub tunnel_resolvers: Vec<String>,
    pub tunnel_auto_connect: bool,
}

impl Default for SettingsState {
    fn default() -> Self {
        let env_pass = std::env::var(mewser_cli::ENV_SOCKS5_PASSWORD).unwrap_or_default();
        let env_key = std::env::var("MEWSER_TUNNEL_ENCRYPTION_KEY").unwrap_or_default();

        let initial_profile = MasterDnsProfile::new(
            "Default MasterDNS Profile",
            default_tunnel_domain(),
            default_encryption_method(),
            default_masterdns_resolvers(),
        );
        let initial_id = initial_profile.id.clone();
        let key_ref = initial_profile.key_ref.clone();

        let mut profile_store = ProfileStore::new();
        profile_store.profiles.push(initial_profile);
        profile_store.selected_profile_id = Some(initial_id);
        profile_store.auto_connect = false;

        let vault = SecretVault::memory();
        if !env_key.is_empty() {
            let _ = vault.set_key(&key_ref, &env_key);
        }

        Self {
            transport: DesktopTransport::Socks5,
            proxy_addr_str: "127.0.0.1:1080".to_string(),
            gateway_addr_str: "127.0.0.1:4040".to_string(),
            tcp_endpoint_str: "127.0.0.1:1080".to_string(),
            proxy_user: String::new(),
            proxy_pass: env_pass,
            gateway_token: String::new(),
            active_mode: BrowsingMode::StandardWeb,
            timeout_secs: 30,
            direct_domains: vec!["127.0.0.1".to_string(), "localhost".to_string()],
            direct_suffixes: Vec::new(),
            profile_store,
            secret_vault: vault,
            vault_file_consent: false,
            tunnel_domain: default_tunnel_domain(),
            tunnel_encryption_method: default_encryption_method(),
            tunnel_encryption_key: env_key,
            tunnel_resolvers: default_masterdns_resolvers(),
            tunnel_auto_connect: false,
        }
    }
}

impl SettingsState {
    pub fn gateway_token_source(&self) -> GatewayTokenSource {
        if !self.gateway_token.trim().is_empty() {
            if self.vault_file_consent {
                GatewayTokenSource::Vault
            } else {
                GatewayTokenSource::Memory
            }
        } else if let Ok(tok) = std::env::var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN) {
            if !tok.trim().is_empty() {
                GatewayTokenSource::Environment
            } else {
                GatewayTokenSource::None
            }
        } else {
            GatewayTokenSource::None
        }
    }

    pub fn effective_gateway_token(&self) -> (String, GatewayTokenSource) {
        let source = self.gateway_token_source();
        match source {
            GatewayTokenSource::Vault | GatewayTokenSource::Memory => {
                (self.gateway_token.trim().to_string(), source)
            }
            GatewayTokenSource::Environment => {
                let env_tok = std::env::var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN).unwrap_or_default();
                (env_tok.trim().to_string(), source)
            }
            GatewayTokenSource::None => (String::new(), source),
        }
    }

    pub fn sync_active_profile_fields(&mut self) {
        self.tunnel_auto_connect = self.profile_store.auto_connect;
        if let Some(prof) = self.profile_store.selected_profile() {
            self.tunnel_domain = prof.domain.clone();
            self.tunnel_encryption_method = prof.encryption_method;
            self.tunnel_resolvers = prof.resolvers.clone();
            if let Ok(Some(k)) = self.secret_vault.get_key(&prof.key_ref) {
                self.tunnel_encryption_key = k;
            }
        }
    }

    pub fn load_or_default() -> Self {
        let mut settings = Self::default();

        let mut is_legacy_migration = true;

        if let Some(path) = get_settings_file_path() {
            if path.exists() {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    if let Ok(p) = serde_json::from_str::<PersistentSettings>(&contents) {
                        settings.transport = p.transport;
                        settings.proxy_addr_str = p.proxy_addr_str;
                        settings.gateway_addr_str = p.gateway_addr_str;
                        settings.tcp_endpoint_str = p.tcp_endpoint_str;
                        settings.proxy_user = p.proxy_user;
                        settings.timeout_secs = p.timeout_secs.clamp(5, 120);
                        if !p.direct_domains.is_empty() {
                            settings.direct_domains = p.direct_domains;
                        }
                        settings.direct_suffixes = p.direct_suffixes;
                        settings.tunnel_auto_connect = p.tunnel_auto_connect;
                        settings.vault_file_consent = p.vault_file_consent;

                        if p.profiles.is_empty() {
                            // Migrate legacy single connection settings into initial profile
                            is_legacy_migration = true;
                            let legacy_domain = if !p.tunnel_domain.is_empty()
                                && !is_developer_domain(&p.tunnel_domain)
                            {
                                p.tunnel_domain
                            } else {
                                String::new()
                            };
                            let legacy_resolvers = if !p.tunnel_resolvers.is_empty() {
                                p.tunnel_resolvers
                            } else {
                                default_masterdns_resolvers()
                            };
                            let auto_connect = if legacy_domain.is_empty() {
                                false
                            } else {
                                p.tunnel_auto_connect
                            };
                            settings.profile_store = ProfileStore::migrate_legacy(
                                &legacy_domain,
                                p.tunnel_encryption_method,
                                &legacy_resolvers,
                                auto_connect,
                            );
                        } else {
                            is_legacy_migration = false;
                            let mut profiles = p.profiles;
                            let mut auto_connect = p.tunnel_auto_connect;
                            for prof in &mut profiles {
                                if is_developer_domain(&prof.domain) {
                                    prof.domain = String::new();
                                    auto_connect = false;
                                }
                            }
                            settings.profile_store = ProfileStore {
                                version: 1,
                                profiles,
                                selected_profile_id: p.selected_profile_id,
                                auto_connect,
                            };
                        }
                    }
                }
            }
        }

        // Only open unencrypted persistent file vault if informed user consent was given
        if settings.vault_file_consent {
            if let Some(v_path) = get_secrets_file_path() {
                if let Ok(vault) = SecretVault::file_backed(v_path) {
                    if let Ok(Some(tok)) = vault.get_key(GATEWAY_TOKEN_SECRET_REF) {
                        if !tok.trim().is_empty() {
                            settings.gateway_token = tok;
                        }
                    }
                    settings.secret_vault = vault;
                }
            }
        }

        settings.sync_active_profile_fields();
        if is_developer_domain(&settings.tunnel_domain) {
            settings.tunnel_domain = String::new();
            settings.tunnel_auto_connect = false;
        }

        if let Ok(env_direct) = std::env::var("MEWSER_DIRECT_DOMAINS") {
            settings.direct_domains = env_direct
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if let Ok(env_trans) = std::env::var("MEWSER_TRANSPORT") {
            if env_trans.eq_ignore_ascii_case("FixedTcp") {
                settings.transport = DesktopTransport::FixedTcp;
            }
        }

        // Environment variable MEWSER_TUNNEL_ENCRYPTION_KEY is ONLY used during initial/legacy migration
        if is_legacy_migration && settings.tunnel_encryption_key.is_empty() {
            if let Ok(env_key) = std::env::var("MEWSER_TUNNEL_ENCRYPTION_KEY") {
                if !env_key.trim().is_empty() {
                    settings.tunnel_encryption_key = env_key.trim().to_string();
                    if let Some(prof) = settings.profile_store.selected_profile() {
                        let _ = settings
                            .secret_vault
                            .set_key(&prof.key_ref, &settings.tunnel_encryption_key);
                    }
                }
            }
        }

        settings
    }

    pub fn save_persistent(&self) -> Result<(), String> {
        let path = get_settings_file_path()
            .ok_or_else(|| "Could not determine config path".to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config dir: {e}"))?;
        }

        // 1. Save active key in current secret vault if non-empty
        if !self.tunnel_encryption_key.is_empty() {
            if let Some(active) = self.profile_store.selected_profile() {
                let _ = self
                    .secret_vault
                    .set_key(&active.key_ref, &self.tunnel_encryption_key);
            }
        }

        // Save active gateway token in secret vault
        if !self.gateway_token.is_empty() {
            let _ = self
                .secret_vault
                .set_key(GATEWAY_TOKEN_SECRET_REF, &self.gateway_token);
        } else {
            let _ = self.secret_vault.delete_key(GATEWAY_TOKEN_SECRET_REF);
        }

        // 2. Only write to persistent file vault if user gave explicit consent
        if self.vault_file_consent {
            if let Some(v_path) = get_secrets_file_path() {
                if let Ok(file_vault) = SecretVault::file_backed(v_path) {
                    for prof in &self.profile_store.profiles {
                        if let Ok(Some(k)) = self.secret_vault.get_key(&prof.key_ref) {
                            let _ = file_vault.set_key(&prof.key_ref, &k);
                        }
                    }
                    if !self.gateway_token.is_empty() {
                        let _ = file_vault.set_key(GATEWAY_TOKEN_SECRET_REF, &self.gateway_token);
                    } else {
                        let _ = file_vault.delete_key(GATEWAY_TOKEN_SECRET_REF);
                    }
                }
            }
        }

        let auto_connect = self.profile_store.auto_connect;
        let persisted = PersistentSettings {
            transport: self.transport,
            proxy_addr_str: self.proxy_addr_str.clone(),
            gateway_addr_str: self.gateway_addr_str.clone(),
            tcp_endpoint_str: self.tcp_endpoint_str.clone(),
            proxy_user: self.proxy_user.clone(),
            timeout_secs: self.timeout_secs,
            direct_domains: self.direct_domains.clone(),
            direct_suffixes: self.direct_suffixes.clone(),
            profiles: self.profile_store.profiles.clone(),
            selected_profile_id: self.profile_store.selected_profile_id.clone(),
            vault_file_consent: self.vault_file_consent,
            tunnel_domain: self.tunnel_domain.clone(),
            tunnel_encryption_method: self.tunnel_encryption_method,
            tunnel_resolvers: self.tunnel_resolvers.clone(),
            tunnel_auto_connect: auto_connect,
        };
        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| format!("Failed to serialize settings: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("Failed to write settings file: {e}"))?;
        Ok(())
    }

    pub fn build_masterdns_config(&self) -> MasterDnsConfig {
        if let Some(prof) = self.profile_store.selected_profile() {
            let key = if !self.tunnel_encryption_key.is_empty() {
                self.tunnel_encryption_key.clone()
            } else {
                self.secret_vault
                    .get_key(&prof.key_ref)
                    .unwrap_or(None)
                    .unwrap_or_default()
            };
            MasterDnsConfig {
                profile_id: Some(prof.id.clone()),
                profile_name: Some(prof.name.clone()),
                binary_path: None,
                domain: prof.domain.clone(),
                encryption_method: prof.encryption_method,
                encryption_key: key,
                resolvers: prof.resolvers.clone(),
                custom_port: prof.custom_port,
                startup_timeout: Duration::from_secs(
                    prof.timeout_secs.unwrap_or(self.timeout_secs.max(60)),
                ),
                verify_pid_ownership: true,
                probe_target: if self.transport == DesktopTransport::Socks5 {
                    Some(self.gateway_addr_str.clone())
                } else {
                    None
                },
                auto_recovery: true,
                max_recovery_attempts: 3,
            }
        } else {
            MasterDnsConfig {
                profile_id: None,
                profile_name: None,
                binary_path: None,
                domain: self.tunnel_domain.clone(),
                encryption_method: self.tunnel_encryption_method,
                encryption_key: self.tunnel_encryption_key.clone(),
                resolvers: self.tunnel_resolvers.clone(),
                custom_port: None,
                startup_timeout: Duration::from_secs(self.timeout_secs.max(60)),
                verify_pid_ownership: true,
                probe_target: if self.transport == DesktopTransport::Socks5 {
                    Some(self.gateway_addr_str.clone())
                } else {
                    None
                },
                auto_recovery: true,
                max_recovery_attempts: 3,
            }
        }
    }

    pub fn build_routing_policy(&self) -> RoutingPolicy {
        let mut policy = RoutingPolicy::new();
        for d in &self.direct_domains {
            let trimmed = d.trim();
            if !trimmed.is_empty() {
                policy.add_direct_domain(trimmed);
            }
        }
        for s in &self.direct_suffixes {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                policy.add_direct_suffix(trimmed);
            }
        }
        policy
    }

    pub fn build_policy_proxy_config(
        &self,
        bind_addr: SocketAddr,
    ) -> Result<PolicyProxyConfig, String> {
        let socks5_endpoint: SocketAddr = self
            .proxy_addr_str
            .trim()
            .parse()
            .map_err(|e| format!("Invalid SOCKS5 proxy address: {e}"))?;

        let auth = if !self.proxy_user.trim().is_empty() {
            Some(Socks5Auth {
                username: self.proxy_user.trim().to_string(),
                password: self.proxy_pass.clone(),
            })
        } else {
            None
        };

        let allow_loopback = std::env::var("MEWSER_ALLOW_LOOPBACK_FOR_TESTING")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Ok(
            PolicyProxyConfig::new(bind_addr, self.build_routing_policy(), socks5_endpoint)
                .with_auth(auth)
                .with_allow_loopback_for_testing(allow_loopback),
        )
    }

    pub fn build_policy_proxy_config_with_dynamic(
        &self,
        bind_addr: SocketAddr,
        dynamic_ep: std::sync::Arc<std::sync::RwLock<Option<SocketAddr>>>,
    ) -> Result<PolicyProxyConfig, String> {
        let cfg = self.build_policy_proxy_config(bind_addr)?;
        Ok(cfg.with_dynamic_socks5_endpoint(dynamic_ep))
    }

    pub fn test_local_endpoint(&self) -> Result<String, String> {
        let target_str = match self.transport {
            DesktopTransport::Socks5 => &self.proxy_addr_str,
            DesktopTransport::FixedTcp => &self.tcp_endpoint_str,
        };
        let addr: SocketAddr = target_str
            .trim()
            .parse()
            .map_err(|e| format!("Invalid address '{target_str}': {e}"))?;

        match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(1000)) {
            Ok(_) => Ok(format!("Local listener at {addr} is accessible")),
            Err(e) => Err(format!(
                "Local listener at {addr} is unreachable ({e}). Start MasterDNS client first."
            )),
        }
    }

    pub fn build_socks5_config(&self) -> Result<(Socks5Config, Socks5Target), String> {
        let proxy_addr: SocketAddr = self
            .proxy_addr_str
            .trim()
            .parse()
            .map_err(|e| format!("Invalid SOCKS5 proxy address: {e}"))?;

        let gateway_target = if let Ok(ip_addr) = self.gateway_addr_str.trim().parse::<SocketAddr>()
        {
            Socks5Target::Ip(ip_addr)
        } else {
            let raw = self.gateway_addr_str.trim();
            if let Some((host, port_str)) = raw.rsplit_once(':') {
                let clean_host = host.trim_start_matches('[').trim_end_matches(']');
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid Gateway address '{raw}': invalid port"))?;
                if clean_host.is_empty() {
                    return Err(format!("Invalid Gateway address '{raw}': empty host"));
                }
                Socks5Target::Domain(clean_host.to_string(), port)
            } else {
                return Err(format!("Invalid Gateway address '{raw}': missing port"));
            }
        };

        let auth = if !self.proxy_user.trim().is_empty() {
            Some(Socks5Auth {
                username: self.proxy_user.trim().to_string(),
                password: self.proxy_pass.clone(),
            })
        } else {
            None
        };

        let config = Socks5Config {
            proxy_addr,
            auth,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(self.timeout_secs),
            write_timeout: Duration::from_secs(5),
            max_response_bytes: 2 * 1024 * 1024,
        };

        Ok((config, gateway_target))
    }

    pub fn build_fixed_tcp_config(&self) -> Result<FixedTcpConfig, String> {
        let endpoint: SocketAddr = self
            .tcp_endpoint_str
            .trim()
            .parse()
            .map_err(|e| format!("Invalid TCP listener address: {e}"))?;

        Ok(FixedTcpConfig {
            endpoint,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(self.timeout_secs),
            write_timeout: Duration::from_secs(5),
            max_response_bytes: 2 * 1024 * 1024,
        })
    }

    pub fn build_tunnel_adapter(&self) -> Result<Box<dyn TunnelAdapter + Send + Sync>, String> {
        match self.transport {
            DesktopTransport::FixedTcp => {
                let cfg = self.build_fixed_tcp_config()?;
                Ok(Box::new(FixedTcpTunnelAdapter::new(cfg)))
            }
            DesktopTransport::Socks5 => {
                let (cfg, target) = self.build_socks5_config()?;
                Ok(Box::new(Socks5TunnelAdapter::new(cfg, target)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_stack_transitions() {
        let mut history = HistoryStack::new();
        assert!(!history.can_go_back());
        assert!(!history.can_go_forward());

        // Navigating A -> B -> C
        history.push_new(Some("https://example.com/A".into()));
        assert_eq!(history.past_len(), 1);
        assert_eq!(history.future_len(), 0);

        history.push_new(Some("https://example.com/B".into()));
        assert_eq!(history.past_len(), 2);
        assert_eq!(history.future_len(), 0);

        // User is at C. Click Back:
        let prev = history.go_back(Some("https://example.com/C".into()));
        assert_eq!(prev, Some("https://example.com/B".into()));
        assert!(history.can_go_back());
        assert!(history.can_go_forward());
        assert_eq!(history.past_len(), 1);
        assert_eq!(history.future_len(), 1);

        // Click Back again:
        let prev2 = history.go_back(Some("https://example.com/B".into()));
        assert_eq!(prev2, Some("https://example.com/A".into()));
        assert!(!history.can_go_back());
        assert!(history.can_go_forward());
        assert_eq!(history.future_len(), 2);

        // Click Forward:
        let next = history.go_forward(Some("https://example.com/A".into()));
        assert_eq!(next, Some("https://example.com/B".into()));
        assert!(history.can_go_back());
        assert!(history.can_go_forward());

        // Click Forward again:
        let next2 = history.go_forward(Some("https://example.com/B".into()));
        assert_eq!(next2, Some("https://example.com/C".into()));
        assert!(history.can_go_back());
        assert!(!history.can_go_forward());

        // Click Back to B, then push new navigation to D (should clear future)
        history.go_back(Some("https://example.com/C".into()));
        assert!(history.can_go_forward());
        history.push_new(Some("https://example.com/B".into()));
        assert!(!history.can_go_forward());
    }

    #[test]
    fn test_history_empty_operations() {
        let mut history = HistoryStack::new();
        assert_eq!(history.go_back(None), None);
        assert_eq!(history.go_forward(None), None);

        // Blank or whitespace-only URLs should not clutter history
        history.push_new(Some("   ".to_string()));
        assert!(!history.can_go_back());
    }

    #[test]
    fn test_page_state_from_client_error_classification() {
        let settings = SettingsState {
            transport: DesktopTransport::FixedTcp,
            tcp_endpoint_str: "127.0.0.1:1080".to_string(),
            ..Default::default()
        };

        // Disconnected classification
        let err_conn = mewser_cli::ClientError::Tunnel(
            "Failed to connect to fixed TCP endpoint at 127.0.0.1:1080: Connection refused (os error 111)".into()
        );
        let state = PageState::from_client_error("https://example.com".into(), err_conn, &settings);
        match state {
            PageState::Disconnected {
                url,
                endpoint,
                details,
            } => {
                assert_eq!(url, "https://example.com");
                assert_eq!(endpoint, "127.0.0.1:1080");
                assert!(details.contains("Connection refused"));
            }
            _ => panic!("Expected Disconnected state"),
        }

        // SSRF classification
        let err_ssrf = mewser_cli::ClientError::Gateway {
            status: 403,
            message: "SSRF defense blocked destination 127.0.0.1: Host IP 127.0.0.1 is in a restricted range".into(),
        };
        let state_ssrf =
            PageState::from_client_error("http://127.0.0.1:8080".into(), err_ssrf, &settings);
        match state_ssrf {
            PageState::SsrfBlocked { url, message } => {
                assert_eq!(url, "http://127.0.0.1:8080");
                assert!(message.contains("SSRF defense blocked"));
            }
            _ => panic!("Expected SsrfBlocked state"),
        }

        // Generic error classification
        let err_gen = mewser_cli::ClientError::InvalidUrl("missing scheme".into());
        let state_gen = PageState::from_client_error("bad_url".into(), err_gen, &settings);
        match state_gen {
            PageState::Error { url, message } => {
                assert_eq!(url, "bad_url");
                assert!(message.contains("missing scheme"));
            }
            _ => panic!("Expected Error state"),
        }
    }

    #[test]
    fn test_settings_builds_socks5_config() {
        let settings = SettingsState::default();
        let (config, target) = settings.build_socks5_config().unwrap();
        assert_eq!(config.proxy_addr.port(), 1080);
        assert_eq!(target, Socks5Target::Ip("127.0.0.1:4040".parse().unwrap()));
        assert!(config.auth.is_none());
    }

    #[test]
    fn test_settings_with_auth() {
        let settings = SettingsState {
            proxy_user: "user123".to_string(),
            proxy_pass: "secret456".to_string(),
            ..Default::default()
        };

        let (config, _) = settings.build_socks5_config().unwrap();
        let auth = config.auth.expect("Auth should be present");
        assert_eq!(auth.username, "user123");
        assert_eq!(auth.password, "secret456");
    }

    #[test]
    fn test_settings_invalid_addresses() {
        let settings = SettingsState {
            proxy_addr_str: "not_an_ip:1080".to_string(),
            ..Default::default()
        };
        let err = settings.build_socks5_config().unwrap_err();
        assert!(err.contains("Invalid SOCKS5 proxy address"));

        let settings2 = SettingsState {
            gateway_addr_str: "invalid_gateway".to_string(),
            ..Default::default()
        };
        let err2 = settings2.build_socks5_config().unwrap_err();
        assert!(err2.contains("Invalid Gateway address"));
    }

    #[test]
    fn test_settings_builds_fixed_tcp_config() {
        let settings = SettingsState {
            transport: DesktopTransport::FixedTcp,
            tcp_endpoint_str: "127.0.0.1:9090".to_string(),
            timeout_secs: 45,
            ..Default::default()
        };
        let config = settings.build_fixed_tcp_config().unwrap();
        assert_eq!(config.endpoint.port(), 9090);
        assert_eq!(config.read_timeout, Duration::from_secs(45));

        let adapter = settings.build_tunnel_adapter().unwrap();
        assert_eq!(adapter.max_payload_size(), 2 * 1024 * 1024);
    }

    #[test]
    fn test_settings_invalid_tcp_endpoint() {
        let settings = SettingsState {
            transport: DesktopTransport::FixedTcp,
            tcp_endpoint_str: "bad_endpoint".to_string(),
            ..Default::default()
        };
        let err = settings.build_fixed_tcp_config().unwrap_err();
        assert!(err.contains("Invalid TCP listener address"));
    }

    #[test]
    fn test_persistent_settings_serialization_has_no_secrets() {
        let settings = SettingsState {
            transport: DesktopTransport::FixedTcp,
            proxy_addr_str: "127.0.0.1:1080".to_string(),
            gateway_addr_str: "127.0.0.1:4040".to_string(),
            tcp_endpoint_str: "127.0.0.1:1080".to_string(),
            proxy_user: "mewser_user".to_string(),
            proxy_pass: "super_secret_password_never_saved".to_string(),
            gateway_token: "super_secret_auth_token_never_saved".to_string(),
            active_mode: BrowsingMode::ResilientText,
            timeout_secs: 25,
            direct_domains: vec!["bank.local".to_string()],
            direct_suffixes: vec![".local".to_string()],
            tunnel_domain: "primary.example.com".to_string(),
            tunnel_encryption_method: 1,
            tunnel_encryption_key: "super_secret_masterdns_key_never_saved".to_string(),
            tunnel_resolvers: vec!["1.1.1.1:53".to_string()],
            tunnel_auto_connect: true,
            ..Default::default()
        };

        let persisted = PersistentSettings {
            transport: settings.transport,
            proxy_addr_str: settings.proxy_addr_str.clone(),
            gateway_addr_str: settings.gateway_addr_str.clone(),
            tcp_endpoint_str: settings.tcp_endpoint_str.clone(),
            proxy_user: settings.proxy_user.clone(),
            timeout_secs: settings.timeout_secs,
            direct_domains: settings.direct_domains.clone(),
            direct_suffixes: settings.direct_suffixes.clone(),
            profiles: settings.profile_store.profiles.clone(),
            selected_profile_id: settings.profile_store.selected_profile_id.clone(),
            vault_file_consent: false,
            tunnel_domain: settings.tunnel_domain.clone(),
            tunnel_encryption_method: settings.tunnel_encryption_method,
            tunnel_resolvers: settings.tunnel_resolvers.clone(),
            tunnel_auto_connect: settings.tunnel_auto_connect,
        };

        let json = serde_json::to_string(&persisted).unwrap();
        assert!(!json.contains("super_secret_password_never_saved"));
        assert!(!json.contains("proxy_pass"));
        assert!(!json.contains("super_secret_auth_token_never_saved"));
        assert!(!json.contains("gateway_token"));
        assert!(!json.contains("super_secret_masterdns_key_never_saved"));
        assert!(!json.contains("tunnel_encryption_key"));
        assert!(json.contains("mewser_user"));
        assert!(json.contains("primary.example.com"));
        assert!(!json.contains("blue-boy.sbs"));
    }

    #[test]
    fn test_socks5_target_domain_addressing() {
        let settings = SettingsState {
            gateway_addr_str: "gateway.remote-node.example.org:4040".to_string(),
            ..Default::default()
        };
        let (_cfg, target) = settings.build_socks5_config().unwrap();
        match target {
            Socks5Target::Domain(host, port) => {
                assert_eq!(host, "gateway.remote-node.example.org");
                assert_eq!(port, 4040);
            }
            _ => panic!("Expected Socks5Target::Domain"),
        }
    }

    #[test]
    fn test_gateway_token_source_precedence() {
        let mut settings = SettingsState::default();
        assert_eq!(settings.gateway_token_source(), GatewayTokenSource::None);

        // UI token in memory
        settings.gateway_token = "in_memory_token".to_string();
        settings.vault_file_consent = false;
        assert_eq!(settings.gateway_token_source(), GatewayTokenSource::Memory);
        let (tok, src) = settings.effective_gateway_token();
        assert_eq!(tok, "in_memory_token");
        assert_eq!(src, GatewayTokenSource::Memory);

        // UI token with vault consent
        settings.vault_file_consent = true;
        assert_eq!(settings.gateway_token_source(), GatewayTokenSource::Vault);
        let (tok, src) = settings.effective_gateway_token();
        assert_eq!(tok, "in_memory_token");
        assert_eq!(src, GatewayTokenSource::Vault);
    }
}
