use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

static PROFILE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a stable, unique, alphanumeric profile identifier.
pub fn generate_profile_id() -> String {
    let seq = PROFILE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("prof_{:x}_{:x}", nanos, seq)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn default_store_version() -> u32 {
    1
}

fn default_auto_connect() -> bool {
    true
}

/// Represents a persistent MasterDNS connection profile.
/// Notice: Sensitive encryption keys are NEVER serialized into this structure.
/// Only the stable `key_ref` reference is persisted in profile metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterDnsProfile {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub domain: String,
    pub encryption_method: u8,
    pub key_ref: String,
    pub resolvers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

impl MasterDnsProfile {
    /// Creates a new profile with sanitized resolvers and generated stable IDs.
    pub fn new(
        name: impl Into<String>,
        domain: impl Into<String>,
        encryption_method: u8,
        resolvers: Vec<String>,
    ) -> Self {
        let id = generate_profile_id();
        let key_ref = format!("key_{id}");
        let now = current_timestamp();
        Self {
            id,
            name: name.into(),
            created_at: now,
            modified_at: now,
            domain: domain.into(),
            encryption_method,
            key_ref,
            resolvers: Self::sanitize_resolvers(&resolvers),
            custom_port: None,
            timeout_secs: Some(60),
        }
    }

    /// Duplicates this profile, assigning a new unique ID and secret reference.
    pub fn duplicate(&self, new_name: &str) -> Self {
        let id = generate_profile_id();
        let key_ref = format!("key_{id}");
        let now = current_timestamp();
        Self {
            id,
            name: new_name.to_string(),
            created_at: now,
            modified_at: now,
            domain: self.domain.clone(),
            encryption_method: self.encryption_method,
            key_ref,
            resolvers: self.resolvers.clone(),
            custom_port: self.custom_port,
            timeout_secs: self.timeout_secs,
        }
    }

    /// Sanitizes and deduplicates a list of resolver addresses while preserving order.
    pub fn sanitize_resolvers(resolvers: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for r in resolvers {
            let trimmed = r.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let normalized = if trimmed.contains(':') {
                trimmed.to_string()
            } else {
                format!("{trimmed}:53")
            };
            if seen.insert(normalized.clone()) {
                out.push(normalized);
            }
        }
        out
    }

    /// Validates a raw timeout input string.
    /// Rejects non-numeric input and values outside the supported 5–300 second range.
    pub fn validate_timeout_input(raw: &str) -> Result<u64, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("Startup timeout must be specified (5–300 seconds)".to_string());
        }
        match trimmed.parse::<u64>() {
            Ok(val) => {
                if (5..=300).contains(&val) {
                    Ok(val)
                } else {
                    Err(format!(
                        "Startup timeout must be between 5 and 300 seconds (got {val}s)"
                    ))
                }
            }
            Err(_) => Err("Startup timeout must be a valid numeric integer".to_string()),
        }
    }

    /// Validates profile configuration. Returns a user-friendly error without secrets.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Profile name cannot be empty".to_string());
        }
        let domain = self.domain.trim();
        if domain.is_empty() {
            return Err("Tunnel domain cannot be empty".to_string());
        }
        if domain.contains(' ') || domain.contains('/') || domain.contains('\\') {
            return Err("Tunnel domain contains invalid characters".to_string());
        }
        if self.encryption_method == 0 {
            return Err("Encryption method must be non-zero (1 or 2)".to_string());
        }
        if self.resolvers.is_empty() {
            return Err("At least one resolver must be specified".to_string());
        }
        for res in &self.resolvers {
            let trimmed = res.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.parse::<SocketAddr>().is_err() && trimmed.parse::<IpAddr>().is_err() {
                return Err(format!("Invalid resolver address: {trimmed}"));
            }
        }
        if self.key_ref.trim().is_empty() {
            return Err("Secret reference cannot be empty".to_string());
        }
        if let Some(t) = self.timeout_secs {
            if !(5..=300).contains(&t) {
                return Err(format!(
                    "Startup timeout must be between 5 and 300 seconds (got {t}s)"
                ));
            }
        }
        Ok(())
    }
}

/// Persistent container for multiple MasterDNS profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileStore {
    #[serde(default = "default_store_version")]
    pub version: u32,
    #[serde(default)]
    pub profiles: Vec<MasterDnsProfile>,
    #[serde(default)]
    pub selected_profile_id: Option<String>,
    #[serde(default = "default_auto_connect")]
    pub auto_connect: bool,
}

impl Default for ProfileStore {
    fn default() -> Self {
        Self {
            version: 1,
            profiles: Vec::new(),
            selected_profile_id: None,
            auto_connect: true,
        }
    }
}

impl ProfileStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn profiles(&self) -> &[MasterDnsProfile] {
        &self.profiles
    }

    pub fn add_profile(&mut self, profile: MasterDnsProfile) {
        if self.selected_profile_id.is_none() {
            self.selected_profile_id = Some(profile.id.clone());
        }
        self.profiles.push(profile);
    }

    pub fn get_profile(&self, id: &str) -> Option<&MasterDnsProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn get_profile_mut(&mut self, id: &str) -> Option<&mut MasterDnsProfile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    pub fn selected_profile(&self) -> Option<&MasterDnsProfile> {
        if let Some(ref sel_id) = self.selected_profile_id {
            if let Some(prof) = self.get_profile(sel_id) {
                return Some(prof);
            }
        }
        self.profiles.first()
    }

    /// Selects an active profile without establishing any connection.
    pub fn select_profile(&mut self, id: &str) -> Result<(), String> {
        if self.profiles.iter().any(|p| p.id == id) {
            self.selected_profile_id = Some(id.to_string());
            Ok(())
        } else {
            Err(format!("Profile with ID {id} not found"))
        }
    }

    /// Removes a profile. If the removed profile was selected, updates selection.
    pub fn remove_profile(&mut self, id: &str) -> Option<MasterDnsProfile> {
        let idx = self.profiles.iter().position(|p| p.id == id)?;
        let removed = self.profiles.remove(idx);
        if self.selected_profile_id.as_deref() == Some(id) {
            self.selected_profile_id = self.profiles.first().map(|p| p.id.clone());
        }
        Some(removed)
    }

    /// Duplicates a profile by ID, generating a fresh ID and secret reference.
    pub fn duplicate_profile(
        &mut self,
        id: &str,
        new_name: Option<&str>,
    ) -> Result<MasterDnsProfile, String> {
        let base = self
            .get_profile(id)
            .ok_or_else(|| format!("Profile with ID {id} not found"))?;
        let default_name = format!("{} (Copy)", base.name);
        let name = new_name.unwrap_or(&default_name);
        let duplicated = base.duplicate(name);
        self.profiles.push(duplicated.clone());
        Ok(duplicated)
    }

    /// Migrates legacy single-connection parameters into an initial MasterDNS profile.
    pub fn migrate_legacy(
        domain: &str,
        encryption_method: u8,
        resolvers: &[String],
        auto_connect: bool,
    ) -> Self {
        let mut store = Self::new();
        let default_profile = MasterDnsProfile::new(
            "Default MasterDNS Profile",
            domain,
            encryption_method,
            resolvers.to_vec(),
        );
        let id = default_profile.id.clone();
        store.profiles.push(default_profile);
        store.selected_profile_id = Some(id);
        store.auto_connect = auto_connect;
        store
    }
}

/// Abstract contract for secure secret storage associated with profile secret references.
pub trait ProfileSecretStore: Send + Sync {
    fn get_key(&self, key_ref: &str) -> Result<Option<String>, String>;
    fn set_key(&mut self, key_ref: &str, key: &str) -> Result<(), String>;
    fn delete_key(&mut self, key_ref: &str) -> Result<(), String>;
}

/// In-memory secret store for ephemeral sessions and testing.
#[derive(Debug, Default, Clone)]
pub struct MemorySecretStore {
    secrets: HashMap<String, String>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProfileSecretStore for MemorySecretStore {
    fn get_key(&self, key_ref: &str) -> Result<Option<String>, String> {
        Ok(self.secrets.get(key_ref).cloned())
    }

    fn set_key(&mut self, key_ref: &str, key: &str) -> Result<(), String> {
        self.secrets.insert(key_ref.to_string(), key.to_string());
        Ok(())
    }

    fn delete_key(&mut self, key_ref: &str) -> Result<(), String> {
        self.secrets.remove(key_ref);
        Ok(())
    }
}

/// File-based secure credential store with strict filesystem permissions (`0600` on Unix).
#[derive(Debug, Clone)]
pub struct FileSecretStore {
    path: PathBuf,
    secrets: HashMap<String, String>,
}

impl FileSecretStore {
    /// Loads or creates a file-backed secret store enforcing strict permissions (`0600`).
    pub fn open_or_create(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create secrets directory: {e}"))?;
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        let mut secrets = HashMap::new();
        if path.is_file() {
            #[cfg(unix)]
            {
                let metadata = fs::metadata(&path)
                    .map_err(|e| format!("Failed to read metadata for secrets file: {e}"))?;
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    // Try to fix overly permissive permissions
                    if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
                        return Err(format!(
                            "Insecure permissions on secrets file {}: mode {:o}. Failed to restrict: {e}",
                            path.display(),
                            mode
                        ));
                    }
                }
            }

            let contents = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read secrets file: {e}"))?;
            if !contents.trim().is_empty() {
                secrets = serde_json::from_str(&contents)
                    .map_err(|e| format!("Malformed secrets file: {e}"))?;
            }
        }

        Ok(Self { path, secrets })
    }

    fn save_to_disk(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create secrets directory: {e}"))?;
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        let json = serde_json::to_string_pretty(&self.secrets)
            .map_err(|e| format!("Failed to serialize secrets: {e}"))?;

        // Write via atomic rename with 0600 permissions
        let temp_path = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));

        #[cfg(unix)]
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            use std::io::Write;
            let mut file = opts
                .open(&temp_path)
                .map_err(|e| format!("Failed to open temp secrets file: {e}"))?;
            file.write_all(json.as_bytes())
                .map_err(|e| format!("Failed to write temp secrets file: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Failed to sync temp secrets file: {e}"))?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&temp_path, json.as_bytes())
                .map_err(|e| format!("Failed to write temp secrets file: {e}"))?;
        }

        fs::rename(&temp_path, &self.path)
            .map_err(|e| format!("Failed to commit secrets file: {e}"))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }
}

impl ProfileSecretStore for FileSecretStore {
    fn get_key(&self, key_ref: &str) -> Result<Option<String>, String> {
        Ok(self.secrets.get(key_ref).cloned())
    }

    fn set_key(&mut self, key_ref: &str, key: &str) -> Result<(), String> {
        self.secrets.insert(key_ref.to_string(), key.to_string());
        self.save_to_disk()
    }

    fn delete_key(&mut self, key_ref: &str) -> Result<(), String> {
        self.secrets.remove(key_ref);
        self.save_to_disk()
    }
}

/// Unified SecretVault providing memory and file-backed secret storage with environment fallback.
#[derive(Clone)]
pub struct SecretVault {
    backend: Arc<Mutex<Box<dyn ProfileSecretStore>>>,
    storage_desc: &'static str,
}

impl std::fmt::Debug for SecretVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretVault")
            .field("storage", &self.storage_desc)
            .finish()
    }
}

impl SecretVault {
    pub fn memory() -> Self {
        Self {
            backend: Arc::new(Mutex::new(Box::new(MemorySecretStore::new()))),
            storage_desc: "In-memory ephemeral store",
        }
    }

    pub fn file_backed(path: PathBuf) -> Result<Self, String> {
        let store = FileSecretStore::open_or_create(path)?;
        Ok(Self {
            backend: Arc::new(Mutex::new(Box::new(store))),
            storage_desc: "Local file vault (0600 user permissions; unencrypted on disk)",
        })
    }

    pub fn storage_description(&self) -> &'static str {
        self.storage_desc
    }

    pub fn get_key(&self, key_ref: &str) -> Result<Option<String>, String> {
        self.backend.lock().unwrap().get_key(key_ref)
    }

    pub fn set_key(&self, key_ref: &str, key: &str) -> Result<(), String> {
        self.backend.lock().unwrap().set_key(key_ref, key)
    }

    pub fn delete_key(&self, key_ref: &str) -> Result<(), String> {
        self.backend.lock().unwrap().delete_key(key_ref)
    }
}

/// Safely exports a profile configuration to standard MasterDNS files (`client_config.toml` and `client_resolvers.txt`).
/// Excludes secrets by default unless explicit `secret` is provided.
pub fn export_masterdns_profile(
    profile: &MasterDnsProfile,
    target_dir: &Path,
    secret: Option<&str>,
) -> Result<(PathBuf, PathBuf), String> {
    profile.validate()?;

    fs::create_dir_all(target_dir).map_err(|e| {
        format!(
            "Failed to create export directory {}: {e}",
            target_dir.display()
        )
    })?;

    let cfg_path = target_dir.join("client_config.toml");
    let res_path = target_dir.join("client_resolvers.txt");

    // 1. Write client_resolvers.txt
    let resolvers_content = profile.resolvers.join("\n") + "\n";
    fs::write(&res_path, resolvers_content.as_bytes())
        .map_err(|e| format!("Failed to write {}: {e}", res_path.display()))?;

    // 2. Write client_config.toml
    let key_val = secret.unwrap_or("");
    let port = profile.custom_port.unwrap_or(1080);
    let toml_content = format!(
        r#"# Mewser Exported MasterDNS Client Configuration
# Profile: "{name}"
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["{domain}"]
DATA_ENCRYPTION_METHOD = {encryption_method}
ENCRYPTION_KEY = "{key_val}"

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = {port}
SOCKS5_AUTH = false

# MTU Discovery Settings matching verified baseline
MIN_UPLOAD_MTU = 38
MIN_DOWNLOAD_MTU = 150
MAX_UPLOAD_MTU = 150
MAX_DOWNLOAD_MTU = 888
MTU_TEST_RETRIES = 2
MTU_TEST_TIMEOUT = 2.0
MTU_TEST_PARALLELISM = 16
AUTO_SCALE_PROFILES = true

# ARQ Reliability
MAX_CONNECTION_ATTEMPTS = 10
ARQ_WINDOW_SIZE = 1000
ARQ_INITIAL_RTO = 0.5
ARQ_MAX_RTO = 3.0

LOG_LEVEL = "INFO"
CONFIG_VERSION = 5.0
"#,
        name = profile.name,
        domain = profile.domain,
        encryption_method = profile.encryption_method,
    );

    fs::write(&cfg_path, toml_content.as_bytes())
        .map_err(|e| format!("Failed to write {}: {e}", cfg_path.display()))?;

    #[cfg(unix)]
    {
        let perm_mode = if secret.is_some() { 0o600 } else { 0o644 };
        let _ = fs::set_permissions(&cfg_path, fs::Permissions::from_mode(perm_mode));
        let _ = fs::set_permissions(&res_path, fs::Permissions::from_mode(0o644));
    }

    Ok((cfg_path, res_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation_and_unique_ids() {
        let p1 = MasterDnsProfile::new(
            "Profile 1",
            "tunnel1.example.com",
            1,
            vec!["1.1.1.1:53".into()],
        );
        let p2 = MasterDnsProfile::new(
            "Profile 2",
            "tunnel2.example.com",
            2,
            vec!["8.8.8.8:53".into()],
        );
        assert_ne!(p1.id, p2.id);
        assert_ne!(p1.key_ref, p2.key_ref);
        assert_eq!(p1.name, "Profile 1");
        assert_eq!(p1.domain, "tunnel1.example.com");
        assert_eq!(p1.encryption_method, 1);
        assert_eq!(p1.resolvers, vec!["1.1.1.1:53"]);
    }

    #[test]
    fn test_profile_duplication() {
        let original = MasterDnsProfile::new(
            "Original",
            "tunnel.example.com",
            1,
            vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
        );
        let duplicated = original.duplicate("Original Copy");

        assert_ne!(original.id, duplicated.id);
        assert_ne!(original.key_ref, duplicated.key_ref);
        assert_eq!(duplicated.name, "Original Copy");
        assert_eq!(duplicated.domain, original.domain);
        assert_eq!(duplicated.encryption_method, original.encryption_method);
        assert_eq!(duplicated.resolvers, original.resolvers);
    }

    #[test]
    fn test_resolver_sanitization_and_deduplication() {
        let raw = vec![
            " 1.1.1.1:53 ".to_string(),
            "".to_string(),
            "# comment".to_string(),
            "8.8.8.8".to_string(),    // Missing port normalized to :53
            "1.1.1.1:53".to_string(), // Duplicate
            "8.8.8.8:53".to_string(), // Duplicate after normalization
            "9.9.9.9:53".to_string(),
        ];
        let sanitized = MasterDnsProfile::sanitize_resolvers(&raw);
        assert_eq!(
            sanitized,
            vec![
                "1.1.1.1:53".to_string(),
                "8.8.8.8:53".to_string(),
                "9.9.9.9:53".to_string()
            ]
        );
    }

    #[test]
    fn test_profile_validation() {
        let mut p =
            MasterDnsProfile::new("Valid", "valid.domain.com", 1, vec!["1.1.1.1:53".into()]);
        assert!(p.validate().is_ok());

        p.name = "  ".to_string();
        assert!(p.validate().is_err());

        p.name = "Valid".to_string();
        p.domain = "".to_string();
        assert!(p.validate().is_err());

        p.domain = "invalid domain with space".to_string();
        assert!(p.validate().is_err());

        p.domain = "valid.com".to_string();
        p.encryption_method = 0;
        assert!(p.validate().is_err());

        p.encryption_method = 1;
        p.resolvers = vec![];
        assert!(p.validate().is_err());

        p.resolvers = vec!["not_an_ip".to_string()];
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_profile_serialization_has_no_secret() {
        let profile = MasterDnsProfile::new(
            "Test Profile",
            "test.tunnel.local",
            1,
            vec!["1.1.1.1:53".into()],
        );
        let serialized = serde_json::to_string_pretty(&profile).unwrap();
        assert!(
            !serialized.contains("encryption_key"),
            "encryption_key found in profile serialization!"
        );
        assert!(serialized.contains("key_ref"));
    }

    #[test]
    fn test_secret_vault_memory_operations() {
        let vault = SecretVault::memory();
        assert_eq!(vault.get_key("key_1").unwrap(), None);

        vault.set_key("key_1", "super_secret_123").unwrap();
        assert_eq!(
            vault.get_key("key_1").unwrap().as_deref(),
            Some("super_secret_123")
        );

        vault.delete_key("key_1").unwrap();
        assert_eq!(vault.get_key("key_1").unwrap(), None);
    }

    #[test]
    fn test_secret_vault_file_backed_permissions_and_operations() {
        let temp_dir = std::env::temp_dir().join(format!("test_vault_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let vault_file = temp_dir.join("vault.json");

        let vault = SecretVault::file_backed(vault_file.clone()).expect("Failed to create vault");
        vault
            .set_key("key_abc", "my_secret_token_val")
            .expect("Failed to set key");

        // Verify file on disk
        let file_contents = fs::read_to_string(&vault_file).unwrap();
        assert!(file_contents.contains("key_abc"));
        assert!(file_contents.contains("my_secret_token_val"));

        #[cfg(unix)]
        {
            let meta = fs::metadata(&vault_file).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Secret file must have 0600 permissions");
        }

        // Verify retrieval across reload
        let reloaded = SecretVault::file_backed(vault_file).expect("Failed to reload vault");
        assert_eq!(
            reloaded.get_key("key_abc").unwrap().as_deref(),
            Some("my_secret_token_val")
        );

        reloaded.delete_key("key_abc").unwrap();
        assert_eq!(reloaded.get_key("key_abc").unwrap(), None);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_export_masterdns_profile_safe_and_with_secrets() {
        let temp_dir = std::env::temp_dir().join(format!("test_export_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let profile = MasterDnsProfile::new(
            "Export Profile",
            "export.example.com",
            2,
            vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
        );

        // 1. Safe Export (default: secrets omitted)
        let safe_dir = temp_dir.join("safe");
        let (cfg_path, res_path) =
            export_masterdns_profile(&profile, &safe_dir, None).expect("Safe export failed");

        let cfg_str = fs::read_to_string(&cfg_path).unwrap();
        let res_str = fs::read_to_string(&res_path).unwrap();

        assert!(cfg_str.contains("DOMAINS = [\"export.example.com\"]"));
        assert!(cfg_str.contains("DATA_ENCRYPTION_METHOD = 2"));
        assert!(cfg_str.contains("ENCRYPTION_KEY = \"\"")); // Empty!
        assert!(res_str.contains("1.1.1.1:53"));
        assert!(res_str.contains("8.8.8.8:53"));

        // 2. Export with Secrets
        let full_dir = temp_dir.join("full");
        let (full_cfg_path, _) =
            export_masterdns_profile(&profile, &full_dir, Some("explicitly_exported_secret_key"))
                .expect("Full export failed");

        let full_cfg_str = fs::read_to_string(&full_cfg_path).unwrap();
        assert!(full_cfg_str.contains("ENCRYPTION_KEY = \"explicitly_exported_secret_key\""));

        #[cfg(unix)]
        {
            let mode = fs::metadata(&full_cfg_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Secret-containing export must be 0600");
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
