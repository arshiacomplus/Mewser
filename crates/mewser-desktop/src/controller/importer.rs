use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::profile::{generate_profile_id, MasterDnsProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedMasterDnsConfig {
    pub domain: String,
    pub encryption_method: u8,
    pub encryption_key: String,
    pub resolvers: Vec<String>,
    pub source_path: PathBuf,
}

impl ImportedMasterDnsConfig {
    /// Separates configuration metadata into a `MasterDnsProfile` and isolates the sensitive encryption key.
    pub fn into_profile(self, name: Option<String>) -> (MasterDnsProfile, String) {
        let profile_name = name.unwrap_or_else(|| format!("Imported ({})", self.domain));
        let id = generate_profile_id();
        let key_ref = format!("key_{id}");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let profile = MasterDnsProfile {
            id,
            name: profile_name,
            created_at: now,
            modified_at: now,
            domain: self.domain,
            encryption_method: self.encryption_method,
            key_ref,
            resolvers: MasterDnsProfile::sanitize_resolvers(&self.resolvers),
            custom_port: None,
            timeout_secs: Some(60),
        };

        (profile, self.encryption_key)
    }
}

/// Imports and validates a MasterDNS client setup from explicitly specified configuration and optional resolvers files.
pub fn import_masterdns_files(
    config_file: &Path,
    resolvers_file: Option<&Path>,
) -> Result<ImportedMasterDnsConfig, String> {
    if !config_file.is_file() {
        return Err(format!(
            "Specified configuration file does not exist: {}",
            config_file.display()
        ));
    }

    let content = fs::read_to_string(config_file)
        .map_err(|e| format!("Failed to read {}: {e}", config_file.display()))?;

    let mut domain = String::new();
    let mut encryption_method = 1u8;
    let mut encryption_key = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_ascii_uppercase();
            let val = v.trim();

            match key.as_str() {
                "DOMAINS" | "DOMAIN" => {
                    let cleaned =
                        val.trim_matches(|c| c == '[' || c == ']' || c == '"' || c == '\'');
                    let first = cleaned
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'');
                    if !first.is_empty() {
                        domain = first.to_string();
                    }
                }
                "DATA_ENCRYPTION_METHOD" => {
                    let parsed = val
                        .trim_matches('"')
                        .trim_matches('\'')
                        .parse::<u8>()
                        .map_err(|_| {
                            "Invalid DATA_ENCRYPTION_METHOD (expected integer 1 or 2)".to_string()
                        })?;
                    if parsed == 0 {
                        return Err("Invalid DATA_ENCRYPTION_METHOD (cannot be 0)".to_string());
                    }
                    encryption_method = parsed;
                }
                "ENCRYPTION_KEY" => {
                    encryption_key = val.trim_matches('"').trim_matches('\'').to_string();
                }
                _ => {}
            }
        }
    }

    let domain_trimmed = domain.trim();
    if domain_trimmed.is_empty() {
        return Err("Configuration does not specify a valid DOMAIN or DOMAINS".into());
    }
    if domain_trimmed.contains(' ') || domain_trimmed.contains('/') || domain_trimmed.contains('\\')
    {
        return Err("Specified DOMAIN contains invalid characters".into());
    }

    // Determine resolvers file: passed explicitly, or sibling client_resolvers.txt
    let resolved_res_path = match resolvers_file {
        Some(p) => {
            if !p.is_file() {
                return Err(format!(
                    "Specified resolvers file does not exist: {}",
                    p.display()
                ));
            }
            Some(p.to_path_buf())
        }
        None => {
            let parent = config_file.parent().unwrap_or_else(|| Path::new("."));
            let sibling = parent.join("client_resolvers.txt");
            if sibling.is_file() {
                Some(sibling)
            } else {
                None
            }
        }
    };

    let mut raw_resolvers = Vec::new();
    if let Some(ref res_path) = resolved_res_path {
        let res_content = fs::read_to_string(res_path)
            .map_err(|e| format!("Failed to read {}: {e}", res_path.display()))?;
        for line in res_content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                raw_resolvers.push(trimmed.to_string());
            }
        }
    }

    let resolvers = MasterDnsProfile::sanitize_resolvers(&raw_resolvers);
    if resolvers.is_empty() {
        return Err("No valid resolvers found in resolvers file or configuration".into());
    }

    // Validate resolver formats
    for res in &resolvers {
        let trimmed = res.trim();
        if trimmed.parse::<SocketAddr>().is_err() && trimmed.parse::<IpAddr>().is_err() {
            return Err(format!("Invalid resolver address: {trimmed}"));
        }
    }

    Ok(ImportedMasterDnsConfig {
        domain: domain_trimmed.to_string(),
        encryption_method,
        encryption_key,
        resolvers,
        source_path: config_file.to_path_buf(),
    })
}

/// Imports an existing MasterDNS client setup from either a directory or a specific configuration file.
pub fn import_masterdns_config(path: &Path) -> Result<ImportedMasterDnsConfig, String> {
    if path.is_dir() {
        let cfg = path.join("client_config.toml");
        let res = path.join("client_resolvers.txt");
        if !cfg.is_file() {
            return Err(format!(
                "Directory {} does not contain client_config.toml",
                path.display()
            ));
        }
        import_masterdns_files(&cfg, if res.is_file() { Some(&res) } else { None })
    } else if path.is_file() {
        import_masterdns_files(path, None)
    } else {
        Err(format!("Specified path does not exist: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_config_from_toml_content() {
        let temp_dir = std::env::temp_dir().join(format!("test_import_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let cfg_path = temp_dir.join("client_config.toml");
        let res_path = temp_dir.join("client_resolvers.txt");

        let toml_sample = r#"
            PROTOCOL_TYPE = "SOCKS5"
            DOMAINS = ["test.tunnel.local"]
            DATA_ENCRYPTION_METHOD = 2
            ENCRYPTION_KEY = "test_imported_key_123"
        "#;
        fs::write(&cfg_path, toml_sample).unwrap();
        fs::write(&res_path, "1.1.1.1:53\n8.8.8.8:53\n").unwrap();

        let imported = import_masterdns_config(&temp_dir).expect("Failed to import");
        assert_eq!(imported.domain, "test.tunnel.local");
        assert_eq!(imported.encryption_method, 2);
        assert_eq!(imported.encryption_key, "test_imported_key_123");
        assert_eq!(imported.resolvers.len(), 2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_import_with_separate_resolvers_and_deduplication() {
        let temp_dir = std::env::temp_dir().join(format!("test_import_sep_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let cfg_path = temp_dir.join("custom_config.toml");
        let res_path = temp_dir.join("other_resolvers.txt");

        let toml_sample = r#"
            DOMAINS = ["separate.tunnel.net"]
            DATA_ENCRYPTION_METHOD = 1
            ENCRYPTION_KEY = "key_sep_456"
        "#;
        fs::write(&cfg_path, toml_sample).unwrap();
        fs::write(
            &res_path,
            "1.1.1.1:53\n# duplicate line below\n1.1.1.1:53\n9.9.9.9\n",
        )
        .unwrap();

        let imported = import_masterdns_files(&cfg_path, Some(&res_path)).expect("Failed import");
        assert_eq!(imported.domain, "separate.tunnel.net");
        assert_eq!(imported.encryption_method, 1);
        assert_eq!(imported.encryption_key, "key_sep_456");
        assert_eq!(
            imported.resolvers,
            vec!["1.1.1.1:53".to_string(), "9.9.9.9:53".to_string()]
        );

        // Convert into profile
        let (prof, key) = imported.into_profile(Some("Custom Profile".to_string()));
        assert_eq!(prof.name, "Custom Profile");
        assert_eq!(prof.domain, "separate.tunnel.net");
        assert_eq!(key, "key_sep_456");
        assert!(!prof.key_ref.is_empty());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_import_validation_errors() {
        let temp_dir = std::env::temp_dir().join(format!("test_import_err_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        // Missing domain
        let cfg1 = temp_dir.join("no_domain.toml");
        fs::write(&cfg1, "DATA_ENCRYPTION_METHOD = 1\n").unwrap();
        assert!(import_masterdns_files(&cfg1, None).is_err());

        // Invalid encryption method
        let cfg2 = temp_dir.join("bad_method.toml");
        fs::write(&cfg2, "DOMAIN = \"test.com\"\nDATA_ENCRYPTION_METHOD = 0\n").unwrap();
        assert!(import_masterdns_files(&cfg2, None).is_err());

        // Missing resolvers
        let cfg3 = temp_dir.join("no_resolvers.toml");
        fs::write(&cfg3, "DOMAIN = \"test.com\"\nDATA_ENCRYPTION_METHOD = 1\n").unwrap();
        assert!(import_masterdns_files(&cfg3, None).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
