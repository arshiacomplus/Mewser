use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct RuntimeEnvironment {
    dir: PathBuf,
    config_path: PathBuf,
    resolvers_path: PathBuf,
}

impl RuntimeEnvironment {
    pub fn create(
        base_dir: Option<&Path>,
        port: u16,
        domain: &str,
        encryption_method: u8,
        encryption_key: &str,
        resolvers: &[String],
    ) -> Result<Self, String> {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let parent = match base_dir {
            Some(p) => p.to_path_buf(),
            None => std::env::temp_dir(),
        };

        let dir = parent.join(format!(
            "mewser_runtime_{}_{}",
            std::process::id(),
            unique_id
        ));
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create runtime directory {}: {e}", dir.display()))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }

        let config_path = dir.join("client_config.toml");
        let resolvers_path = dir.join("client_resolvers.txt");

        // 1. Write resolvers file
        let resolvers_content = resolvers.join("\n") + "\n";
        fs::write(&resolvers_path, resolvers_content.as_bytes())
            .map_err(|e| format!("Failed to write {}: {e}", resolvers_path.display()))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&resolvers_path, fs::Permissions::from_mode(0o600));
        }

        // 2. Generate minimal, secure client_config.toml
        let toml_content = format!(
            r#"# Mewser Managed MasterDNS Client Runtime Configuration
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["{domain}"]
DATA_ENCRYPTION_METHOD = {encryption_method}
ENCRYPTION_KEY = "{encryption_key}"

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
"#
        );

        fs::write(&config_path, toml_content.as_bytes())
            .map_err(|e| format!("Failed to write {}: {e}", config_path.display()))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600));
        }

        Ok(Self {
            dir,
            config_path,
            resolvers_path,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn resolvers_path(&self) -> &Path {
        &self.resolvers_path
    }

    pub fn cleanup(&self) {
        let _ = fs::remove_file(&self.config_path);
        let _ = fs::remove_file(&self.resolvers_path);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Drop for RuntimeEnvironment {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_environment_creation_and_cleanup() {
        let env = RuntimeEnvironment::create(
            None,
            49152,
            "primary.example.com",
            1,
            "secret_key_abc_123",
            &["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
        )
        .expect("Failed to create runtime environment");

        assert!(env.dir().exists());
        assert!(env.config_path().exists());
        assert!(env.resolvers_path().exists());

        let cfg = fs::read_to_string(env.config_path()).unwrap();
        assert!(cfg.contains("LISTEN_PORT = 49152"));
        assert!(cfg.contains("DOMAINS = [\"primary.example.com\"]"));

        let res = fs::read_to_string(env.resolvers_path()).unwrap();
        assert!(res.contains("1.1.1.1:53"));
        assert!(res.contains("8.8.8.8:53"));

        let dir_to_check = env.dir().to_path_buf();
        drop(env);
        assert!(!dir_to_check.exists());
    }
}
