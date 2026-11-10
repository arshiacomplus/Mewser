use std::net::SocketAddr;
use std::time::Duration;

use mewser_cli::engine::ClientEngine;
use mewser_cli::error::ClientError;
use mewser_cli::BrowsingMode;
use mewser_core::tunnel::socks5::{Socks5Config, Socks5Target, Socks5TunnelAdapter};
use mewser_desktop::app::validate_gateway_endpoint;
use mewser_desktop::controller::manifest::{
    locate_masterdns_binary, validate_masterdns_binary, LINUX_AMD64_BINARY_NAME,
};
use mewser_desktop::controller::{MasterDnsConfig, MasterDnsController, TunnelState};
use mewser_desktop::profile::MasterDnsProfile;
use mewser_desktop::state::{
    default_tunnel_domain, is_developer_domain, GatewayTokenSource, PersistentSettings,
    SettingsState, GATEWAY_TOKEN_SECRET_REF,
};
use mewser_desktop::DesktopTransport;

static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

// 1. Fresh installation with no developer-owned profile
#[test]
fn test_01_fresh_install_has_no_developer_profile() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let settings = SettingsState::default();

    // Default tunnel domain must be empty, never a developer domain
    assert!(settings.tunnel_domain.is_empty());
    assert!(!is_developer_domain(&settings.tunnel_domain));
    assert!(!settings.tunnel_auto_connect);

    // Initial profile in profile store must be in an explicit unconfigured state
    let prof = settings.profile_store.selected_profile().unwrap();
    assert!(prof.domain.is_empty());
    assert!(!is_developer_domain(&prof.domain));
    assert!(!settings.profile_store.auto_connect);

    // Verification across all initial profiles
    for p in settings.profile_store.profiles() {
        assert!(!is_developer_domain(&p.domain));
    }
}

// 2. No automatic connection when no valid profile exists
#[test]
fn test_02_no_auto_connect_when_no_valid_profile() {
    let cfg = MasterDnsConfig::default();
    assert!(cfg.domain.is_empty());

    let controller = MasterDnsController::new(cfg);
    let result = controller.connect();

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("not configured"),
        "Expected error about unconfigured domain, got: {err_msg}"
    );

    match controller.state() {
        TunnelState::Failed(msg) => {
            assert!(msg.contains("not configured"));
        }
        other => panic!("Expected TunnelState::Failed, got {other:?}"),
    }
    assert!(controller.endpoint().is_none());
}

// 3. Legacy profile migration
#[test]
fn test_03_legacy_profile_migration() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "mewser_test_legacy_mig_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(temp_dir.join("mewser")).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    // Old settings created by a previous version targeting developer infrastructure
    let legacy_json = r#"{
        "transport": "Socks5",
        "proxy_addr_str": "127.0.0.1:1080",
        "gateway_addr_str": "127.0.0.1:4040",
        "tcp_endpoint_str": "127.0.0.1:1080",
        "proxy_user": "",
        "timeout_secs": 30,
        "direct_domains": [],
        "direct_suffixes": [],
        "profiles": [],
        "selected_profile_id": null,
        "vault_file_consent": false,
        "tunnel_domain": "z8.blue-boy.sbs",
        "tunnel_encryption_method": 1,
        "tunnel_resolvers": ["1.1.1.1:53"],
        "tunnel_auto_connect": true
    }"#;

    std::fs::write(temp_dir.join("mewser/desktop_settings.json"), legacy_json).unwrap();

    let migrated = SettingsState::load_or_default();

    // Must prevent old developer-owned default from being used or auto-connected
    assert!(migrated.tunnel_domain.is_empty());
    assert!(!migrated.tunnel_auto_connect);
    assert!(!migrated.profile_store.auto_connect);

    let active_prof = migrated.profile_store.selected_profile().unwrap();
    assert!(active_prof.domain.is_empty());
    assert!(!is_developer_domain(&active_prof.domain));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// 4. Preservation of existing user-created profiles
#[test]
fn test_04_preservation_of_existing_user_profiles() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "mewser_test_user_pres_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(temp_dir.join("mewser")).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    let user_profile = MasterDnsProfile::new(
        "My Personal VPS",
        "vpn.mycustomserver.net",
        2,
        vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
    );
    let prof_id = user_profile.id.clone();

    let settings = PersistentSettings {
        transport: DesktopTransport::Socks5,
        proxy_addr_str: "127.0.0.1:1080".to_string(),
        gateway_addr_str: "10.0.0.5:4040".to_string(),
        tcp_endpoint_str: "127.0.0.1:1080".to_string(),
        proxy_user: String::new(),
        timeout_secs: 45,
        direct_domains: vec!["internal.user".to_string()],
        direct_suffixes: vec![".internal".to_string()],
        profiles: vec![user_profile],
        selected_profile_id: Some(prof_id.clone()),
        vault_file_consent: false,
        tunnel_domain: "vpn.mycustomserver.net".to_string(),
        tunnel_encryption_method: 2,
        tunnel_resolvers: vec!["8.8.8.8:53".to_string()],
        tunnel_auto_connect: true,
    };

    let json = serde_json::to_string(&settings).unwrap();
    std::fs::write(temp_dir.join("mewser/desktop_settings.json"), json).unwrap();

    let loaded = SettingsState::load_or_default();

    // User's profile must be preserved intact
    let active = loaded.profile_store.selected_profile().unwrap();
    assert_eq!(active.id, prof_id);
    assert_eq!(active.name, "My Personal VPS");
    assert_eq!(active.domain, "vpn.mycustomserver.net");
    assert_eq!(active.encryption_method, 2);
    assert_eq!(loaded.gateway_addr_str, "10.0.0.5:4040");
    assert!(loaded.tunnel_auto_connect);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// 5. Developer-domain detection in initial defaults
#[test]
fn test_05_developer_domain_detection() {
    assert!(is_developer_domain("z8.blue-boy.sbs"));
    assert!(is_developer_domain("vpn2.blue-boy.sbs"));
    assert!(is_developer_domain("vpn3.blue-boy.sbs"));
    assert!(is_developer_domain("node.blue-boy.sbs"));
    assert!(is_developer_domain("blue-boy.sbs"));

    // Case-insensitivity
    assert!(is_developer_domain("Z8.BLUE-BOY.SBS"));

    // Valid user domains are not flagged
    assert!(!is_developer_domain("my-tunnel.example.com"));
    assert!(!is_developer_domain("vpn.mydomain.org"));
    assert!(!is_developer_domain("localhost"));
    assert!(!is_developer_domain(""));

    // Default tunnel domain must be empty
    assert_eq!(default_tunnel_domain(), "");
}

// 6. Binary discovery without developer-specific paths
#[test]
fn test_06_binary_discovery_without_developer_paths() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let prev = std::env::var("MEWSER_MASTERDNS_BIN").ok();
    std::env::remove_var("MEWSER_MASTERDNS_BIN");

    let err = locate_masterdns_binary();
    if let Err(msg) = err {
        assert!(
            !msg.contains("/mnt/D84AE43F4AE41C4E"),
            "Error contains developer partition path: {msg}"
        );
        assert!(
            !msg.contains("Mylinxfiles"),
            "Error contains developer specific dir: {msg}"
        );
        assert!(msg.contains("~/.local/share/mewser/bin/"));
        assert!(msg.contains(LINUX_AMD64_BINARY_NAME));
    }

    // Verify MEWSER_MASTERDNS_BIN override with non-executable file is rejected
    let temp_file = std::env::temp_dir().join(format!("test_bin_{}", std::process::id()));
    std::fs::write(&temp_file, b"#!/bin/sh\necho mock").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    std::env::set_var("MEWSER_MASTERDNS_BIN", &temp_file);
    let val_res = validate_masterdns_binary(&temp_file);
    #[cfg(unix)]
    assert!(val_res.is_err(), "Non-executable file must be rejected");

    let _ = std::fs::remove_file(&temp_file);
    if let Some(v) = prev {
        std::env::set_var("MEWSER_MASTERDNS_BIN", v);
    } else {
        std::env::remove_var("MEWSER_MASTERDNS_BIN");
    }
}

// 7. Gateway token input and masking state
#[test]
fn test_07_gateway_token_input_and_masking_state() {
    let mut settings = SettingsState::default();
    assert_eq!(settings.gateway_token, "");
    assert_eq!(settings.gateway_token_source(), GatewayTokenSource::None);

    // Staging token in memory
    settings.gateway_token = "secret_bearer_token_xyz_789".to_string();
    assert_eq!(settings.gateway_token_source(), GatewayTokenSource::Memory);
    assert_eq!(
        settings.effective_gateway_token().0,
        "secret_bearer_token_xyz_789"
    );
}

// 8. Vault-backed Gateway token persistence
#[test]
fn test_08_vault_backed_gateway_token_persistence() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "mewser_test_vault_tok_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(temp_dir.join("mewser")).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    let settings = SettingsState {
        vault_file_consent: true,
        gateway_token: "vault_persisted_secret_token_12345".to_string(),
        ..Default::default()
    };

    settings
        .save_persistent()
        .expect("Save persistent settings");

    // 1. Vault file must exist on disk and contain the token
    let vault_path = temp_dir.join("mewser/.vault.json");
    assert!(vault_path.is_file(), "Vault file must be created on disk");
    let vault_content = std::fs::read_to_string(&vault_path).unwrap();
    assert!(vault_content.contains(GATEWAY_TOKEN_SECRET_REF));
    assert!(vault_content.contains("vault_persisted_secret_token_12345"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&vault_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Vault file must have strict 0600 permissions");
    }

    // 2. Settings JSON file must NEVER contain the secret token
    let settings_path = temp_dir.join("mewser/desktop_settings.json");
    let settings_content = std::fs::read_to_string(&settings_path).unwrap();
    assert!(!settings_content.contains("vault_persisted_secret_token_12345"));
    assert!(!settings_content.contains("gateway_token"));

    // 3. Reload in a fresh session: Token should be loaded from vault
    let loaded = SettingsState::load_or_default();
    assert_eq!(loaded.gateway_token, "vault_persisted_secret_token_12345");
    assert_eq!(loaded.gateway_token_source(), GatewayTokenSource::Vault);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// 9. Memory-only Gateway token behavior
#[test]
fn test_09_memory_only_gateway_token_behavior() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "mewser_test_mem_tok_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(temp_dir.join("mewser")).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    let settings = SettingsState {
        vault_file_consent: false,
        gateway_token: "volatile_memory_only_token_777".to_string(),
        ..Default::default()
    };

    settings
        .save_persistent()
        .expect("Save persistent settings");

    // Vault file must NOT be written to disk
    let vault_path = temp_dir.join("mewser/.vault.json");
    assert!(
        !vault_path.exists(),
        "Vault file must not exist when consent is false"
    );

    // Settings JSON must NOT contain token
    let settings_path = temp_dir.join("mewser/desktop_settings.json");
    let settings_content = std::fs::read_to_string(&settings_path).unwrap();
    assert!(!settings_content.contains("volatile_memory_only_token_777"));
    assert!(!settings_content.contains("gateway_token"));

    // Reloading fresh process must not have the token
    let loaded = SettingsState::load_or_default();
    assert!(loaded.gateway_token.is_empty());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// 10. Environment/UI credential precedence
#[test]
fn test_10_environment_ui_credential_precedence() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let prev_env = std::env::var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN).ok();

    // Case A: No UI token, no ENV
    std::env::remove_var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN);
    let mut settings = SettingsState::default();
    assert_eq!(settings.effective_gateway_token().0, "");
    assert_eq!(settings.gateway_token_source(), GatewayTokenSource::None);

    // Case B: Environment variable only
    std::env::set_var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN, "env_token_val_111");
    let (eff_tok, src) = settings.effective_gateway_token();
    assert_eq!(eff_tok, "env_token_val_111");
    assert_eq!(src, GatewayTokenSource::Environment);

    // Case C: UI token overrides environment variable (Memory mode)
    settings.gateway_token = "ui_override_memory_222".to_string();
    settings.vault_file_consent = false;
    let (eff_tok, src) = settings.effective_gateway_token();
    assert_eq!(eff_tok, "ui_override_memory_222");
    assert_eq!(src, GatewayTokenSource::Memory);

    // Case D: UI token overrides environment variable (Vault mode)
    settings.vault_file_consent = true;
    let (eff_tok, src) = settings.effective_gateway_token();
    assert_eq!(eff_tok, "ui_override_memory_222");
    assert_eq!(src, GatewayTokenSource::Vault);

    // Case E: Clearing UI token falls back to Environment variable
    settings.gateway_token = String::new();
    let (eff_tok, src) = settings.effective_gateway_token();
    assert_eq!(eff_tok, "env_token_val_111");
    assert_eq!(src, GatewayTokenSource::Environment);

    if let Some(v) = prev_env {
        std::env::set_var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN, v);
    } else {
        std::env::remove_var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN);
    }
}

// 11. Token deletion and replacement
#[test]
fn test_11_token_deletion_and_replacement() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "mewser_test_tok_del_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(temp_dir.join("mewser")).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    let mut settings = SettingsState {
        vault_file_consent: true,
        gateway_token: "token_v1".to_string(),
        ..Default::default()
    };
    settings.save_persistent().unwrap();

    let vault_path = temp_dir.join("mewser/.vault.json");
    let content = std::fs::read_to_string(&vault_path).unwrap();
    assert!(content.contains("token_v1"));

    // Replace token
    settings.gateway_token = "token_v2".to_string();
    settings.save_persistent().unwrap();
    let content = std::fs::read_to_string(&vault_path).unwrap();
    assert!(!content.contains("token_v1"));
    assert!(content.contains("token_v2"));

    // Delete token
    settings.gateway_token.clear();
    settings.save_persistent().unwrap();
    let content = std::fs::read_to_string(&vault_path).unwrap();
    assert!(!content.contains("token_v2"));
    assert!(!content.contains(GATEWAY_TOKEN_SECRET_REF));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// 12. Token absence from serialized settings
#[test]
fn test_12_token_absence_from_serialized_settings() {
    let settings = SettingsState {
        gateway_token: "critical_secret_bearer_token".to_string(),
        proxy_pass: "critical_secret_socks_pass".to_string(),
        tunnel_encryption_key: "critical_secret_masterdns_key".to_string(),
        ..Default::default()
    };

    let persistent = PersistentSettings {
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

    let serialized = serde_json::to_string(&persistent).unwrap();
    assert!(!serialized.contains("critical_secret_bearer_token"));
    assert!(!serialized.contains("critical_secret_socks_pass"));
    assert!(!serialized.contains("critical_secret_masterdns_key"));
    assert!(!serialized.contains("gateway_token"));
    assert!(!serialized.contains("proxy_pass"));
    assert!(!serialized.contains("tunnel_encryption_key"));
}

// 13. SOCKS5 hostname addressing without local DNS resolution
#[test]
fn test_13_socks5_hostname_addressing_without_local_dns() {
    let settings = SettingsState {
        proxy_addr_str: "127.0.0.1:1080".to_string(),
        // Use an intentionally unresolvable private remote hostname
        gateway_addr_str: "gw.remote-vps.internal:4040".to_string(),
        ..Default::default()
    };

    let (cfg, target) = settings
        .build_socks5_config()
        .expect("Building SOCKS5 config with hostname endpoint must succeed");

    assert_eq!(cfg.proxy_addr, "127.0.0.1:1080".parse().unwrap());
    match target {
        Socks5Target::Domain(domain, port) => {
            assert_eq!(domain, "gw.remote-vps.internal");
            assert_eq!(port, 4040);
        }
        Socks5Target::Ip(_) => panic!("Expected Socks5Target::Domain for hostname endpoint"),
    }
}

// 14. Endpoint validation for IPv4, IPv6, and hostname forms
#[test]
fn test_14_endpoint_validation_ipv4_ipv6_hostname() {
    // Valid IPv4
    assert_eq!(
        validate_gateway_endpoint("127.0.0.1:4040").unwrap(),
        "127.0.0.1:4040"
    );
    assert_eq!(
        validate_gateway_endpoint("10.0.0.5:8080").unwrap(),
        "10.0.0.5:8080"
    );

    // Valid IPv6
    assert_eq!(
        validate_gateway_endpoint("[::1]:4040").unwrap(),
        "[::1]:4040"
    );
    assert_eq!(
        validate_gateway_endpoint("[2001:db8::1]:4040").unwrap(),
        "[2001:db8::1]:4040"
    );

    // Valid Hostname
    assert_eq!(
        validate_gateway_endpoint("gw.example.com:4040").unwrap(),
        "gw.example.com:4040"
    );
    assert_eq!(
        validate_gateway_endpoint("sub.domain-node.example.org:80").unwrap(),
        "sub.domain-node.example.org:80"
    );

    // Invalid: missing port
    assert!(validate_gateway_endpoint("127.0.0.1").is_err());
    assert!(validate_gateway_endpoint("gw.example.com").is_err());

    // Invalid: URL schemes
    assert!(validate_gateway_endpoint("http://127.0.0.1:4040").is_err());
    assert!(validate_gateway_endpoint("https://gw.example.com:4040").is_err());

    // Invalid: URL paths and queries
    assert!(validate_gateway_endpoint("gw.example.com:4040/extract").is_err());
    assert!(validate_gateway_endpoint("gw.example.com:4040?query=1").is_err());

    // Invalid: port 0 or out of bounds
    assert!(validate_gateway_endpoint("gw.example.com:0").is_err());
    assert!(validate_gateway_endpoint("gw.example.com:70000").is_err());

    // Invalid: characters in hostname
    assert!(validate_gateway_endpoint("gw_invalid.com:4040").is_err());
    assert!(validate_gateway_endpoint("-start-dash.com:4040").is_err());
    assert!(validate_gateway_endpoint("end-dash-.com:4040").is_err());
}

// 15. Fail-closed behavior when Gateway authentication or transport fails
#[test]
fn test_15_fail_closed_when_gateway_auth_or_transport_fails() {
    // When the tunnel proxy is offline, adapter failure must immediately return an error
    // and MUST NEVER fall back to a direct connection.
    let offline_proxy_addr: SocketAddr = "127.0.0.1:49999".parse().unwrap();
    let target = Socks5Target::Ip("127.0.0.1:4040".parse().unwrap());
    let cfg = Socks5Config {
        proxy_addr: offline_proxy_addr,
        auth: None,
        connect_timeout: Duration::from_millis(100),
        read_timeout: Duration::from_millis(100),
        write_timeout: Duration::from_millis(100),
        max_response_bytes: 1024 * 1024,
    };

    let adapter = Socks5TunnelAdapter::new(cfg, target);
    let engine = ClientEngine::new(Box::new(adapter));

    let res = engine.navigate(
        "https://example.com/sensitive-article",
        BrowsingMode::ResilientText,
    );

    match res {
        Err(ClientError::Tunnel(msg)) => {
            assert!(
                msg.contains("Connection failed")
                    || msg.contains("refused")
                    || msg.contains("127.0.0.1"),
                "Expected connection failure, got: {msg}"
            );
        }
        other => panic!("Expected ClientError::Tunnel fail-closed error, got {other:?}"),
    }
}
