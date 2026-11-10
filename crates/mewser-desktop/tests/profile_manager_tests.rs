use std::fs;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

use mewser_desktop::controller::{import_masterdns_files, MasterDnsController, TunnelState};
use mewser_desktop::profile::{MasterDnsProfile, ProfileStore, SecretVault};
use mewser_desktop::state::{DesktopTransport, PersistentSettings, SettingsState};

#[test]
fn test_profile_creation_and_unique_ids() {
    let p1 = MasterDnsProfile::new(
        "Frankfurt Primary",
        "de.mewser.vpn",
        1,
        vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
    );
    let p2 = MasterDnsProfile::new(
        "Amsterdam Secondary",
        "nl.mewser.vpn",
        2,
        vec!["9.9.9.9:53".to_string()],
    );

    assert_ne!(p1.id, p2.id, "Profile IDs must be unique");
    assert_ne!(p1.key_ref, p2.key_ref, "Secret references must be unique");
    assert_eq!(p1.name, "Frankfurt Primary");
    assert_eq!(p1.domain, "de.mewser.vpn");
    assert_eq!(p1.encryption_method, 1);
    assert_eq!(p1.resolvers.len(), 2);
    assert!(p1.created_at > 0);
    assert!(p1.modified_at >= p1.created_at);
}

#[test]
fn test_profile_renaming_and_editing() {
    let mut store = ProfileStore::new();
    let p1 = MasterDnsProfile::new(
        "Profile A",
        "tunnel-a.net",
        1,
        vec!["1.1.1.1:53".to_string()],
    );
    let p2 = MasterDnsProfile::new(
        "Profile B",
        "tunnel-b.net",
        2,
        vec!["8.8.8.8:53".to_string()],
    );
    let id1 = p1.id.clone();
    let id2 = p2.id.clone();

    store.add_profile(p1);
    store.add_profile(p2);

    // Edit Profile A
    {
        let prof_a = store.get_profile_mut(&id1).expect("Find profile A");
        prof_a.name = "Renamed Profile A".to_string();
        prof_a.domain = "updated-a.net".to_string();
        prof_a.encryption_method = 2;
        prof_a.resolvers = vec!["9.9.9.9:53".to_string()];
        prof_a.custom_port = Some(1088);
    }

    // Verify Profile A was modified
    let updated_a = store.get_profile(&id1).expect("Find profile A");
    assert_eq!(updated_a.name, "Renamed Profile A");
    assert_eq!(updated_a.domain, "updated-a.net");
    assert_eq!(updated_a.encryption_method, 2);
    assert_eq!(updated_a.resolvers, vec!["9.9.9.9:53".to_string()]);
    assert_eq!(updated_a.custom_port, Some(1088));

    // Verify Profile B was completely unaffected
    let untouched_b = store.get_profile(&id2).expect("Find profile B");
    assert_eq!(untouched_b.name, "Profile B");
    assert_eq!(untouched_b.domain, "tunnel-b.net");
    assert_eq!(untouched_b.encryption_method, 2);
    assert_eq!(untouched_b.resolvers, vec!["8.8.8.8:53".to_string()]);
}

#[test]
fn test_profile_duplication() {
    let mut store = ProfileStore::new();
    let p1 = MasterDnsProfile::new(
        "Production VPS",
        "primary.example.com",
        1,
        vec!["1.1.1.1:53".to_string()],
    );
    let id1 = p1.id.clone();
    store.add_profile(p1);

    let dup = store
        .duplicate_profile(&id1, Some("Production VPS Backup"))
        .expect("Duplicate profile");

    assert_eq!(store.profiles().len(), 2);
    assert_ne!(dup.id, id1);
    assert_ne!(dup.key_ref, format!("key_{id1}"));
    assert_eq!(dup.name, "Production VPS Backup");
    assert_eq!(dup.domain, "primary.example.com");
    assert_eq!(dup.encryption_method, 1);
    assert_eq!(dup.resolvers, vec!["1.1.1.1:53".to_string()]);
}

#[test]
fn test_profile_deletion() {
    let mut store = ProfileStore::new();
    let p1 = MasterDnsProfile::new("First", "first.net", 1, vec!["1.1.1.1:53".into()]);
    let p2 = MasterDnsProfile::new("Second", "second.net", 1, vec!["8.8.8.8:53".into()]);
    let id1 = p1.id.clone();
    let id2 = p2.id.clone();

    store.add_profile(p1);
    store.add_profile(p2);
    store.select_profile(&id1).unwrap();
    assert_eq!(store.selected_profile_id.as_deref(), Some(id1.as_str()));

    // Delete active profile 1
    let removed = store.remove_profile(&id1).expect("Remove profile 1");
    assert_eq!(removed.id, id1);
    assert_eq!(store.profiles().len(), 1);
    assert_eq!(store.get_profile(&id1), None);

    // Selection automatically updates to remaining profile 2
    assert_eq!(store.selected_profile_id.as_deref(), Some(id2.as_str()));
}

#[test]
fn test_selecting_profile() {
    let mut store = ProfileStore::new();
    let p1 = MasterDnsProfile::new("P1", "p1.net", 1, vec!["1.1.1.1:53".into()]);
    let p2 = MasterDnsProfile::new("P2", "p2.net", 2, vec!["8.8.8.8:53".into()]);
    let id1 = p1.id.clone();
    let id2 = p2.id.clone();

    store.add_profile(p1);
    store.add_profile(p2);

    assert_eq!(store.selected_profile().unwrap().id, id1);

    store.select_profile(&id2).expect("Select P2");
    assert_eq!(store.selected_profile().unwrap().id, id2);
    assert_eq!(store.selected_profile().unwrap().domain, "p2.net");

    // Invalid ID returns error
    assert!(store.select_profile("non_existent_id").is_err());
}

#[test]
fn test_persistence_across_reload() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("test_persist_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);
    let settings_file = mewser_desktop::state::get_settings_file_path().unwrap();
    let secrets_file = mewser_desktop::state::get_secrets_file_path().unwrap();

    // 1. Build initial settings with multiple profiles and secrets
    let mut store = ProfileStore::new();
    let p1 = MasterDnsProfile::new("Node 1", "node1.vpn", 1, vec!["1.1.1.1:53".into()]);
    let p2 = MasterDnsProfile::new("Node 2", "node2.vpn", 2, vec!["8.8.8.8:53".into()]);
    let id2 = p2.id.clone();
    let key_ref2 = p2.key_ref.clone();

    store.add_profile(p1);
    store.add_profile(p2);
    store.select_profile(&id2).unwrap();
    store.auto_connect = false;

    let vault = SecretVault::file_backed(secrets_file.clone()).unwrap();
    vault
        .set_key(&key_ref2, "secret_key_for_node2")
        .expect("Store secret");

    let settings = SettingsState {
        profile_store: store,
        secret_vault: vault,
        timeout_secs: 45,
        vault_file_consent: true,
        ..SettingsState::default()
    };
    settings.save_persistent().expect("Save settings");
    assert!(
        settings_file.exists(),
        "desktop_settings.json must exist after save"
    );

    // 2. Reload settings from disk
    let reloaded = SettingsState::load_or_default();
    assert_eq!(reloaded.profile_store.profiles().len(), 2);
    assert_eq!(
        reloaded.profile_store.selected_profile_id.as_deref(),
        Some(id2.as_str())
    );
    assert!(!reloaded.profile_store.auto_connect);

    // Active profile fields synchronized
    assert_eq!(reloaded.tunnel_domain, "node2.vpn");
    assert_eq!(reloaded.tunnel_encryption_method, 2);
    assert_eq!(reloaded.tunnel_encryption_key, "secret_key_for_node2");

    // Cleanup
    std::env::remove_var("XDG_CONFIG_HOME");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_migration_from_existing_single_profile_settings() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("test_migrate_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);
    let settings_file = mewser_desktop::state::get_settings_file_path().unwrap();
    if let Some(parent) = settings_file.parent() {
        let _ = fs::create_dir_all(parent);
    }

    // Write a legacy settings file without `profiles` or `selected_profile_id`
    let legacy_json = r#"{
        "transport": "Socks5",
        "proxy_addr_str": "127.0.0.1:1080",
        "gateway_addr_str": "127.0.0.1:4040",
        "tcp_endpoint_str": "127.0.0.1:1080",
        "proxy_user": "legacy_user",
        "timeout_secs": 35,
        "direct_domains": ["legacy.local"],
        "direct_suffixes": [".local"],
        "tunnel_domain": "migrated.tunnel.org",
        "tunnel_encryption_method": 2,
        "tunnel_resolvers": ["109.125.169.20:53", "8.8.8.8:53"],
        "tunnel_auto_connect": true
    }"#;
    fs::write(&settings_file, legacy_json).expect("Write legacy settings");

    // Load settings - must automatically migrate into an initial profile
    let loaded = SettingsState::load_or_default();
    assert_eq!(
        loaded.profile_store.profiles().len(),
        1,
        "Legacy settings must migrate to exactly 1 initial profile"
    );

    let initial_prof = loaded.profile_store.selected_profile().unwrap();
    assert_eq!(initial_prof.name, "Default MasterDNS Profile");
    assert_eq!(initial_prof.domain, "migrated.tunnel.org");
    assert_eq!(initial_prof.encryption_method, 2);
    assert_eq!(
        initial_prof.resolvers,
        vec!["109.125.169.20:53".to_string(), "8.8.8.8:53".to_string()]
    );

    // Non-tunnel settings preserved
    assert_eq!(loaded.proxy_user, "legacy_user");
    assert_eq!(loaded.timeout_secs, 35);
    assert_eq!(loaded.direct_domains, vec!["legacy.local".to_string()]);

    // Cleanup
    std::env::remove_var("XDG_CONFIG_HOME");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_import_parsing_and_validation() {
    let temp_dir = std::env::temp_dir().join(format!("test_import_parse_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    let cfg_file = temp_dir.join("client_config.toml");
    let res_file = temp_dir.join("client_resolvers.txt");

    let toml = r#"
        PROTOCOL_TYPE = "SOCKS5"
        DOMAINS = ["custom.tunnel.example"]
        DATA_ENCRYPTION_METHOD = 1
        ENCRYPTION_KEY = "my_imported_secret_key"
    "#;
    fs::write(&cfg_file, toml).unwrap();
    fs::write(&res_file, "1.1.1.1:53\n8.8.8.8:53\n").unwrap();

    let imported = import_masterdns_files(&cfg_file, Some(&res_file)).expect("Import success");
    assert_eq!(imported.domain, "custom.tunnel.example");
    assert_eq!(imported.encryption_method, 1);
    assert_eq!(imported.encryption_key, "my_imported_secret_key");
    assert_eq!(imported.resolvers.len(), 2);

    let (profile, secret) = imported.into_profile(Some("Imported Test Node".to_string()));
    assert_eq!(profile.name, "Imported Test Node");
    assert_eq!(profile.domain, "custom.tunnel.example");
    assert_eq!(secret, "my_imported_secret_key");
    assert!(!profile.id.is_empty());
    assert!(!profile.key_ref.is_empty());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_duplicate_resolver_handling() {
    let raw = vec![
        " 8.8.8.8:53 ".to_string(),
        "8.8.8.8:53".to_string(),
        "1.1.1.1".to_string(),    // Should normalize to 1.1.1.1:53
        "1.1.1.1:53".to_string(), // Duplicate after normalization
        "# Comment".to_string(),
        "".to_string(),
        "9.9.9.9:53".to_string(),
    ];

    let sanitized = MasterDnsProfile::sanitize_resolvers(&raw);
    assert_eq!(
        sanitized,
        vec![
            "8.8.8.8:53".to_string(),
            "1.1.1.1:53".to_string(),
            "9.9.9.9:53".to_string()
        ]
    );
}

#[test]
fn test_invalid_configuration_handling() {
    let temp_dir = std::env::temp_dir().join(format!("test_invalid_cfg_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    // 1. Missing DOMAIN
    let f1 = temp_dir.join("no_dom.toml");
    fs::write(&f1, "DATA_ENCRYPTION_METHOD = 1\n").unwrap();
    assert!(import_masterdns_files(&f1, None).is_err());

    // 2. Invalid Method (0)
    let f2 = temp_dir.join("zero_method.toml");
    fs::write(&f2, "DOMAIN = \"test.com\"\nDATA_ENCRYPTION_METHOD = 0\n").unwrap();
    assert!(import_masterdns_files(&f2, None).is_err());

    // 3. Domain with spaces or illegal characters
    let f3 = temp_dir.join("bad_domain.toml");
    fs::write(
        &f3,
        "DOMAIN = \"bad domain name\"\nDATA_ENCRYPTION_METHOD = 1\n",
    )
    .unwrap();
    assert!(import_masterdns_files(&f3, None).is_err());

    // 4. Missing resolvers
    let f4 = temp_dir.join("no_resolvers.toml");
    fs::write(&f4, "DOMAIN = \"valid.com\"\nDATA_ENCRYPTION_METHOD = 1\n").unwrap();
    assert!(import_masterdns_files(&f4, None).is_err());

    // 5. Invalid Resolver Address
    let f5 = temp_dir.join("bad_resolver.toml");
    let r5 = temp_dir.join("bad_resolvers.txt");
    fs::write(&f5, "DOMAIN = \"valid.com\"\nDATA_ENCRYPTION_METHOD = 1\n").unwrap();
    fs::write(&r5, "not_an_ip_address\n").unwrap();
    let err = import_masterdns_files(&f5, Some(&r5)).unwrap_err();
    assert!(err.contains("Invalid resolver address"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_secret_separation_from_serialized_metadata() {
    let profile = MasterDnsProfile::new(
        "Secure Profile",
        "secret-tunnel.local",
        1,
        vec!["1.1.1.1:53".into()],
    );

    let store = ProfileStore {
        version: 1,
        profiles: vec![profile.clone()],
        selected_profile_id: Some(profile.id.clone()),
        auto_connect: true,
    };

    let persistent = PersistentSettings {
        transport: DesktopTransport::Socks5,
        proxy_addr_str: "127.0.0.1:1080".into(),
        gateway_addr_str: "127.0.0.1:4040".into(),
        tcp_endpoint_str: "127.0.0.1:1080".into(),
        proxy_user: "audit_user".into(),
        timeout_secs: 30,
        direct_domains: vec![],
        direct_suffixes: vec![],
        profiles: store.profiles.clone(),
        selected_profile_id: store.selected_profile_id.clone(),
        vault_file_consent: false,
        tunnel_domain: profile.domain.clone(),
        tunnel_encryption_method: profile.encryption_method,
        tunnel_resolvers: profile.resolvers.clone(),
        tunnel_auto_connect: store.auto_connect,
    };

    let serialized_profile = serde_json::to_string(&profile).unwrap();
    let serialized_settings = serde_json::to_string(&persistent).unwrap();

    // Invariants: secrets must NEVER be present in metadata JSON
    assert!(!serialized_profile.contains("encryption_key"));
    assert!(!serialized_settings.contains("encryption_key"));
    assert!(!serialized_settings.contains("tunnel_encryption_key"));
    assert!(!serialized_settings.contains("proxy_pass"));
    assert!(!serialized_settings.contains("gateway_token"));

    // Secret references are retained
    assert!(serialized_profile.contains("key_ref"));
    assert!(serialized_settings.contains("key_ref"));
}

#[test]
fn test_secret_cleanup_on_profile_deletion() {
    let temp_dir = std::env::temp_dir().join(format!("test_sec_del_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let secrets_file = temp_dir.join(".vault.json");

    let vault = SecretVault::file_backed(secrets_file.clone()).unwrap();
    let mut store = ProfileStore::new();
    let p1 = MasterDnsProfile::new("Node 1", "node1.org", 1, vec!["1.1.1.1:53".into()]);
    let p2 = MasterDnsProfile::new("Node 2", "node2.org", 2, vec!["8.8.8.8:53".into()]);

    let id1 = p1.id.clone();
    let key_ref1 = p1.key_ref.clone();
    let key_ref2 = p2.key_ref.clone();

    vault
        .set_key(&key_ref1, "node1_secret_to_be_deleted")
        .unwrap();
    vault.set_key(&key_ref2, "node2_secret_to_stay").unwrap();

    store.add_profile(p1);
    store.add_profile(p2);

    assert_eq!(
        vault.get_key(&key_ref1).unwrap().as_deref(),
        Some("node1_secret_to_be_deleted")
    );
    assert_eq!(
        vault.get_key(&key_ref2).unwrap().as_deref(),
        Some("node2_secret_to_stay")
    );

    // Delete Profile 1 and its secret
    let removed = store.remove_profile(&id1).unwrap();
    vault.delete_key(&removed.key_ref).unwrap();

    // Verify secret is deleted from vault and disk
    assert_eq!(vault.get_key(&key_ref1).unwrap(), None);
    assert_eq!(
        vault.get_key(&key_ref2).unwrap().as_deref(),
        Some("node2_secret_to_stay")
    );

    let disk_content = fs::read_to_string(&secrets_file).unwrap();
    assert!(!disk_content.contains("node1_secret_to_be_deleted"));
    assert!(disk_content.contains("node2_secret_to_stay"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_profile_loading_and_selection_does_not_launch_runtime() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("test_no_spawn_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    // 1. Loading settings must not start any tunnel
    let mut settings = SettingsState::load_or_default();
    let controller = MasterDnsController::new(settings.build_masterdns_config());
    assert_eq!(
        controller.state(),
        TunnelState::Disconnected,
        "Tunnel controller must remain Disconnected when loading settings"
    );

    // 2. Adding profiles and selecting profiles must not start tunnel
    let p = MasterDnsProfile::new("Node Test", "test.vpn", 1, vec!["1.1.1.1:53".into()]);
    let pid = p.id.clone();
    settings.profile_store.add_profile(p);
    settings.profile_store.select_profile(&pid).unwrap();
    settings.sync_active_profile_fields();

    assert_eq!(
        controller.state(),
        TunnelState::Disconnected,
        "Tunnel controller must remain Disconnected when selecting a profile"
    );

    std::env::remove_var("XDG_CONFIG_HOME");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_auto_connect_remains_explicit_preference() {
    let _guard = ENV_LOCK.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("test_autoconnect_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    // Save with auto_connect = false
    let mut store_false = ProfileStore::new();
    store_false.auto_connect = false;
    let settings = SettingsState {
        tunnel_auto_connect: false,
        profile_store: store_false,
        ..Default::default()
    };
    settings.save_persistent().unwrap();

    // Reload
    let reloaded = SettingsState::load_or_default();
    assert!(!reloaded.tunnel_auto_connect);
    assert!(!reloaded.profile_store.auto_connect);

    // Save with auto_connect = true
    let mut settings2 = reloaded;
    settings2.tunnel_auto_connect = true;
    settings2.profile_store.auto_connect = true;
    settings2.save_persistent().unwrap();

    let reloaded2 = SettingsState::load_or_default();
    assert!(reloaded2.tunnel_auto_connect);
    assert!(reloaded2.profile_store.auto_connect);

    std::env::remove_var("XDG_CONFIG_HOME");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_profile_custom_port_and_timeout_roundtrip_and_duplicate() {
    let mut profile = MasterDnsProfile::new(
        "Custom Port Profile",
        "custom.node.org",
        2,
        vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()],
    );
    profile.custom_port = Some(1088);
    profile.timeout_secs = Some(45);

    // 1. JSON Roundtrip
    let serialized = serde_json::to_string(&profile).expect("Serialization failed");
    assert!(serialized.contains("\"custom_port\":1088"));
    assert!(serialized.contains("\"timeout_secs\":45"));

    let deserialized: MasterDnsProfile =
        serde_json::from_str(&serialized).expect("Deserialization failed");
    assert_eq!(deserialized.name, "Custom Port Profile");
    assert_eq!(deserialized.custom_port, Some(1088));
    assert_eq!(deserialized.timeout_secs, Some(45));
    assert_eq!(
        deserialized.resolvers,
        vec!["1.1.1.1:53".to_string(), "9.9.9.9:53".to_string()]
    );

    // 2. Duplication preserves port and timeout
    let dup = profile.duplicate("Duplicated Custom Node");
    assert_ne!(dup.id, profile.id);
    assert_ne!(dup.key_ref, profile.key_ref);
    assert_eq!(dup.name, "Duplicated Custom Node");
    assert_eq!(dup.custom_port, Some(1088));
    assert_eq!(dup.timeout_secs, Some(45));
    assert_eq!(dup.resolvers, profile.resolvers);
}

#[test]
fn test_resolver_sanitization_and_validation() {
    // 1. Sanitization: removes comments, empty lines, trims, appends :53 if missing, deduplicates while preserving order
    let raw = vec![
        "   ".to_string(),
        "# This is a comment".to_string(),
        "1.1.1.1".to_string(),
        "  1.1.1.1:53  ".to_string(),
        "9.9.9.9:5353".to_string(),
        "8.8.8.8".to_string(),
        "# Another comment".to_string(),
        "9.9.9.9:5353".to_string(),
    ];
    let sanitized = MasterDnsProfile::sanitize_resolvers(&raw);
    assert_eq!(
        sanitized,
        vec![
            "1.1.1.1:53".to_string(),
            "9.9.9.9:5353".to_string(),
            "8.8.8.8:53".to_string(),
        ]
    );

    // 2. Validation: fails on empty resolvers
    let empty_prof = MasterDnsProfile::new("Empty", "test.org", 1, vec![]);
    assert!(empty_prof.validate().is_err());

    // 3. Validation: fails on invalid socket/IP addresses
    let mut invalid_prof = MasterDnsProfile::new("Invalid Res", "test.org", 1, vec![]);
    invalid_prof.resolvers = vec!["not_an_ip:53".into()];
    assert!(invalid_prof.validate().is_err());

    // 4. Validation: passes on valid socket addresses
    let mut valid_prof = MasterDnsProfile::new("Valid Res", "test.org", 1, sanitized);
    valid_prof.custom_port = Some(1080);
    valid_prof.timeout_secs = Some(30);
    assert!(valid_prof.validate().is_ok());
}

#[test]
fn test_profile_store_update_and_advanced_fields_preservation() {
    let mut store = ProfileStore::new();
    let p = MasterDnsProfile::new("Node Alpha", "alpha.org", 1, vec!["1.1.1.1:53".into()]);
    let pid = p.id.clone();
    store.add_profile(p);

    // Mutate advanced and resolver fields in store
    if let Some(prof) = store.get_profile_mut(&pid) {
        prof.custom_port = Some(2080);
        prof.timeout_secs = Some(90);
        prof.resolvers = vec!["9.9.9.9:53".into(), "149.112.112.112:53".into()];
    }

    // Verify preservation
    let loaded = store.get_profile(&pid).unwrap();
    assert_eq!(loaded.custom_port, Some(2080));
    assert_eq!(loaded.timeout_secs, Some(90));
    assert_eq!(loaded.resolvers.len(), 2);
    assert_eq!(loaded.resolvers[0], "9.9.9.9:53");
}

#[test]
fn test_startup_timeout_input_validation() {
    // 1. Valid numbers within 5..=300
    assert_eq!(MasterDnsProfile::validate_timeout_input("5"), Ok(5));
    assert_eq!(MasterDnsProfile::validate_timeout_input("60"), Ok(60));
    assert_eq!(MasterDnsProfile::validate_timeout_input("300"), Ok(300));
    assert_eq!(MasterDnsProfile::validate_timeout_input("  45  "), Ok(45));

    // 2. Out of range values (< 5 or > 300)
    assert!(MasterDnsProfile::validate_timeout_input("0").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("4").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("301").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("9999").is_err());

    // 3. Non-numeric inputs
    assert!(MasterDnsProfile::validate_timeout_input("").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("   ").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("abc").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("-10").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("12.5").is_err());
    assert!(MasterDnsProfile::validate_timeout_input("60s").is_err());

    // 4. MasterDnsProfile::validate() checks timeout_secs range
    let mut prof = MasterDnsProfile::new("Node", "test.vpn", 1, vec!["1.1.1.1:53".into()]);
    prof.timeout_secs = Some(4);
    assert!(prof.validate().is_err());
    prof.timeout_secs = Some(301);
    assert!(prof.validate().is_err());
    prof.timeout_secs = Some(5);
    assert!(prof.validate().is_ok());
    prof.timeout_secs = Some(300);
    assert!(prof.validate().is_ok());
}

#[test]
fn test_startup_timeout_invalid_save_prevention_and_preservation() {
    let mut store = ProfileStore::new();
    let mut p = MasterDnsProfile::new("Node Timeout", "timeout.vpn", 1, vec!["1.1.1.1:53".into()]);
    p.timeout_secs = Some(45);
    let pid = p.id.clone();
    store.add_profile(p);

    // Simulate form submission logic:
    // When input is invalid, do NOT update prof.timeout_secs; preserve the last valid value!
    let invalid_inputs = vec!["abc", "999", "0", "-5", "4", "301", "   ", "60seconds"];
    for bad in invalid_inputs {
        if let Some(prof) = store.get_profile_mut(&pid) {
            if let Ok(valid) = MasterDnsProfile::validate_timeout_input(bad) {
                prof.timeout_secs = Some(valid);
            }
        }
        // Assert value was NOT overwritten and remained at 45
        assert_eq!(
            store.get_profile(&pid).unwrap().timeout_secs,
            Some(45),
            "Stored timeout must not be overwritten by invalid input '{bad}'"
        );
    }

    // When valid replacement is provided, it updates correctly
    if let Some(prof) = store.get_profile_mut(&pid) {
        if let Ok(valid) = MasterDnsProfile::validate_timeout_input("120") {
            prof.timeout_secs = Some(valid);
        }
    }
    assert_eq!(
        store.get_profile(&pid).unwrap().timeout_secs,
        Some(120),
        "Stored timeout must update to 120"
    );
}
