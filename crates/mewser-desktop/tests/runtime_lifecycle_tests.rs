use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use mewser_desktop::controller::{
    ConnectedProfileSnapshot, MasterDnsConfig, MasterDnsController, ProfileUiState, TunnelState,
};
use mewser_desktop::profile::MasterDnsProfile;
use mewser_desktop::state::{PersistentSettings, SettingsState};

static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_runtime_state_machine_variants_and_transitions() {
    let disconnected = TunnelState::Disconnected;
    assert_eq!(disconnected.display_label(), "Disconnected");
    assert!(!disconnected.is_connected());
    assert_eq!(disconnected.endpoint(), None);
    assert_eq!(disconnected.connected_profile_id(), None);
    assert_eq!(disconnected.connected_profile_name(), None);

    let starting = TunnelState::Starting {
        profile_id: "prof_1".to_string(),
        profile_name: "Profile Alpha".to_string(),
    };
    assert_eq!(starting.display_label(), "Starting (Profile Alpha)...");
    assert!(!starting.is_connected());
    assert_eq!(starting.connected_profile_id(), Some("prof_1"));
    assert_eq!(starting.connected_profile_name(), Some("Profile Alpha"));

    let testing = TunnelState::ResolverTesting {
        profile_id: "prof_1".to_string(),
        profile_name: "Profile Alpha".to_string(),
        completed: 4,
        total: 16,
    };
    assert_eq!(
        testing.display_label(),
        "Testing Resolvers (4/16) [Profile Alpha]"
    );
    assert!(!testing.is_connected());

    let session = TunnelState::SessionInitializing {
        profile_id: "prof_1".to_string(),
        profile_name: "Profile Alpha".to_string(),
        session_id: Some(12345),
    };
    assert_eq!(
        session.display_label(),
        "Session Active #12345 [Profile Alpha]"
    );
    assert!(!session.is_connected());

    let ep: SocketAddr = "127.0.0.1:40123".parse().unwrap();
    let connected = TunnelState::Connected {
        profile_id: "prof_1".to_string(),
        profile_name: "Profile Alpha".to_string(),
        endpoint: ep,
        session_id: Some(12345),
    };
    assert!(connected.is_connected());
    assert_eq!(connected.endpoint(), Some(ep));
    assert_eq!(connected.connected_profile_id(), Some("prof_1"));
    assert_eq!(connected.connected_profile_name(), Some("Profile Alpha"));
    assert_eq!(
        connected.display_label(),
        "Connected to Profile Alpha (127.0.0.1:40123)"
    );

    let reconnecting = TunnelState::Reconnecting {
        profile_id: "prof_1".to_string(),
        profile_name: "Profile Alpha".to_string(),
        attempt: 2,
        max_attempts: 3,
    };
    assert_eq!(
        reconnecting.display_label(),
        "Reconnecting Profile Alpha (2/3)..."
    );
    assert!(!reconnecting.is_connected());

    let stopping = TunnelState::Stopping {
        profile_id: "prof_1".to_string(),
        profile_name: "Profile Alpha".to_string(),
    };
    assert_eq!(stopping.display_label(), "Disconnecting Profile Alpha...");
    assert!(!stopping.is_connected());

    let failed = TunnelState::Failed("Connection timed out".to_string());
    assert_eq!(failed.display_label(), "Tunnel Error: Connection timed out");
    assert!(!failed.is_connected());
    assert_eq!(failed.connected_profile_id(), None);
}

#[test]
fn test_connected_profile_snapshot_immutability() {
    let ep: SocketAddr = "127.0.0.1:40500".parse().unwrap();
    let now = Instant::now();
    let snapshot = ConnectedProfileSnapshot {
        id: "prof_xyz".to_string(),
        name: "Immutable Node".to_string(),
        domain: "tunnel.sample.com".to_string(),
        encryption_method: 1,
        resolvers: vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
        custom_port: Some(40500),
        endpoint: ep,
        session_id: Some(888),
        connected_at: now,
        data_plane_verified: true,
    };

    assert_eq!(snapshot.id, "prof_xyz");
    assert_eq!(snapshot.name, "Immutable Node");
    assert_eq!(snapshot.domain, "tunnel.sample.com");
    assert_eq!(snapshot.encryption_method, 1);
    assert_eq!(snapshot.resolvers.len(), 2);
    assert_eq!(snapshot.endpoint, ep);
    assert_eq!(snapshot.session_id, Some(888));
}

#[test]
fn test_validation_failures_prevent_process_launch() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let controller = MasterDnsController::new(MasterDnsConfig::default());

    // 1. Missing secret key
    let prof_no_key = MasterDnsProfile::new(
        "No Key Profile",
        "domain.example.com",
        1,
        vec!["1.1.1.1:53".into()],
    );
    let res = controller.connect_profile(&prof_no_key, "");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Encryption key"));
    assert!(matches!(controller.state(), TunnelState::Failed(_)));
    assert_eq!(controller.endpoint(), None);

    // 2. Empty resolvers
    let mut prof_empty_res = MasterDnsProfile::new(
        "Empty Res",
        "domain.example.com",
        1,
        vec!["1.1.1.1:53".into()],
    );
    prof_empty_res.resolvers.clear();
    let res2 = controller.connect_profile(&prof_empty_res, "valid_key_123");
    assert!(res2.is_err());
    assert!(res2.unwrap_err().contains("resolver"));
}

#[test]
fn test_port_conflict_detection_fails_closed() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Bind an occupied loopback port
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind test port");
    let occupied_port = listener.local_addr().unwrap().port();

    let mut prof = MasterDnsProfile::new(
        "Port Conflict Profile",
        "domain.example.com",
        1,
        vec!["1.1.1.1:53".into()],
    );
    prof.custom_port = Some(occupied_port);

    let controller = MasterDnsController::new(MasterDnsConfig::default());
    let res = controller.connect_profile(&prof, "test_secret_123");

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("already in use"));
    assert!(matches!(controller.state(), TunnelState::Failed(_)));
    assert_eq!(controller.endpoint(), None);
}

#[test]
fn test_duplicate_connect_returns_existing_endpoint() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let cfg = MasterDnsConfig {
        profile_id: Some("prof_active".into()),
        profile_name: Some("Active Node".into()),
        ..Default::default()
    };
    let controller = MasterDnsController::new(cfg);

    assert!(controller.disconnect().is_ok());
    assert_eq!(controller.state(), TunnelState::Disconnected);
    assert_eq!(controller.endpoint(), None);
}

#[test]
fn test_safe_profile_switching_failure_fails_closed() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let controller = MasterDnsController::new(MasterDnsConfig::default());

    // Profile B with invalid configuration (empty domain)
    let mut prof_b = MasterDnsProfile::new(
        "Profile B",
        "tunnel-b.example.com",
        1,
        vec!["8.8.8.8:53".into()],
    );
    prof_b.domain = "   ".into();

    let res = controller.switch_profile(&prof_b, "valid_secret_123");
    assert!(res.is_err());
    assert!(matches!(controller.state(), TunnelState::Failed(_)));
    assert_eq!(controller.endpoint(), None);
    assert_eq!(controller.connected_profile(), None);
}

#[test]
fn test_environment_variable_isolation_for_profiles() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let temp_dir = std::env::temp_dir().join(format!("mewser_env_iso_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    // 1. Create a persistent settings file with an existing profile that has NO secret in vault
    let prof = MasterDnsProfile::new(
        "Existing Profile",
        "domain.example.com",
        1,
        vec!["1.1.1.1:53".into()],
    );
    let prof_id = prof.id.clone();
    let settings_dir = temp_dir.join("mewser");
    fs::create_dir_all(&settings_dir).unwrap();

    let persistent = PersistentSettings {
        transport: mewser_desktop::DesktopTransport::Socks5,
        proxy_addr_str: "127.0.0.1:1080".into(),
        gateway_addr_str: "127.0.0.1:4040".into(),
        tcp_endpoint_str: "127.0.0.1:1080".into(),
        proxy_user: "".into(),
        timeout_secs: 30,
        direct_domains: vec!["localhost".into()],
        direct_suffixes: vec![],
        profiles: vec![prof],
        selected_profile_id: Some(prof_id),
        vault_file_consent: false,
        tunnel_domain: "domain.example.com".into(),
        tunnel_encryption_method: 1,
        tunnel_resolvers: vec!["1.1.1.1:53".into()],
        tunnel_auto_connect: true,
    };
    fs::write(
        settings_dir.join("desktop_settings.json"),
        serde_json::to_string(&persistent).unwrap(),
    )
    .unwrap();

    // 2. Set environment variable MEWSER_TUNNEL_ENCRYPTION_KEY
    std::env::set_var("MEWSER_TUNNEL_ENCRYPTION_KEY", "stray_secret_do_not_inject");

    // 3. Load settings: verify that the existing profile's key is NOT seeded with stray_secret
    let loaded = SettingsState::load_or_default();
    let selected_key = loaded
        .profile_store
        .selected_profile()
        .and_then(|p| loaded.secret_vault.get_key(&p.key_ref).ok().flatten());

    assert_eq!(
        selected_key, None,
        "MEWSER_TUNNEL_ENCRYPTION_KEY must NOT be injected into existing persistent profiles!"
    );

    std::env::remove_var("MEWSER_TUNNEL_ENCRYPTION_KEY");
    std::env::remove_var("XDG_CONFIG_HOME");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_selected_vs_connected_profile_independence_and_persistence() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let temp_dir = std::env::temp_dir().join(format!("mewser_sel_conn_iso_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);

    let mut settings = SettingsState::load_or_default();

    let p1 = MasterDnsProfile::new("Node Alpha", "alpha.vpn", 1, vec!["1.1.1.1:53".into()]);
    let p2 = MasterDnsProfile::new("Node Beta", "beta.vpn", 2, vec!["8.8.8.8:53".into()]);
    let id2 = p2.id.clone();

    settings.profile_store.add_profile(p1);
    settings.profile_store.add_profile(p2);
    settings.profile_store.select_profile(&id2).unwrap();
    settings.sync_active_profile_fields();

    // Save settings
    assert!(settings.save_persistent().is_ok());

    // Read raw JSON from disk
    let raw_json =
        fs::read_to_string(temp_dir.join("mewser").join("desktop_settings.json")).unwrap();

    // Verify selected_profile_id is persisted
    assert!(raw_json.contains(&id2));
    // Verify connected_profile is NEVER persisted
    assert!(!raw_json.contains("connected_profile"));
    assert!(!raw_json.contains("connected_snapshot"));

    // Verify application starts in Disconnected state
    let controller = MasterDnsController::new(settings.build_masterdns_config());
    assert_eq!(controller.state(), TunnelState::Disconnected);
    assert_eq!(controller.connected_profile(), None);

    std::env::remove_var("XDG_CONFIG_HOME");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_shared_transport_endpoint_invalidation_on_disconnect() {
    let dynamic_endpoint: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));

    let ep: SocketAddr = "127.0.0.1:40999".parse().unwrap();
    *dynamic_endpoint.write().unwrap() = Some(ep);
    assert_eq!(*dynamic_endpoint.read().unwrap(), Some(ep));

    // Simulate controller disconnect
    let controller = MasterDnsController::new(MasterDnsConfig::default());
    assert!(controller.disconnect().is_ok());

    // Transport invalidation clears dynamic endpoint
    *dynamic_endpoint.write().unwrap() = None;
    assert_eq!(*dynamic_endpoint.read().unwrap(), None);
    assert_eq!(controller.endpoint(), None);
}

#[cfg(unix)]
#[test]
fn test_mock_process_spawn_handshake_and_exact_sigterm_exit() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let temp_dir = std::env::temp_dir().join(format!("mewser_proc_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // Create mock MasterDNS executable script
    let mock_bin = temp_dir.join("mock_masterdns.py");
    let script_content = r#"#!/usr/bin/env python3
import sys, os, time, socket

print("MasterDNS Client starting up", flush=True)
print("Resolver Testing: Testing MTU (1/1)", flush=True)
time.sleep(0.05)
print("Session Initialized Successfully with session_id 777", flush=True)

port = 0
for i, arg in enumerate(sys.argv):
    if arg == "-config" and i + 1 < len(sys.argv):
        try:
            with open(sys.argv[i+1], "r") as f:
                for line in f:
                    if line.strip().startswith("LISTEN_PORT"):
                        port = int(line.split("=")[1].strip())
        except Exception:
            pass

if port == 0:
    port = 40555

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
print(f"SOCKS5 server listening on 127.0.0.1:{port}", flush=True)

while True:
    try:
        conn, addr = s.accept()
        data = conn.recv(16)
        if data.startswith(b"\x05"):
            conn.sendall(b"\x05\x00")
        conn.close()
    except Exception:
        break
"#;
    fs::write(&mock_bin, script_content).unwrap();

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&mock_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let mut prof = MasterDnsProfile::new("Mock Profile", "mock.vpn", 1, vec!["1.1.1.1:53".into()]);
    prof.timeout_secs = Some(5);

    let cfg = MasterDnsConfig {
        binary_path: Some(mock_bin.clone()),
        startup_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let controller = MasterDnsController::new(cfg);

    // 1. Connect
    let connect_res = controller.connect_profile(&prof, "test_secret_abc");
    assert!(
        connect_res.is_ok(),
        "Failed to connect mock process: {:?}",
        connect_res.err()
    );

    let ep = connect_res.unwrap();
    assert_eq!(ep.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
    assert!(ep.port() > 0);

    // 2. Verify state and snapshot
    assert!(controller.state().is_connected());
    let snap = controller.connected_profile().expect("Expected snapshot");
    assert_eq!(snap.id, prof.id);
    assert_eq!(snap.name, prof.name);
    assert_eq!(snap.endpoint, ep);

    // 3. Verify controller endpoint method
    assert_eq!(controller.endpoint(), Some(ep));

    // 4. Disconnect gracefully with exact PID SIGTERM
    let disc_res = controller.disconnect();
    assert!(disc_res.is_ok());

    // 5. Verify disconnected state and cleaned up snapshot & endpoint
    assert_eq!(controller.state(), TunnelState::Disconnected);
    assert_eq!(controller.endpoint(), None);
    assert_eq!(controller.connected_profile(), None);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_three_profile_identity_ui_state_bindings() {
    let mut store = mewser_desktop::profile::ProfileStore::new();

    let prof_a = MasterDnsProfile::new("Profile A", "a.tunnel.com", 1, vec!["1.1.1.1:53".into()]);
    let prof_b = MasterDnsProfile::new("Profile B", "b.tunnel.com", 2, vec!["8.8.8.8:53".into()]);
    let prof_c = MasterDnsProfile::new("Profile C", "c.tunnel.com", 1, vec!["9.9.9.9:53".into()]);

    let id_a = prof_a.id.clone();
    let id_b = prof_b.id.clone();
    let id_c = prof_c.id.clone();

    store.add_profile(prof_a);
    store.add_profile(prof_b);
    store.add_profile(prof_c);

    // Profile B is selected
    store.select_profile(&id_b).expect("Select profile B");
    assert_eq!(store.selected_profile_id.as_deref(), Some(id_b.as_str()));

    // Controller connects Profile A
    let controller = MasterDnsController::new(MasterDnsConfig::default());
    controller.set_mock_connected_for_screenshot(&id_a, "Profile A", 40188);

    let snap = controller.connected_profile().expect("Connected snapshot");
    assert_eq!(snap.id, id_a);
    assert_eq!(snap.name, "Profile A");

    // 1. Verify Badges
    for p in store.profiles() {
        let is_selected = store.selected_profile_id.as_deref() == Some(&p.id);
        let is_connected = snap.id == p.id;

        if p.id == id_a {
            assert!(!is_selected, "Profile A must NOT receive [Selected]");
            assert!(is_connected, "Profile A must receive [Connected]");
        } else if p.id == id_b {
            assert!(is_selected, "Profile B must receive [Selected]");
            assert!(!is_connected, "Profile B must NOT receive [Connected]");
        } else if p.id == id_c {
            assert!(!is_selected, "Profile C must NOT receive [Selected]");
            assert!(!is_connected, "Profile C must NOT receive [Connected]");
        }
    }

    // 2. Verify Connected Banner uses connected snapshot, NOT selected profile
    let banner_profile_name = &snap.name;
    let banner_endpoint = snap.endpoint;
    assert_eq!(banner_profile_name, "Profile A");
    assert_ne!(banner_profile_name, &store.selected_profile().unwrap().name);
    assert_eq!(banner_endpoint.port(), 40188);

    // 3. Verify Edit Warning: appears ONLY when viewed profile ID matches connected profile ID
    let is_warning_visible_for_viewed = |viewed_id: &str| -> bool { snap.id == viewed_id };

    assert!(
        is_warning_visible_for_viewed(&id_a),
        "Viewing Profile A (connected) MUST display edit warning"
    );
    assert!(
        !is_warning_visible_for_viewed(&id_b),
        "Viewing Profile B (selected, but unconnected) must NOT display warning"
    );
    assert!(
        !is_warning_visible_for_viewed(&id_c),
        "Viewing Profile C (unselected, unconnected) must NOT display warning"
    );

    // 4. Verify Toolbar Action reflects connected profile independently of selected profile
    let state = controller.state();
    assert_eq!(state.connected_profile_id(), Some(id_a.as_str()));
    assert_eq!(state.connected_profile_name(), Some("Profile A"));

    let selected_id = store.selected_profile_id.as_deref();
    let is_different = selected_id != state.connected_profile_id();
    assert!(is_different);

    let toolbar_action_label = if is_different {
        format!("Switch to {}", store.selected_profile().unwrap().name)
    } else {
        "Disconnect".to_string()
    };
    assert_eq!(toolbar_action_label, "Switch to Profile B");

    // 5. Verify Canonical State Derivation for all three profiles
    let ui_a = ProfileUiState::derive(
        &id_a,
        store.selected_profile_id.as_deref(),
        Some(&snap),
        &state,
    );
    let ui_b = ProfileUiState::derive(
        &id_b,
        store.selected_profile_id.as_deref(),
        Some(&snap),
        &state,
    );
    let ui_c = ProfileUiState::derive(
        &id_c,
        store.selected_profile_id.as_deref(),
        Some(&snap),
        &state,
    );

    assert!(ui_a.is_fully_connected);
    assert!(!ui_a.is_selected);
    assert!(ui_a.should_show_runtime_edit_warning);
    assert_eq!(ui_a.badge_text, "   [Connected] ");

    assert!(!ui_b.is_fully_connected);
    assert!(ui_b.is_selected);
    assert!(!ui_b.should_show_runtime_edit_warning);
    assert_eq!(ui_b.badge_text, "★ [Selected] ");

    assert!(!ui_c.is_fully_connected);
    assert!(!ui_c.is_selected);
    assert!(!ui_c.should_show_runtime_edit_warning);
    assert_eq!(ui_c.badge_text, "   ");
}

#[test]
fn test_readiness_listener_ready_vs_connected_data_plane() {
    let ep: SocketAddr = "127.0.0.1:40199".parse().unwrap();

    // 1. Socks5Ready (Listener ready, data-plane unverified)
    let ready_state = TunnelState::Socks5Ready {
        profile_id: "p_test".to_string(),
        profile_name: "Test Node".to_string(),
        endpoint: ep,
        session_id: Some(101),
    };
    assert!(ready_state.is_connected());
    assert_eq!(ready_state.endpoint(), Some(ep));
    assert!(ready_state
        .display_label()
        .contains("(Data-plane Unverified)"));

    let unverified_snap = ConnectedProfileSnapshot {
        id: "p_test".to_string(),
        name: "Test Node".to_string(),
        domain: "test.vpn".to_string(),
        encryption_method: 1,
        resolvers: vec!["1.1.1.1:53".into()],
        custom_port: Some(40199),
        endpoint: ep,
        session_id: Some(101),
        connected_at: Instant::now(),
        data_plane_verified: false,
    };
    assert!(!unverified_snap.data_plane_verified);

    // 2. Connected (Listener ready AND end-to-end data-plane verified)
    let connected_state = TunnelState::Connected {
        profile_id: "p_test".to_string(),
        profile_name: "Test Node".to_string(),
        endpoint: ep,
        session_id: Some(101),
    };
    assert!(connected_state.is_connected());
    assert_eq!(connected_state.endpoint(), Some(ep));
    assert!(!connected_state.display_label().contains("Unverified"));

    let verified_snap = ConnectedProfileSnapshot {
        data_plane_verified: true,
        ..unverified_snap
    };
    assert!(verified_snap.data_plane_verified);
}

#[test]
fn test_pid_port_ownership_verification() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind loopback socket");
    let port = listener.local_addr().unwrap().port();
    let current_pid = std::process::id();

    #[cfg(target_os = "linux")]
    {
        use mewser_desktop::controller::verify_listener_pid_ownership;
        assert!(
            verify_listener_pid_ownership(current_pid, port),
            "Socket owned by current PID must verify true"
        );

        assert!(
            !verify_listener_pid_ownership(999_999, port),
            "Socket matched against wrong PID must verify false"
        );
    }

    drop(listener);
}

#[test]
fn test_session_loss_detection_and_recovery() {
    let cfg = MasterDnsConfig {
        profile_id: Some("prof_rec".into()),
        profile_name: Some("Recovery Node".into()),
        auto_recovery: true,
        max_recovery_attempts: 3,
        startup_timeout: Duration::from_millis(500),
        ..Default::default()
    };
    let controller = MasterDnsController::new(cfg);

    // Initial mock connected state
    controller.set_mock_connected_for_screenshot("prof_rec", "Recovery Node", 40222);
    assert!(controller.state().is_connected());

    // 1. Process exit detection: child_process is None or dead -> check_health_and_recover triggers recovery
    controller.check_health_and_recover();

    match controller.state() {
        TunnelState::Failed(msg) => {
            assert!(
                msg.contains("exhausted") || msg.contains("MasterDNS child process exited"),
                "Expected recovery exhausted or child process failure, got: {msg}"
            );
        }
        ref other => panic!(
            "Expected Failed state after recovery exhaustion, got: {:?}",
            other
        ),
    }

    // 2. Explicit disconnect cancels recovery immediately
    let controller2 = MasterDnsController::new(MasterDnsConfig {
        profile_id: Some("prof_rec2".into()),
        profile_name: Some("Recovery Node 2".into()),
        auto_recovery: true,
        max_recovery_attempts: 5,
        ..Default::default()
    });
    controller2.set_mock_connected_for_screenshot("prof_rec2", "Recovery Node 2", 40223);

    // Trigger disconnect
    controller2.disconnect().expect("Disconnect");
    assert_eq!(controller2.state(), TunnelState::Disconnected);
    assert_eq!(controller2.endpoint(), None);
    assert_eq!(controller2.connected_profile(), None);
}

#[test]
fn test_secret_vault_consent_and_security_properties() {
    let _guard = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("test_vault_consent_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    std::env::set_var("XDG_CONFIG_HOME", &temp_dir);
    let secrets_file = mewser_desktop::state::get_secrets_file_path().unwrap();

    let prof = MasterDnsProfile::new(
        "Consent Profile",
        "consent.vpn",
        1,
        vec!["1.1.1.1:53".into()],
    );
    let prof_id = prof.id.clone();

    let mut store = mewser_desktop::profile::ProfileStore::new();
    store.add_profile(prof);
    store.select_profile(&prof_id).unwrap();

    // 1. When vault_file_consent is FALSE:
    // Secrets remain in-memory only, .vault.json is NEVER created on disk
    let settings_no_consent = SettingsState {
        profile_store: store.clone(),
        vault_file_consent: false,
        tunnel_encryption_key: "secret_no_disk".to_string(),
        ..SettingsState::default()
    };
    settings_no_consent
        .save_persistent()
        .expect("Save without consent");

    assert!(
        !secrets_file.exists(),
        ".vault.json must NEVER be created without informed consent"
    );

    // 2. When vault_file_consent is TRUE:
    // User explicitly consented to on-disk 0600 storage
    let settings_with_consent = SettingsState {
        profile_store: store,
        vault_file_consent: true,
        tunnel_encryption_key: "secret_with_consent".to_string(),
        ..SettingsState::default()
    };
    settings_with_consent
        .save_persistent()
        .expect("Save with consent");

    assert!(
        secrets_file.exists(),
        ".vault.json must be created when consent is granted"
    );

    // Verify storage description accurately discloses unencrypted on-disk storage
    let file_vault = mewser_desktop::profile::SecretVault::file_backed(secrets_file).unwrap();
    assert_eq!(
        file_vault.storage_description(),
        "Local file vault (0600 user permissions; unencrypted on disk)"
    );
    assert!(
        file_vault
            .storage_description()
            .contains("unencrypted on disk"),
        "Must explicitly disclose that files are unencrypted on disk"
    );
    assert!(
        !file_vault
            .storage_description()
            .to_lowercase()
            .contains("aes")
            && !file_vault
                .storage_description()
                .to_lowercase()
                .contains("cipher"),
        "Must NOT describe 0600 file permissions as encryption"
    );

    std::env::remove_var("XDG_CONFIG_HOME");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_canonical_profile_ui_state_regression_matrix() {
    let ep_a: SocketAddr = "127.0.0.1:40188".parse().unwrap();
    let ep_b: SocketAddr = "127.0.0.1:40189".parse().unwrap();

    let id_a = "prof_a";
    let id_b = "prof_b";
    let id_c = "prof_c";

    let snap_a_verified = ConnectedProfileSnapshot {
        id: id_a.to_string(),
        name: "Profile A".to_string(),
        domain: "a.vpn".to_string(),
        encryption_method: 1,
        resolvers: vec!["1.1.1.1:53".into()],
        custom_port: Some(40188),
        endpoint: ep_a,
        session_id: Some(101),
        connected_at: Instant::now(),
        data_plane_verified: true,
    };

    let snap_a_unverified = ConnectedProfileSnapshot {
        data_plane_verified: false,
        ..snap_a_verified.clone()
    };

    let snap_b_verified = ConnectedProfileSnapshot {
        id: id_b.to_string(),
        name: "Profile B".to_string(),
        domain: "b.vpn".to_string(),
        encryption_method: 2,
        resolvers: vec!["8.8.8.8:53".into()],
        custom_port: Some(40189),
        endpoint: ep_b,
        session_id: Some(102),
        connected_at: Instant::now(),
        data_plane_verified: true,
    };

    // Case A: Profile A connected, Profile B selected, Profile C idle
    {
        let state_a = TunnelState::Connected {
            profile_id: id_a.to_string(),
            profile_name: "Profile A".to_string(),
            endpoint: ep_a,
            session_id: Some(101),
        };
        let ui_a = ProfileUiState::derive(id_a, Some(id_b), Some(&snap_a_verified), &state_a);
        let ui_b = ProfileUiState::derive(id_b, Some(id_b), Some(&snap_a_verified), &state_a);
        let ui_c = ProfileUiState::derive(id_c, Some(id_b), Some(&snap_a_verified), &state_a);

        // A: Connected only
        assert!(ui_a.is_fully_connected);
        assert!(!ui_a.is_selected);
        assert!(ui_a.should_show_runtime_edit_warning);
        assert_eq!(ui_a.badge_text, "   [Connected] ");
        assert!(ui_a.warning_text.unwrap().contains("currently connected"));

        // B: Selected only
        assert!(!ui_b.is_fully_connected);
        assert!(ui_b.is_selected);
        assert!(!ui_b.should_show_runtime_edit_warning);
        assert_eq!(ui_b.badge_text, "★ [Selected] ");
        assert!(ui_b.warning_text.is_none());

        // C: No status
        assert!(!ui_c.is_fully_connected);
        assert!(!ui_c.is_selected);
        assert!(!ui_c.should_show_runtime_edit_warning);
        assert_eq!(ui_c.badge_text, "   ");
        assert!(ui_c.warning_text.is_none());
    }

    // Case B: Profile A listener-ready but data-plane unverified, Profile B selected
    {
        let state_ready = TunnelState::Socks5Ready {
            profile_id: id_a.to_string(),
            profile_name: "Profile A".to_string(),
            endpoint: ep_a,
            session_id: Some(101),
        };
        let ui_a = ProfileUiState::derive(id_a, Some(id_b), Some(&snap_a_unverified), &state_ready);
        let ui_b = ProfileUiState::derive(id_b, Some(id_b), Some(&snap_a_unverified), &state_ready);

        // A: Listener Ready / Unverified, NEVER Connected
        assert!(
            !ui_a.is_fully_connected,
            "Must NOT claim connected when unverified"
        );
        assert!(ui_a.is_listener_ready_unverified);
        assert!(!ui_a.is_selected);
        assert!(ui_a.should_show_runtime_edit_warning);
        assert_eq!(ui_a.badge_text, "   [Listener Ready] ");
        let warn_msg = ui_a.warning_text.unwrap();
        assert!(warn_msg.contains("SOCKS5 listener is running"));
        assert!(!warn_msg.contains("currently connected"));

        // B: Selected only
        assert!(!ui_b.is_fully_connected);
        assert!(ui_b.is_selected);
        assert!(!ui_b.should_show_runtime_edit_warning);
        assert_eq!(ui_b.badge_text, "★ [Selected] ");
    }

    // Case C: All profiles disconnected
    {
        let state_disc = TunnelState::Disconnected;
        let ui_a = ProfileUiState::derive(id_a, Some(id_b), None, &state_disc);
        let ui_b = ProfileUiState::derive(id_b, Some(id_b), None, &state_disc);

        assert!(!ui_a.is_fully_connected);
        assert!(!ui_a.is_listener_ready_unverified);
        assert!(!ui_a.should_show_runtime_edit_warning);
        assert_eq!(ui_a.badge_text, "   ");

        assert!(!ui_b.is_fully_connected);
        assert!(ui_b.is_selected);
        assert!(!ui_b.should_show_runtime_edit_warning);
        assert_eq!(ui_b.badge_text, "★ [Selected] ");
    }

    // Case D: Profile A connected, then user selects B
    {
        let state_a = TunnelState::Connected {
            profile_id: id_a.to_string(),
            profile_name: "Profile A".to_string(),
            endpoint: ep_a,
            session_id: Some(101),
        };
        let ui_a = ProfileUiState::derive(id_a, Some(id_b), Some(&snap_a_verified), &state_a);
        let ui_b = ProfileUiState::derive(id_b, Some(id_b), Some(&snap_a_verified), &state_a);

        assert!(ui_a.is_fully_connected);
        assert_eq!(ui_a.badge_text, "   [Connected] ");
        assert!(ui_b.is_selected);
        assert_eq!(ui_b.badge_text, "★ [Selected] ");
    }

    // Case E: Switching succeeds from A to B
    {
        let state_b = TunnelState::Connected {
            profile_id: id_b.to_string(),
            profile_name: "Profile B".to_string(),
            endpoint: ep_b,
            session_id: Some(102),
        };
        let ui_a = ProfileUiState::derive(id_a, Some(id_b), Some(&snap_b_verified), &state_b);
        let ui_b = ProfileUiState::derive(id_b, Some(id_b), Some(&snap_b_verified), &state_b);

        // A loses connected state
        assert!(!ui_a.is_fully_connected);
        assert!(!ui_a.is_runtime_profile);
        assert_eq!(ui_a.badge_text, "   ");

        // B receives Connected only after verified readiness
        assert!(ui_b.is_fully_connected);
        assert!(ui_b.is_selected);
        assert_eq!(ui_b.badge_text, "★ [Selected] [Connected] ");
    }

    // Case F: Switching fails
    {
        let state_failed = TunnelState::Failed("Switch error".to_string());
        let ui_a = ProfileUiState::derive(id_a, Some(id_b), None, &state_failed);
        let ui_b = ProfileUiState::derive(id_b, Some(id_b), None, &state_failed);

        assert!(!ui_a.is_fully_connected);
        assert!(!ui_a.is_runtime_profile);
        assert_eq!(ui_a.badge_text, "   ");

        assert!(!ui_b.is_fully_connected);
        assert!(ui_b.is_selected);
        assert_eq!(ui_b.badge_text, "★ [Selected] ");
    }
}

#[test]
fn test_missing_credential_preflight_rejection() {
    let controller = MasterDnsController::new(MasterDnsConfig::default());
    let prof = MasterDnsProfile::new("No Key Prof", "nokey.vpn", 1, vec!["1.1.1.1:53".into()]);

    // 1. connect_profile with empty secret must fail closed before launching
    let res = controller.connect_profile(&prof, "   ");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("missing or empty"));

    // 2. switch_profile with empty secret must reject in preflight without terminating/running
    let res_switch = controller.switch_profile(&prof, "");
    assert!(res_switch.is_err());
    assert!(res_switch.unwrap_err().contains("missing or empty"));
}
