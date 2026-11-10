pub mod config;
pub mod importer;
pub mod manifest;
pub mod sanitizer;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub use config::RuntimeEnvironment;
pub use importer::{import_masterdns_config, import_masterdns_files, ImportedMasterDnsConfig};
pub use manifest::{locate_masterdns_binary, validate_masterdns_binary};
pub use sanitizer::{LogSanitizer, TunnelMilestone};

use crate::profile::MasterDnsProfile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Starting {
        profile_id: String,
        profile_name: String,
    },
    ResolverTesting {
        profile_id: String,
        profile_name: String,
        completed: usize,
        total: usize,
    },
    SessionInitializing {
        profile_id: String,
        profile_name: String,
        session_id: Option<u64>,
    },
    Socks5Ready {
        profile_id: String,
        profile_name: String,
        endpoint: SocketAddr,
        session_id: Option<u64>,
    },
    Connected {
        profile_id: String,
        profile_name: String,
        endpoint: SocketAddr,
        session_id: Option<u64>,
    },
    Reconnecting {
        profile_id: String,
        profile_name: String,
        attempt: usize,
        max_attempts: usize,
    },
    Stopping {
        profile_id: String,
        profile_name: String,
    },
    Failed(String),
}

impl TunnelState {
    pub fn display_label(&self) -> String {
        match self {
            Self::Disconnected => "Disconnected".to_string(),
            Self::Starting { profile_name, .. } => format!("Starting ({profile_name})..."),
            Self::ResolverTesting {
                profile_name,
                completed,
                total,
                ..
            } => {
                format!("Testing Resolvers ({completed}/{total}) [{profile_name}]")
            }
            Self::SessionInitializing {
                profile_name,
                session_id,
                ..
            } => {
                if let Some(id) = session_id {
                    format!("Session Active #{id} [{profile_name}]")
                } else {
                    format!("Initializing Session [{profile_name}]...")
                }
            }
            Self::Socks5Ready {
                profile_name,
                endpoint,
                ..
            } => format!("SOCKS5 Ready at {endpoint} [{profile_name}] (Data-plane Unverified)"),
            Self::Connected {
                profile_name,
                endpoint,
                ..
            } => format!("Connected to {profile_name} ({endpoint})"),
            Self::Reconnecting {
                profile_name,
                attempt,
                max_attempts,
                ..
            } => format!("Reconnecting {profile_name} ({attempt}/{max_attempts})..."),
            Self::Stopping { profile_name, .. } => format!("Disconnecting {profile_name}..."),
            Self::Failed(err) => format!("Tunnel Error: {err}"),
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. } | Self::Socks5Ready { .. })
    }

    pub fn endpoint(&self) -> Option<SocketAddr> {
        match self {
            Self::Connected { endpoint, .. } | Self::Socks5Ready { endpoint, .. } => {
                Some(*endpoint)
            }
            _ => None,
        }
    }

    pub fn connected_profile_id(&self) -> Option<&str> {
        match self {
            Self::Starting { profile_id, .. }
            | Self::ResolverTesting { profile_id, .. }
            | Self::SessionInitializing { profile_id, .. }
            | Self::Socks5Ready { profile_id, .. }
            | Self::Connected { profile_id, .. }
            | Self::Reconnecting { profile_id, .. }
            | Self::Stopping { profile_id, .. } => Some(profile_id.as_str()),
            Self::Disconnected | Self::Failed(_) => None,
        }
    }

    pub fn connected_profile_name(&self) -> Option<&str> {
        match self {
            Self::Starting { profile_name, .. }
            | Self::ResolverTesting { profile_name, .. }
            | Self::SessionInitializing { profile_name, .. }
            | Self::Socks5Ready { profile_name, .. }
            | Self::Connected { profile_name, .. }
            | Self::Reconnecting { profile_name, .. }
            | Self::Stopping { profile_name, .. } => Some(profile_name.as_str()),
            Self::Disconnected | Self::Failed(_) => None,
        }
    }
}

/// A frozen runtime snapshot of a profile's configuration at the moment connection was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedProfileSnapshot {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub encryption_method: u8,
    pub resolvers: Vec<String>,
    pub custom_port: Option<u16>,
    pub endpoint: SocketAddr,
    pub session_id: Option<u64>,
    pub connected_at: Instant,
    pub data_plane_verified: bool,
}

/// Canonical UI state derived for a profile given stable IDs and runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileUiState {
    pub is_selected: bool,
    pub is_runtime_profile: bool,
    pub is_fully_connected: bool,
    pub is_listener_ready_unverified: bool,
    pub should_show_runtime_edit_warning: bool,
    pub badge_text: String,
    pub warning_text: Option<String>,
}

impl ProfileUiState {
    /// Canonical derivation of UI state for a profile.
    /// Never compares names; strictly uses stable IDs and verified data plane status.
    pub fn derive(
        profile_id: &str,
        selected_profile_id: Option<&str>,
        runtime_snapshot: Option<&ConnectedProfileSnapshot>,
        tunnel_state: &TunnelState,
    ) -> Self {
        let is_selected = selected_profile_id
            .map(|s| s == profile_id)
            .unwrap_or(false);

        // A profile is the active runtime profile if either:
        // 1. The connected snapshot references this profile ID.
        // 2. The tunnel_state actively references this profile ID.
        let is_snapshot_match = runtime_snapshot
            .map(|s| s.id == profile_id)
            .unwrap_or(false);
        let is_state_match = tunnel_state
            .connected_profile_id()
            .map(|id| id == profile_id)
            .unwrap_or(false);
        let is_runtime_profile = is_snapshot_match || is_state_match;

        // Fully connected requires:
        // 1. Matches active runtime profile
        // 2. State is TunnelState::Connected
        // 3. Runtime snapshot confirms data_plane_verified == true
        let is_fully_connected = is_runtime_profile
            && match tunnel_state {
                TunnelState::Connected {
                    profile_id: pid, ..
                } => {
                    pid == profile_id
                        && runtime_snapshot
                            .map(|s| s.id == profile_id && s.data_plane_verified)
                            .unwrap_or(false)
                }
                _ => false,
            };

        // Listener ready unverified requires:
        // 1. Matches active runtime profile
        // 2. NOT fully connected
        // 3. State is Socks5Ready OR (Connected but data_plane_verified == false)
        let is_listener_ready_unverified = is_runtime_profile
            && !is_fully_connected
            && match tunnel_state {
                TunnelState::Socks5Ready {
                    profile_id: pid, ..
                } => pid == profile_id,
                TunnelState::Connected {
                    profile_id: pid, ..
                } => {
                    pid == profile_id
                        && runtime_snapshot
                            .map(|s| s.id == profile_id && !s.data_plane_verified)
                            .unwrap_or(true)
                }
                _ => false,
            };

        // Edit warning: shown ONLY when viewing/editing the active runtime profile
        // while the runtime is active (either fully connected or listener-ready).
        let should_show_runtime_edit_warning =
            is_runtime_profile && (is_fully_connected || is_listener_ready_unverified);

        let warning_text = if is_fully_connected {
            Some("⚠️ Notice: This profile is currently connected. Edits will apply on next reconnect.".to_string())
        } else if is_listener_ready_unverified {
            Some("⚠️ Notice: SOCKS5 listener is running with this profile's configuration. Edits will apply on next reconnect.".to_string())
        } else {
            None
        };

        let status_badge = if is_fully_connected {
            "[Connected]"
        } else if is_listener_ready_unverified {
            "[Listener Ready]"
        } else {
            ""
        };

        let badge_text = match (is_selected, !status_badge.is_empty()) {
            (true, true) => format!("★ [Selected] {status_badge} "),
            (true, false) => "★ [Selected] ".to_string(),
            (false, true) => format!("   {status_badge} "),
            (false, false) => "   ".to_string(),
        };

        Self {
            is_selected,
            is_runtime_profile,
            is_fully_connected,
            is_listener_ready_unverified,
            should_show_runtime_edit_warning,
            badge_text,
            warning_text,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MasterDnsConfig {
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub binary_path: Option<PathBuf>,
    pub domain: String,
    pub encryption_method: u8,
    pub encryption_key: String,
    pub resolvers: Vec<String>,
    pub custom_port: Option<u16>,
    pub startup_timeout: Duration,
    pub verify_pid_ownership: bool,
    pub probe_target: Option<String>,
    pub auto_recovery: bool,
    pub max_recovery_attempts: usize,
}

impl Default for MasterDnsConfig {
    fn default() -> Self {
        Self {
            profile_id: None,
            profile_name: None,
            binary_path: None,
            domain: String::new(),
            encryption_method: 1,
            encryption_key: String::new(),
            resolvers: Vec::new(),
            custom_port: None,
            startup_timeout: Duration::from_secs(60),
            verify_pid_ownership: true,
            probe_target: None,
            auto_recovery: true,
            max_recovery_attempts: 3,
        }
    }
}

pub struct MasterDnsController {
    config: Mutex<MasterDnsConfig>,
    state: Arc<Mutex<TunnelState>>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    connected_snapshot: Arc<Mutex<Option<ConnectedProfileSnapshot>>>,
    child_process: Mutex<Option<Child>>,
    runtime_env: Mutex<Option<RuntimeEnvironment>>,
    sanitizer: Arc<Mutex<LogSanitizer>>,
    recent_logs: Arc<Mutex<Vec<String>>>,
    shutdown_flag: Arc<AtomicBool>,
    is_recovering: Arc<AtomicBool>,
    active_session_id: Arc<Mutex<Option<u64>>>,
    _consecutive_probe_failures: Arc<Mutex<usize>>,
    lifecycle_lock: Arc<Mutex<()>>,
}

impl MasterDnsController {
    pub fn new(config: MasterDnsConfig) -> Self {
        let sanitizer = LogSanitizer::new(vec![config.encryption_key.clone()]);
        Self {
            config: Mutex::new(config),
            state: Arc::new(Mutex::new(TunnelState::Disconnected)),
            endpoint: Arc::new(Mutex::new(None)),
            connected_snapshot: Arc::new(Mutex::new(None)),
            child_process: Mutex::new(None),
            runtime_env: Mutex::new(None),
            sanitizer: Arc::new(Mutex::new(sanitizer)),
            recent_logs: Arc::new(Mutex::new(Vec::new())),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            is_recovering: Arc::new(AtomicBool::new(false)),
            active_session_id: Arc::new(Mutex::new(None)),
            _consecutive_probe_failures: Arc::new(Mutex::new(0)),
            lifecycle_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn state(&self) -> TunnelState {
        self.state.lock().unwrap().clone()
    }

    pub fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.lock().unwrap()
    }

    pub fn connected_profile(&self) -> Option<ConnectedProfileSnapshot> {
        self.connected_snapshot.lock().unwrap().clone()
    }

    pub fn update_config(&self, new_config: MasterDnsConfig) {
        let mut sanitizer = self.sanitizer.lock().unwrap();
        *sanitizer = LogSanitizer::new(vec![new_config.encryption_key.clone()]);
        *self.config.lock().unwrap() = new_config;
    }

    pub fn recent_logs(&self) -> Vec<String> {
        self.recent_logs.lock().unwrap().clone()
    }

    /// Connects using the currently configured profile settings.
    pub fn connect(&self) -> Result<SocketAddr, String> {
        let cfg = self.config.lock().unwrap().clone();
        self.connect_internal(&cfg)
    }

    /// Explicitly connects using the provided MasterDNS profile and secret key.
    pub fn connect_profile(
        &self,
        profile: &MasterDnsProfile,
        secret: &str,
    ) -> Result<SocketAddr, String> {
        profile.validate()?;
        if secret.trim().is_empty() {
            let err = format!(
                "Encryption key for profile '{}' is missing or empty. Please configure credentials.",
                profile.name
            );
            *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
            return Err(err);
        }

        let (existing_bin, existing_timeout, v_pid, probe_t, auto_rec, max_rec) = {
            let cur = self.config.lock().unwrap();
            (
                cur.binary_path.clone(),
                cur.startup_timeout,
                cur.verify_pid_ownership,
                cur.probe_target.clone(),
                cur.auto_recovery,
                cur.max_recovery_attempts,
            )
        };
        let startup_timeout = profile
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(existing_timeout);

        let cfg = MasterDnsConfig {
            profile_id: Some(profile.id.clone()),
            profile_name: Some(profile.name.clone()),
            binary_path: existing_bin,
            domain: profile.domain.clone(),
            encryption_method: profile.encryption_method,
            encryption_key: secret.to_string(),
            resolvers: profile.resolvers.clone(),
            custom_port: profile.custom_port,
            startup_timeout,
            verify_pid_ownership: v_pid,
            probe_target: probe_t,
            auto_recovery: auto_rec,
            max_recovery_attempts: max_rec,
        };

        self.update_config(cfg.clone());
        self.connect_internal(&cfg)
    }

    /// Safely switches to a new profile by stopping any active runtime, verifying process exit,
    /// invalidating transport endpoints, and connecting to the new profile.
    pub fn switch_profile(
        &self,
        target_profile: &MasterDnsProfile,
        secret: &str,
    ) -> Result<SocketAddr, String> {
        // Preflight validation before disconnecting active tunnel
        if let Err(e) = target_profile.validate() {
            *self.endpoint.lock().unwrap() = None;
            *self.connected_snapshot.lock().unwrap() = None;
            *self.state.lock().unwrap() =
                TunnelState::Failed(format!("Invalid profile configuration: {e}"));
            return Err(e);
        }
        if secret.trim().is_empty() {
            let err = format!(
                "Encryption key for profile '{}' is missing or empty. Please configure credentials.",
                target_profile.name
            );
            *self.endpoint.lock().unwrap() = None;
            *self.connected_snapshot.lock().unwrap() = None;
            *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
            return Err(err);
        }

        // 1. Gracefully disconnect current tunnel
        self.disconnect()?;

        // 2. Connect target profile
        match self.connect_profile(target_profile, secret) {
            Ok(ep) => Ok(ep),
            Err(e) => {
                *self.endpoint.lock().unwrap() = None;
                *self.connected_snapshot.lock().unwrap() = None;
                *self.state.lock().unwrap() = TunnelState::Failed(format!(
                    "Failed to switch to profile '{}': {e}",
                    target_profile.name
                ));
                Err(e)
            }
        }
    }

    fn connect_internal(&self, cfg: &MasterDnsConfig) -> Result<SocketAddr, String> {
        let _guard = self.lifecycle_lock.lock().unwrap();

        let prof_id = cfg
            .profile_id
            .clone()
            .unwrap_or_else(|| "default".to_string());

        if let Some(current_id) = self.state().connected_profile_id() {
            if current_id == prof_id {
                if let Some(ep) = self.endpoint() {
                    return Ok(ep);
                }
            }
        }

        self.connect_child_and_wait_locked(cfg)
    }

    fn cleanup_child_and_runtime_locked(&self) {
        if let Some(mut child) = self.child_process.lock().unwrap().take() {
            #[cfg(unix)]
            {
                let pid = child.id() as i32;
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                let start = Instant::now();
                let mut exited = false;
                while start.elapsed() < Duration::from_millis(1500) {
                    if let Ok(Some(_)) = child.try_wait() {
                        exited = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                if !exited {
                    let _ = child.kill();
                }
            }

            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }

            let _ = child.wait();
        }

        if let Some(runtime) = self.runtime_env.lock().unwrap().take() {
            runtime.cleanup();
        }
    }

    fn connect_child_and_wait_locked(&self, cfg: &MasterDnsConfig) -> Result<SocketAddr, String> {
        let prof_id = cfg
            .profile_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let prof_name = cfg
            .profile_name
            .clone()
            .unwrap_or_else(|| "Default Profile".to_string());

        self.cleanup_child_and_runtime_locked();
        self.shutdown_flag.store(false, Ordering::SeqCst);
        *self.active_session_id.lock().unwrap() = None;

        if cfg.domain.trim().is_empty() {
            let err = "Tunnel domain is not configured".to_string();
            *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
            return Err(err);
        }
        if cfg.encryption_key.trim().is_empty() {
            let err = "Tunnel encryption key is missing or empty".to_string();
            *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
            return Err(err);
        }
        if cfg.resolvers.is_empty() {
            let err = "Resolver list is empty; add at least one resolver".to_string();
            *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
            return Err(err);
        }

        let port = match cfg.custom_port {
            Some(p) if p > 0 => {
                if TcpListener::bind(format!("127.0.0.1:{p}")).is_err() {
                    let err = format!("Custom port {p} is already in use by another process");
                    *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
                    return Err(err);
                }
                p
            }
            _ => find_free_loopback_port_with_retries(5)
                .map_err(|e| format!("Failed to find free loopback port: {e}"))?,
        };
        let assigned_endpoint = SocketAddr::from(([127, 0, 0, 1], port));

        let bin_path = match cfg.binary_path {
            Some(ref p) if p.is_file() => p.clone(),
            _ => locate_masterdns_binary()?,
        };
        validate_masterdns_binary(&bin_path)?;

        *self.state.lock().unwrap() = TunnelState::Starting {
            profile_id: prof_id.clone(),
            profile_name: prof_name.clone(),
        };

        let runtime = RuntimeEnvironment::create(
            None,
            port,
            &cfg.domain,
            cfg.encryption_method,
            &cfg.encryption_key,
            &cfg.resolvers,
        )?;

        let mut child = Command::new(&bin_path)
            .args([
                "-config",
                runtime
                    .config_path()
                    .to_str()
                    .unwrap_or("client_config.toml"),
                "-resolvers",
                runtime
                    .resolvers_path()
                    .to_str()
                    .unwrap_or("client_resolvers.txt"),
            ])
            .current_dir(runtime.dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to launch MasterDNS child process: {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(b"\n");
            let _ = stdin.flush();
        }

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let stdout_handle = {
            let monitor = StreamMonitor {
                profile_id: prof_id.clone(),
                profile_name: prof_name.clone(),
                state: Arc::clone(&self.state),
                active_session_id: Arc::clone(&self.active_session_id),
                sanitizer: Arc::clone(&self.sanitizer),
                logs: Arc::clone(&self.recent_logs),
                shutdown_flag: Arc::clone(&self.shutdown_flag),
            };
            thread::spawn(move || process_stream(Box::new(stdout), monitor))
        };

        let stderr_handle = {
            let monitor = StreamMonitor {
                profile_id: prof_id.clone(),
                profile_name: prof_name.clone(),
                state: Arc::clone(&self.state),
                active_session_id: Arc::clone(&self.active_session_id),
                sanitizer: Arc::clone(&self.sanitizer),
                logs: Arc::clone(&self.recent_logs),
                shutdown_flag: Arc::clone(&self.shutdown_flag),
            };
            thread::spawn(move || process_stream(Box::new(stderr), monitor))
        };
        let _ = (stdout_handle, stderr_handle);

        let child_pid = child.id();
        *self.child_process.lock().unwrap() = Some(child);
        *self.runtime_env.lock().unwrap() = Some(runtime);

        let start = Instant::now();
        let timeout = cfg.startup_timeout;
        let mut verified = false;

        while start.elapsed() < timeout {
            if self.shutdown_flag.load(Ordering::SeqCst) {
                let _ = self.disconnect_locked();
                return Err("Connection cancelled by user".into());
            }

            if let Some(ref mut proc) = *self.child_process.lock().unwrap() {
                if let Ok(Some(status)) = proc.try_wait() {
                    let err = format!("MasterDNS exited prematurely with status: {status}");
                    *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
                    let _ = self.disconnect_locked();
                    return Err(err);
                }
            }

            if let Ok(mut stream) =
                TcpStream::connect_timeout(&assigned_endpoint, Duration::from_millis(500))
            {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                if stream.write_all(b"\x05\x01\x00").is_ok() {
                    let mut resp = [0u8; 2];
                    if stream.read_exact(&mut resp).is_ok() && resp == [0x05, 0x00] {
                        verified = true;
                        break;
                    }
                }
            }

            thread::sleep(Duration::from_millis(250));
        }

        if !verified {
            let err = format!(
                "Timed out after {}s waiting for MasterDNS SOCKS5 listener at {assigned_endpoint}",
                timeout.as_secs()
            );
            *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
            let _ = self.disconnect_locked();
            return Err(err);
        }

        // Verify SOCKS5 listener belongs to the child process PID
        if cfg.verify_pid_ownership && !verify_listener_pid_ownership(child_pid, port) {
            let err = format!(
                "Security Violation: SOCKS5 listener port {port} does not belong to child process PID {child_pid}"
            );
            *self.state.lock().unwrap() = TunnelState::Failed(err.clone());
            let _ = self.disconnect_locked();
            return Err(err);
        }

        *self.endpoint.lock().unwrap() = Some(assigned_endpoint);
        let sess_id = *self.active_session_id.lock().unwrap();

        // End-to-end data plane probe (domain addressing, zero local DNS resolution)
        let mut data_plane_verified = false;
        if let Some(ref target) = cfg.probe_target {
            if let Some((host, port_s)) = target.split_once(':') {
                if let Ok(p) = port_s.parse::<u16>() {
                    if probe_socks5_data_plane(assigned_endpoint, host, p, Duration::from_secs(3))
                        .is_ok()
                    {
                        data_plane_verified = true;
                    }
                }
            }
        }

        if data_plane_verified {
            *self.state.lock().unwrap() = TunnelState::Connected {
                profile_id: prof_id.clone(),
                profile_name: prof_name.clone(),
                endpoint: assigned_endpoint,
                session_id: sess_id,
            };
        } else {
            *self.state.lock().unwrap() = TunnelState::Socks5Ready {
                profile_id: prof_id.clone(),
                profile_name: prof_name.clone(),
                endpoint: assigned_endpoint,
                session_id: sess_id,
            };
        }

        *self.connected_snapshot.lock().unwrap() = Some(ConnectedProfileSnapshot {
            id: prof_id,
            name: prof_name,
            domain: cfg.domain.clone(),
            encryption_method: cfg.encryption_method,
            resolvers: cfg.resolvers.clone(),
            custom_port: cfg.custom_port,
            endpoint: assigned_endpoint,
            session_id: sess_id,
            connected_at: Instant::now(),
            data_plane_verified,
        });

        Ok(assigned_endpoint)
    }

    /// Gracefully stops only the child process managed by this controller and cleans up temporary files.
    pub fn disconnect(&self) -> Result<(), String> {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.is_recovering.store(false, Ordering::SeqCst);
        let _guard = self.lifecycle_lock.lock().unwrap();
        self.disconnect_locked()
    }

    fn disconnect_locked(&self) -> Result<(), String> {
        let (p_id, p_name) = match self.state() {
            TunnelState::Disconnected => return Ok(()),
            TunnelState::Failed(_) => (String::new(), String::new()),
            ref s => (
                s.connected_profile_id().unwrap_or("").to_string(),
                s.connected_profile_name().unwrap_or("").to_string(),
            ),
        };

        if !p_id.is_empty() {
            *self.state.lock().unwrap() = TunnelState::Stopping {
                profile_id: p_id,
                profile_name: p_name,
            };
        }

        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.is_recovering.store(false, Ordering::SeqCst);
        self.cleanup_child_and_runtime_locked();

        *self.connected_snapshot.lock().unwrap() = None;
        *self.endpoint.lock().unwrap() = None;
        *self.state.lock().unwrap() = TunnelState::Disconnected;
        Ok(())
    }

    pub fn reconnect(&self) -> Result<SocketAddr, String> {
        self.disconnect()?;
        self.connect()
    }

    pub fn is_healthy(&self) -> bool {
        if let Some(ref mut child) = *self.child_process.lock().unwrap() {
            matches!(child.try_wait(), Ok(None))
        } else {
            false
        }
    }

    pub fn trigger_recovery(&self, reason: &str) {
        if self.shutdown_flag.load(Ordering::SeqCst) {
            return;
        }
        if self
            .is_recovering
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let cfg = self.config.lock().unwrap().clone();
        if !cfg.auto_recovery {
            *self.state.lock().unwrap() = TunnelState::Failed(reason.to_string());
            self.is_recovering.store(false, Ordering::SeqCst);
            return;
        }

        let max_attempts = cfg.max_recovery_attempts.max(1);
        let prof_id = cfg.profile_id.clone().unwrap_or_else(|| "default".into());
        let prof_name = cfg
            .profile_name
            .clone()
            .unwrap_or_else(|| "Default Profile".into());

        for attempt in 1..=max_attempts {
            if self.shutdown_flag.load(Ordering::SeqCst) {
                self.is_recovering.store(false, Ordering::SeqCst);
                return;
            }

            *self.state.lock().unwrap() = TunnelState::Reconnecting {
                profile_id: prof_id.clone(),
                profile_name: prof_name.clone(),
                attempt,
                max_attempts,
            };

            thread::sleep(Duration::from_millis(50 * (1 << (attempt - 1))));

            if self.shutdown_flag.load(Ordering::SeqCst) {
                self.is_recovering.store(false, Ordering::SeqCst);
                return;
            }

            let connect_res = {
                let _guard = self.lifecycle_lock.lock().unwrap();
                if self.shutdown_flag.load(Ordering::SeqCst) {
                    self.is_recovering.store(false, Ordering::SeqCst);
                    return;
                }
                self.connect_child_and_wait_locked(&cfg)
            };

            if connect_res.is_ok() {
                self.is_recovering.store(false, Ordering::SeqCst);
                return;
            }
        }

        *self.state.lock().unwrap() = TunnelState::Failed(format!(
            "Session recovery exhausted after {max_attempts} attempts: {reason}"
        ));
        *self.endpoint.lock().unwrap() = None;
        *self.connected_snapshot.lock().unwrap() = None;
        self.is_recovering.store(false, Ordering::SeqCst);
    }

    pub fn check_health_and_recover(&self) {
        if self.shutdown_flag.load(Ordering::SeqCst) || self.is_recovering.load(Ordering::SeqCst) {
            return;
        }
        let is_active = self.state().is_connected();
        if !is_active {
            return;
        }

        let child_dead = if let Some(ref mut child) = *self.child_process.lock().unwrap() {
            matches!(child.try_wait(), Ok(Some(_)) | Err(_))
        } else {
            true
        };

        if child_dead {
            self.trigger_recovery("MasterDNS child process exited unexpectedly");
        }
    }

    #[doc(hidden)]
    pub fn set_mock_connected_for_screenshot(
        &self,
        profile_id: &str,
        profile_name: &str,
        port: u16,
    ) {
        let ep = SocketAddr::from(([127, 0, 0, 1], port));
        *self.endpoint.lock().unwrap() = Some(ep);
        *self.state.lock().unwrap() = TunnelState::Connected {
            profile_id: profile_id.to_string(),
            profile_name: profile_name.to_string(),
            endpoint: ep,
            session_id: Some(1042),
        };
        *self.connected_snapshot.lock().unwrap() = Some(ConnectedProfileSnapshot {
            id: profile_id.to_string(),
            name: profile_name.to_string(),
            domain: "masterdns.example.com".to_string(),
            encryption_method: 1,
            resolvers: vec!["1.1.1.1:53".to_string()],
            custom_port: Some(port),
            endpoint: ep,
            session_id: Some(1042),
            connected_at: Instant::now(),
            data_plane_verified: true,
        });
    }

    #[doc(hidden)]
    pub fn set_mock_socks5_ready_for_screenshot(
        &self,
        profile_id: &str,
        profile_name: &str,
        port: u16,
    ) {
        let ep = SocketAddr::from(([127, 0, 0, 1], port));
        *self.endpoint.lock().unwrap() = Some(ep);
        *self.state.lock().unwrap() = TunnelState::Socks5Ready {
            profile_id: profile_id.to_string(),
            profile_name: profile_name.to_string(),
            endpoint: ep,
            session_id: Some(1042),
        };
        *self.connected_snapshot.lock().unwrap() = Some(ConnectedProfileSnapshot {
            id: profile_id.to_string(),
            name: profile_name.to_string(),
            domain: "masterdns.example.com".to_string(),
            encryption_method: 1,
            resolvers: vec!["1.1.1.1:53".to_string()],
            custom_port: Some(port),
            endpoint: ep,
            session_id: Some(1042),
            connected_at: Instant::now(),
            data_plane_verified: false,
        });
    }

    #[doc(hidden)]
    pub fn set_mock_failed_for_screenshot(&self, message: &str) {
        *self.endpoint.lock().unwrap() = None;
        *self.state.lock().unwrap() = TunnelState::Failed(message.to_string());
        *self.connected_snapshot.lock().unwrap() = None;
    }
}

impl Drop for MasterDnsController {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

pub fn find_free_loopback_port() -> Result<u16, std::io::Error> {
    find_free_loopback_port_with_retries(5)
}

pub fn find_free_loopback_port_with_retries(retries: usize) -> Result<u16, std::io::Error> {
    let mut last_err = None;
    for _ in 0..retries {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                let port = listener.local_addr()?.port();
                drop(listener);
                return Ok(port);
            }
            Err(e) => {
                last_err = Some(e);
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "Exhausted port retries",
        )
    }))
}

/// Verifies that the TCP listener port on loopback belongs to the given child process PID.
#[cfg(target_os = "linux")]
pub fn verify_listener_pid_ownership(pid: u32, port: u16) -> bool {
    let port_hex = format!("{:04X}", port);
    let mut inodes = Vec::new();
    if let Ok(contents) = std::fs::read_to_string("/proc/net/tcp") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let local = parts[1];
                let state = parts[3];
                if (local.starts_with("0100007F:") || local.starts_with("00000000:"))
                    && local.ends_with(&format!(":{}", port_hex))
                    && state == "0A"
                {
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        inodes.push(inode);
                    }
                }
            }
        }
    }
    if inodes.is_empty() {
        return false;
    }
    let fd_dir = format!("/proc/{pid}/fd");
    if let Ok(entries) = std::fs::read_dir(fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let s = target.to_string_lossy();
                for inode in &inodes {
                    if s == format!("socket:[{inode}]") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
pub fn verify_listener_pid_ownership(_pid: u32, _port: u16) -> bool {
    true
}

/// Probes the end-to-end data plane through SOCKS5 domain CONNECT without local DNS resolution.
pub fn probe_socks5_data_plane(
    socks_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&socks_addr, timeout)
        .map_err(|e| format!("SOCKS5 connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;

    // 1. SOCKS5 greeting handshake: [VER=5, NMETHODS=1, METHOD=0(NO_AUTH)]
    stream
        .write_all(b"\x05\x01\x00")
        .map_err(|e| format!("SOCKS5 greeting send failed: {e}"))?;
    let mut greet_resp = [0u8; 2];
    stream
        .read_exact(&mut greet_resp)
        .map_err(|e| format!("SOCKS5 greeting recv failed: {e}"))?;
    if greet_resp != [0x05, 0x00] {
        return Err(format!("SOCKS5 auth rejected: {greet_resp:?}"));
    }

    // 2. SOCKS5 CONNECT using domain addressing (RFC 1928, zero local DNS resolution)
    let mut req = Vec::with_capacity(7 + target_host.len());
    req.push(0x05); // VER
    req.push(0x01); // CMD: CONNECT
    req.push(0x00); // RSV
    req.push(0x03); // ATYP: DOMAINNAME
    req.push(target_host.len() as u8);
    req.extend_from_slice(target_host.as_bytes());
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xFF) as u8);

    stream
        .write_all(&req)
        .map_err(|e| format!("SOCKS5 CONNECT request failed: {e}"))?;

    let mut resp_header = [0u8; 4];
    stream
        .read_exact(&mut resp_header)
        .map_err(|e| format!("SOCKS5 CONNECT response failed: {e}"))?;
    if resp_header[0] != 0x05 || resp_header[1] != 0x00 {
        return Err(format!(
            "SOCKS5 CONNECT failed with status code: {}",
            resp_header[1]
        ));
    }

    // Consume remainder of SOCKS5 reply based on ATYP
    match resp_header[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
            let mut domain_and_port = vec![0u8; len_buf[0] as usize + 2];
            stream
                .read_exact(&mut domain_and_port)
                .map_err(|e| e.to_string())?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        _ => return Err(format!("Unknown ATYP: {}", resp_header[3])),
    }

    // 3. Send HTTP /health probe
    let probe_req = format!(
        "GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target_host
    );
    stream
        .write_all(probe_req.as_bytes())
        .map_err(|e| format!("HTTP probe send failed: {e}"))?;

    let mut resp_buf = [0u8; 12];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| format!("HTTP probe recv failed: {e}"))?;
    let resp_str = String::from_utf8_lossy(&resp_buf);
    if resp_str.starts_with("HTTP/1.") {
        Ok(())
    } else {
        Err(format!("Unexpected probe response: {resp_str}"))
    }
}

struct StreamMonitor {
    profile_id: String,
    profile_name: String,
    state: Arc<Mutex<TunnelState>>,
    active_session_id: Arc<Mutex<Option<u64>>>,
    sanitizer: Arc<Mutex<LogSanitizer>>,
    logs: Arc<Mutex<Vec<String>>>,
    shutdown_flag: Arc<AtomicBool>,
}

fn process_stream(reader: Box<dyn Read + Send>, monitor: StreamMonitor) {
    let buf = BufReader::new(reader);
    for line_res in buf.lines() {
        if monitor.shutdown_flag.load(Ordering::SeqCst) {
            break;
        }
        if let Ok(raw_line) = line_res {
            let sanitized = {
                let san = monitor.sanitizer.lock().unwrap();
                san.sanitize(&raw_line)
            };

            {
                let mut log_list = monitor.logs.lock().unwrap();
                log_list.push(sanitized);
                if log_list.len() > 200 {
                    log_list.remove(0);
                }
            }

            let milestone = {
                let san = monitor.sanitizer.lock().unwrap();
                san.parse_milestone(&raw_line)
            };

            match milestone {
                TunnelMilestone::ResolverTesting { completed, total } => {
                    let mut s = monitor.state.lock().unwrap();
                    if !s.is_connected() {
                        *s = TunnelState::ResolverTesting {
                            profile_id: monitor.profile_id.clone(),
                            profile_name: monitor.profile_name.clone(),
                            completed,
                            total,
                        };
                    }
                }
                TunnelMilestone::SessionInitialized { session_id } => {
                    *monitor.active_session_id.lock().unwrap() = Some(session_id);
                    let mut s = monitor.state.lock().unwrap();
                    if !s.is_connected() {
                        *s = TunnelState::SessionInitializing {
                            profile_id: monitor.profile_id.clone(),
                            profile_name: monitor.profile_name.clone(),
                            session_id: Some(session_id),
                        };
                    }
                }
                TunnelMilestone::SessionLost => {
                    *monitor.state.lock().unwrap() =
                        TunnelState::Failed("MasterDNS upstream session lost".into());
                }
                TunnelMilestone::MtuFailed => {
                    *monitor.state.lock().unwrap() =
                        TunnelState::Failed("MTU testing failed: all resolvers rejected".into());
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_free_loopback_port() {
        let port = find_free_loopback_port().expect("Failed to find free port");
        assert!(port > 0);
    }

    #[test]
    fn test_tunnel_state_labels_and_helpers() {
        let disconnected = TunnelState::Disconnected;
        assert_eq!(disconnected.display_label(), "Disconnected");
        assert!(!disconnected.is_connected());
        assert_eq!(disconnected.endpoint(), None);
        assert_eq!(disconnected.connected_profile_id(), None);
        assert_eq!(disconnected.connected_profile_name(), None);

        let starting = TunnelState::Starting {
            profile_id: "p1".into(),
            profile_name: "Profile One".into(),
        };
        assert_eq!(starting.display_label(), "Starting (Profile One)...");
        assert!(!starting.is_connected());
        assert_eq!(starting.connected_profile_id(), Some("p1"));
        assert_eq!(starting.connected_profile_name(), Some("Profile One"));

        let testing = TunnelState::ResolverTesting {
            profile_id: "p1".into(),
            profile_name: "Profile One".into(),
            completed: 3,
            total: 10,
        };
        assert_eq!(
            testing.display_label(),
            "Testing Resolvers (3/10) [Profile One]"
        );
        assert!(!testing.is_connected());

        let ep: SocketAddr = "127.0.0.1:40123".parse().unwrap();
        let ready = TunnelState::Socks5Ready {
            profile_id: "p1".into(),
            profile_name: "Profile One".into(),
            endpoint: ep,
            session_id: Some(999),
        };
        assert!(ready.is_connected());
        assert_eq!(ready.endpoint(), Some(ep));
        assert_eq!(ready.connected_profile_id(), Some("p1"));
        assert_eq!(ready.connected_profile_name(), Some("Profile One"));
        assert_eq!(
            ready.display_label(),
            "SOCKS5 Ready at 127.0.0.1:40123 [Profile One] (Data-plane Unverified)"
        );

        let connected = TunnelState::Connected {
            profile_id: "p1".into(),
            profile_name: "Profile One".into(),
            endpoint: ep,
            session_id: Some(999),
        };
        assert!(connected.is_connected());
        assert_eq!(connected.endpoint(), Some(ep));
        assert_eq!(connected.connected_profile_id(), Some("p1"));
        assert_eq!(connected.connected_profile_name(), Some("Profile One"));
        assert_eq!(
            connected.display_label(),
            "Connected to Profile One (127.0.0.1:40123)"
        );

        let stopping = TunnelState::Stopping {
            profile_id: "p1".into(),
            profile_name: "Profile One".into(),
        };
        assert_eq!(stopping.display_label(), "Disconnecting Profile One...");
        assert!(!stopping.is_connected());

        let failed = TunnelState::Failed("Connection refused".into());
        assert_eq!(failed.display_label(), "Tunnel Error: Connection refused");
        assert!(!failed.is_connected());
        assert_eq!(failed.connected_profile_id(), None);
    }

    #[test]
    fn test_connected_profile_snapshot() {
        let ep: SocketAddr = "127.0.0.1:40123".parse().unwrap();
        let snap = ConnectedProfileSnapshot {
            id: "prof_123".into(),
            name: "Primary Tunnel".into(),
            domain: "tunnel.example.com".into(),
            encryption_method: 1,
            resolvers: vec!["1.1.1.1:53".into()],
            custom_port: Some(40123),
            endpoint: ep,
            session_id: Some(42),
            connected_at: Instant::now(),
            data_plane_verified: true,
        };
        assert_eq!(snap.id, "prof_123");
        assert_eq!(snap.name, "Primary Tunnel");
        assert_eq!(snap.endpoint, ep);
        assert_eq!(snap.session_id, Some(42));
        assert!(snap.data_plane_verified);
    }
}
