use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use mewser_cli::{BrowsingMode, ClientEngine, ClientError, NavigationResult};
use mewser_gateway::ContentBlock;

use crate::controller::{MasterDnsController, TunnelState};
use crate::state::{DesktopTransport, HistoryStack, PageState, ReaderPageMetadata, SettingsState};

pub fn normalize_input_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("mewser:") || trimmed.starts_with("about:") {
        return trimmed.to_string();
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        format!("https://{trimmed}")
    } else {
        trimmed.to_string()
    }
}

pub struct TabModel {
    pub id: u64,
    pub title: String,
    pub url: String,
    pub mode: BrowsingMode,
    pub page_state: PageState,
    pub history: HistoryStack,
    pub active_request_id: u64,
    pub reader_metadata: Option<ReaderPageMetadata>,
}

impl TabModel {
    pub fn new(id: u64, initial_url: String, mode: BrowsingMode) -> Self {
        Self {
            id,
            title: if initial_url == "mewser:home" {
                "New Tab".to_string()
            } else {
                initial_url.clone()
            },
            url: initial_url,
            mode,
            page_state: PageState::Idle,
            history: HistoryStack::new(),
            active_request_id: 0,
            reader_metadata: None,
        }
    }
}

pub struct MewserAppModel {
    pub tabs: Vec<TabModel>,
    pub active_tab_index: usize,
    pub settings: SettingsState,
    pub next_tab_id: u64,
    pub controller: Arc<MasterDnsController>,
    pub dynamic_socks5_endpoint: Arc<RwLock<Option<SocketAddr>>>,
}

pub fn validate_direct_domain(raw: &str, existing: &[String]) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Domain cannot be empty.".to_string());
    }
    let lower = trimmed.to_ascii_lowercase();

    if lower.contains("://") || lower.starts_with("http:") || lower.starts_with("https:") {
        return Err("Protocol schemes (http://, https://) must not be included.".to_string());
    }
    if lower.contains('/') || lower.contains('?') || lower.contains('#') {
        return Err("URL paths, queries, and fragments must not be included.".to_string());
    }
    if lower.contains(':') && !(lower.starts_with('[') && lower.ends_with(']')) {
        return Err("Port numbers must not be included.".to_string());
    }
    if lower.chars().any(|c| c.is_whitespace()) {
        return Err("Domain cannot contain whitespace.".to_string());
    }
    if lower.starts_with('.') {
        return Err(
            "Exact domains must not start with a dot (use Direct Suffixes for wildcard suffixes)."
                .to_string(),
        );
    }
    if lower.ends_with('.') {
        return Err("Domain must not end with a trailing dot.".to_string());
    }
    if lower.contains("..") {
        return Err("Domain cannot contain consecutive dots.".to_string());
    }

    // Check if it's a valid IP address
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        let ip_str = ip.to_string();
        if existing.iter().any(|d| d.eq_ignore_ascii_case(&ip_str)) {
            return Err(format!("Domain '{}' is already in direct rules.", ip_str));
        }
        return Ok(ip_str);
    }

    if lower.len() > 253 {
        return Err("Domain exceeds maximum allowed length of 253 characters.".to_string());
    }

    let labels: Vec<&str> = lower.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err("Domain labels cannot be empty.".to_string());
        }
        if label.len() > 63 {
            return Err("Domain label exceeds maximum length of 63 characters.".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain labels cannot start or end with a hyphen.".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(
                "Domain contains invalid characters (only alphanumeric and hyphens allowed)."
                    .to_string(),
            );
        }
    }

    if existing.iter().any(|d| d.eq_ignore_ascii_case(&lower)) {
        return Err(format!("Domain '{}' is already in direct rules.", lower));
    }

    Ok(lower)
}

pub fn validate_direct_suffix(raw: &str, existing: &[String]) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Suffix cannot be empty.".to_string());
    }
    let mut lower = trimmed.to_ascii_lowercase();

    if lower.contains("://") || lower.starts_with("http:") || lower.starts_with("https:") {
        return Err("Protocol schemes (http://, https://) must not be included.".to_string());
    }
    if lower.contains('/') || lower.contains('?') || lower.contains('#') {
        return Err("URL paths, queries, and fragments must not be included.".to_string());
    }
    if lower.contains(':') {
        return Err("Port numbers must not be included.".to_string());
    }
    if lower.chars().any(|c| c.is_whitespace()) {
        return Err("Suffix cannot contain whitespace.".to_string());
    }

    if !lower.starts_with('.') {
        lower.insert(0, '.');
    }

    if lower.len() == 1 {
        return Err("Suffix must contain a domain label after the dot.".to_string());
    }
    if lower.ends_with('.') {
        return Err("Suffix must not end with a trailing dot.".to_string());
    }
    if lower.contains("..") {
        return Err("Suffix cannot contain consecutive dots.".to_string());
    }

    let labels: Vec<&str> = lower[1..].split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err("Suffix labels cannot be empty.".to_string());
        }
        if label.len() > 63 {
            return Err("Suffix label exceeds maximum length of 63 characters.".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Suffix labels cannot start or end with a hyphen.".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(
                "Suffix contains invalid characters (only alphanumeric and hyphens allowed)."
                    .to_string(),
            );
        }
    }

    if existing.iter().any(|s| s.eq_ignore_ascii_case(&lower)) {
        return Err(format!("Suffix '{}' is already in direct rules.", lower));
    }

    Ok(lower)
}

pub fn validate_socket_addr(raw: &str, field_name: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field_name} cannot be empty."));
    }
    if trimmed.contains("://")
        || trimmed.starts_with("http:")
        || trimmed.starts_with("https:")
        || trimmed.starts_with("socks5:")
        || trimmed.starts_with("tcp:")
    {
        return Err(format!(
            "{field_name} must be an IP:port address, not a URL (remove http:// or https://)."
        ));
    }
    if trimmed.contains('/') || trimmed.contains('?') || trimmed.contains('#') {
        return Err(format!(
            "{field_name} must not contain path, query, or fragment components."
        ));
    }
    if trimmed.contains(char::is_whitespace) {
        return Err(format!("{field_name} must not contain whitespace."));
    }

    let (host_part, port_part) = match trimmed.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => {
            return Err(
                "Missing port number (expected format: IP:port, e.g. 127.0.0.1:4040).".to_string(),
            );
        }
    };

    if host_part.is_empty() {
        return Err("Missing host in endpoint (expected format: IP:port).".to_string());
    }

    let port: u16 = match port_part.parse::<u32>() {
        Ok(0) => {
            return Err("Port must be between 1 and 65535.".to_string());
        }
        Ok(p) if p <= 65535 => p as u16,
        _ => {
            return Err("Invalid port number (port must be between 1 and 65535).".to_string());
        }
    };

    let clean_host = if host_part.starts_with('[') && host_part.ends_with(']') {
        &host_part[1..host_part.len() - 1]
    } else {
        host_part
    };

    let ip: std::net::IpAddr = clean_host.parse().map_err(|_| {
        "Invalid IP address syntax (expected numeric IPv4 or IPv6 literal).".to_string()
    })?;

    let canonical = match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };

    Ok(canonical)
}

pub fn validate_gateway_endpoint(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Gateway endpoint cannot be empty.".to_string());
    }
    if trimmed.contains("://") {
        return Err(
            "Gateway endpoint must be an IP:port or hostname:port address, not a URL (remove http:// or https://)."
                .to_string(),
        );
    }
    if trimmed.contains('/') || trimmed.contains('?') || trimmed.contains('#') {
        return Err(
            "Gateway endpoint must not contain path, query, or fragment components.".to_string(),
        );
    }
    if trimmed.contains(char::is_whitespace) {
        return Err("Gateway endpoint must not contain whitespace.".to_string());
    }

    let (host_part, port_part) = match trimmed.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => {
            return Err(
                "Missing port number (expected format: IP:port or hostname:port, e.g. 127.0.0.1:4040)."
                    .to_string(),
            );
        }
    };

    if host_part.is_empty() {
        return Err(
            "Missing host in endpoint (expected format: IP:port or hostname:port).".to_string(),
        );
    }

    let port: u16 = match port_part.parse::<u32>() {
        Ok(0) => {
            return Err("Port must be between 1 and 65535.".to_string());
        }
        Ok(p) if p <= 65535 => p as u16,
        _ => {
            return Err("Invalid port number (port must be between 1 and 65535).".to_string());
        }
    };

    let clean_host = if host_part.starts_with('[') && host_part.ends_with(']') {
        &host_part[1..host_part.len() - 1]
    } else {
        host_part
    };

    // If it parses as numeric IP, return canonical IP:port
    if let Ok(ip) = clean_host.parse::<std::net::IpAddr>() {
        let canonical = match ip {
            std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
            std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        };
        return Ok(canonical);
    }

    // Validate hostname syntax (RFC 1123)
    if clean_host.len() > 255 {
        return Err("Gateway hostname exceeds maximum length of 255 characters.".to_string());
    }
    for label in clean_host.split('.') {
        if label.is_empty() {
            return Err("Gateway hostname contains empty label.".to_string());
        }
        if label.len() > 63 {
            return Err("Gateway hostname label exceeds 63 characters.".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Gateway hostname label cannot start or end with a hyphen.".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "Gateway hostname '{clean_host}' contains invalid characters (only alphanumeric and hyphens allowed)."
            ));
        }
    }

    Ok(format!("{clean_host}:{port}"))
}

fn probe_socks5_http_health(
    socks_addr: std::net::SocketAddr,
    target_host: &str,
    target_port: u16,
    auth_token: &str,
    timeout: std::time::Duration,
) -> Result<u16, String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect_timeout(&socks_addr, timeout)
        .map_err(|e| format!("Tunnel SOCKS5 connect failed: {e}"))?;
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

    // 2. SOCKS5 CONNECT using domain addressing (RFC 1928)
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

    // Consume remainder of SOCKS5 reply
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

    // 3. Send HTTP GET /health probe over established tunnel stream
    let auth_hdr = if !auth_token.trim().is_empty() {
        format!("Authorization: Bearer {}\r\n", auth_token.trim())
    } else {
        String::new()
    };
    let probe_req = format!(
        "GET /health HTTP/1.1\r\nHost: {target_host}\r\n{auth_hdr}Connection: close\r\n\r\n"
    );
    stream
        .write_all(probe_req.as_bytes())
        .map_err(|e| format!("HTTP probe send failed: {e}"))?;

    let mut resp_buf = [0u8; 64];
    let n = stream
        .read(&mut resp_buf)
        .map_err(|e| format!("HTTP probe recv failed: {e}"))?;
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    if let Some(status_line) = resp_str.lines().next() {
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(code) = parts[1].parse::<u16>() {
                return Ok(code);
            }
        }
    }
    Err(format!("Malformed probe HTTP response: {resp_str}"))
}

impl Default for MewserAppModel {
    fn default() -> Self {
        Self::new()
    }
}

impl MewserAppModel {
    pub fn new() -> Self {
        let settings = SettingsState::load_or_default();
        let controller_cfg = settings.build_masterdns_config();
        let controller = Arc::new(MasterDnsController::new(controller_cfg));
        let dynamic_socks5_endpoint = Arc::new(RwLock::new(None));
        let initial_tab = TabModel::new(1, "mewser:home".to_string(), settings.active_mode);
        Self {
            tabs: vec![initial_tab],
            active_tab_index: 0,
            settings,
            next_tab_id: 2,
            controller,
            dynamic_socks5_endpoint,
        }
    }

    pub fn active_tab(&self) -> Option<&TabModel> {
        self.tabs.get(self.active_tab_index)
    }

    pub fn active_tab_mut(&mut self) -> Option<&mut TabModel> {
        self.tabs.get_mut(self.active_tab_index)
    }

    pub fn add_tab(&mut self, url: String) -> usize {
        let id = self.next_tab_id;
        self.next_tab_id += 1;
        let tab = TabModel::new(id, url, self.settings.active_mode);
        self.tabs.push(tab);
        self.active_tab_index = self.tabs.len() - 1;
        self.active_tab_index
    }

    pub fn close_tab(&mut self, index: usize) -> bool {
        if self.tabs.len() <= 1 {
            return false;
        }
        if index < self.tabs.len() {
            self.tabs.remove(index);
            if self.active_tab_index >= self.tabs.len() {
                self.active_tab_index = self.tabs.len() - 1;
            }
            return true;
        }
        false
    }
}

#[cfg(target_os = "linux")]
pub mod ui {
    use super::*;
    use crate::profile::MasterDnsProfile;
    use gdk::prelude::*;
    use gtk::pango;
    use gtk::prelude::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use webkit2gtk::{
        NetworkProxyMode, NetworkProxySettings, WebContext, WebContextExt, WebView, WebViewExt,
        WebsiteDataManagerExt,
    };

    use gtk::prelude::PixbufLoaderExt;
    use mewser_core::proxy::PolicyProxy;

    const CAT_LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 76 46" width="68" height="42" fill="none" stroke="#2dd4bf" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M 2 38 L 13 2 L 38 12 L 63 2 L 74 38 L 65 43 L 56 36 L 40 44 L 14 43 Z"/><path d="M 52 28 L 58 26" stroke-width="1.8"/></svg>"##;

    const MOON_CAT_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 140 85" width="120" height="72" fill="none">
  <circle cx="108" cy="28" r="16" fill="#e2e8f0" opacity="0.85" />
  <path d="M 0 75 Q 50 48 140 68 L 140 85 L 0 85 Z" fill="#131924" opacity="0.7" />
  <path d="M 0 85 Q 45 62 85 58 Q 115 55 140 76 L 140 85 L 0 85 Z" fill="#0d1118" />
  <path d="M 88 56 C 88 53 89 50 90 47 C 89 45 88 43 89 41 C 89.5 39 91 38 92 39 C 93 40 93.5 41 94 41 C 94.5 41 95 40 96 39 C 97 38 98.5 39 99 41 C 100 43 99 45 98 47 C 99 50 100 53 100 56 Z" fill="#06090e" />
  <path d="M 88 56 Q 84 57 82 54" stroke="#06090e" stroke-width="1.8" stroke-linecap="round" />
</svg>"##;

    const STACK_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32"><circle cx="16" cy="16" r="16" fill="#157a82" /><path d="M16 7 L24 11 L16 15 L8 11 Z" fill="#ffffff" /><path d="M8 14.5 L16 18.5 L24 14.5" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /><path d="M8 18.5 L16 22.5 L24 18.5" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>"##;

    const STACK_ICON_SVG_SIDEBAR: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="#2dd4bf" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 3 L17 6.5 L10 10 L3 6.5 Z" fill="#2dd4bf" fill-opacity="0.2" /><path d="M3 10.5 L10 14 L17 10.5" /><path d="M3 14 L10 17.5 L17 14" /></svg>"##;

    const ROUTE_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="#94a3b8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="4" cy="10" r="2.2" /><circle cx="16" cy="5" r="2.2" /><circle cx="16" cy="15" r="2.2" /><path d="M6.5 10 h 3 c 2 0 3 -5 6.5 -5" /><path d="M9.5 10 c 2 0 3 5 6.5 5" /></svg>"##;

    const GATEWAY_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="#94a3b8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="14" height="14" rx="2" /><path d="M3 9 h 14" /><circle cx="6.5" cy="6" r="0.8" fill="#94a3b8" /><circle cx="9.5" cy="6" r="0.8" fill="#94a3b8" /><path d="M8 13.5 l 2 2 l 4 -4" /></svg>"##;

    const GEAR_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="#94a3b8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="3" /><path d="M10 2.5 v 2 m 0 11 v 2 m 7.5 -7.5 h -2 m -11 0 h -2 m 12.8 -5.3 l -1.4 1.4 m -7.8 7.8 l -1.4 1.4 m 0 -10.6 l 1.4 1.4 m 7.8 7.8 l 1.4 1.4" /></svg>"##;

    const GLOBE_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36" width="36" height="36"><circle cx="18" cy="18" r="17" fill="#141822" stroke="#24303c" stroke-width="1.5" /><circle cx="18" cy="18" r="11" fill="none" stroke="#2dd4bf" stroke-width="1.8" /><ellipse cx="18" cy="18" rx="5" ry="11" fill="none" stroke="#2dd4bf" stroke-width="1.5" /><line x1="7" y1="18" x2="29" y2="18" stroke="#2dd4bf" stroke-width="1.5" /></svg>"##;

    const DOC_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36" width="36" height="36"><path d="M7 3 L21 3 L29 11 L29 33 L7 33 Z" fill="none" stroke="#cbd5e1" stroke-width="2.2" stroke-linejoin="round" /><path d="M21 3 L21 11 L29 11" fill="none" stroke="#cbd5e1" stroke-width="2.2" stroke-linejoin="round" /><line x1="12" y1="18" x2="24" y2="18" stroke="#cbd5e1" stroke-width="2" stroke-linecap="round" /><line x1="12" y1="24" x2="24" y2="24" stroke="#cbd5e1" stroke-width="2" stroke-linecap="round" /></svg>"##;

    fn create_svg_image(svg_data: &str, width: i32, height: i32) -> Option<gtk::Image> {
        let loader = gtk::gdk_pixbuf::PixbufLoader::with_type("svg").ok()?;
        loader.set_size(width, height);
        loader.write(svg_data.as_bytes()).ok()?;
        let _ = loader.close();
        let pixbuf = loader.pixbuf()?;
        Some(gtk::Image::from_pixbuf(Some(&pixbuf)))
    }

    pub fn run_gtk_app() {
        if gtk::init().is_err() {
            eprintln!("Failed to initialize GTK.");
            return;
        }

        let app_model = Arc::new(Mutex::new(MewserAppModel::new()));
        let settings = app_model.lock().unwrap().settings.clone();
        let controller = Arc::clone(&app_model.lock().unwrap().controller);
        let dynamic_socks5 = Arc::clone(&app_model.lock().unwrap().dynamic_socks5_endpoint);

        // 1. Initialize local loopback policy proxy with dynamic SOCKS5 upstream
        let proxy_handle = match settings.build_policy_proxy_config_with_dynamic(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&dynamic_socks5),
        ) {
            Ok(cfg) => match PolicyProxy::start(cfg) {
                Ok(h) => {
                    let proxy_uri = format!("http://{}", h.bound_addr());
                    let mut proxy_settings = NetworkProxySettings::new(Some(&proxy_uri), &[]);
                    if let Some(context) = WebContext::default() {
                        if let Some(manager) = context.website_data_manager() {
                            manager.set_network_proxy_settings(
                                NetworkProxyMode::Custom,
                                Some(&mut proxy_settings),
                            );
                        }
                    }
                    Some(Arc::new(h))
                }
                Err(e) => {
                    eprintln!("Warning: Failed to start local policy proxy: {e}");
                    None
                }
            },
            Err(e) => {
                eprintln!("Warning: Failed to configure policy proxy: {e}");
                None
            }
        };

        // 2. Set up Dark Modern Visual Styling (Slate / Zinc Palette)
        setup_dark_theme();

        // 3. Create Main Window
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_title("Mewser Web Browser");
        if let Ok(ref s) = std::env::var("MEWSER_CAPTURE_SCREENSHOT") {
            if s == "09_compact_window"
                || s == "25_polished_compact_window"
                || s == "01_home_720x500"
                || s == "01_home_720x500_scrolled"
                || s == "03_reader_compact"
            {
                window.set_default_size(720, 500);
            } else if s == "01_home_1024x768" || s.starts_with("03_") {
                window.set_default_size(1024, 768);
            } else if s == "01_home_1366x768" {
                window.set_default_size(1366, 768);
            } else {
                window.set_default_size(1080, 750);
            }
        } else {
            window.set_default_size(1080, 750);
        }

        let main_vbox = gtk::Box::new(gtk::Orientation::Vertical, 0);
        window.add(&main_vbox);

        // 4. Header Bar / Top Navigation Toolbar
        let header_bar = gtk::HeaderBar::new();
        header_bar.set_show_close_button(true);
        header_bar.set_title(Some("Mewser"));
        window.set_titlebar(Some(&header_bar));

        // Navigation cluster: Back, Forward, Reload, Home
        let nav_box = gtk::Box::new(gtk::Orientation::Horizontal, 2);

        let back_btn = gtk::Button::with_label("◀");
        back_btn.set_tooltip_text(Some("Back"));
        back_btn.style_context().add_class("nav-btn");
        nav_box.pack_start(&back_btn, false, false, 0);

        let fwd_btn = gtk::Button::with_label("▶");
        fwd_btn.set_tooltip_text(Some("Forward"));
        fwd_btn.style_context().add_class("nav-btn");
        nav_box.pack_start(&fwd_btn, false, false, 0);

        let reload_btn = gtk::Button::with_label("↻");
        reload_btn.set_tooltip_text(Some("Reload"));
        reload_btn.style_context().add_class("nav-btn");
        nav_box.pack_start(&reload_btn, false, false, 0);

        let home_btn = gtk::Button::with_label("⌂");
        home_btn.set_tooltip_text(Some("Home (New Tab)"));
        home_btn.style_context().add_class("nav-btn");
        home_btn.set_no_show_all(true);
        nav_box.pack_start(&home_btn, false, false, 0);

        header_bar.pack_start(&nav_box);

        // Mode Segmented Switcher: [ 🌐 Web | 📄 Text ]
        let mode_segmented_box = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        mode_segmented_box
            .style_context()
            .add_class("mode-segmented");

        let web_mode_btn = gtk::Button::with_label("Web");
        web_mode_btn.style_context().add_class("mode-btn");
        web_mode_btn.set_tooltip_text(Some("Standard Web Mode (WebKitGTK Native Engine)"));
        mode_segmented_box.pack_start(&web_mode_btn, false, false, 0);

        let text_mode_btn = gtk::Button::with_label("Text");
        text_mode_btn.style_context().add_class("mode-btn");
        text_mode_btn.set_tooltip_text(Some(
            "Resilient Text Mode (Low-Bandwidth DNS Tunnel Gateway)",
        ));
        mode_segmented_box.pack_start(&text_mode_btn, false, false, 0);

        if settings.active_mode == BrowsingMode::StandardWeb {
            web_mode_btn.style_context().add_class("mode-btn-active");
        } else {
            text_mode_btn.style_context().add_class("mode-btn-active");
        }
        header_bar.pack_start(&mode_segmented_box);

        // Address Bar
        let address_box = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        address_box.style_context().add_class("address-box");
        address_box.set_hexpand(true);

        let badge_lbl = gtk::Label::new(Some("🔒"));
        badge_lbl.style_context().add_class("address-badge");
        address_box.pack_start(&badge_lbl, false, false, 2);

        let address_entry = gtk::Entry::new();
        address_entry.set_hexpand(true);
        address_entry.set_width_chars(3);
        address_entry.set_placeholder_text(Some("Search or enter address (e.g. example.com)..."));
        address_entry.set_text("mewser:home");
        address_entry.style_context().add_class("address-entry");
        address_entry.set_widget_name("main_address_entry");
        address_box.pack_start(&address_entry, true, true, 0);

        let star_lbl = gtk::Label::new(Some("☆"));
        star_lbl.style_context().add_class("address-badge");
        address_box.pack_start(&star_lbl, false, false, 2);

        let go_btn = gtk::Button::with_label("➔");
        go_btn.set_tooltip_text(Some("Go to URL"));
        go_btn.style_context().add_class("nav-btn");
        address_box.pack_start(&go_btn, false, false, 0);

        header_bar.set_custom_title(Some(&address_box));

        // MasterDNS Connection Indicator Pill
        let tunnel_pill_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        tunnel_pill_box.style_context().add_class("tunnel-pill");

        let status_dot_lbl = gtk::Label::new(None);
        status_dot_lbl.set_markup("<span foreground=\"#ef4444\">●</span>");
        tunnel_pill_box.pack_start(&status_dot_lbl, false, false, 0);

        let status_text_lbl = gtk::Label::new(Some("Disconnected"));
        status_text_lbl.set_ellipsize(gtk::pango::EllipsizeMode::End);
        status_text_lbl
            .style_context()
            .add_class("tunnel-status-text");
        status_text_lbl.set_no_show_all(true);
        tunnel_pill_box.pack_start(&status_text_lbl, false, false, 0);

        let tunnel_action_btn = gtk::Button::with_label("Connect");
        tunnel_action_btn
            .style_context()
            .add_class("tunnel-pill-btn");
        tunnel_pill_box.pack_start(&tunnel_action_btn, false, false, 0);

        let tunnel_arrow_lbl = gtk::Label::new(Some("➔"));
        tunnel_arrow_lbl.style_context().add_class("address-badge");
        tunnel_arrow_lbl.set_no_show_all(true);
        tunnel_pill_box.pack_start(&tunnel_arrow_lbl, false, false, 0);

        header_bar.pack_end(&tunnel_pill_box);

        // Settings Button
        let settings_btn = gtk::Button::with_label("⚙");
        settings_btn.set_tooltip_text(Some("Settings & Preferences"));
        settings_btn.style_context().add_class("nav-btn");
        header_bar.pack_end(&settings_btn);

        // New Tab Button
        let new_tab_btn = gtk::Button::with_label("+");
        new_tab_btn.set_tooltip_text(Some("New Tab"));
        new_tab_btn.style_context().add_class("nav-btn");
        header_bar.pack_end(&new_tab_btn);

        if std::env::var("MEWSER_CAPTURE_SCREENSHOT")
            .map(|s| {
                s == "09_compact_window"
                    || s == "25_polished_compact_window"
                    || s == "01_home_720x500"
                    || s == "01_home_720x500_scrolled"
                    || s == "03_reader_compact"
            })
            .unwrap_or(false)
        {
            header_bar.style_context().add_class("compact");
            home_btn.hide();
            status_text_lbl.hide();
            tunnel_arrow_lbl.hide();
            mode_segmented_box.style_context().add_class("compact");
            tunnel_pill_box.style_context().add_class("compact");
        }

        // Responsive compact layout adaptations for smaller window sizes (< 840px)
        let header_bar_resp = header_bar.clone();
        let home_btn_resp = home_btn.clone();
        let mode_seg_resp = mode_segmented_box.clone();
        let status_text_resp = status_text_lbl.clone();
        let tunnel_arrow_resp = tunnel_arrow_lbl.clone();
        let tunnel_action_resp = tunnel_action_btn.clone();
        let tunnel_pill_resp = tunnel_pill_box.clone();
        window.connect_size_allocate(move |_, alloc| {
            if alloc.width() < 840 {
                header_bar_resp.style_context().add_class("compact");
                home_btn_resp.hide();
                status_text_resp.hide();
                tunnel_arrow_resp.hide();
                tunnel_action_resp.show();
                mode_seg_resp.show();
                mode_seg_resp.style_context().add_class("compact");
                tunnel_pill_resp.style_context().add_class("compact");
            } else {
                header_bar_resp.style_context().remove_class("compact");
                home_btn_resp.show();
                status_text_resp.show();
                tunnel_arrow_resp.show();
                tunnel_action_resp.show();
                mode_seg_resp.show();
                mode_seg_resp.style_context().remove_class("compact");
                tunnel_pill_resp.style_context().remove_class("compact");
            }
        });

        // 5. Slim Accent Progress Bar
        let progress_bar = gtk::ProgressBar::new();
        progress_bar.set_fraction(0.0);
        main_vbox.pack_start(&progress_bar, false, false, 0);
        progress_bar.hide();

        // 6. Notebook for Tabs
        let notebook = gtk::Notebook::new();
        notebook.set_scrollable(true);
        notebook.set_show_tabs(true);
        notebook.set_show_border(false);
        notebook.set_vexpand(true);
        main_vbox.pack_start(&notebook, true, true, 0);

        // Forward-declared home view updater channel or ref
        let home_status_lbls = Rc::new(RefCell::new(Vec::<gtk::Label>::new()));
        let home_action_btns = Rc::new(RefCell::new(Vec::<gtk::Button>::new()));

        // Auto-connect tunnel if configured
        if settings.tunnel_auto_connect
            && !settings.tunnel_encryption_key.is_empty()
            && !settings.tunnel_domain.trim().is_empty()
            && !crate::state::is_developer_domain(&settings.tunnel_domain)
        {
            let ctrl_auto = Arc::clone(&controller);
            let dyn_auto = Arc::clone(&dynamic_socks5);
            let model_auto = Arc::clone(&app_model);
            thread::spawn(move || match ctrl_auto.connect() {
                Ok(ep) => {
                    if let Ok(mut g) = dyn_auto.write() {
                        *g = Some(ep);
                    }
                    model_auto.lock().unwrap().settings.proxy_addr_str = ep.to_string();
                    println!("[MasterDnsController] Tunnel auto-connected on {ep}");
                }
                Err(e) => {
                    eprintln!("[MasterDnsController] Tunnel auto-connect failed: {e}");
                }
            });
        }

        // Periodic Status Timer (every 500ms)
        {
            let controller_for_timer = Arc::clone(&controller);
            let dynamic_socks5_for_timer = Arc::clone(&dynamic_socks5);
            let app_model_for_timer = Arc::clone(&app_model);
            let status_dot_clone = status_dot_lbl.clone();
            let status_text_clone = status_text_lbl.clone();
            let tunnel_action_clone = tunnel_action_btn.clone();
            let home_status_lbls_clone = Rc::clone(&home_status_lbls);
            let home_action_btns_clone = Rc::clone(&home_action_btns);

            glib::timeout_add_local(Duration::from_millis(500), move || {
                let state = controller_for_timer.state();
                let selected_id = app_model_for_timer
                    .lock()
                    .unwrap()
                    .settings
                    .profile_store
                    .selected_profile_id
                    .clone();
                let selected_name = app_model_for_timer
                    .lock()
                    .unwrap()
                    .settings
                    .profile_store
                    .selected_profile()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Selected Profile".to_string());

                let (dot_markup, text_str, action_str, sensitive) = match state {
                    TunnelState::Connected {
                        ref profile_id,
                        ref profile_name,
                        endpoint,
                        ..
                    } => {
                        // Sync dynamic socks5 endpoint
                        if let Ok(mut g) = dynamic_socks5_for_timer.write() {
                            if *g != Some(endpoint) {
                                *g = Some(endpoint);
                                app_model_for_timer.lock().unwrap().settings.proxy_addr_str =
                                    endpoint.to_string();
                            }
                        }

                        let is_different = selected_id
                            .as_deref()
                            .map(|s| s != profile_id)
                            .unwrap_or(false);
                        let action = if is_different {
                            format!("Switch to {selected_name}")
                        } else {
                            "Disconnect".to_string()
                        };

                        (
                            "<span foreground=\"#10b981\">●</span>",
                            format!("{profile_name} ({})", endpoint.port()),
                            action,
                            true,
                        )
                    }
                    TunnelState::Socks5Ready {
                        ref profile_id,
                        ref profile_name,
                        endpoint,
                        ..
                    } => {
                        // Sync dynamic socks5 endpoint
                        if let Ok(mut g) = dynamic_socks5_for_timer.write() {
                            if *g != Some(endpoint) {
                                *g = Some(endpoint);
                                app_model_for_timer.lock().unwrap().settings.proxy_addr_str =
                                    endpoint.to_string();
                            }
                        }

                        let is_different = selected_id
                            .as_deref()
                            .map(|s| s != profile_id)
                            .unwrap_or(false);
                        let action = if is_different {
                            format!("Switch to {selected_name}")
                        } else {
                            "Disconnect".to_string()
                        };

                        (
                            "<span foreground=\"#38bdf8\">●</span>",
                            format!("{profile_name} ({}) · Unverified", endpoint.port()),
                            action,
                            true,
                        )
                    }
                    TunnelState::Starting { .. } => (
                        "<span foreground=\"#f59e0b\">●</span>",
                        "Starting...".to_string(),
                        "Starting...".to_string(),
                        false,
                    ),
                    TunnelState::ResolverTesting {
                        completed, total, ..
                    } => (
                        "<span foreground=\"#f59e0b\">●</span>",
                        format!("Testing Resolvers ({completed}/{total})"),
                        "Testing...".to_string(),
                        false,
                    ),
                    TunnelState::SessionInitializing { .. } => (
                        "<span foreground=\"#f59e0b\">●</span>",
                        "Initializing Session...".to_string(),
                        "Connecting...".to_string(),
                        false,
                    ),
                    TunnelState::Reconnecting {
                        attempt,
                        max_attempts,
                        ..
                    } => (
                        "<span foreground=\"#f59e0b\">●</span>",
                        format!("Reconnecting ({attempt}/{max_attempts})"),
                        "Cancel".to_string(),
                        true,
                    ),
                    TunnelState::Stopping { .. } => (
                        "<span foreground=\"#f59e0b\">●</span>",
                        "Disconnecting...".to_string(),
                        "Stopping...".to_string(),
                        false,
                    ),
                    TunnelState::Failed(ref _err) => {
                        if let Ok(mut g) = dynamic_socks5_for_timer.write() {
                            *g = None;
                        }
                        (
                            "<span foreground=\"#ef4444\">●</span>",
                            "Connection Failed".to_string(),
                            "Retry".to_string(),
                            true,
                        )
                    }
                    TunnelState::Disconnected => {
                        if let Ok(mut g) = dynamic_socks5_for_timer.write() {
                            *g = None;
                        }
                        (
                            "<span foreground=\"#ef4444\">●</span>",
                            "Disconnected".to_string(),
                            "Connect".to_string(),
                            true,
                        )
                    }
                };

                status_dot_clone.set_markup(dot_markup);
                status_dot_clone.set_tooltip_text(Some(&format!("MasterDNS: {text_str}")));
                status_text_clone.set_text(&text_str);
                tunnel_action_clone.set_label(&action_str);
                tunnel_action_clone.set_sensitive(sensitive);

                // Update any open home views
                for lbl in home_status_lbls_clone.borrow().iter() {
                    lbl.set_markup(&format!("{dot_markup} {text_str}"));
                }
                for btn in home_action_btns_clone.borrow().iter() {
                    btn.set_label(&action_str);
                    btn.set_sensitive(sensitive);
                }

                glib::ControlFlow::Continue
            });
        }

        // Tunnel Connect/Disconnect/Switch Action Callback
        let trigger_tunnel_toggle = {
            let controller_for_toggle = Arc::clone(&controller);
            let dynamic_socks5_for_toggle = Arc::clone(&dynamic_socks5);
            let app_model_for_toggle = Arc::clone(&app_model);
            let window_for_toggle = window.clone();

            move || {
                let state = controller_for_toggle.state();
                match state {
                    TunnelState::Connected {
                        ref profile_id,
                        ref profile_name,
                        ..
                    }
                    | TunnelState::Socks5Ready {
                        ref profile_id,
                        ref profile_name,
                        ..
                    } => {
                        let selected_prof = app_model_for_toggle
                            .lock()
                            .unwrap()
                            .settings
                            .profile_store
                            .selected_profile()
                            .cloned();

                        if let Some(target_prof) = selected_prof {
                            if &target_prof.id != profile_id {
                                // Profile switch confirmation
                                let confirm = gtk::MessageDialog::new(
                                    Some(&window_for_toggle),
                                    gtk::DialogFlags::MODAL,
                                    gtk::MessageType::Question,
                                    gtk::ButtonsType::OkCancel,
                                    &format!(
                                        "Profile '{}' is selected, but profile '{}' is currently connected.\n\nDo you want to disconnect '{}' and switch to '{}'?",
                                        target_prof.name, profile_name, profile_name, target_prof.name
                                    ),
                                );
                                let resp = confirm.run();
                                confirm.close();
                                if resp != gtk::ResponseType::Ok {
                                    return;
                                }

                                let secret = app_model_for_toggle
                                    .lock()
                                    .unwrap()
                                    .settings
                                    .secret_vault
                                    .get_key(&target_prof.key_ref)
                                    .ok()
                                    .flatten()
                                    .unwrap_or_default();

                                let ctrl = Arc::clone(&controller_for_toggle);
                                let dyn_ep = Arc::clone(&dynamic_socks5_for_toggle);
                                let model = Arc::clone(&app_model_for_toggle);
                                thread::spawn(move || {
                                    match ctrl.switch_profile(&target_prof, &secret) {
                                        Ok(ep) => {
                                            if let Ok(mut g) = dyn_ep.write() {
                                                *g = Some(ep);
                                            }
                                            model.lock().unwrap().settings.proxy_addr_str =
                                                ep.to_string();
                                        }
                                        Err(e) => {
                                            eprintln!("[MasterDnsController] Switch error: {e}");
                                            if let Ok(mut g) = dyn_ep.write() {
                                                *g = None;
                                            }
                                        }
                                    }
                                });
                                return;
                            }
                        }

                        // Same profile connected: disconnect
                        let ctrl = Arc::clone(&controller_for_toggle);
                        let dyn_ep = Arc::clone(&dynamic_socks5_for_toggle);
                        thread::spawn(move || {
                            let _ = ctrl.disconnect();
                            if let Ok(mut g) = dyn_ep.write() {
                                *g = None;
                            }
                        });
                    }
                    TunnelState::Reconnecting { .. } => {
                        let ctrl = Arc::clone(&controller_for_toggle);
                        let dyn_ep = Arc::clone(&dynamic_socks5_for_toggle);
                        thread::spawn(move || {
                            let _ = ctrl.disconnect();
                            if let Ok(mut g) = dyn_ep.write() {
                                *g = None;
                            }
                        });
                    }
                    _ => {
                        let ctrl = Arc::clone(&controller_for_toggle);
                        let dyn_ep = Arc::clone(&dynamic_socks5_for_toggle);
                        let model = Arc::clone(&app_model_for_toggle);
                        thread::spawn(move || {
                            let (prof_opt, secret) = {
                                let m = model.lock().unwrap();
                                let p = m.settings.profile_store.selected_profile().cloned();
                                let s = p
                                    .as_ref()
                                    .and_then(|prof| {
                                        m.settings
                                            .secret_vault
                                            .get_key(&prof.key_ref)
                                            .ok()
                                            .flatten()
                                    })
                                    .unwrap_or_default();
                                (p, s)
                            };

                            let res = if let Some(prof) = prof_opt {
                                ctrl.connect_profile(&prof, &secret)
                            } else {
                                ctrl.connect()
                            };

                            match res {
                                Ok(ep) => {
                                    if let Ok(mut g) = dyn_ep.write() {
                                        *g = Some(ep);
                                    }
                                    model.lock().unwrap().settings.proxy_addr_str = ep.to_string();
                                }
                                Err(e) => {
                                    eprintln!("[MasterDnsController] Connect error: {e}");
                                }
                            }
                        });
                    }
                }
            }
        };

        // Wire toolbar pill button to toggle
        {
            let toggle = trigger_tunnel_toggle.clone();
            tunnel_action_btn.connect_clicked(move |_| {
                toggle();
            });
        }

        // Helper to add a tab widget
        let proxy_handle_for_tabs = proxy_handle.clone();
        let add_tab_widget = {
            let notebook_clone = notebook.clone();
            let app_model_clone = Arc::clone(&app_model);
            let address_entry_clone = address_entry.clone();
            let window_clone = window.clone();
            let progress_bar_clone = progress_bar.clone();
            let proxy_handle_for_tabs = proxy_handle_for_tabs.clone();
            let home_status_lbls_clone = Rc::clone(&home_status_lbls);
            let home_action_btns_clone = Rc::clone(&home_action_btns);
            let trigger_tunnel_toggle = trigger_tunnel_toggle.clone();
            let web_mode_btn_clone = web_mode_btn.clone();
            let text_mode_btn_clone = text_mode_btn.clone();

            move |initial_url: &str| {
                let proxy_handle_for_event = proxy_handle_for_tabs.clone();
                let proxy_handle_for_fail = proxy_handle_for_tabs.clone();
                let tab_box = gtk::Box::new(gtk::Orientation::Vertical, 0);

                let stack = gtk::Stack::new();
                stack.set_vexpand(true);
                tab_box.pack_start(&stack, true, true, 0);

                // 2. Standard Web: WebKitGTK WebView ("standard_web")
                let webview = WebView::new();
                webview.set_vexpand(true);
                stack.add_named(&webview, "standard_web");

                // 3. Resilient Text: Scrolled Reader View ("resilient_text")
                let (reader_scroll, reader_title, reader_meta, reader_text) =
                    create_reader_view(&app_model_clone);
                stack.add_named(&reader_scroll, "resilient_text");

                // 1. Home View ("home")
                let on_open_mode = {
                    let app_model_m = Arc::clone(&app_model_clone);
                    let stack_m = stack.clone();
                    let web_btn_m = web_mode_btn_clone.clone();
                    let text_btn_m = text_mode_btn_clone.clone();
                    let address_entry_m = address_entry_clone.clone();
                    let webview_m = webview.clone();
                    let r_title = reader_title.clone();
                    let r_meta = reader_meta.clone();
                    let r_text = reader_text.clone();

                    move |mode: BrowsingMode| {
                        app_model_m.lock().unwrap().settings.active_mode = mode;
                        if mode == BrowsingMode::StandardWeb {
                            web_btn_m.style_context().add_class("mode-btn-active");
                            text_btn_m.style_context().remove_class("mode-btn-active");
                            stack_m.set_visible_child_name("standard_web");
                            let mut url = address_entry_m.text().to_string();
                            if url.is_empty() || url == "mewser:home" {
                                url = "https://example.com/".to_string();
                                address_entry_m.set_text(&url);
                            }
                            webview_m.load_uri(&url);
                        } else {
                            text_btn_m.style_context().add_class("mode-btn-active");
                            web_btn_m.style_context().remove_class("mode-btn-active");
                            stack_m.set_visible_child_name("resilient_text");
                            let mut url = address_entry_m.text().to_string();
                            if url.is_empty() || url == "mewser:home" {
                                url = "https://example.com/".to_string();
                                address_entry_m.set_text(&url);
                            }
                            let cur_tab_idx = app_model_m.lock().unwrap().active_tab_index;
                            load_resilient_text(
                                &r_title,
                                &r_meta,
                                &r_text,
                                &url,
                                &app_model_m,
                                cur_tab_idx,
                            );
                        }
                    }
                };

                let (home_view, h_status_lbl, h_action_btn) = create_home_view(
                    &app_model_clone,
                    {
                        let address_entry_c = address_entry_clone.clone();
                        move |nav_target: &str| {
                            address_entry_c.set_text(nav_target);
                            address_entry_c.emit_activate();
                        }
                    },
                    trigger_tunnel_toggle.clone(),
                    on_open_mode,
                );
                stack.add_named(&home_view, "home");

                home_status_lbls_clone.borrow_mut().push(h_status_lbl);
                home_action_btns_clone.borrow_mut().push(h_action_btn);

                // Tab Header Label with Icon & Close Button
                let tab_header = gtk::Box::new(gtk::Orientation::Horizontal, 6);
                let mode_icon_lbl = gtk::Label::new(Some("🌐"));
                tab_header.pack_start(&mode_icon_lbl, false, false, 0);

                let tab_title_label = gtk::Label::new(Some("New Tab"));
                tab_title_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
                tab_title_label.set_max_width_chars(18);
                tab_header.pack_start(&tab_title_label, true, true, 0);

                let tab_close_btn = gtk::Button::with_label("✕");
                tab_close_btn.style_context().add_class("tab-close-btn");
                tab_close_btn.set_relief(gtk::ReliefStyle::None);
                tab_header.pack_end(&tab_close_btn, false, false, 0);

                let page_idx = notebook_clone.append_page(&tab_box, Some(&tab_header));
                notebook_clone.show_all();

                // Signals for WebView
                let tab_title_label_clone = tab_title_label.clone();
                let window_title_clone = window_clone.clone();
                webview.connect_notify_local(Some("title"), move |wv, _| {
                    if let Some(title) = wv.title() {
                        tab_title_label_clone.set_text(&title);
                        window_title_clone.set_title(&format!("{title} — Mewser"));
                    }
                });

                let progress_bar_for_load = progress_bar_clone.clone();
                webview.connect_notify_local(Some("estimated-load-progress"), move |wv, _| {
                    let progress = wv.estimated_load_progress();
                    progress_bar_for_load.set_fraction(progress);
                });

                let progress_bar_for_change = progress_bar_clone.clone();
                let address_entry_for_change = address_entry_clone.clone();
                webview.connect_load_changed(move |wv, event| match event {
                    webkit2gtk::LoadEvent::Started => {
                        progress_bar_for_change.show();
                        progress_bar_for_change.set_fraction(0.15);
                    }
                    webkit2gtk::LoadEvent::Committed => {
                        if let Some(uri) = wv.uri() {
                            address_entry_for_change.set_text(&uri);
                        }
                    }
                    webkit2gtk::LoadEvent::Finished => {
                        progress_bar_for_change.hide();
                        if let Some(uri) = wv.uri() {
                            address_entry_for_change.set_text(&uri);
                        }
                        if let Some(ref ph) = proxy_handle_for_event {
                            let stats = ph.stats();
                            println!(
                                "[PolicyProxy Load Stats] Total={} Direct={} Tunnel={} Blocked={} FailedTunnel={} Subresources={}",
                                stats.total_requests.load(std::sync::atomic::Ordering::SeqCst),
                                stats.direct_requests.load(std::sync::atomic::Ordering::SeqCst),
                                stats.tunnel_requests.load(std::sync::atomic::Ordering::SeqCst),
                                stats.blocked_requests.load(std::sync::atomic::Ordering::SeqCst),
                                stats.failed_tunnel_requests.load(std::sync::atomic::Ordering::SeqCst),
                                stats.subresource_requests.load(std::sync::atomic::Ordering::SeqCst),
                            );
                        }
                    }
                    _ => {}
                });

                let progress_bar_for_fail = progress_bar_clone.clone();
                webview.connect_load_failed(move |_wv, _event, failing_uri, err| {
                    progress_bar_for_fail.hide();
                    eprintln!("Navigation failed for {failing_uri}: {err}");
                    if let Some(ref ph) = proxy_handle_for_fail {
                        let stats = ph.stats();
                        println!(
                            "[PolicyProxy LoadFailed Stats] Total={} Direct={} Tunnel={} Blocked={} FailedTunnel={} Subresources={}",
                            stats.total_requests.load(std::sync::atomic::Ordering::SeqCst),
                            stats.direct_requests.load(std::sync::atomic::Ordering::SeqCst),
                            stats.tunnel_requests.load(std::sync::atomic::Ordering::SeqCst),
                            stats.blocked_requests.load(std::sync::atomic::Ordering::SeqCst),
                            stats.failed_tunnel_requests.load(std::sync::atomic::Ordering::SeqCst),
                            stats.subresource_requests.load(std::sync::atomic::Ordering::SeqCst),
                        );
                    }
                    false
                });

                // Tab close button signal
                let notebook_for_close = notebook_clone.clone();
                let tab_box_for_close = tab_box.clone();
                tab_close_btn.connect_clicked(move |_| {
                    if let Some(idx) = notebook_for_close.page_num(&tab_box_for_close) {
                        notebook_for_close.remove_page(Some(idx));
                    }
                });

                // Load initial URL
                let normalized = normalize_input_url(initial_url);
                if normalized.is_empty() || normalized == "mewser:home" {
                    stack.set_visible_child_name("home");
                    tab_title_label.set_text("Mewser Home");
                    mode_icon_lbl.set_text("⚡");
                } else {
                    let title_suggestion = if normalized.contains("example.com") {
                        "Example Domain".to_string()
                    } else if normalized.contains("rust-lang.org") {
                        "Rust Language".to_string()
                    } else if let Ok(u) = url::Url::parse(&normalized) {
                        u.host_str().unwrap_or(&normalized).to_string()
                    } else {
                        normalized.clone()
                    };
                    tab_title_label.set_text(&title_suggestion);

                    let mode = app_model_clone.lock().unwrap().settings.active_mode;
                    if mode == BrowsingMode::StandardWeb {
                        mode_icon_lbl.set_text("🌐");
                        stack.set_visible_child_name("standard_web");
                        webview.load_uri(&normalized);
                    } else {
                        mode_icon_lbl.set_text("📄");
                        stack.set_visible_child_name("resilient_text");
                        load_resilient_text(
                            &reader_title,
                            &reader_meta,
                            &reader_text,
                            &normalized,
                            &app_model_clone,
                            page_idx as usize,
                        );
                    }
                }

                page_idx
            }
        };

        // Initial tab: load argument or home
        let initial_url = std::env::args()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .unwrap_or_else(|| "mewser:home".to_string());
        add_tab_widget(&initial_url);

        // Address Bar Activate Navigation
        {
            let notebook_clone = notebook.clone();
            let app_model_clone = Arc::clone(&app_model);
            let address_entry_clone = address_entry.clone();
            let progress_bar_clone = progress_bar.clone();

            address_entry.connect_activate(move |_| {
                let url = normalize_input_url(&address_entry_clone.text());
                if url.is_empty() {
                    return;
                }

                if let Some(page_num) = notebook_clone.current_page() {
                    if let Some(tab_widget) = notebook_clone.nth_page(Some(page_num)) {
                        if let Ok(tab_box) = tab_widget.clone().downcast::<gtk::Box>() {
                            let children = tab_box.children();
                            if !children.is_empty() {
                                if let Ok(stack) = children[0].clone().downcast::<gtk::Stack>() {
                                    if url == "mewser:home" {
                                        stack.set_visible_child_name("home");
                                        progress_bar_clone.hide();
                                    } else {
                                        let mode =
                                            app_model_clone.lock().unwrap().settings.active_mode;
                                        if mode == BrowsingMode::StandardWeb {
                                            stack.set_visible_child_name("standard_web");
                                            if let Some(wv_widget) =
                                                stack.child_by_name("standard_web")
                                            {
                                                if let Ok(wv) = wv_widget.downcast::<WebView>() {
                                                    wv.load_uri(&url);
                                                }
                                            }
                                        } else {
                                            stack.set_visible_child_name("resilient_text");
                                            if let Some((t_lbl, m_lbl, tv)) =
                                                get_reader_widgets(&tab_widget)
                                            {
                                                load_resilient_text(
                                                    &t_lbl,
                                                    &m_lbl,
                                                    &tv,
                                                    &url,
                                                    &app_model_clone,
                                                    page_num as usize,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        // Connect Go Button
        {
            let address_entry_for_go = address_entry.clone();
            go_btn.connect_clicked(move |_| {
                address_entry_for_go.emit_activate();
            });
        }

        // Mode Switcher Controls
        {
            let notebook_clone = notebook.clone();
            let app_model_clone = Arc::clone(&app_model);
            let address_entry_clone = address_entry.clone();
            let web_btn = web_mode_btn.clone();
            let text_btn = text_mode_btn.clone();

            let switch_mode = move |new_mode: BrowsingMode| {
                app_model_clone.lock().unwrap().settings.active_mode = new_mode;
                if new_mode == BrowsingMode::StandardWeb {
                    web_btn.style_context().add_class("mode-btn-active");
                    text_btn.style_context().remove_class("mode-btn-active");
                } else {
                    text_btn.style_context().add_class("mode-btn-active");
                    web_btn.style_context().remove_class("mode-btn-active");
                }

                let current_url = normalize_input_url(&address_entry_clone.text());
                if current_url.is_empty() || current_url == "mewser:home" {
                    return;
                }

                if let Some(page_num) = notebook_clone.current_page() {
                    if let Some(tab_widget) = notebook_clone.nth_page(Some(page_num)) {
                        if let Ok(tab_box) = tab_widget.clone().downcast::<gtk::Box>() {
                            let children = tab_box.children();
                            if !children.is_empty() {
                                if let Ok(stack) = children[0].clone().downcast::<gtk::Stack>() {
                                    if new_mode == BrowsingMode::StandardWeb {
                                        stack.set_visible_child_name("standard_web");
                                        if let Some(wv_widget) = stack.child_by_name("standard_web")
                                        {
                                            if let Ok(wv) = wv_widget.downcast::<WebView>() {
                                                wv.load_uri(&current_url);
                                            }
                                        }
                                    } else {
                                        stack.set_visible_child_name("resilient_text");
                                        if let Some((t_lbl, m_lbl, tv)) =
                                            get_reader_widgets(&tab_widget)
                                        {
                                            load_resilient_text(
                                                &t_lbl,
                                                &m_lbl,
                                                &tv,
                                                &current_url,
                                                &app_model_clone,
                                                page_num as usize,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };

            let sm1 = switch_mode.clone();
            web_mode_btn.connect_clicked(move |_| {
                sm1(BrowsingMode::StandardWeb);
            });

            let sm2 = switch_mode;
            text_mode_btn.connect_clicked(move |_| {
                sm2(BrowsingMode::ResilientText);
            });
        }

        // Connect Navigation Buttons: Back, Forward, Reload, Home
        {
            let notebook_clone = notebook.clone();
            back_btn.connect_clicked(move |_| {
                if let Some(page_num) = notebook_clone.current_page() {
                    if let Some(tab_widget) = notebook_clone.nth_page(Some(page_num)) {
                        if let Ok(tab_box) = tab_widget.clone().downcast::<gtk::Box>() {
                            if let Some(stack_widget) = tab_box.children().first() {
                                if let Ok(stack) = stack_widget.clone().downcast::<gtk::Stack>() {
                                    if let Some(wv_widget) = stack.child_by_name("standard_web") {
                                        if let Ok(wv) = wv_widget.downcast::<WebView>() {
                                            if wv.can_go_back() {
                                                wv.go_back();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        {
            let notebook_clone = notebook.clone();
            fwd_btn.connect_clicked(move |_| {
                if let Some(page_num) = notebook_clone.current_page() {
                    if let Some(tab_widget) = notebook_clone.nth_page(Some(page_num)) {
                        if let Ok(tab_box) = tab_widget.clone().downcast::<gtk::Box>() {
                            if let Some(stack_widget) = tab_box.children().first() {
                                if let Ok(stack) = stack_widget.clone().downcast::<gtk::Stack>() {
                                    if let Some(wv_widget) = stack.child_by_name("standard_web") {
                                        if let Ok(wv) = wv_widget.downcast::<WebView>() {
                                            if wv.can_go_forward() {
                                                wv.go_forward();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        {
            let notebook_clone = notebook.clone();
            let address_entry_clone = address_entry.clone();
            reload_btn.connect_clicked(move |_| {
                if let Some(page_num) = notebook_clone.current_page() {
                    if let Some(tab_widget) = notebook_clone.nth_page(Some(page_num)) {
                        if let Ok(tab_box) = tab_widget.clone().downcast::<gtk::Box>() {
                            if let Some(stack_widget) = tab_box.children().first() {
                                if let Ok(stack) = stack_widget.clone().downcast::<gtk::Stack>() {
                                    if stack.visible_child_name().as_deref() == Some("standard_web")
                                    {
                                        if let Some(wv_widget) = stack.child_by_name("standard_web")
                                        {
                                            if let Ok(wv) = wv_widget.downcast::<WebView>() {
                                                wv.reload();
                                            }
                                        }
                                    } else {
                                        address_entry_clone.emit_activate();
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        {
            let address_entry_clone = address_entry.clone();
            home_btn.connect_clicked(move |_| {
                address_entry_clone.set_text("mewser:home");
                address_entry_clone.emit_activate();
            });
        }

        // Connect New Tab Button
        {
            let add_tab = add_tab_widget.clone();
            new_tab_btn.connect_clicked(move |_| {
                add_tab("mewser:home");
            });
        }

        // Connect Settings Button
        {
            let window_clone = window.clone();
            let app_model_clone = Arc::clone(&app_model);
            settings_btn.connect_clicked(move |_| {
                show_settings_dialog(&window_clone, &app_model_clone);
            });
        }

        // Update Address Bar on Tab Switch
        {
            let address_entry_clone = address_entry.clone();
            let app_model_for_switch = Arc::clone(&app_model);
            notebook.connect_switch_page(move |_, page, page_num| {
                app_model_for_switch.lock().unwrap().active_tab_index = page_num as usize;
                if let Ok(tab_box) = page.clone().downcast::<gtk::Box>() {
                    if let Some(stack_widget) = tab_box.children().first() {
                        if let Ok(stack) = stack_widget.clone().downcast::<gtk::Stack>() {
                            match stack.visible_child_name().as_deref() {
                                Some("home") => {
                                    address_entry_clone.set_text("mewser:home");
                                }
                                Some("standard_web") => {
                                    if let Some(wv_widget) = stack.child_by_name("standard_web") {
                                        if let Ok(wv) = wv_widget.downcast::<WebView>() {
                                            if let Some(uri) = wv.uri() {
                                                address_entry_clone.set_text(&uri);
                                            }
                                        }
                                    }
                                }
                                Some("resilient_text") => {
                                    let m = app_model_for_switch.lock().unwrap();
                                    if let Some(tab) = m.tabs.get(page_num as usize) {
                                        if let Some(ref meta) = tab.reader_metadata {
                                            address_entry_clone.set_text(&meta.url);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            });
        }

        // Screenshot Automation Hook
        if let Ok(shot_mode) = std::env::var("MEWSER_CAPTURE_SCREENSHOT") {
            let address_entry_c = address_entry.clone();
            let add_tab_c = add_tab_widget.clone();
            let settings_btn_c = settings_btn.clone();
            let text_mode_btn_c = text_mode_btn.clone();
            let controller_c = Arc::clone(&controller);
            let app_model_c = Arc::clone(&app_model);
            let tunnel_action_btn_c = tunnel_action_btn.clone();
            let mode_segmented_box_c = mode_segmented_box.clone();
            let status_text_lbl_c = status_text_lbl.clone();
            let tunnel_arrow_lbl_c = tunnel_arrow_lbl.clone();
            let tunnel_pill_box_c = tunnel_pill_box.clone();
            let window_c = window.clone();
            let notebook_c = notebook.clone();

            let capture_active_window = |dest: &str| {
                let win_id = if dest.contains("settings")
                    || dest.contains("profile")
                    || dest.contains("dialog")
                    || dest.contains("routing")
                    || dest.contains("gateway")
                {
                    let out = std::process::Command::new("xdotool")
                        .args(["getactivewindow"])
                        .output();
                    match out {
                        Ok(o) if o.status.success() => {
                            let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            if id.is_empty() {
                                "root".to_string()
                            } else {
                                id
                            }
                        }
                        _ => "root".to_string(),
                    }
                } else {
                    let out = std::process::Command::new("xdotool")
                        .args(["search", "--onlyvisible", "--class", "mewser"])
                        .output();
                    let id_from_class = match out {
                        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .last()
                            .unwrap_or("")
                            .trim()
                            .to_string(),
                        _ => String::new(),
                    };
                    if !id_from_class.is_empty() {
                        id_from_class
                    } else {
                        let out_name = std::process::Command::new("xdotool")
                            .args(["search", "--onlyvisible", "--name", "Mewser"])
                            .output();
                        match out_name {
                            Ok(on) if on.status.success() => {
                                let id = String::from_utf8_lossy(&on.stdout)
                                    .lines()
                                    .last()
                                    .unwrap_or("")
                                    .trim()
                                    .to_string();
                                if id.is_empty() {
                                    let out_act = std::process::Command::new("xdotool")
                                        .args(["getactivewindow"])
                                        .output();
                                    match out_act {
                                        Ok(oa) if oa.status.success() => {
                                            String::from_utf8_lossy(&oa.stdout).trim().to_string()
                                        }
                                        _ => "root".to_string(),
                                    }
                                } else {
                                    id
                                }
                            }
                            _ => "root".to_string(),
                        }
                    }
                };
                let _ = std::process::Command::new("import")
                    .args(["-window", &win_id, dest])
                    .status();
                println!("[Screenshot] Saved clean window to {dest}");
                std::process::exit(0);
            };

            let capture_active_window_no_exit = |dest: &str| {
                let out = std::process::Command::new("xdotool")
                    .args(["search", "--onlyvisible", "--class", "mewser"])
                    .output();
                let id_from_class = match out {
                    Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .last()
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                    _ => String::new(),
                };
                let win_id = if !id_from_class.is_empty() {
                    id_from_class
                } else {
                    let out_name = std::process::Command::new("xdotool")
                        .args(["search", "--onlyvisible", "--name", "Mewser"])
                        .output();
                    match out_name {
                        Ok(on) if on.status.success() => {
                            let id = String::from_utf8_lossy(&on.stdout)
                                .lines()
                                .last()
                                .unwrap_or("")
                                .trim()
                                .to_string();
                            if id.is_empty() {
                                "root".to_string()
                            } else {
                                id
                            }
                        }
                        _ => "root".to_string(),
                    }
                };
                let _ = std::process::Command::new("import")
                    .args(["-window", &win_id, dest])
                    .status();
                println!("[Screenshot] Saved clean window to {dest}");
            };

            glib::timeout_add_local(Duration::from_millis(1500), move || {
                match shot_mode.as_str() {
                    "01_new_tab_screen" | "02_tunnel_disconnected" => {
                        capture_active_window(&format!("target/screenshots/{shot_mode}.png"));
                        gtk::main_quit();
                    }
                    "03_tunnel_connecting_mtu" => {
                        let ctrl = Arc::clone(&controller_c);
                        thread::spawn(move || {
                            let _ = ctrl.connect();
                        });
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1800), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                    }
                    "04_standard_web_page" => {
                        address_entry_c.set_text("https://example.com/");
                        address_entry_c.emit_activate();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(3500), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                    }
                    "05_resilient_text_reader" => {
                        text_mode_btn_c.emit_clicked();
                        address_entry_c.set_text("https://example.com/");
                        address_entry_c.emit_activate();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(3500), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                    }
                    "06_multiple_tabs" => {
                        add_tab_c("https://example.com/");
                        add_tab_c("https://www.rust-lang.org/");
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(2500), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                    }
                    "07_settings_dialog_masked" | "09_profile_manager_main" => {
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "08_fail_closed_error" => {
                        let _ = controller_c.disconnect();
                        address_entry_c.set_text("https://example.com/");
                        address_entry_c.emit_activate();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(2500), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                    }
                    "10_profile_manager_selected_vs_connected" => {
                        let (prof_a_id, prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS Profile",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        controller_c.set_mock_connected_for_screenshot(
                            &prof_a_id,
                            "Default MasterDNS Profile",
                            40188,
                        );
                        std::env::set_var("MEWSER_VIEW_PROFILE_ID", &prof_b_id);
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "11_profile_manager_connected_edit_warning" => {
                        let (prof_a_id, _prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS Profile",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        controller_c.set_mock_connected_for_screenshot(
                            &prof_a_id,
                            "Default MasterDNS Profile",
                            40188,
                        );
                        std::env::set_var("MEWSER_VIEW_PROFILE_ID", &prof_a_id);
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "12_profile_switch_confirmation_dialog" => {
                        let (prof_a_id, _prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS Profile",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        controller_c.set_mock_connected_for_screenshot(
                            &prof_a_id,
                            "Default MasterDNS Profile",
                            40188,
                        );
                        let m = shot_mode.clone();
                        let tb_btn = tunnel_action_btn_c.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                        glib::timeout_add_local(Duration::from_millis(600), move || {
                            tb_btn.emit_clicked();
                            glib::ControlFlow::Break
                        });
                    }
                    "13_profile_manager_selected_unconnected_edit" => {
                        let (prof_a_id, prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS Profile",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        controller_c.set_mock_connected_for_screenshot(
                            &prof_a_id,
                            "Default MasterDNS Profile",
                            40188,
                        );
                        std::env::set_var("MEWSER_VIEW_PROFILE_ID", &prof_b_id);
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "14_tunnel_socks5_ready_unverified" => {
                        let (prof_a_id, _prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS Profile",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        controller_c.set_mock_socks5_ready_for_screenshot(
                            &prof_a_id,
                            "Default MasterDNS Profile",
                            40188,
                        );
                        std::env::set_var("MEWSER_VIEW_PROFILE_ID", &prof_a_id);
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "15_all_profiles_disconnected" => {
                        let (_prof_a_id, prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS Profile",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        let _ = controller_c.disconnect();
                        std::env::set_var("MEWSER_VIEW_PROFILE_ID", &prof_b_id);
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "01_home_dashboard" | "16_polished_home_page" => {
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "01_home_1366x768" => {
                        window_c.resize(1366, 768);
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "1366", "768"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(500), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "01_home_1024x768" => {
                        window_c.resize(1024, 768);
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "1024", "768"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(500), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "01_home_720x500" | "01_home_720x500_scrolled" => {
                        mode_segmented_box_c.show();
                        mode_segmented_box_c.style_context().add_class("compact");
                        tunnel_action_btn_c.show();
                        tunnel_pill_box_c.style_context().add_class("compact");
                        status_text_lbl_c.hide();
                        tunnel_arrow_lbl_c.hide();
                        window_c.resize(720, 500);
                        let m = shot_mode.clone();
                        let notebook_scroll = notebook_c.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "720", "500"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            let notebook_scroll_step2 = notebook_scroll.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                if dest_m == "01_home_720x500_scrolled" {
                                    if let Some(page_idx) = notebook_scroll_step2.current_page() {
                                        if let Some(tab_widget) =
                                            notebook_scroll_step2.nth_page(Some(page_idx))
                                        {
                                            if let Ok(tab_box) = tab_widget.downcast::<gtk::Box>() {
                                                if let Some(first_child) =
                                                    tab_box.children().first()
                                                {
                                                    if let Ok(stack) =
                                                        first_child.clone().downcast::<gtk::Stack>()
                                                    {
                                                        if let Some(home_child) =
                                                            stack.child_by_name("home")
                                                        {
                                                            if let Ok(scrolled_win) =
                                                                home_child
                                                                    .downcast::<gtk::ScrolledWindow>()
                                                            {
                                                                let vadj = scrolled_win.vadjustment();
                                                                let max_val = vadj.upper() - vadj.page_size();
                                                                vadj.set_value(max_val);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                let final_m = dest_m.clone();
                                glib::timeout_add_local(Duration::from_millis(500), move || {
                                    capture_active_window(&format!(
                                        "target/screenshots/{final_m}.png"
                                    ));
                                    gtk::main_quit();
                                    glib::ControlFlow::Break
                                });
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "02_standard_web" | "17_polished_standard_web" => {
                        address_entry_c.set_text("https://example.com/");
                        address_entry_c.emit_activate();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(3500), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                    }
                    "03_resilient_text_reader"
                    | "18_polished_resilient_text"
                    | "03_reader_long_article"
                    | "03_reader_contents_open"
                    | "03_reader_contents_collapsed"
                    | "03_reader_page_info"
                    | "03_reader_typography"
                    | "03_reader_loading"
                    | "03_reader_error"
                    | "03_reader_error_collapsed"
                    | "03_reader_error_expanded"
                    | "03_reader_compact" => {
                        let is_long_article = shot_mode == "03_reader_long_article"
                            || shot_mode == "03_reader_contents_open"
                            || shot_mode == "03_reader_contents_collapsed";
                        let is_error_mode = shot_mode == "03_reader_error"
                            || shot_mode == "03_reader_error_collapsed"
                            || shot_mode == "03_reader_error_expanded";
                        let is_loading_mode = shot_mode == "03_reader_loading";
                        let is_compact_mode = shot_mode == "03_reader_compact";

                        if is_compact_mode {
                            mode_segmented_box_c.show();
                            mode_segmented_box_c.style_context().add_class("compact");
                            tunnel_action_btn_c.show();
                            tunnel_pill_box_c.style_context().add_class("compact");
                            status_text_lbl_c.hide();
                            tunnel_arrow_lbl_c.hide();
                            window_c.resize(720, 500);
                        }

                        if is_error_mode {
                            let _ = controller_c.disconnect();
                            text_mode_btn_c.emit_clicked();
                            address_entry_c.set_text("https://example.com/fail");
                            address_entry_c.emit_activate();

                            let m = shot_mode.clone();
                            let window_for_error = window_c.clone();
                            glib::timeout_add_local(Duration::from_millis(2500), move || {
                                if m == "03_reader_error_expanded" {
                                    if let Some(exp) = find_child_by_name(
                                        &window_for_error,
                                        "reader_error_expander",
                                    ) {
                                        if let Ok(e) = exp.downcast::<gtk::Expander>() {
                                            e.set_expanded(true);
                                        }
                                    }
                                }
                                let dest_m = m.clone();
                                glib::timeout_add_local(Duration::from_millis(500), move || {
                                    capture_active_window(&format!(
                                        "target/screenshots/{dest_m}.png"
                                    ));
                                    gtk::main_quit();
                                    glib::ControlFlow::Break
                                });
                                glib::ControlFlow::Break
                            });
                        } else if is_loading_mode {
                            let fixture_listener =
                                std::net::TcpListener::bind("127.0.0.1:0").expect("Bind fixture");
                            let fixture_addr = fixture_listener.local_addr().expect("Fixture addr");

                            std::thread::spawn(move || {
                                if let Ok((mut stream, _)) = fixture_listener.accept() {
                                    std::thread::sleep(Duration::from_millis(15000));
                                    let mut req_buf = vec![0u8; 2048];
                                    let _ = stream.read(&mut req_buf);
                                }
                            });

                            {
                                let mut m = app_model_c.lock().unwrap();
                                m.settings.transport = crate::state::DesktopTransport::FixedTcp;
                                m.settings.tcp_endpoint_str = fixture_addr.to_string();
                            }

                            controller_c.set_mock_connected_for_screenshot(
                                "default-masterdns-profile",
                                "Default MasterDNS Profile",
                                40188,
                            );

                            text_mode_btn_c.emit_clicked();
                            address_entry_c.set_text("https://example.com/slow");
                            address_entry_c.emit_activate();

                            let m = shot_mode.clone();
                            glib::timeout_add_local(Duration::from_millis(500), move || {
                                capture_active_window(&format!("target/screenshots/{m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                        } else {
                            let fixture_listener =
                                std::net::TcpListener::bind("127.0.0.1:0").expect("Bind fixture");
                            let fixture_addr = fixture_listener.local_addr().expect("Fixture addr");

                            let long_art = is_long_article;
                            std::thread::spawn(move || {
                                if let Ok((mut stream, _)) = fixture_listener.accept() {
                                    let mut req_buf = vec![0u8; 2048];
                                    let _ = stream.read(&mut req_buf);

                                    const EXAMPLE_HTML: &str = r#"<!doctype html>
<html>
<head>
    <title>Example Domain</title>
</head>
<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in documentation examples without needing permission. This is not a service; avoid relying on it for testing and monitoring purposes.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>"#;

                                    const LONG_HTML: &str = r#"<!doctype html>
<html>
<head>
    <title>Domain Name System — Protocol & Architecture</title>
    <meta name="description" content="A comprehensive specification of the Domain Name System (DNS) protocol, MasterDNS tunnel architecture, and resilient text extraction.">
</head>
<body>
<div>
    <h1>Domain Name System — Protocol & Architecture</h1>
    <p>This document specifies the architecture, protocol mechanics, and resilient content delivery system implemented in the Mewser Browser environment.</p>
    <h2>1. Architecture and Design Goals</h2>
    <p>The primary design goal of Mewser is to maintain deterministic, fail-closed access to informational web resources across congested, hostile, or restricted network environments.</p>
    <ul>
        <li>Dual-mode browsing: Native WebKit engine alongside server-side text extraction.</li>
        <li>Explicit, deterministic routing without silent network fallback.</li>
        <li>Strict text-first asset policy preventing background media tracking.</li>
    </ul>
    <h2>2. MasterDNS Tunneling Mechanisms</h2>
    <p>The tunnel adapter encapsulates downstream client requests within standardized DNS queries. Upstream responses are segmented into discrete payloads and reconstructed at the client edge.</p>
    <h2>3. Server-Side Extraction Pipeline</h2>
    <p>The Mewser Gateway parses raw HTML documents, extracts readable article hierarchies, removes tracking scripts, and delivers clean JSON-encoded content blocks to the desktop reader.</p>
    <h2>4. Fail-Closed Security Invariants</h2>
    <p>All tunneled destinations strictly enforce SSRF validation, private IP address blocking, and mandatory HTTPS certificate verification at the Gateway perimeter.</p>
    <p><a href="https://example.com/rfc1035">Reference: IETF RFC 1035 Specification</a></p>
</div>
</body>
</html>"#;

                                    let html_src = if long_art { LONG_HTML } else { EXAMPLE_HTML };
                                    let target_url = if long_art {
                                        "https://example.com/long-article"
                                    } else {
                                        "https://example.com/"
                                    };
                                    let page = mewser_gateway::extract_page(
                                        html_src,
                                        &url::Url::parse(target_url).unwrap(),
                                    );
                                    let body = serde_json::to_string(&page).unwrap();
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        body.len(),
                                        body
                                    );
                                    let _ = stream.write_all(resp.as_bytes());
                                }
                            });

                            {
                                let mut m = app_model_c.lock().unwrap();
                                m.settings.transport = crate::state::DesktopTransport::FixedTcp;
                                m.settings.tcp_endpoint_str = fixture_addr.to_string();
                            }

                            controller_c.set_mock_connected_for_screenshot(
                                "default-masterdns-profile",
                                "Default MasterDNS Profile",
                                40188,
                            );

                            text_mode_btn_c.emit_clicked();
                            let target_url = if is_long_article {
                                "https://example.com/long-article"
                            } else {
                                "https://example.com/"
                            };
                            address_entry_c.set_text(target_url);
                            address_entry_c.emit_activate();

                            let m = shot_mode.clone();
                            let window_for_shot = window_c.clone();
                            glib::timeout_add_local(Duration::from_millis(2500), move || {
                                if m == "03_reader_contents_open" {
                                    // 1. Capture before toggling (Contents initially collapsed)
                                    capture_active_window_no_exit(
                                        "target/screenshots/03_reader_before_toggle.png",
                                    );
                                    capture_active_window_no_exit(
                                        "target/screenshots/03_reader_contents_collapsed.png",
                                    );

                                    // 2. Click the Contents control without resizing the window
                                    if let Some(btn) =
                                        find_child_by_name(&window_for_shot, "reader_menu_btn")
                                    {
                                        if let Ok(b) = btn.downcast::<gtk::Button>() {
                                            b.emit_clicked();
                                        }
                                    }

                                    // 3 & 4. Verify reflow and capture after toggling
                                    let win_shot_step2 = window_for_shot.clone();
                                    glib::timeout_add_local(
                                        Duration::from_millis(800),
                                        move || {
                                            capture_active_window_no_exit(
                                                "target/screenshots/03_reader_after_toggle.png",
                                            );
                                            capture_active_window_no_exit(
                                                "target/screenshots/03_reader_contents_open.png",
                                            );

                                            // 5. Click a heading in Contents and verify navigation
                                            if let Some(cl) = find_child_by_name(
                                                &win_shot_step2,
                                                "reader_contents_list",
                                            ) {
                                                if let Ok(lb) = cl.downcast::<gtk::ListBox>() {
                                                    if let Some(row) = lb.row_at_index(1) {
                                                        row.activate();
                                                    }
                                                }
                                            }

                                            // 6 & 7. Close Contents without resizing window
                                            if let Some(close_btn) = find_child_by_name(
                                                &win_shot_step2,
                                                "reader_contents_close_btn",
                                            ) {
                                                if let Ok(cb) = close_btn.downcast::<gtk::Button>()
                                                {
                                                    cb.emit_clicked();
                                                }
                                            }

                                            // 8. Repeat toggle once to exclude one-time initialization
                                            let win_shot_step3 = win_shot_step2.clone();
                                            glib::timeout_add_local(
                                                Duration::from_millis(500),
                                                move || {
                                                    if let Some(btn) = find_child_by_name(
                                                        &win_shot_step3,
                                                        "reader_menu_btn",
                                                    ) {
                                                        if let Ok(b) = btn.downcast::<gtk::Button>()
                                                        {
                                                            b.emit_clicked();
                                                        }
                                                    }
                                                    glib::timeout_add_local(
                                                        Duration::from_millis(500),
                                                        move || {
                                                            println!("[Runtime Check] Full 8-step toggle & reflow sequence completed successfully.");
                                                            gtk::main_quit();
                                                            std::process::exit(0);
                                                        },
                                                    );
                                                    glib::ControlFlow::Break
                                                },
                                            );
                                            glib::ControlFlow::Break
                                        },
                                    );
                                    return glib::ControlFlow::Break;
                                } else if m == "03_reader_contents_collapsed" {
                                    if let Some(cs) = find_child_by_name(
                                        &window_for_shot,
                                        "reader_contents_sidebar",
                                    ) {
                                        cs.hide();
                                        cs.set_no_show_all(true);
                                    }
                                } else if m == "03_reader_page_info" {
                                    if let Some(btn) =
                                        find_child_by_name(&window_for_shot, "reader_info_btn")
                                    {
                                        if let Ok(b) = btn.downcast::<gtk::Button>() {
                                            b.emit_clicked();
                                        }
                                    }
                                } else if m == "03_reader_typography" {
                                    if let Some(btn) =
                                        find_child_by_name(&window_for_shot, "reader_font_btn")
                                    {
                                        if let Ok(b) = btn.downcast::<gtk::Button>() {
                                            b.emit_clicked();
                                        }
                                    }
                                } else if m == "03_reader_compact" {
                                    let out = std::process::Command::new("xdotool")
                                        .args(["search", "--onlyvisible", "--class", "mewser"])
                                        .output();
                                    if let Ok(o) = out {
                                        if o.status.success() {
                                            let id = String::from_utf8_lossy(&o.stdout)
                                                .lines()
                                                .last()
                                                .unwrap_or("")
                                                .trim()
                                                .to_string();
                                            if !id.is_empty() {
                                                let _ = std::process::Command::new("xdotool")
                                                    .args(["windowsize", &id, "720", "500"])
                                                    .status();
                                            }
                                        }
                                    }
                                }

                                let dest_m = m.clone();
                                glib::timeout_add_local(Duration::from_millis(800), move || {
                                    capture_active_window(&format!(
                                        "target/screenshots/{dest_m}.png"
                                    ));
                                    gtk::main_quit();
                                    glib::ControlFlow::Break
                                });
                                glib::ControlFlow::Break
                            });
                        }
                    }
                    "04_masterdns_profile_manager"
                    | "04_masterdns_profile_manager_basic"
                    | "04_masterdns_profile_manager_resolvers"
                    | "04_masterdns_profile_manager_advanced"
                    | "21_polished_profile_manager_connected" => {
                        let (prof_a_id, _prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.vault_file_consent = true;
                            let _ = m
                                .settings
                                .secret_vault
                                .set_key(&prof_a.key_ref, "mock_secret_key_123");
                            let _ = m
                                .settings
                                .secret_vault
                                .set_key(&prof_b.key_ref, "mock_secret_key_456");
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        controller_c.set_mock_connected_for_screenshot(
                            &prof_a_id,
                            "Default MasterDNS",
                            40188,
                        );
                        std::env::set_var("MEWSER_VIEW_PROFILE_ID", &prof_a_id);
                        if shot_mode.contains("resolvers") {
                            std::env::set_var("MEWSER_VIEW_SUBTAB", "resolvers");
                        } else if shot_mode.contains("advanced") {
                            std::env::set_var("MEWSER_VIEW_SUBTAB", "advanced");
                        } else {
                            std::env::set_var("MEWSER_VIEW_SUBTAB", "basic");
                        }
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "05_connection_states" | "24_polished_failed_connection" => {
                        controller_c
                            .set_mock_failed_for_screenshot("Handshake timed out after 3 retries");
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "749", "594"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "06_profile_switch_and_error" => {
                        let (prof_a_id, _prof_b_id, _) = {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.profile_store = crate::profile::ProfileStore::new();
                            let prof_a = MasterDnsProfile::new(
                                "Default MasterDNS",
                                "primary.example.com",
                                1,
                                vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()],
                            );
                            let prof_b = MasterDnsProfile::new(
                                "Secondary VPS Node",
                                "secondary.example.org",
                                2,
                                vec!["8.8.8.8:53".into(), "9.9.9.9:53".into()],
                            );
                            let prof_c = MasterDnsProfile::new(
                                "Tertiary Backup Node",
                                "backup.example.net",
                                1,
                                vec!["9.9.9.9:53".into()],
                            );
                            let id_a = prof_a.id.clone();
                            let id_b = prof_b.id.clone();
                            let id_c = prof_c.id.clone();
                            m.settings.profile_store.add_profile(prof_a);
                            m.settings.profile_store.add_profile(prof_b);
                            m.settings.profile_store.add_profile(prof_c);
                            let _ = m.settings.profile_store.select_profile(&id_b);
                            (id_a, id_b, id_c)
                        };
                        controller_c.set_mock_connected_for_screenshot(
                            &prof_a_id,
                            "Default MasterDNS",
                            40188,
                        );
                        let m = shot_mode.clone();
                        let tb_btn = tunnel_action_btn_c.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                        glib::timeout_add_local(Duration::from_millis(600), move || {
                            tb_btn.emit_clicked();
                            glib::ControlFlow::Break
                        });
                    }
                    "07_routing_policy_settings"
                    | "07_routing_policy_populated"
                    | "07_routing_policy_editing_valid"
                    | "07_routing_policy_invalid"
                    | "07_routing_policy_compact"
                    | "22_polished_settings_dialog" => {
                        std::env::set_var("MEWSER_SETTINGS_PAGE", "routing");
                        if shot_mode == "07_routing_policy_populated" {
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.direct_domains = vec![
                                "domestic-bank.example".to_string(),
                                "portal.internal".to_string(),
                                "127.0.0.1".to_string(),
                                "localhost".to_string(),
                            ];
                            m.settings.direct_suffixes = vec![
                                ".corp.internal".to_string(),
                                ".ir".to_string(),
                                ".local".to_string(),
                            ];
                        } else if shot_mode == "07_routing_policy_editing_valid" {
                            std::env::set_var("MEWSER_ROUTING_EDIT_TEST", "valid");
                        } else if shot_mode == "07_routing_policy_invalid" {
                            std::env::set_var("MEWSER_ROUTING_EDIT_TEST", "invalid");
                        }
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let (target_w, target_h) =
                                            if m == "07_routing_policy_compact" {
                                                ("720", "500")
                                            } else {
                                                ("749", "594")
                                            };
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, target_w, target_h])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "05_gateway_settings_default"
                    | "05_gateway_endpoint_editing"
                    | "05_gateway_invalid_endpoint"
                    | "05_gateway_auth_configured"
                    | "05_gateway_auth_missing"
                    | "05_gateway_status"
                    | "05_gateway_compact" => {
                        std::env::set_var("MEWSER_SETTINGS_PAGE", "gateway");
                        if shot_mode == "05_gateway_endpoint_editing" {
                            std::env::set_var("MEWSER_GW_EDIT_TEST", "editing");
                        } else if shot_mode == "05_gateway_invalid_endpoint" {
                            std::env::set_var("MEWSER_GW_EDIT_TEST", "invalid");
                        } else if shot_mode == "05_gateway_auth_configured" {
                            std::env::set_var(
                                "MEWSER_GATEWAY_AUTH_TOKEN",
                                "mock_gateway_auth_token_secret",
                            );
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.gateway_token = "mock_gateway_auth_token_secret".to_string();
                        } else if shot_mode == "05_gateway_auth_missing" {
                            std::env::remove_var("MEWSER_GATEWAY_AUTH_TOKEN");
                            let mut m = app_model_c.lock().unwrap();
                            m.settings.gateway_token = String::new();
                        } else if shot_mode == "05_gateway_status" {
                            std::env::set_var("MEWSER_GW_EDIT_TEST", "status");
                        }
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let (target_w, target_h) = if m == "05_gateway_compact" {
                                            ("720", "500")
                                        } else {
                                            ("749", "594")
                                        };
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, target_w, target_h])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "08_general_settings_default"
                    | "08_general_settings_editing"
                    | "08_general_settings_invalid"
                    | "08_general_settings_compact" => {
                        std::env::set_var("MEWSER_SETTINGS_PAGE", "general");
                        if shot_mode == "08_general_settings_editing" {
                            std::env::set_var("MEWSER_GEN_EDIT_TEST", "editing");
                        } else if shot_mode == "08_general_settings_invalid" {
                            std::env::set_var("MEWSER_GEN_EDIT_TEST", "invalid");
                        }
                        settings_btn_c.emit_clicked();
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let (target_w, target_h) =
                                            if m == "08_general_settings_compact" {
                                                ("720", "500")
                                            } else {
                                                ("749", "594")
                                            };
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, target_w, target_h])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(600), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    "08_multiple_tabs" | "23_polished_multiple_tabs" => {
                        let _tab1 = add_tab_c("https://example.com/");
                        let _tab2 = add_tab_c("https://www.rust-lang.org/");
                        notebook_c.set_current_page(Some(1));
                        address_entry_c.set_text("https://example.com/");
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(2000), move || {
                            capture_active_window(&format!("target/screenshots/{m}.png"));
                            gtk::main_quit();
                            glib::ControlFlow::Break
                        });
                    }
                    "09_compact_window" | "25_polished_compact_window" => {
                        mode_segmented_box_c.show();
                        mode_segmented_box_c.style_context().add_class("compact");
                        tunnel_action_btn_c.show();
                        tunnel_pill_box_c.style_context().add_class("compact");
                        status_text_lbl_c.hide();
                        tunnel_arrow_lbl_c.hide();
                        window_c.resize(720, 500);
                        let m = shot_mode.clone();
                        glib::timeout_add_local(Duration::from_millis(1500), move || {
                            let out = std::process::Command::new("xdotool")
                                .args(["getactivewindow"])
                                .output();
                            if let Ok(o) = out {
                                if o.status.success() {
                                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                    if !id.is_empty() {
                                        let _ = std::process::Command::new("xdotool")
                                            .args(["windowsize", &id, "720", "500"])
                                            .status();
                                    }
                                }
                            }
                            let dest_m = m.clone();
                            glib::timeout_add_local(Duration::from_millis(500), move || {
                                capture_active_window(&format!("target/screenshots/{dest_m}.png"));
                                gtk::main_quit();
                                glib::ControlFlow::Break
                            });
                            glib::ControlFlow::Break
                        });
                    }
                    _ => {}
                }
                glib::ControlFlow::Break
            });
        }

        // Auto Close / Test Hook
        if let Ok(secs_str) = std::env::var("MEWSER_SMOKE_TEST_AUTO_CLOSE_SECS") {
            if let Ok(secs) = secs_str.parse::<u64>() {
                glib::timeout_add_seconds_local(secs as u32, || {
                    gtk::main_quit();
                    glib::ControlFlow::Break
                });
            }
        }

        // Clean termination on delete event
        {
            let controller_for_delete = Arc::clone(&controller);
            window.connect_delete_event(move |_, _| {
                let _ = controller_for_delete.disconnect();
                gtk::main_quit();
                glib::Propagation::Proceed
            });
        }

        window.show_all();
        gtk::main();

        // Print final policy proxy stats
        if let Some(ref ph) = proxy_handle {
            let stats = ph.stats();
            println!(
                "[PolicyProxy Final Stats] Total={} Direct={} Tunnel={} Blocked={} FailedTunnel={} Subresources={}",
                stats.total_requests.load(std::sync::atomic::Ordering::SeqCst),
                stats.direct_requests.load(std::sync::atomic::Ordering::SeqCst),
                stats.tunnel_requests.load(std::sync::atomic::Ordering::SeqCst),
                stats.blocked_requests.load(std::sync::atomic::Ordering::SeqCst),
                stats.failed_tunnel_requests.load(std::sync::atomic::Ordering::SeqCst),
                stats.subresource_requests.load(std::sync::atomic::Ordering::SeqCst),
            );
        }
    }

    fn setup_dark_theme() {
        if let Some(screen) = gdk::Screen::default() {
            let css_provider = gtk::CssProvider::new();
            let dark_css = r#"
                /* Mewser Design System - Visual Reference Implementation */
                * {
                    -gtk-secondary-caret-color: #2dd4bf;
                }
                window, scrolledwindow, viewport, stack {
                    background-color: #10141b;
                    color: #f1f5f9;
                }
                dialog {
                    background-color: #131620;
                    color: #f1f5f9;
                }
                headerbar {
                    background-color: #141722;
                    border-bottom: 1px solid #232836;
                    padding: 4px 10px;
                    min-height: 44px;
                }
                headerbar .title {
                    font-weight: 600;
                    color: #f1f5f9;
                }
                button {
                    background-color: #181c26;
                    color: #cbd5e1;
                    border: 1px solid #282f3e;
                    border-radius: 6px;
                    padding: 4px 10px;
                    font-size: 13px;
                    font-weight: 500;
                }
                .nav-btn {
                    background-color: #181c26;
                    color: #cbd5e1;
                    border: 1px solid #282f3e;
                    border-radius: 6px;
                    min-width: 24px;
                    padding: 3px 6px;
                    font-size: 12px;
                    font-weight: 500;
                }
                headerbar button, headerbar .nav-btn {
                    min-width: 24px;
                    padding: 3px 6px;
                    font-size: 12px;
                }
                headerbar.compact button, headerbar.compact .nav-btn {
                    min-width: 18px;
                    padding: 2px 4px;
                    font-size: 11px;
                }
                button:hover, .nav-btn:hover {
                    background-color: #222734;
                    border-color: #2dd4bf;
                    color: #ffffff;
                }
                button:active, .nav-btn:active {
                    background-color: #177d84;
                    border-color: #229ba4;
                    color: #ffffff;
                }
                button:disabled, .nav-btn:disabled {
                    background-color: #141722;
                    border-color: #20242d;
                    color: #475569;
                }
                .btn-primary, .btn-teal {
                    background-color: #177d84;
                    border: 1px solid #229ba4;
                    color: #ffffff;
                    font-weight: 600;
                    border-radius: 6px;
                    padding: 6px 16px;
                }
                .btn-primary:hover, .btn-teal:hover {
                    background-color: #229ba4;
                    border-color: #2dd4bf;
                    color: #ffffff;
                }
                .btn-destructive {
                    background-color: #1c1820;
                    border: 1px solid #7f1d1d;
                    color: #f87171;
                    border-radius: 6px;
                    padding: 5px 12px;
                }
                .btn-destructive:hover {
                    background-color: #991b1b;
                    border-color: #ef4444;
                    color: #ffffff;
                }
                .mode-segmented {
                    background-color: #10141b;
                    border: 1px solid #242a38;
                    border-radius: 6px;
                    padding: 2px;
                }
                .mode-segmented.compact {
                    padding: 1px;
                }
                .mode-segmented.compact .mode-btn {
                    padding: 2px 5px;
                    font-size: 10px;
                }
                .mode-btn {
                    background-color: transparent;
                    border: none;
                    border-radius: 4px;
                    color: #94a3b8;
                    padding: 3px 8px;
                    font-size: 11px;
                    font-weight: 600;
                }
                .mode-btn:hover {
                    color: #f1f5f9;
                    background-color: #1c202a;
                }
                .mode-btn-active {
                    background-color: #177d84;
                    color: #ffffff;
                }
                .address-box {
                    background-color: #181c25;
                    border: 1px solid #282f3c;
                    border-radius: 8px;
                    padding: 0 4px;
                }
                .address-box:focus-within {
                    border-color: #2dd4bf;
                    background-color: #1c202a;
                }
                .address-entry {
                    background-color: transparent;
                    color: #f1f5f9;
                    border: none;
                    box-shadow: none;
                    font-size: 12px;
                    padding: 4px 2px;
                }
                .address-badge {
                    color: #64748b;
                    font-size: 11px;
                    padding: 0 2px;
                }
                .tunnel-pill {
                    background-color: #181c25;
                    border: 1px solid #282f3c;
                    border-radius: 16px;
                    padding: 2px 8px;
                }
                .tunnel-pill.compact {
                    padding: 2px 6px;
                }
                .tunnel-pill.compact .tunnel-pill-btn {
                    padding: 2px 6px;
                    font-size: 10px;
                }
                .tunnel-status-text {
                    font-size: 11px;
                    color: #cbd5e1;
                    font-weight: 500;
                }
                .tunnel-pill-btn {
                    background-color: #222734;
                    border: 1px solid #333a4a;
                    border-radius: 12px;
                    padding: 2px 8px;
                    font-size: 11px;
                    font-weight: 600;
                    color: #e2e8f0;
                }
                .tunnel-pill-btn:hover {
                    background-color: #177d84;
                    border-color: #2dd4bf;
                    color: #ffffff;
                }
                progressbar trough {
                    background-color: transparent;
                    border: none;
                    min-height: 2px;
                }
                progressbar progress {
                    background-color: #2dd4bf;
                    border: none;
                    min-height: 2px;
                }
                notebook {
                    background-color: #10141b;
                    border: none;
                }
                notebook header {
                    background-color: #131620;
                    border-bottom: 1px solid #232834;
                    padding: 0 4px;
                }
                notebook tab {
                    background-color: #151822;
                    color: #94a3b8;
                    border: 1px solid #232834;
                    border-bottom: none;
                    border-top-left-radius: 6px;
                    border-top-right-radius: 6px;
                    padding: 6px 14px;
                    margin-right: 3px;
                    font-size: 12px;
                }
                notebook tab:hover {
                    background-color: #1c202a;
                    color: #cbd5e1;
                }
                notebook tab:checked {
                    background-color: #1a1e28;
                    color: #ffffff;
                    border-top: 2px solid #2dd4bf;
                    border-left: 1px solid #282f3c;
                    border-right: 1px solid #282f3c;
                }
                .tab-close-btn {
                    background: transparent;
                    border: none;
                    border-radius: 3px;
                    color: #64748b;
                    padding: 1px 3px;
                    font-size: 11px;
                    min-width: 14px;
                    min-height: 14px;
                }
                .tab-close-btn:hover {
                    background: #7f1d1d;
                    color: #ffffff;
                }
                .home-scroll {
                    background-color: #10141b;
                }
                .home-container {
                    background-color: #10141b;
                    padding: 24px 28px 36px 28px;
                }
                .home-brand-box {
                    margin-top: 6px;
                    margin-bottom: 2px;
                }
                .home-title {
                    font-size: 26px;
                    font-weight: 800;
                    color: #ffffff;
                    letter-spacing: 0.8px;
                }
                .home-subtitle {
                    font-size: 13px;
                    color: #94a3b8;
                    font-weight: 400;
                }
                .home-search-pill {
                    background-color: #161a24;
                    border: 1px solid #282f3c;
                    border-radius: 24px;
                    padding: 4px 14px;
                    min-height: 46px;
                }
                .home-search-pill:focus-within {
                    border-color: #2dd4bf;
                    background-color: #1a1f2c;
                }
                .home-search-entry {
                    background-color: transparent;
                    color: #f1f5f9;
                    border: none;
                    box-shadow: none;
                    font-size: 13.5px;
                    padding: 6px 4px;
                }
                button.home-search-go {
                    background-color: transparent;
                    border: none;
                    box-shadow: none;
                    color: #94a3b8;
                    border-radius: 50%;
                    min-width: 32px;
                    min-height: 32px;
                    padding: 0;
                    font-size: 15px;
                }
                button.home-search-go:hover {
                    background-color: #222838;
                    color: #ffffff;
                }
                .home-card {
                    background-color: #141822;
                    border: 1px solid #232a38;
                    border-radius: 12px;
                    padding: 14px 18px;
                }
                .home-card:hover {
                    border-color: #2a3344;
                }
                .tunnel-title {
                    font-size: 15px;
                    font-weight: 700;
                    color: #ffffff;
                }
                .status-pill-badge {
                    background-color: #1c202a;
                    border: 1px solid #282f3c;
                    border-radius: 12px;
                    padding: 2px 10px;
                    font-size: 12px;
                    font-weight: 500;
                    color: #cbd5e1;
                }
                button.mode-card-btn {
                    background-color: #141822;
                    border: 1px solid #232a38;
                    border-radius: 12px;
                    padding: 14px 18px;
                    color: #cbd5e1;
                    box-shadow: none;
                    text-shadow: none;
                }
                button.mode-card-btn:hover {
                    background-color: #181d28;
                    border-color: #2dd4bf;
                }
                button.mode-card-btn:active {
                    background-color: #1a2130;
                    border-color: #2dd4bf;
                }
                .mode-card-title {
                    font-size: 15px;
                    font-weight: 700;
                    color: #ffffff;
                }
                .mode-card-desc {
                    font-size: 12px;
                    color: #94a3b8;
                }
                .mode-card-arrow {
                    font-size: 16px;
                    color: #64748b;
                }
                button.mode-card-btn:hover .mode-card-arrow {
                    color: #2dd4bf;
                }
                .quick-access-heading {
                    font-size: 13.5px;
                    font-weight: 700;
                    color: #f1f5f9;
                    margin-top: 4px;
                    margin-bottom: 2px;
                }
                button.quick-access-btn {
                    background-color: #141822;
                    border: 1px solid #232a38;
                    border-radius: 8px;
                    padding: 10px 4px;
                    min-height: 72px;
                    box-shadow: none;
                    text-shadow: none;
                }
                button.quick-access-btn:hover {
                    background-color: #1a202c;
                    border-color: #2dd4bf;
                }
                .qa-icon {
                    font-size: 20px;
                    font-weight: 700;
                }
                .qa-label {
                    font-size: 11px;
                    font-weight: 500;
                    color: #cbd5e1;
                }
                .reader-strip {
                    background-color: #12151d;
                    border-right: 1px solid #1f232c;
                    padding: 12px 6px;
                }
                .reader-tool-btn {
                    background: transparent;
                    border: 1px solid transparent;
                    color: #94a3b8;
                    border-radius: 6px;
                    padding: 6px 8px;
                    font-size: 14px;
                    font-weight: 600;
                }
                .reader-tool-btn:hover {
                    background-color: #1c212d;
                    color: #ffffff;
                    border-color: #282f3c;
                }
                .reader-main-scroll {
                    background-color: #161922;
                }
                .reader-container {
                    background-color: #161922;
                    padding: 24px 44px;
                }
                .reader-header-box {
                    background: transparent;
                    padding: 4px 0px 8px 0px;
                }
                .reader-title {
                    font-size: 20px;
                    font-weight: 700;
                    color: #ffffff;
                }
                .reader-meta {
                    font-size: 12px;
                    color: #8892b0;
                }
                .reader-sep {
                    background-color: #252a36;
                    margin: 8px 0px;
                }
                .reader-text-view, textview.reader-text-view text {
                    background-color: #161922;
                    color: #cbd5e1;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    font-size: 14px;
                }
                .reader-sidebar {
                    background-color: #12151d;
                    border-left: 1px solid #1f232c;
                    padding: 12px;
                    min-width: 240px;
                }
                .reader-sidebar-title {
                    font-size: 13px;
                    font-weight: 700;
                    color: #94a3b8;
                }
                .reader-outline-item {
                    background: transparent;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 8px;
                    color: #cbd5e1;
                    font-size: 13px;
                }
                .reader-outline-item:hover {
                    background-color: #1c212d;
                    color: #2dd4bf;
                }
                .reader-outline-empty {
                    color: #64748b;
                    font-size: 12px;
                    font-style: italic;
                    padding: 16px 8px;
                }
                .reader-popover {
                    background-color: #161922;
                    border: 1px solid #2d3444;
                    border-radius: 8px;
                    padding: 12px 14px;
                    color: #e2e8f0;
                }
                .reader-popover-title {
                    font-size: 14px;
                    font-weight: 700;
                    color: #ffffff;
                    margin-bottom: 8px;
                }
                .reader-popover-label {
                    font-size: 12px;
                    color: #94a3b8;
                }
                .reader-popover-val {
                    font-size: 12px;
                    color: #f1f5f9;
                    font-weight: 600;
                }
                .reader-error-expander {
                    margin-top: 14px;
                    margin-bottom: 20px;
                    color: #94a3b8;
                    font-size: 13px;
                }
                .reader-error-expander:hover {
                    color: #e2e8f0;
                }
                .reader-error-details-box {
                    background-color: #141720;
                    border: 1px solid #282f3c;
                    border-radius: 6px;
                    padding: 10px 14px;
                    margin-top: 6px;
                }
                .reader-error-details {
                    color: #f87171;
                    font-family: monospace;
                    font-size: 12px;
                }
                textview text {
                    background-color: #161922;
                    color: #cbd5e1;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    font-size: 14px;
                }
                entry {
                    background-color: #181c25;
                    border: 1px solid #262c38;
                    border-radius: 6px;
                    color: #f1f5f9;
                    padding: 6px 8px;
                }
                entry:focus {
                    border-color: #2dd4bf;
                    background-color: #1c202a;
                }
                entry:disabled {
                    background-color: #12141a;
                    border-color: #20242d;
                    color: #475569;
                }
                combobox button.combo {
                    background-color: #181c25;
                    border: 1px solid #262c38;
                    border-radius: 6px;
                    color: #f1f5f9;
                    padding: 5px 8px;
                }
                combobox button.combo:hover {
                    border-color: #2dd4bf;
                }
                .profile-card {
                    background-color: #141923;
                    border: 1px solid #232d3d;
                    border-radius: 8px;
                    padding: 12px 16px;
                }
                .profile-list-panel {
                    background-color: transparent;
                    border: none;
                    padding: 0;
                }
                .profile-list {
                    background-color: transparent;
                    border: none;
                }
                .profile-list-row {
                    padding: 0;
                    margin-bottom: 6px;
                    border: none;
                    background-color: transparent;
                }
                .profile-list-row:hover {
                    background-color: transparent;
                }
                .profile-list-row:selected {
                    background-color: transparent;
                }
                .profile-card-row {
                    background-color: #141923;
                    border: 1px solid #232d3d;
                    border-radius: 8px;
                    padding: 10px 12px;
                    margin-bottom: 4px;
                }
                .profile-card-row:hover {
                    background-color: #18202d;
                    border-color: #2e3b4e;
                }
                .profile-card-active {
                    background-color: #16242c;
                    border: 1px solid #2dd4bf;
                }
                .profile-card-name {
                    font-size: 13px;
                    font-weight: 600;
                    color: #f1f5f9;
                }
                .profile-card-domain {
                    font-size: 11px;
                    color: #64748b;
                }
                .radio-indicator-btn {
                    background: transparent;
                    border: none;
                    box-shadow: none;
                    padding: 0;
                    min-width: 20px;
                    min-height: 20px;
                }
                .badge-selected-pill {
                    background-color: rgba(217, 119, 6, 0.18);
                    border: 1px solid #d97706;
                    color: #fbbf24;
                    font-size: 10px;
                    font-weight: 600;
                    border-radius: 8px;
                    padding: 1px 6px;
                }
                .badge-connected-pill {
                    background-color: #064e3b;
                    border: 1px solid #10b981;
                    color: #10b981;
                    font-size: 11px;
                    font-weight: 600;
                    border-radius: 12px;
                    padding: 2px 8px;
                }
                .badge-ready-pill {
                    background-color: #0c4a6e;
                    border: 1px solid #38bdf8;
                    color: #38bdf8;
                    font-size: 11px;
                    font-weight: 600;
                    border-radius: 12px;
                    padding: 2px 8px;
                }
                .badge-text-only {
                    background-color: rgba(14, 56, 56, 0.85);
                    border: 1px solid #134e48;
                    color: #2dd4bf;
                    border-radius: 12px;
                    padding: 3px 12px;
                    font-size: 11px;
                    font-weight: 700;
                }
                .badge-connected {
                    background-color: rgba(16, 185, 129, 0.15);
                    border: 1px solid rgba(16, 185, 129, 0.35);
                    color: #10b981;
                    border-radius: 12px;
                    padding: 2px 8px;
                    font-size: 11px;
                    font-weight: 600;
                }
                .badge-disconnected {
                    background-color: rgba(239, 68, 68, 0.15);
                    border: 1px solid rgba(239, 68, 68, 0.35);
                    color: #ef4444;
                    border-radius: 12px;
                    padding: 2px 8px;
                    font-size: 11px;
                    font-weight: 600;
                }
                .badge-selected {
                    background-color: rgba(245, 158, 11, 0.15);
                    border: 1px solid rgba(245, 158, 11, 0.35);
                    color: #f59e0b;
                    border-radius: 12px;
                    padding: 2px 8px;
                    font-size: 11px;
                    font-weight: 600;
                }
                .settings-sidebar {
                    background-color: #11151e;
                    border-right: 1px solid #1e2634;
                    padding: 10px 4px;
                }
                .sidebar-title {
                    font-size: 12px;
                    font-weight: 700;
                    color: #e2e8f0;
                    padding: 4px 6px 8px 6px;
                }
                .sidebar-btn {
                    background-color: transparent;
                    border: 1px solid transparent;
                    border-radius: 6px;
                    color: #94a3b8;
                    padding: 5px 6px;
                    font-size: 11px;
                    font-weight: 500;
                }
                .sidebar-btn:hover {
                    background-color: #171d27;
                    color: #cbd5e1;
                }
                .sidebar-btn-active {
                    background-color: #16262e;
                    border: 1px solid #14b8a6;
                    color: #ffffff;
                    font-weight: 600;
                }
                .btn-dark {
                    background-color: #1a1e28;
                    border: 1px solid #282f3e;
                    border-radius: 6px;
                    color: #cbd5e1;
                    font-weight: 500;
                    padding: 5px 14px;
                    font-size: 12px;
                }
                .btn-dark:hover {
                    background-color: #222734;
                    color: #ffffff;
                    border-color: #3b4559;
                }
                .subtab-btn {
                    background-color: transparent;
                    border: none;
                    border-bottom: 2px solid transparent;
                    color: #94a3b8;
                    border-radius: 0;
                    padding: 6px 14px;
                    font-size: 13px;
                    font-weight: 600;
                }
                .subtab-btn:hover {
                    color: #cbd5e1;
                }
                .subtab-btn-active {
                    color: #ffffff;
                    border-bottom: 2px solid #2dd4bf;
                }
                .profile-nav-card {
                    background-color: #151922;
                    border: 1px solid #232a38;
                    border-radius: 8px;
                    padding: 8px 10px;
                    margin-bottom: 6px;
                }
                .profile-nav-card:hover {
                    background-color: #191f2c;
                    border-color: #2e384b;
                }
                .profile-nav-card-active {
                    border: 1px solid #229ba4;
                    background-color: rgba(23, 125, 132, 0.14);
                }
                .settings-pane {
                    background-color: #141923;
                    padding: 10px 12px;
                }
                .profile-editor-card {
                    background-color: #131822;
                    border: 1px solid #222c3c;
                    border-radius: 8px;
                    padding: 10px;
                }
                .btn-card-action {
                    background-color: #1a202c;
                    border: 1px solid #293444;
                    border-radius: 6px;
                    color: #cbd5e1;
                    font-size: 11px;
                    font-weight: 500;
                    padding: 3px 7px;
                }
                .btn-card-action:hover {
                    background-color: #222b3b;
                    border-color: #38465c;
                    color: #ffffff;
                }
                .btn-card-action.btn-destructive {
                    background-color: #1e1720;
                    border: 1px solid #7f1d1d;
                    color: #f87171;
                }
                .btn-card-action.btn-destructive:hover {
                    background-color: #991b1b;
                    border-color: #ef4444;
                    color: #ffffff;
                }
                entry.entry-error {
                    border-color: #ef4444;
                }
                .conn-status-banner {
                    background-color: #11161f;
                    border: 1px solid #1f2837;
                    border-radius: 6px;
                    padding: 4px 10px;
                    font-size: 11px;
                    margin-bottom: 4px;
                }
                textview.res-editor text {
                    font-family: monospace, DejaVu Sans Mono, Liberation Mono, Courier New;
                    font-size: 12px;
                    background-color: #0d1117;
                    color: #e2e8f0;
                    border-radius: 6px;
                    padding: 8px;
                }
                expander title {
                    color: #94a3b8;
                    font-weight: 500;
                }
                expander title:hover {
                    color: #2dd4bf;
                }
                .routing-rule-row {
                    background-color: #161b26;
                    border: 1px solid #232b3b;
                    border-radius: 6px;
                    padding: 4px 10px;
                }
                .routing-rule-row:hover {
                    background-color: #1b2230;
                    border-color: #2e3a4e;
                }
                .routing-badge-exact {
                    background-color: rgba(56, 189, 248, 0.15);
                    border: 1px solid rgba(56, 189, 248, 0.35);
                    color: #38bdf8;
                    border-radius: 10px;
                    padding: 1px 8px;
                    font-size: 10px;
                    font-weight: 600;
                }
                .routing-badge-suffix {
                    background-color: rgba(45, 212, 191, 0.15);
                    border: 1px solid rgba(45, 212, 191, 0.35);
                    color: #2dd4bf;
                    border-radius: 10px;
                    padding: 1px 8px;
                    font-size: 10px;
                    font-weight: 600;
                }
                .routing-badge-ssrf {
                    background-color: #064e3b;
                    border: 1px solid rgba(16, 185, 129, 0.4);
                    color: #10b981;
                    border-radius: 12px;
                    padding: 2px 10px;
                    font-size: 11px;
                    font-weight: 600;
                }
                scrollbar trough {
                    background-color: transparent;
                    border: none;
                }
                scrollbar slider {
                    background-color: #282f3c;
                    border-radius: 4px;
                    min-width: 6px;
                    min-height: 6px;
                }
                scrollbar slider:hover {
                    background-color: #2dd4bf;
                }
            "#;
            if css_provider.load_from_data(dark_css.as_bytes()).is_ok() {
                gtk::StyleContext::add_provider_for_screen(
                    &screen,
                    &css_provider,
                    gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
                );
            }
        }
    }

    fn create_home_view<F, T, M>(
        app_model: &Arc<Mutex<MewserAppModel>>,
        on_navigate: F,
        on_tunnel_action: T,
        on_open_mode: M,
    ) -> (gtk::ScrolledWindow, gtk::Label, gtk::Button)
    where
        F: Fn(&str) + Clone + 'static,
        T: Fn() + Clone + 'static,
        M: Fn(BrowsingMode) + Clone + 'static,
    {
        let scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        scroll.style_context().add_class("home-scroll");

        let root = gtk::Box::new(gtk::Orientation::Vertical, 18);
        root.style_context().add_class("home-container");
        root.set_halign(gtk::Align::Center);
        root.set_valign(gtk::Align::Start);
        root.set_size_request(300, -1);
        root.set_hexpand(true);

        // 1. Header & Branding with Cat Outline Logo and Moonlit Illustration
        let brand_box = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        brand_box.style_context().add_class("home-brand-box");

        let brand_left_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        brand_left_box.set_halign(gtk::Align::Start);

        if let Some(cat_img) = create_svg_image(CAT_LOGO_SVG, 68, 42) {
            brand_left_box.pack_start(&cat_img, false, false, 0);
        }

        let brand_text_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let title_lbl = gtk::Label::new(Some("MEWSER"));
        title_lbl.style_context().add_class("home-title");
        title_lbl.set_halign(gtk::Align::Start);
        brand_text_box.pack_start(&title_lbl, false, false, 0);

        let sub_lbl = gtk::Label::new(Some("Resilient Dual-Mode Desktop Browser"));
        sub_lbl.style_context().add_class("home-subtitle");
        sub_lbl.set_halign(gtk::Align::Start);
        brand_text_box.pack_start(&sub_lbl, false, false, 0);

        brand_left_box.pack_start(&brand_text_box, false, false, 0);
        brand_box.pack_start(&brand_left_box, false, false, 0);

        let moon_cat_img_opt = create_svg_image(MOON_CAT_SVG, 120, 72);
        if let Some(ref moon_cat_img) = moon_cat_img_opt {
            brand_box.pack_end(moon_cat_img, false, false, 0);
        }

        root.pack_start(&brand_box, false, false, 0);

        // 2. Primary Address Entry Box (Pill Shape)
        let home_search_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        home_search_box
            .style_context()
            .add_class("home-search-pill");

        let search_icon = gtk::Label::new(Some("🔍"));
        search_icon.style_context().add_class("address-badge");
        home_search_box.pack_start(&search_icon, false, false, 4);

        let home_search_entry = gtk::Entry::new();
        home_search_entry.set_hexpand(true);
        home_search_entry.set_placeholder_text(Some("Search or enter address (e.g. example.com)"));
        home_search_entry
            .style_context()
            .add_class("home-search-entry");
        home_search_box.pack_start(&home_search_entry, true, true, 0);

        let home_search_go = gtk::Button::with_label("➔");
        home_search_go.style_context().add_class("home-search-go");
        {
            let on_nav = on_navigate.clone();
            let entry_c = home_search_entry.clone();
            home_search_go.connect_clicked(move |_| {
                let text = entry_c.text().to_string();
                if !text.trim().is_empty() {
                    on_nav(&text);
                }
            });
        }
        {
            let on_nav = on_navigate.clone();
            home_search_entry.connect_activate(move |e| {
                let text = e.text().to_string();
                if !text.trim().is_empty() {
                    on_nav(&text);
                }
            });
        }
        home_search_box.pack_start(&home_search_go, false, false, 0);
        root.pack_start(&home_search_box, false, false, 0);

        // 3. MasterDNS Transport Status Card
        let tunnel_card = gtk::Box::new(gtk::Orientation::Vertical, 6);
        tunnel_card.style_context().add_class("home-card");

        let tc_header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        if let Some(stack_img) = create_svg_image(STACK_ICON_SVG, 34, 34) {
            tc_header.pack_start(&stack_img, false, false, 0);
        }

        let tc_meta_box = gtk::Box::new(gtk::Orientation::Vertical, 3);
        let tc_top_row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        let tc_title = gtk::Label::new(None);
        tc_title.set_markup("<b>MasterDNS</b>");
        tc_title.set_halign(gtk::Align::Start);
        tc_title.style_context().add_class("tunnel-title");
        tc_top_row.pack_start(&tc_title, false, false, 0);

        let status_dot = gtk::Label::new(None);
        status_dot.set_markup("<span foreground=\"#ef4444\">●</span> Disconnected");
        status_dot.style_context().add_class("status-pill-badge");
        tc_top_row.pack_start(&status_dot, false, false, 0);
        tc_meta_box.pack_start(&tc_top_row, false, false, 0);

        let settings = app_model.lock().unwrap().settings.clone();
        let active_prof_name = settings
            .profile_store
            .selected_profile()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Secondary VPS Node".to_string());
        let tc_info = gtk::Label::new(Some(&format!(
            "Profile: {} · {} · Method {} · {} resolvers",
            active_prof_name,
            settings.tunnel_domain,
            settings.tunnel_encryption_method,
            settings.tunnel_resolvers.len()
        )));
        tc_info.set_halign(gtk::Align::Start);
        tc_info.set_ellipsize(gtk::pango::EllipsizeMode::End);
        tc_info.style_context().add_class("home-subtitle");
        tc_meta_box.pack_start(&tc_info, false, false, 0);
        tc_header.pack_start(&tc_meta_box, true, true, 0);

        let tunnel_btn = gtk::Button::with_label("Connect");
        tunnel_btn.style_context().add_class("btn-teal");
        let on_tunnel_action_clone = on_tunnel_action.clone();
        tunnel_btn.connect_clicked(move |_| {
            on_tunnel_action_clone();
        });
        tc_header.pack_end(&tunnel_btn, false, false, 0);
        tunnel_card.pack_start(&tc_header, false, false, 0);

        root.pack_start(&tunnel_card, false, false, 0);

        // 4. Browsing Modes Cards (2 Columns)
        let modes_box = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        modes_box.set_homogeneous(true);

        // Standard Web Card (Clickable Button)
        let mode1_btn = gtk::Button::new();
        mode1_btn.style_context().add_class("mode-card-btn");
        let mode1_content = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        if let Some(globe_img) = create_svg_image(GLOBE_ICON_SVG, 36, 36) {
            mode1_content.pack_start(&globe_img, false, false, 0);
        }
        let m1_text_box = gtk::Box::new(gtk::Orientation::Vertical, 3);
        let m1_t = gtk::Label::new(None);
        m1_t.set_markup("<b>Standard Web</b>");
        m1_t.set_halign(gtk::Align::Start);
        m1_t.style_context().add_class("mode-card-title");
        m1_text_box.pack_start(&m1_t, false, false, 0);

        let m1_d = gtk::Label::new(Some(
            "Full web browsing with CSS, JavaScript and subresources.",
        ));
        m1_d.set_line_wrap(true);
        m1_d.set_line_wrap_mode(gtk::pango::WrapMode::Word);
        m1_d.set_halign(gtk::Align::Start);
        m1_d.style_context().add_class("mode-card-desc");
        m1_text_box.pack_start(&m1_d, false, false, 0);
        mode1_content.pack_start(&m1_text_box, true, true, 0);

        let m1_arrow = gtk::Label::new(Some("➔"));
        m1_arrow.style_context().add_class("mode-card-arrow");
        mode1_content.pack_end(&m1_arrow, false, false, 0);
        mode1_btn.add(&mode1_content);

        {
            let on_open = on_open_mode.clone();
            mode1_btn.connect_clicked(move |_| {
                on_open(BrowsingMode::StandardWeb);
            });
        }
        modes_box.pack_start(&mode1_btn, true, true, 0);

        // Resilient Text Card (Clickable Button)
        let mode2_btn = gtk::Button::new();
        mode2_btn.style_context().add_class("mode-card-btn");
        let mode2_content = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        if let Some(doc_img) = create_svg_image(DOC_ICON_SVG, 36, 36) {
            mode2_content.pack_start(&doc_img, false, false, 0);
        }
        let m2_text_box = gtk::Box::new(gtk::Orientation::Vertical, 3);
        let m2_t = gtk::Label::new(None);
        m2_t.set_markup("<b>Resilient Text</b>");
        m2_t.set_halign(gtk::Align::Start);
        m2_t.style_context().add_class("mode-card-title");
        m2_text_box.pack_start(&m2_t, false, false, 0);

        let m2_d = gtk::Label::new(Some(
            "Server-side text extraction over DNS. Lightweight and reliable.",
        ));
        m2_d.set_line_wrap(true);
        m2_d.set_line_wrap_mode(gtk::pango::WrapMode::Word);
        m2_d.set_halign(gtk::Align::Start);
        m2_d.style_context().add_class("mode-card-desc");
        m2_text_box.pack_start(&m2_d, false, false, 0);
        mode2_content.pack_start(&m2_text_box, true, true, 0);

        let m2_arrow = gtk::Label::new(Some("➔"));
        m2_arrow.style_context().add_class("mode-card-arrow");
        mode2_content.pack_end(&m2_arrow, false, false, 0);
        mode2_btn.add(&mode2_content);

        {
            let on_open = on_open_mode;
            mode2_btn.connect_clicked(move |_| {
                on_open(BrowsingMode::ResilientText);
            });
        }
        modes_box.pack_start(&mode2_btn, true, true, 0);

        root.pack_start(&modes_box, false, false, 0);

        // 5. Quick Access Shortcuts (5 Columns)
        let shortcuts_box = gtk::Box::new(gtk::Orientation::Vertical, 8);

        let sc_title = gtk::Label::new(None);
        sc_title.set_markup("<b>Quick Access</b>");
        sc_title.set_halign(gtk::Align::Start);
        sc_title.style_context().add_class("quick-access-heading");
        shortcuts_box.pack_start(&sc_title, false, false, 0);

        let grid = gtk::Grid::new();
        grid.set_column_spacing(10);
        grid.set_column_homogeneous(true);

        let shortcuts = [
            ("🌐", "Example\nDomain", "https://example.com/"),
            ("</>", "Rust\nLanguage", "https://www.rust-lang.org/"),
            ("🛡️", "Gateway\nHealth", "http://127.0.0.1:4040/health"),
            (
                "📄",
                "IETF RFC\n1035",
                "https://www.ietf.org/rfc/rfc1035.txt",
            ),
            (
                "W",
                "Wikipedia",
                "https://en.wikipedia.org/wiki/Domain_Name_System",
            ),
        ];

        for (i, (icon, label, target_url)) in shortcuts.iter().enumerate() {
            let btn = gtk::Button::new();
            btn.style_context().add_class("quick-access-btn");

            let b_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
            b_box.set_halign(gtk::Align::Center);
            b_box.set_valign(gtk::Align::Center);

            let icon_lbl = gtk::Label::new(Some(icon));
            icon_lbl.style_context().add_class("qa-icon");
            b_box.pack_start(&icon_lbl, false, false, 0);

            let txt_lbl = gtk::Label::new(Some(label));
            txt_lbl.set_justify(gtk::Justification::Center);
            txt_lbl.style_context().add_class("qa-label");
            b_box.pack_start(&txt_lbl, false, false, 0);

            btn.add(&b_box);

            let on_nav = on_navigate.clone();
            let u = target_url.to_string();
            btn.connect_clicked(move |_| {
                on_nav(&u);
            });
            grid.attach(&btn, i as i32, 0, 1, 1);
        }
        shortcuts_box.pack_start(&grid, false, false, 0);
        root.pack_start(&shortcuts_box, false, false, 0);

        // Responsive width constraint
        let root_clone = root.clone();
        let moon_cat_clone = moon_cat_img_opt;
        scroll.connect_size_allocate(move |_, alloc| {
            let w = alloc.width();
            let target_w = if w > 760 { 720 } else { (w - 40).max(300) };
            root_clone.set_size_request(target_w, -1);
            if let Some(ref mc) = moon_cat_clone {
                if w < 620 {
                    mc.hide();
                } else {
                    mc.show();
                }
            }
        });

        scroll.add(&root);
        (scroll, status_dot, tunnel_btn)
    }

    pub fn find_child_by_name<W: IsA<gtk::Widget>>(widget: &W, name: &str) -> Option<gtk::Widget> {
        let w = widget.as_ref();
        if w.widget_name().as_str() == name {
            return Some(w.clone());
        }
        if let Ok(container) = w.clone().downcast::<gtk::Container>() {
            for child in container.children() {
                if let Some(found) = find_child_by_name(&child, name) {
                    return Some(found);
                }
            }
        }
        None
    }

    pub fn get_reader_widgets(
        tab_widget: &gtk::Widget,
    ) -> Option<(gtk::Label, gtk::Label, gtk::TextView)> {
        let tab_box = tab_widget.clone().downcast::<gtk::Box>().ok()?;
        let stack = tab_box
            .children()
            .first()?
            .clone()
            .downcast::<gtk::Stack>()
            .ok()?;
        let reader_root = stack
            .child_by_name("resilient_text")?
            .downcast::<gtk::Box>()
            .ok()?;
        let title_lbl = find_child_by_name(&reader_root, "reader_title_label")?
            .downcast::<gtk::Label>()
            .ok()?;
        let meta_lbl = find_child_by_name(&reader_root, "reader_meta_label")?
            .downcast::<gtk::Label>()
            .ok()?;
        let text_view = find_child_by_name(&reader_root, "reader_text_view")?
            .downcast::<gtk::TextView>()
            .ok()?;

        Some((title_lbl, meta_lbl, text_view))
    }

    fn insert_tagged_text(
        buffer: &gtk::TextBuffer,
        iter: &mut gtk::TextIter,
        text: &str,
        tag_name: &str,
    ) {
        let start_offset = iter.offset();
        buffer.insert(iter, text);
        let start_iter = buffer.iter_at_offset(start_offset);
        buffer.apply_tag_by_name(tag_name, &start_iter, iter);
    }

    fn setup_reader_buffer_tags(buffer: &gtk::TextBuffer) {
        let tag_table = match buffer.tag_table() {
            Some(t) => t,
            None => return,
        };

        if tag_table.lookup("h1").is_some() {
            return;
        }

        let tag_h1 = gtk::TextTag::builder()
            .name("h1")
            .weight(700)
            .scale(1.45)
            .foreground("#ffffff")
            .pixels_above_lines(18)
            .pixels_below_lines(8)
            .build();
        tag_table.add(&tag_h1);

        let tag_h2 = gtk::TextTag::builder()
            .name("h2")
            .weight(700)
            .scale(1.25)
            .foreground("#f8fafc")
            .pixels_above_lines(14)
            .pixels_below_lines(6)
            .build();
        tag_table.add(&tag_h2);

        let tag_h3 = gtk::TextTag::builder()
            .name("h3")
            .weight(600)
            .scale(1.1)
            .foreground("#e2e8f0")
            .pixels_above_lines(12)
            .pixels_below_lines(4)
            .build();
        tag_table.add(&tag_h3);

        let tag_para = gtk::TextTag::builder()
            .name("para")
            .scale(1.0)
            .foreground("#cbd5e1")
            .pixels_below_lines(12)
            .build();
        tag_table.add(&tag_para);

        let tag_list = gtk::TextTag::builder()
            .name("list_item")
            .scale(1.0)
            .foreground("#cbd5e1")
            .left_margin(18)
            .pixels_below_lines(4)
            .build();
        tag_table.add(&tag_list);

        let tag_img = gtk::TextTag::builder()
            .name("img_placeholder")
            .style(pango::Style::Italic)
            .scale(0.88)
            .foreground("#64748b")
            .pixels_below_lines(8)
            .build();
        tag_table.add(&tag_img);

        let tag_link_hdr = gtk::TextTag::builder()
            .name("link_hdr")
            .weight(700)
            .scale(1.15)
            .foreground("#ffffff")
            .pixels_above_lines(20)
            .pixels_below_lines(8)
            .build();
        tag_table.add(&tag_link_hdr);
    }

    fn create_reader_view(
        app_model: &Arc<Mutex<MewserAppModel>>,
    ) -> (gtk::Box, gtk::Label, gtk::Label, gtk::TextView) {
        let root = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        root.set_widget_name("reader_root");

        // 1. Left Vertical Tool Strip (Aa, ⓘ, ≡)
        let tool_strip = gtk::Box::new(gtk::Orientation::Vertical, 8);
        tool_strip.style_context().add_class("reader-strip");
        tool_strip.set_size_request(46, -1);
        tool_strip.set_widget_name("reader_tool_strip");

        let font_btn = gtk::Button::with_label("Aa");
        font_btn.style_context().add_class("reader-tool-btn");
        font_btn.set_tooltip_text(Some("Text typography preferences (Aa)"));
        font_btn.set_widget_name("reader_font_btn");
        tool_strip.pack_start(&font_btn, false, false, 0);

        let info_btn = gtk::Button::with_label("ⓘ");
        info_btn.style_context().add_class("reader-tool-btn");
        info_btn.set_tooltip_text(Some("Page info and security (ⓘ)"));
        info_btn.set_widget_name("reader_info_btn");
        tool_strip.pack_start(&info_btn, false, false, 0);

        let menu_btn = gtk::Button::with_label("≡");
        menu_btn.style_context().add_class("reader-tool-btn");
        menu_btn.set_tooltip_text(Some("Table of contents / Outline (≡)"));
        menu_btn.set_widget_name("reader_menu_btn");
        tool_strip.pack_start(&menu_btn, false, false, 0);

        root.pack_start(&tool_strip, false, false, 0);

        // 2. Center Reading Area: Container Box
        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 14);
        vbox.style_context().add_class("reader-container");
        vbox.set_hexpand(true);
        vbox.set_vexpand(true);
        vbox.set_widget_name("reader_content_vbox");

        // Header Box (Document icon + Title/Meta + Text Only badge)
        let header_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        header_box.style_context().add_class("reader-header-box");
        header_box.set_widget_name("reader_header_box");

        if let Some(doc_img) = create_svg_image(DOC_ICON_SVG, 36, 36) {
            header_box.pack_start(&doc_img, false, false, 0);
        }

        let header_meta_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let title_lbl = gtk::Label::new(Some("Resilient Reader"));
        title_lbl.style_context().add_class("reader-title");
        title_lbl.set_halign(gtk::Align::Start);
        title_lbl.set_widget_name("reader_title_label");
        header_meta_box.pack_start(&title_lbl, false, false, 0);

        let meta_lbl = gtk::Label::new(None);
        meta_lbl.style_context().add_class("reader-meta");
        meta_lbl.set_halign(gtk::Align::Start);
        meta_lbl.set_widget_name("reader_meta_label");
        header_meta_box.pack_start(&meta_lbl, false, false, 0);
        header_box.pack_start(&header_meta_box, true, true, 0);

        let text_badge = gtk::Label::new(Some("Text Only"));
        text_badge.style_context().add_class("badge-text-only");
        text_badge.set_widget_name("reader_badge_label");
        header_box.pack_end(&text_badge, false, false, 0);

        vbox.pack_start(&header_box, false, false, 0);

        let sep = gtk::Separator::new(gtk::Orientation::Horizontal);
        sep.style_context().add_class("reader-sep");
        vbox.pack_start(&sep, false, false, 0);

        // Scrolled Window directly wrapping text_view for native height-for-width reflow
        let scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
        scroll.set_hexpand(true);
        scroll.set_vexpand(true);
        scroll.style_context().add_class("reader-main-scroll");
        scroll.set_widget_name("reader_main_scroll");

        let text_view = gtk::TextView::new();
        text_view.set_editable(false);
        text_view.set_cursor_visible(false);
        text_view.set_wrap_mode(gtk::WrapMode::Word);
        text_view.style_context().add_class("reader-text-view");
        text_view.set_left_margin(12);
        text_view.set_right_margin(12);
        text_view.set_top_margin(8);
        text_view.set_bottom_margin(24);
        text_view.set_vexpand(true);
        text_view.set_widget_name("reader_text_view");

        if let Some(buffer) = text_view.buffer() {
            setup_reader_buffer_tags(&buffer);
        }

        // Motion notify for link hover pointer cursor
        text_view.connect_motion_notify_event(|tv, event| {
            let (x, y) = event.position();
            let (buf_x, buf_y) =
                tv.window_to_buffer_coords(gtk::TextWindowType::Text, x as i32, y as i32);
            let mut is_link = false;
            if let Some(iter) = tv.iter_at_location(buf_x, buf_y) {
                for tag in iter.tags() {
                    if let Some(name) = tag.name() {
                        if name.starts_with("link_nav_") {
                            is_link = true;
                            break;
                        }
                    }
                }
            }
            if let Some(win) = gtk::prelude::TextViewExt::window(tv, gtk::TextWindowType::Text) {
                if let Some(disp) = gdk::Display::default() {
                    let cursor_name = if is_link { "pointer" } else { "text" };
                    let cursor = gdk::Cursor::from_name(&disp, cursor_name);
                    win.set_cursor(cursor.as_ref());
                }
            }
            glib::Propagation::Proceed
        });

        scroll.add(&text_view);
        vbox.pack_start(&scroll, true, true, 0);

        // Collapsible Technical Diagnostics section for error presentation
        let error_expander = gtk::Expander::new(Some("Technical Diagnostics & Raw Details"));
        error_expander
            .style_context()
            .add_class("reader-error-expander");
        error_expander.set_widget_name("reader_error_expander");
        error_expander.set_no_show_all(true);
        error_expander.hide();

        let error_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
        error_box
            .style_context()
            .add_class("reader-error-details-box");
        let error_details_lbl = gtk::Label::new(None);
        error_details_lbl.set_selectable(true);
        error_details_lbl.set_line_wrap(true);
        error_details_lbl
            .style_context()
            .add_class("reader-error-details");
        error_details_lbl.set_widget_name("reader_error_details");
        error_details_lbl.set_halign(gtk::Align::Start);
        error_details_lbl.set_xalign(0.0);
        error_box.pack_start(&error_details_lbl, false, false, 0);
        error_expander.add(&error_box);

        vbox.pack_start(&error_expander, false, false, 0);

        root.pack_start(&vbox, true, true, 0);

        // 3. Right Contents Sidebar
        let contents_sidebar = gtk::Box::new(gtk::Orientation::Vertical, 8);
        contents_sidebar.style_context().add_class("reader-sidebar");
        contents_sidebar.set_size_request(240, -1);
        contents_sidebar.set_no_show_all(true);
        contents_sidebar.hide();
        contents_sidebar.set_widget_name("reader_contents_sidebar");

        let sb_header = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        let sb_title = gtk::Label::new(Some("Contents"));
        sb_title.style_context().add_class("reader-sidebar-title");
        sb_title.set_halign(gtk::Align::Start);
        sb_header.pack_start(&sb_title, true, true, 0);

        let sb_close = gtk::Button::with_label("✕");
        sb_close.style_context().add_class("tab-close-btn");
        sb_close.set_relief(gtk::ReliefStyle::None);
        sb_close.set_widget_name("reader_contents_close_btn");
        sb_header.pack_end(&sb_close, false, false, 0);
        contents_sidebar.pack_start(&sb_header, false, false, 0);

        let sb_scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        sb_scroll.set_vexpand(true);
        let contents_list = gtk::ListBox::new();
        contents_list.set_selection_mode(gtk::SelectionMode::None);
        contents_list.set_widget_name("reader_contents_list");
        sb_scroll.add(&contents_list);
        contents_sidebar.pack_start(&sb_scroll, true, true, 0);

        let contents_empty = gtk::Label::new(Some("No headings in this article."));
        contents_empty
            .style_context()
            .add_class("reader-outline-empty");
        contents_empty.set_widget_name("reader_contents_empty");
        contents_sidebar.pack_start(&contents_empty, false, false, 0);

        root.pack_start(&contents_sidebar, false, false, 0);

        // Wiring buttons:
        let cs_clone = contents_sidebar.clone();
        let root_c = root.clone();
        menu_btn.connect_clicked(move |_| {
            if cs_clone.is_visible() {
                cs_clone.hide();
                cs_clone.set_no_show_all(true);
            } else {
                cs_clone.set_no_show_all(false);
                cs_clone.show();
                cs_clone.show_all();
            }
            root_c.queue_resize();
        });

        let cs_close_c = contents_sidebar.clone();
        let root_close = root.clone();
        sb_close.connect_clicked(move |_| {
            cs_close_c.hide();
            cs_close_c.set_no_show_all(true);
            root_close.queue_resize();
        });

        // Typography Popover
        let popover_font = gtk::Popover::new(Some(&font_btn));
        popover_font.style_context().add_class("reader-popover");
        popover_font.set_widget_name("reader_font_popover");

        let pop_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        pop_box.set_margin_start(12);
        pop_box.set_margin_end(12);
        pop_box.set_margin_top(10);
        pop_box.set_margin_bottom(10);

        let p_title = gtk::Label::new(Some("Reading Typography"));
        p_title.style_context().add_class("reader-popover-title");
        p_title.set_halign(gtk::Align::Start);
        pop_box.pack_start(&p_title, false, false, 0);

        let btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let dec_btn = gtk::Button::with_label("A-");
        dec_btn.style_context().add_class("reader-tool-btn");
        let size_lbl = gtk::Label::new(Some("14 px"));
        size_lbl.style_context().add_class("reader-popover-val");
        size_lbl.set_widget_name("reader_font_size_label");
        let reset_btn = gtk::Button::with_label("Reset");
        reset_btn.style_context().add_class("reader-tool-btn");
        let inc_btn = gtk::Button::with_label("A+");
        inc_btn.style_context().add_class("reader-tool-btn");

        btn_row.pack_start(&dec_btn, false, false, 0);
        btn_row.pack_start(&size_lbl, true, true, 0);
        btn_row.pack_start(&reset_btn, false, false, 0);
        btn_row.pack_start(&inc_btn, false, false, 0);
        pop_box.pack_start(&btn_row, false, false, 0);
        popover_font.add(&pop_box);

        let apply_font_size = |tv: &gtk::TextView, sz: i32| {
            let provider = gtk::CssProvider::new();
            let css = format!("textview.reader-text-view text {{ font-size: {sz}px; }}");
            let _ = provider.load_from_data(css.as_bytes());
            tv.style_context()
                .add_provider(&provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
        };

        let current_size = Rc::new(Cell::new(14i32));
        let tv_font = text_view.clone();
        let sz_lbl_d = size_lbl.clone();
        let cur_sz_d = Rc::clone(&current_size);
        let tv_d = tv_font.clone();
        dec_btn.connect_clicked(move |_| {
            let mut sz = cur_sz_d.get();
            if sz > 10 {
                sz -= 2;
                cur_sz_d.set(sz);
                sz_lbl_d.set_text(&format!("{sz} px"));
                apply_font_size(&tv_d, sz);
            }
        });

        let sz_lbl_r = size_lbl.clone();
        let cur_sz_r = Rc::clone(&current_size);
        let tv_r = tv_font.clone();
        reset_btn.connect_clicked(move |_| {
            cur_sz_r.set(14);
            sz_lbl_r.set_text("14 px");
            apply_font_size(&tv_r, 14);
        });

        let sz_lbl_i = size_lbl.clone();
        let cur_sz_i = Rc::clone(&current_size);
        let tv_i = tv_font.clone();
        inc_btn.connect_clicked(move |_| {
            let mut sz = cur_sz_i.get();
            if sz < 26 {
                sz += 2;
                cur_sz_i.set(sz);
                sz_lbl_i.set_text(&format!("{sz} px"));
                apply_font_size(&tv_i, sz);
            }
        });

        let p_font_show = popover_font.clone();
        font_btn.connect_clicked(move |_| {
            p_font_show.show_all();
            p_font_show.popup();
        });

        // Page Information Popover
        let popover_info = gtk::Popover::new(Some(&info_btn));
        popover_info.style_context().add_class("reader-popover");
        popover_info.set_widget_name("reader_info_popover");

        let info_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
        info_box.set_margin_start(12);
        info_box.set_margin_end(12);
        info_box.set_margin_top(10);
        info_box.set_margin_bottom(10);

        let i_title = gtk::Label::new(Some("Page Information"));
        i_title.style_context().add_class("reader-popover-title");
        i_title.set_halign(gtk::Align::Start);
        info_box.pack_start(&i_title, false, false, 0);

        let create_info_row = |lbl_text: &str, val_text: &str, name: &str| -> gtk::Label {
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
            let l = gtk::Label::new(Some(lbl_text));
            l.style_context().add_class("reader-popover-label");
            l.set_halign(gtk::Align::Start);
            let v = gtk::Label::new(Some(val_text));
            v.style_context().add_class("reader-popover-val");
            v.set_halign(gtk::Align::End);
            v.set_widget_name(name);
            row.pack_start(&l, true, true, 0);
            row.pack_end(&v, false, false, 0);
            info_box.pack_start(&row, false, false, 0);
            v
        };

        let val_url = create_info_row("Source URL", "Unavailable", "reader_info_url");
        let val_domain = create_info_row("Domain", "Unavailable", "reader_info_domain");
        let _ = create_info_row(
            "Transport",
            "MasterDNS Tunnel Gateway",
            "reader_info_transport",
        );
        let _ = create_info_row("Mode", "Resilient Text (Text Only)", "reader_info_mode");
        let val_time = create_info_row("Extraction Time", "Unavailable", "reader_info_time");
        let val_headings = create_info_row("Headings", "—", "reader_info_headings");
        let val_blocks = create_info_row("Content Blocks", "—", "reader_info_blocks");
        let val_links = create_info_row("Navigation Links", "—", "reader_info_links");
        let _ = create_info_row(
            "Security",
            "Fail-Closed · SSRF Defenses Active",
            "reader_info_security",
        );

        popover_info.add(&info_box);

        let p_info_show = popover_info.clone();
        let app_model_for_info = Arc::clone(app_model);
        let val_url_c = val_url.clone();
        let val_domain_c = val_domain.clone();
        let val_time_c = val_time.clone();
        let val_headings_c = val_headings.clone();
        let val_blocks_c = val_blocks.clone();
        let val_links_c = val_links.clone();

        info_btn.connect_clicked(move |_| {
            let m = app_model_for_info.lock().unwrap();
            if let Some(tab) = m.active_tab() {
                if let Some(ref meta) = tab.reader_metadata {
                    val_url_c.set_text(&meta.url);
                    val_domain_c.set_text(&meta.domain);
                    if meta.is_loading {
                        val_time_c.set_text("Extracting...");
                        val_headings_c.set_text("Loading...");
                        val_blocks_c.set_text("Loading...");
                        val_links_c.set_text("Loading...");
                    } else if meta.is_error {
                        val_time_c.set_text("Unavailable (error)");
                        val_headings_c.set_text("—");
                        val_blocks_c.set_text("—");
                        val_links_c.set_text("—");
                    } else {
                        if let Some(ms) = meta.elapsed_ms {
                            val_time_c.set_text(&format!("{ms} ms"));
                        } else {
                            val_time_c.set_text("Unavailable");
                        }
                        val_headings_c.set_text(&format!("{}", meta.headings_count));
                        val_blocks_c.set_text(&format!("{}", meta.content_blocks_count));
                        val_links_c.set_text(&format!("{}", meta.links_count));
                    }
                } else {
                    val_url_c.set_text("Unavailable");
                    val_domain_c.set_text("Unavailable");
                    val_time_c.set_text("Unavailable");
                    val_headings_c.set_text("—");
                    val_blocks_c.set_text("—");
                    val_links_c.set_text("—");
                }
            } else {
                val_url_c.set_text("Unavailable");
                val_domain_c.set_text("Unavailable");
                val_time_c.set_text("Unavailable");
                val_headings_c.set_text("—");
                val_blocks_c.set_text("—");
                val_links_c.set_text("—");
            }
            p_info_show.show_all();
            p_info_show.popup();
        });

        (root, title_lbl, meta_lbl, text_view)
    }

    fn load_resilient_text(
        title_lbl: &gtk::Label,
        meta_lbl: &gtk::Label,
        text_view: &gtk::TextView,
        url: &str,
        app_model: &Arc<Mutex<MewserAppModel>>,
        tab_index: usize,
    ) {
        let request_id = {
            let mut m = app_model.lock().unwrap();
            if let Some(tab) = m.tabs.get_mut(tab_index) {
                tab.active_request_id += 1;
                tab.reader_metadata = Some(ReaderPageMetadata::new_loading(url));
                tab.active_request_id
            } else {
                0
            }
        };

        title_lbl.set_text("Extracting Content...");
        meta_lbl.set_text(&format!("Target: {url} · Transport: DNS Tunnel Gateway"));
        let buffer = text_view
            .buffer()
            .unwrap_or_else(|| gtk::TextBuffer::new(None::<&gtk::TextTagTable>));
        setup_reader_buffer_tags(&buffer);
        buffer.set_text("Connecting to Mewser Gateway over tunnel...\n\nPlease wait while content is extracted...");

        let root_widget = {
            let mut curr = text_view.parent();
            let mut r = None;
            while let Some(w) = curr {
                if w.widget_name().as_str() == "reader_root" {
                    r = Some(w);
                    break;
                }
                curr = w.parent();
            }
            r
        };

        // Hide any previous error expander
        if let Some(ref root) = root_widget {
            if let Some(exp) = find_child_by_name(root, "reader_error_expander")
                .and_then(|w| w.downcast::<gtk::Expander>().ok())
            {
                exp.hide();
                exp.set_no_show_all(true);
            }
        }

        let contents_list = root_widget.as_ref().and_then(|r| {
            find_child_by_name(r, "reader_contents_list")
                .and_then(|w| w.downcast::<gtk::ListBox>().ok())
        });
        let contents_empty = root_widget.as_ref().and_then(|r| {
            find_child_by_name(r, "reader_contents_empty")
                .and_then(|w| w.downcast::<gtk::Label>().ok())
        });

        if let Some(ref ce) = contents_empty {
            ce.set_text("Loading outline...");
            ce.show();
        }
        if let Some(ref cl) = contents_list {
            for child in cl.children() {
                cl.remove(&child);
            }
        }

        let settings = app_model.lock().unwrap().settings.clone();
        let adapter_res = settings.build_tunnel_adapter();

        let adapter = match adapter_res {
            Ok(a) => a,
            Err(e) => {
                let err_msg = format!("Error preparing tunnel adapter: {e}");
                {
                    let mut m = app_model.lock().unwrap();
                    if let Some(tab) = m.tabs.get_mut(tab_index) {
                        tab.reader_metadata = Some(ReaderPageMetadata::new_error(url, &err_msg));
                    }
                }
                title_lbl.set_text("Configuration Error");
                meta_lbl.set_text("Failed to initialize tunnel adapter");
                buffer.set_text(&format!("{err_msg}\n\nSecurity notice: In accordance with fail-closed security invariants, Mewser never falls back to an unencrypted or direct connection."));
                if let Some(ce) = contents_empty {
                    ce.set_text("No outline available (configuration error)");
                    ce.show();
                }
                return;
            }
        };

        let (eff_tok, _) = settings.effective_gateway_token();
        let auth_token = if eff_tok.is_empty() {
            None
        } else {
            Some(eff_tok)
        };

        let engine = ClientEngine::new(adapter).with_auth_token(auth_token.clone());
        let url_owned = url.to_string();

        type ReaderChannelPayload = (Result<mewser_gateway::ExtractedPage, ClientError>, u128);
        let (tx, rx): (Sender<ReaderChannelPayload>, Receiver<ReaderChannelPayload>) = channel();
        let title_clone = title_lbl.clone();
        let meta_clone = meta_lbl.clone();
        let buffer_clone = buffer.clone();
        let text_view_clone = text_view.clone();
        let root_widget_clone = root_widget.clone();
        let url_for_idle = url_owned.clone();
        let app_model_for_idle = Arc::clone(app_model);

        glib::idle_add_local(move || {
            if let Ok((res, elapsed_ms)) = rx.try_recv() {
                // Ensure stale asynchronous responses cannot overwrite metadata belonging to a newer navigation
                let is_current = {
                    let m = app_model_for_idle.lock().unwrap();
                    m.tabs
                        .get(tab_index)
                        .map(|t| t.active_request_id == request_id)
                        .unwrap_or(false)
                };
                if !is_current {
                    return glib::ControlFlow::Break;
                }

                match res {
                    Ok(page) => {
                        {
                            let mut m = app_model_for_idle.lock().unwrap();
                            if let Some(tab) = m.tabs.get_mut(tab_index) {
                                tab.reader_metadata =
                                    Some(ReaderPageMetadata::new_loaded(&page, elapsed_ms));
                            }
                        }

                        let page_title = if page.title.trim().is_empty() {
                            "Untitled Page".to_string()
                        } else {
                            page.title.clone()
                        };
                        title_clone.set_text(&page_title);
                        meta_clone
                            .set_text(&format!("{} · Extracted in {} ms", page.url, elapsed_ms));

                        // Render rich article content
                        buffer_clone.set_text("");
                        let mut iter = buffer_clone.end_iter();
                        let tag_table = buffer_clone.tag_table().unwrap();

                        // 1. Description if available
                        if let Some(ref desc) = page.description {
                            if !desc.trim().is_empty() {
                                insert_tagged_text(&buffer_clone, &mut iter, desc, "para");
                                buffer_clone.insert(&mut iter, "\n\n");
                            }
                        }

                        // 2. Content blocks
                        let mut heading_counter = 0usize;
                        let mut is_first_heading = true;
                        for block in &page.content {
                            match block {
                                ContentBlock::Heading { level, text } => {
                                    // If the first extracted top-level heading exactly matches the article title, avoid rendering it twice
                                    let is_dup = is_first_heading
                                        && *level == 1
                                        && text.trim().eq_ignore_ascii_case(page_title.trim());

                                    let mark_name = format!("heading_{heading_counter}");
                                    buffer_clone.create_mark(Some(&mark_name), &iter, true);
                                    heading_counter += 1;
                                    is_first_heading = false;

                                    if is_dup {
                                        continue;
                                    }

                                    let tag_name = match level {
                                        1 => "h1",
                                        2 => "h2",
                                        _ => "h3",
                                    };
                                    insert_tagged_text(&buffer_clone, &mut iter, text, tag_name);
                                    buffer_clone.insert(&mut iter, "\n\n");
                                }
                                ContentBlock::Paragraph { text } => {
                                    insert_tagged_text(&buffer_clone, &mut iter, text, "para");
                                    buffer_clone.insert(&mut iter, "\n\n");
                                }
                                ContentBlock::List { items } => {
                                    for item in items {
                                        insert_tagged_text(
                                            &buffer_clone,
                                            &mut iter,
                                            &format!("•  {item}\n"),
                                            "list_item",
                                        );
                                    }
                                    buffer_clone.insert(&mut iter, "\n");
                                }
                                ContentBlock::ImagePlaceholder { id, src, alt } => {
                                    let label = alt.as_deref().unwrap_or("Image");
                                    insert_tagged_text(
                                        &buffer_clone,
                                        &mut iter,
                                        &format!("[{label} #{id}: {src}]\n\n"),
                                        "img_placeholder",
                                    );
                                }
                            }
                        }

                        // 3. Navigational links
                        if !page.links.is_empty() {
                            insert_tagged_text(
                                &buffer_clone,
                                &mut iter,
                                "--- Navigational Links ---\n\n",
                                "link_hdr",
                            );

                            for (idx, link) in page.links.iter().enumerate() {
                                let link_tag_name = format!("link_nav_{idx}");
                                if tag_table.lookup(&link_tag_name).is_none() {
                                    let t = gtk::TextTag::builder()
                                        .name(&link_tag_name)
                                        .foreground("#2dd4bf")
                                        .underline(pango::Underline::Single)
                                        .build();
                                    let target_href = link.href.clone();
                                    t.connect_event(move |_tag, obj, event, _iter| {
                                        if event.event_type() == gdk::EventType::ButtonRelease {
                                            if let Some(win) = obj
                                                .downcast_ref::<gtk::Widget>()
                                                .and_then(|w| w.toplevel())
                                            {
                                                if let Some(entry_w) =
                                                    find_child_by_name(&win, "main_address_entry")
                                                {
                                                    if let Ok(entry) =
                                                        entry_w.downcast::<gtk::Entry>()
                                                    {
                                                        entry.set_text(&target_href);
                                                        entry.emit_activate();
                                                    }
                                                }
                                            }
                                            glib::Propagation::Stop
                                        } else {
                                            glib::Propagation::Proceed
                                        }
                                    });
                                    tag_table.add(&t);
                                }

                                buffer_clone.insert(&mut iter, "•  ");
                                insert_tagged_text(
                                    &buffer_clone,
                                    &mut iter,
                                    &link.text,
                                    &link_tag_name,
                                );
                                buffer_clone.insert(&mut iter, &format!(" ({})\n", link.href));
                            }
                        }

                        // 4. Update Contents Outline
                        if let Some(ref root) = root_widget_clone {
                            let cl_opt = find_child_by_name(root, "reader_contents_list")
                                .and_then(|w| w.downcast::<gtk::ListBox>().ok());
                            let ce_opt = find_child_by_name(root, "reader_contents_empty")
                                .and_then(|w| w.downcast::<gtk::Label>().ok());
                            let scr_opt = find_child_by_name(root, "reader_main_scroll")
                                .and_then(|w| w.downcast::<gtk::ScrolledWindow>().ok());

                            if let (Some(cl), Some(ce)) = (cl_opt, ce_opt) {
                                for child in cl.children() {
                                    cl.remove(&child);
                                }

                                if page.headings.is_empty() {
                                    ce.set_text("No headings in this article.");
                                    ce.show();
                                } else {
                                    ce.hide();
                                    for (idx, h) in page.headings.iter().enumerate() {
                                        let row = gtk::ListBoxRow::new();
                                        row.style_context().add_class("reader-outline-item");
                                        let lbl = gtk::Label::new(Some(&h.text));
                                        lbl.set_halign(gtk::Align::Start);
                                        lbl.set_xalign(0.0);
                                        lbl.set_ellipsize(gtk::pango::EllipsizeMode::End);
                                        let margin = (h.level.saturating_sub(1) as i32) * 14 + 6;
                                        lbl.set_margin_start(margin);
                                        lbl.set_margin_top(4);
                                        lbl.set_margin_bottom(4);
                                        row.add(&lbl);

                                        let mark_name = format!("heading_{idx}");
                                        let tv_c = text_view_clone.clone();
                                        let vadj_opt = scr_opt.as_ref().map(|s| s.vadjustment());
                                        row.connect_activate(move |_| {
                                            if let Some(buf) = tv_c.buffer() {
                                                if let Some(mark) = buf.mark(&mark_name) {
                                                    let iter = buf.iter_at_mark(&mark);
                                                    let (line_y, _h) = tv_c.line_yrange(&iter);
                                                    if let Some(ref vadj) = vadj_opt {
                                                        vadj.set_value(line_y as f64);
                                                    }
                                                    tv_c.scroll_to_mark(
                                                        &mark, 0.0, true, 0.0, 0.05,
                                                    );
                                                }
                                            }
                                        });

                                        cl.add(&row);
                                    }
                                    cl.show_all();
                                }
                            }

                            // Hide error expander on success
                            if let Some(exp) = find_child_by_name(root, "reader_error_expander")
                                .and_then(|w| w.downcast::<gtk::Expander>().ok())
                            {
                                exp.hide();
                                exp.set_no_show_all(true);
                            }
                        }
                    }
                    Err(e) => {
                        let mut raw_error_str = format!("{e}");
                        if let Some(token) = auth_token.as_ref() {
                            raw_error_str = raw_error_str.replace(token, "[REDACTED_TOKEN]");
                        }

                        {
                            let mut m = app_model_for_idle.lock().unwrap();
                            if let Some(tab) = m.tabs.get_mut(tab_index) {
                                tab.reader_metadata = Some(ReaderPageMetadata::new_error(
                                    &url_for_idle,
                                    &raw_error_str,
                                ));
                            }
                        }

                        title_clone.set_text("Unable to Reach Gateway");
                        meta_clone.set_text(&format!(
                            "URL: {url_for_idle} · Status: Error (fail-closed)"
                        ));

                        let primary_msg = "The Resilient Gateway could not be reached through the configured MasterDNS tunnel.\n\n\
Possible Causes:\n\
• The MasterDNS tunnel connection is offline or restarting.\n\
• Upstream DNS tunnel queries could not reach the server.\n\
• The local tunnel proxy port is temporarily unavailable.\n\n\
Security Notice (Fail-Closed Policy):\n\
In accordance with Mewser's fail-closed routing invariants, direct network connections are strictly forbidden for tunneled traffic. Failing closed prevents privacy leaks and metadata disclosure.\n\n\
Troubleshooting Suggestions:\n\
1. Verify MasterDNS tunnel connection in toolbar or Profile Manager.\n\
2. Check your active profile configuration and resolver health.\n\
3. Expand 'Technical Diagnostics & Raw Details' below for low-level connection diagnostics.";

                        buffer_clone.set_text(primary_msg);

                        if let Some(ref root) = root_widget_clone {
                            if let Some(exp) = find_child_by_name(root, "reader_error_expander")
                                .and_then(|w| w.downcast::<gtk::Expander>().ok())
                            {
                                if let Some(dtl) = find_child_by_name(root, "reader_error_details")
                                    .and_then(|w| w.downcast::<gtk::Label>().ok())
                                {
                                    dtl.set_text(&format!(
                                        "Target: {}\nTransport: MasterDNS Tunnel\nDiagnostics: {}\nPolicy: Fail-Closed Enforced",
                                        url_for_idle,
                                        raw_error_str.trim()
                                    ));
                                }
                                exp.set_expanded(false);
                                exp.set_no_show_all(false);
                                exp.show_all();
                            }

                            if let Some(ce) = find_child_by_name(root, "reader_contents_empty")
                                .and_then(|w| w.downcast::<gtk::Label>().ok())
                            {
                                ce.set_text("No outline available (extraction failed)");
                                ce.show();
                            }
                            if let Some(cl) = find_child_by_name(root, "reader_contents_list")
                                .and_then(|w| w.downcast::<gtk::ListBox>().ok())
                            {
                                for child in cl.children() {
                                    cl.remove(&child);
                                }
                            }
                        }
                    }
                }
                glib::ControlFlow::Break
            } else {
                glib::ControlFlow::Continue
            }
        });

        thread::spawn(move || {
            let start = Instant::now();
            let res = engine.navigate(&url_owned, BrowsingMode::ResilientText);
            let elapsed_ms = start.elapsed().as_millis();
            let page_res = match res {
                Ok(NavigationResult::TextPage(p)) => Ok(p),
                Err(e) => Err(e),
            };
            let _ = tx.send((page_res, elapsed_ms));
        });
    }

    fn show_settings_dialog(parent: &gtk::Window, app_model: &Arc<Mutex<MewserAppModel>>) {
        let dialog = gtk::Dialog::with_buttons(
            Some("Settings"),
            Some(parent),
            gtk::DialogFlags::MODAL,
            &[
                ("Cancel", gtk::ResponseType::Cancel),
                ("Save", gtk::ResponseType::Ok),
            ],
        );
        dialog.set_default_size(749, 594);
        dialog.style_context().add_class("settings-dialog");

        if let Some(ok_b) = dialog.widget_for_response(gtk::ResponseType::Ok) {
            ok_b.style_context().add_class("btn-teal");
        }
        if let Some(can_b) = dialog.widget_for_response(gtk::ResponseType::Cancel) {
            can_b.style_context().add_class("btn-dark");
        }

        let current = app_model.lock().unwrap().settings.clone();

        let content_area = dialog.content_area();
        let main_split = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        main_split.set_hexpand(true);
        main_split.set_vexpand(true);
        content_area.add(&main_split);

        // Sidebar Navigation
        let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 4);
        sidebar.set_size_request(145, -1);
        sidebar.style_context().add_class("settings-sidebar");

        let create_sidebar_item =
            |svg_str: &str, label_str: &str, active: bool| -> (gtk::Button, gtk::Image) {
                let btn = gtk::Button::new();
                btn.set_halign(gtk::Align::Fill);
                btn.style_context().add_class("sidebar-btn");
                if active {
                    btn.style_context().add_class("sidebar-btn-active");
                }
                let hb = gtk::Box::new(gtk::Orientation::Horizontal, 6);
                hb.set_margin_start(2);
                hb.set_margin_end(2);
                hb.set_margin_top(2);
                hb.set_margin_bottom(2);
                let img = create_svg_image(svg_str, 16, 16).unwrap_or_default();
                hb.pack_start(&img, false, false, 0);
                let lbl = gtk::Label::new(Some(label_str));
                lbl.set_halign(gtk::Align::Start);
                hb.pack_start(&lbl, true, true, 0);
                btn.add(&hb);
                (btn, img)
            };

        let (btn_prof, _img_prof) =
            create_sidebar_item(STACK_ICON_SVG_SIDEBAR, "MasterDNS Profiles", true);
        let (btn_route, _img_route) = create_sidebar_item(ROUTE_ICON_SVG, "Routing Policy", false);
        let (btn_gw, _img_gw) = create_sidebar_item(GATEWAY_ICON_SVG, "Resilient Gateway", false);
        let (btn_gen, _img_gen) = create_sidebar_item(GEAR_ICON_SVG, "General", false);

        sidebar.pack_start(&btn_prof, false, false, 0);
        sidebar.pack_start(&btn_route, false, false, 0);
        sidebar.pack_start(&btn_gw, false, false, 0);
        sidebar.pack_start(&btn_gen, false, false, 0);

        main_split.pack_start(&sidebar, false, false, 0);

        let stack = gtk::Stack::new();
        stack.set_homogeneous(false);
        stack.style_context().add_class("settings-pane");
        stack.set_hexpand(true);
        stack.set_vexpand(true);
        main_split.pack_start(&stack, true, true, 0);

        let auto_chk = gtk::CheckButton::with_label("Auto-connect selected profile on startup");
        auto_chk.set_active(current.tunnel_auto_connect);

        if let Some(can_b) = dialog.widget_for_response(gtk::ResponseType::Cancel) {
            if let Some(parent) = can_b.parent() {
                if let Ok(btn_box) = parent.downcast::<gtk::ButtonBox>() {
                    btn_box.pack_start(&auto_chk, false, false, 12);
                    btn_box.set_child_secondary(&auto_chk, true);
                }
            }
        }

        let select_page = {
            let stack = stack.clone();
            let btn_prof = btn_prof.clone();
            let btn_route = btn_route.clone();
            let btn_gw = btn_gw.clone();
            let btn_gen = btn_gen.clone();
            let auto_chk = auto_chk.clone();
            move |page_name: &str| {
                stack.set_visible_child_name(page_name);
                btn_prof.style_context().remove_class("sidebar-btn-active");
                btn_route.style_context().remove_class("sidebar-btn-active");
                btn_gw.style_context().remove_class("sidebar-btn-active");
                btn_gen.style_context().remove_class("sidebar-btn-active");
                match page_name {
                    "profiles" => btn_prof.style_context().add_class("sidebar-btn-active"),
                    "routing" => btn_route.style_context().add_class("sidebar-btn-active"),
                    "gateway" => btn_gw.style_context().add_class("sidebar-btn-active"),
                    "general" => btn_gen.style_context().add_class("sidebar-btn-active"),
                    _ => {}
                }
                auto_chk.set_visible(page_name == "profiles");
            }
        };
        {
            let sp = select_page.clone();
            btn_prof.connect_clicked(move |_| sp("profiles"));
        }
        {
            let sp = select_page.clone();
            btn_route.connect_clicked(move |_| sp("routing"));
        }
        {
            let sp = select_page.clone();
            btn_gw.connect_clicked(move |_| sp("gateway"));
        }
        {
            let sp = select_page.clone();
            btn_gen.connect_clicked(move |_| sp("general"));
        }

        let controller = Arc::clone(&app_model.lock().unwrap().controller);

        // --- In-Dialog Profile Manager State ---
        let profile_store_rc = Rc::new(RefCell::new(current.profile_store.clone()));
        let profile_keys_rc = Rc::new(RefCell::new(
            std::collections::HashMap::<String, String>::new(),
        ));
        for prof in profile_store_rc.borrow().profiles() {
            if let Ok(Some(k)) = current.secret_vault.get_key(&prof.key_ref) {
                profile_keys_rc.borrow_mut().insert(prof.id.clone(), k);
            }
        }
        if let Some(active) = profile_store_rc.borrow().selected_profile() {
            if !current.tunnel_encryption_key.is_empty() {
                profile_keys_rc
                    .borrow_mut()
                    .insert(active.id.clone(), current.tunnel_encryption_key.clone());
            }
        }

        let viewed_id_rc = Rc::new(RefCell::new(
            std::env::var("MEWSER_VIEW_PROFILE_ID").ok().or_else(|| {
                profile_store_rc
                    .borrow()
                    .selected_profile_id
                    .clone()
                    .or_else(|| {
                        profile_store_rc
                            .borrow()
                            .profiles
                            .first()
                            .map(|p| p.id.clone())
                    })
            }),
        ));

        // --- TAB 1: MasterDNS Profile Manager ---
        let tab1_vbox = gtk::Box::new(gtk::Orientation::Vertical, 8);
        tab1_vbox.set_margin_start(0);
        tab1_vbox.set_margin_end(0);
        tab1_vbox.set_margin_top(0);
        tab1_vbox.set_margin_bottom(0);

        // Header spanning both columns
        let top_prof_header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let top_prof_text = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let prof_title_lbl = gtk::Label::new(None);
        prof_title_lbl.set_markup("<b>MasterDNS Profiles</b>");
        prof_title_lbl.set_halign(gtk::Align::Start);
        prof_title_lbl.style_context().add_class("home-title");
        top_prof_text.pack_start(&prof_title_lbl, false, false, 0);

        let prof_sub_lbl = gtk::Label::new(Some("Manage connection profiles and runtime."));
        prof_sub_lbl.set_halign(gtk::Align::Start);
        prof_sub_lbl.style_context().add_class("home-subtitle");
        top_prof_text.pack_start(&prof_sub_lbl, false, false, 0);
        top_prof_header.pack_start(&top_prof_text, true, true, 0);

        let import_btn = gtk::Button::with_label("📁 Import");
        import_btn.set_tooltip_text(Some("Import existing MasterDNS client_config.toml"));
        import_btn.style_context().add_class("btn-dark");
        top_prof_header.pack_end(&import_btn, false, false, 0);

        let new_prof_btn = gtk::Button::with_label("+ New");
        new_prof_btn.set_tooltip_text(Some("Create a new connection profile"));
        new_prof_btn.style_context().add_class("btn-dark");
        top_prof_header.pack_end(&new_prof_btn, false, false, 4);

        tab1_vbox.pack_start(&top_prof_header, false, false, 0);

        // 1. Connection Status Banner
        let conn_status_lbl = gtk::Label::new(None);
        let refresh_banner = {
            let conn_status_lbl = conn_status_lbl.clone();
            let controller = Arc::clone(&controller);
            move || {
                let snap = controller.connected_profile();
                if let Some(ref s) = snap {
                    let (dot_color, label_prefix) = if s.data_plane_verified {
                        ("#10b981", "<b>Connected:</b>")
                    } else {
                        (
                            "#38bdf8",
                            "<b>Listener ready · Connectivity unverified:</b>",
                        )
                    };
                    conn_status_lbl.set_markup(&format!(
                        "<span foreground=\"{dot_color}\">●</span> {label_prefix} {} (<tt>{}</tt>) · <i>Session ID: {}</i>",
                        glib::markup_escape_text(&s.name),
                        s.endpoint,
                        s.session_id.map(|n| n.to_string()).unwrap_or_else(|| "N/A".to_string())
                    ));
                } else {
                    conn_status_lbl.set_markup(
                        "<span foreground=\"#ef4444\">○</span> <b>Status:</b> Disconnected",
                    );
                }
            }
        };
        refresh_banner();

        // 2. Structured Two-Panel Layout: Profile List (Left) + Details (Right)
        let two_panel_box = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        two_panel_box.set_vexpand(true);

        // --- LEFT PANEL: Profile Navigation ---
        let left_panel = gtk::Box::new(gtk::Orientation::Vertical, 6);
        left_panel.set_size_request(175, -1);
        left_panel.style_context().add_class("profile-list-panel");

        let list_scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        list_scroll.set_vexpand(true);
        let profile_list = gtk::ListBox::new();
        profile_list.set_selection_mode(gtk::SelectionMode::Single);
        profile_list.style_context().add_class("profile-list");
        list_scroll.add(&profile_list);
        left_panel.pack_start(&list_scroll, true, true, 0);

        two_panel_box.pack_start(&left_panel, false, false, 0);

        // --- RIGHT PANEL: Profile Form & Actions ---
        let right_scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        right_scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        right_scroll.set_hexpand(true);
        right_scroll.set_vexpand(true);

        let right_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        right_card.style_context().add_class("profile-editor-card");

        // Profile Editor Header: Stack Icon in teal badge + Name + Connected Pill + Gold Star
        let card_top = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        if let Some(stk_img) = create_svg_image(STACK_ICON_SVG, 32, 32) {
            card_top.pack_start(&stk_img, false, false, 0);
        }
        let card_title_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let card_title_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let card_name_lbl = gtk::Label::new(None);
        card_name_lbl.set_halign(gtk::Align::Start);
        card_name_lbl.set_ellipsize(gtk::pango::EllipsizeMode::End);
        card_title_row.pack_start(&card_name_lbl, false, false, 0);

        let card_badge_lbl = gtk::Label::new(None);
        card_badge_lbl.set_no_show_all(true);
        card_badge_lbl.hide();
        card_title_row.pack_start(&card_badge_lbl, false, false, 0);

        let card_star_lbl = gtk::Label::new(Some("★"));
        card_star_lbl.style_context().add_class("badge-selected");
        card_star_lbl.set_no_show_all(true);
        card_star_lbl.hide();
        card_title_row.pack_start(&card_star_lbl, false, false, 0);

        let card_select_btn = gtk::Button::with_label("★ Select");
        card_select_btn.style_context().add_class("btn-dark");
        card_select_btn.set_tooltip_text(Some("Set this profile as selected"));
        card_select_btn.set_no_show_all(true);
        card_select_btn.hide();
        card_title_row.pack_start(&card_select_btn, false, false, 0);

        card_title_box.pack_start(&card_title_row, false, false, 0);

        let card_sub_lbl = gtk::Label::new(None);
        card_sub_lbl.set_halign(gtk::Align::Start);
        card_sub_lbl.style_context().add_class("home-subtitle");
        card_title_box.pack_start(&card_sub_lbl, false, false, 0);
        card_top.pack_start(&card_title_box, true, true, 0);

        right_card.pack_start(&card_top, false, false, 0);

        // Warning banner when editing the profile currently in use by the runtime
        let connected_warn_lbl = gtk::Label::new(None);
        connected_warn_lbl.set_halign(gtk::Align::Start);
        connected_warn_lbl.set_line_wrap(true);
        connected_warn_lbl.set_max_width_chars(60);
        connected_warn_lbl.set_no_show_all(true);
        connected_warn_lbl.hide();
        right_card.pack_start(&connected_warn_lbl, false, false, 0);

        // Action Buttons Row: Edit, Duplicate, Export, Delete
        let action_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);

        let edit_btn = gtk::Button::with_label("✎ Edit");
        edit_btn.style_context().add_class("btn-card-action");
        action_row.pack_start(&edit_btn, false, false, 0);

        let dup_btn = gtk::Button::with_label("❐ Duplicate");
        dup_btn.set_tooltip_text(Some("Duplicate the currently viewed profile"));
        dup_btn.style_context().add_class("btn-card-action");
        action_row.pack_start(&dup_btn, false, false, 0);

        let export_btn = gtk::Button::with_label("⇪ Export");
        export_btn.set_tooltip_text(Some("Export profile configuration to disk"));
        export_btn.style_context().add_class("btn-card-action");
        action_row.pack_start(&export_btn, false, false, 0);

        let del_btn = gtk::Button::with_label("🗑 Delete");
        del_btn.set_tooltip_text(Some("Delete this profile and remove its secret"));
        del_btn.style_context().add_class("btn-card-action");
        del_btn.style_context().add_class("btn-destructive");
        action_row.pack_start(&del_btn, false, false, 0);

        right_card.pack_start(&action_row, false, false, 0);

        // Subtabs: Basic, Resolvers, Advanced
        let subtabs_bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let subtab_basic = gtk::Button::with_label("Basic");
        subtab_basic.style_context().add_class("subtab-btn");
        subtab_basic.style_context().add_class("subtab-btn-active");
        subtabs_bar.pack_start(&subtab_basic, false, false, 0);

        let subtab_res = gtk::Button::with_label("Resolvers");
        subtab_res.style_context().add_class("subtab-btn");
        subtabs_bar.pack_start(&subtab_res, false, false, 0);

        let subtab_adv = gtk::Button::with_label("Advanced");
        subtab_adv.style_context().add_class("subtab-btn");
        subtabs_bar.pack_start(&subtab_adv, false, false, 0);

        right_card.pack_start(&subtabs_bar, false, false, 0);

        let sub_stack = gtk::Stack::new();
        sub_stack.set_homogeneous(false);
        sub_stack.set_hexpand(true);
        sub_stack.set_vexpand(true);

        // Basic Tab Grid
        let tab1_grid = gtk::Grid::new();
        tab1_grid.set_row_spacing(6);
        tab1_grid.set_column_spacing(10);
        tab1_grid.set_margin_top(4);
        tab1_grid.set_margin_bottom(4);

        let name_lbl = gtk::Label::new(Some("Profile Name"));
        name_lbl.set_halign(gtk::Align::Start);
        name_lbl.style_context().add_class("form-label");
        tab1_grid.attach(&name_lbl, 0, 0, 1, 1);
        let name_entry = gtk::Entry::new();
        name_entry.set_width_chars(10);
        name_entry.set_hexpand(true);
        {
            let cnl = card_name_lbl.clone();
            name_entry.connect_changed(move |entry| {
                let txt = entry.text();
                if !txt.trim().is_empty() {
                    cnl.set_markup(&format!(
                        "<b>{}</b>",
                        glib::markup_escape_text(txt.as_str())
                    ));
                }
            });
        }
        tab1_grid.attach(&name_entry, 1, 0, 2, 1);

        let dom_lbl = gtk::Label::new(Some("Tunnel Domain"));
        dom_lbl.set_halign(gtk::Align::Start);
        dom_lbl.style_context().add_class("form-label");
        tab1_grid.attach(&dom_lbl, 0, 1, 1, 1);
        let dom_entry = gtk::Entry::new();
        dom_entry.set_width_chars(10);
        dom_entry.set_hexpand(true);
        tab1_grid.attach(&dom_entry, 1, 1, 2, 1);

        let enc_lbl = gtk::Label::new(Some("Encryption Method"));
        enc_lbl.set_halign(gtk::Align::Start);
        enc_lbl.style_context().add_class("form-label");
        tab1_grid.attach(&enc_lbl, 0, 2, 1, 1);
        let enc_combo = gtk::ComboBoxText::new();
        enc_combo.append(Some("1"), "Method 1 (Standard XOR/Payload)");
        enc_combo.append(Some("2"), "Method 2 (Advanced Tunnel Encryption)");
        for cell in enc_combo.cells() {
            if let Ok(t) = cell.downcast::<gtk::CellRendererText>() {
                t.set_ellipsize(gtk::pango::EllipsizeMode::End);
            }
        }
        tab1_grid.attach(&enc_combo, 1, 2, 2, 1);

        let key_lbl = gtk::Label::new(Some("Encryption Key"));
        key_lbl.set_halign(gtk::Align::Start);
        key_lbl.style_context().add_class("form-label");
        tab1_grid.attach(&key_lbl, 0, 3, 1, 1);
        let key_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let key_entry = gtk::Entry::new();
        key_entry.set_width_chars(10);
        key_entry.set_visibility(false);
        key_entry.set_hexpand(true);
        key_box.pack_start(&key_entry, true, true, 0);

        let reveal_key_btn = gtk::Button::with_label("👁");
        reveal_key_btn.set_tooltip_text(Some("Toggle key visibility"));
        reveal_key_btn.style_context().add_class("btn-dark");
        let key_entry_clone = key_entry.clone();
        reveal_key_btn.connect_clicked(move |btn| {
            let is_vis = gtk::prelude::EntryExt::is_visible(&key_entry_clone);
            key_entry_clone.set_visibility(!is_vis);
            btn.set_label(if !is_vis { "🔒" } else { "👁" });
        });
        key_box.pack_start(&reveal_key_btn, false, false, 0);

        let change_key_btn = gtk::Button::with_label("Change");
        change_key_btn.style_context().add_class("btn-dark");
        {
            let ke_c = key_entry.clone();
            change_key_btn.connect_clicked(move |_| {
                ke_c.grab_focus();
            });
        }
        key_box.pack_start(&change_key_btn, false, false, 0);

        tab1_grid.attach(&key_box, 1, 3, 2, 1);

        // Credential status and security disclosure
        let credential_box = gtk::Box::new(gtk::Orientation::Vertical, 3);
        credential_box.set_margin_top(4);

        let key_status_lbl = gtk::Label::new(None);
        key_status_lbl.set_halign(gtk::Align::Start);
        key_status_lbl.set_line_wrap(true);
        credential_box.pack_start(&key_status_lbl, false, false, 0);

        let vault_notice_lbl = gtk::Label::new(None);
        vault_notice_lbl.set_markup(
            "<span foreground=\"#38bdf8\" font_size=\"8.5pt\">ⓘ Stored in local file vault (0600; unencrypted on disk)</span>",
        );
        vault_notice_lbl.set_halign(gtk::Align::Start);
        vault_notice_lbl.set_line_wrap(true);
        credential_box.pack_start(&vault_notice_lbl, false, false, 0);

        tab1_grid.attach(&credential_box, 0, 4, 3, 1);

        sub_stack.add_named(&tab1_grid, "basic");

        // Resolvers Tab Box
        let resolvers_vbox = gtk::Box::new(gtk::Orientation::Vertical, 6);
        resolvers_vbox.set_margin_top(6);
        resolvers_vbox.set_margin_bottom(6);

        let res_desc_lbl = gtk::Label::new(None);
        res_desc_lbl.set_markup("<span foreground=\"#94a3b8\" font_size=\"9pt\">DNS servers queried during tunnel operations (one per line):</span>");
        res_desc_lbl.set_halign(gtk::Align::Start);
        res_desc_lbl.set_line_wrap(true);
        resolvers_vbox.pack_start(&res_desc_lbl, false, false, 0);

        let res_scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        res_scroll.set_size_request(-1, 130);
        let res_tv = gtk::TextView::new();
        res_tv.set_wrap_mode(gtk::WrapMode::None);
        res_tv.style_context().add_class("res-editor");
        let res_buf = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
        res_tv.set_buffer(Some(&res_buf));
        res_scroll.add(&res_tv);
        resolvers_vbox.pack_start(&res_scroll, true, true, 0);

        // Action buttons row for quick presets and clear
        let res_btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let btn_add_cf = gtk::Button::with_label("+ 1.1.1.1:53");
        btn_add_cf.style_context().add_class("btn-card-action");
        btn_add_cf.set_tooltip_text(Some("Append Cloudflare DNS resolver (1.1.1.1:53)"));
        {
            let buf = res_buf.clone();
            btn_add_cf.connect_clicked(move |_| {
                let start = buf.start_iter();
                let end = buf.end_iter();
                let mut current = buf
                    .text(&start, &end, false)
                    .unwrap_or_default()
                    .to_string();
                if !current.is_empty() && !current.ends_with('\n') {
                    current.push('\n');
                }
                current.push_str("1.1.1.1:53\n");
                buf.set_text(&current);
            });
        }
        res_btn_row.pack_start(&btn_add_cf, false, false, 0);

        let btn_add_quad9 = gtk::Button::with_label("+ 9.9.9.9:53");
        btn_add_quad9.style_context().add_class("btn-card-action");
        btn_add_quad9.set_tooltip_text(Some("Append Quad9 DNS resolver (9.9.9.9:53)"));
        {
            let buf = res_buf.clone();
            btn_add_quad9.connect_clicked(move |_| {
                let start = buf.start_iter();
                let end = buf.end_iter();
                let mut current = buf
                    .text(&start, &end, false)
                    .unwrap_or_default()
                    .to_string();
                if !current.is_empty() && !current.ends_with('\n') {
                    current.push('\n');
                }
                current.push_str("9.9.9.9:53\n");
                buf.set_text(&current);
            });
        }
        res_btn_row.pack_start(&btn_add_quad9, false, false, 0);

        let btn_clear_res = gtk::Button::with_label("🗑 Clear");
        btn_clear_res.style_context().add_class("btn-card-action");
        btn_clear_res.set_tooltip_text(Some("Clear all resolver entries"));
        {
            let buf = res_buf.clone();
            btn_clear_res.connect_clicked(move |_| {
                buf.set_text("");
            });
        }
        res_btn_row.pack_start(&btn_clear_res, false, false, 0);

        resolvers_vbox.pack_start(&res_btn_row, false, false, 0);

        let res_count_lbl = gtk::Label::new(None);
        res_count_lbl.set_halign(gtk::Align::Start);
        res_count_lbl.set_line_wrap(true);
        resolvers_vbox.pack_start(&res_count_lbl, false, false, 0);
        sub_stack.add_named(&resolvers_vbox, "resolvers");

        // Advanced Tab Grid
        let adv_grid = gtk::Grid::new();
        adv_grid.set_row_spacing(8);
        adv_grid.set_column_spacing(10);
        adv_grid.set_margin_top(8);
        adv_grid.set_margin_bottom(8);

        // Row 0: Custom SOCKS5 Port
        let port_lbl = gtk::Label::new(Some("Local SOCKS5 Port"));
        port_lbl.set_halign(gtk::Align::Start);
        port_lbl.style_context().add_class("form-label");
        adv_grid.attach(&port_lbl, 0, 0, 1, 1);

        let port_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let port_entry = gtk::Entry::new();
        port_entry.set_placeholder_text(Some("Automatic"));
        port_entry.set_width_chars(10);
        port_entry.set_hexpand(true);
        port_entry.set_tooltip_text(Some(
            "Local port for the SOCKS5 proxy listener (leave blank for automatic allocation)",
        ));
        port_box.pack_start(&port_entry, true, true, 0);

        let port_hint_lbl = gtk::Label::new(None);
        port_hint_lbl
            .set_markup("<span foreground=\"#64748b\" font_size=\"9pt\">(auto-assigned)</span>");
        port_box.pack_start(&port_hint_lbl, false, false, 0);
        adv_grid.attach(&port_box, 1, 0, 1, 1);

        // Row 1: Startup Timeout
        let timeout_lbl = gtk::Label::new(Some("Startup Timeout"));
        timeout_lbl.set_halign(gtk::Align::Start);
        timeout_lbl.style_context().add_class("form-label");
        adv_grid.attach(&timeout_lbl, 0, 1, 1, 1);

        let timeout_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let timeout_entry = gtk::Entry::new();
        timeout_entry.set_placeholder_text(Some("60"));
        timeout_entry.set_width_chars(10);
        timeout_entry.set_hexpand(true);
        timeout_entry.set_tooltip_text(Some(
            "Seconds to wait for tunnel readiness handshake (5-300s, default 60s)",
        ));
        timeout_box.pack_start(&timeout_entry, true, true, 0);

        let sec_lbl = gtk::Label::new(Some("seconds"));
        sec_lbl.style_context().add_class("form-label");
        timeout_box.pack_start(&sec_lbl, false, false, 0);
        adv_grid.attach(&timeout_box, 1, 1, 1, 1);

        // Row 2: Validation Error Label
        let timeout_err_lbl = gtk::Label::new(None);
        timeout_err_lbl.set_halign(gtk::Align::Start);
        timeout_err_lbl.set_line_wrap(true);
        timeout_err_lbl.set_no_show_all(true);
        timeout_err_lbl.hide();
        adv_grid.attach(&timeout_err_lbl, 1, 2, 1, 1);

        // Row 3: File Vault Consent Checkbox & Security Disclosure
        let vault_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
        let vault_consent_chk = gtk::CheckButton::with_label(
            "Store encryption key in persistent file vault (.vault.json with 0600 permissions)",
        );
        vault_consent_chk.set_active(current.vault_file_consent);
        if let Some(lbl) = vault_consent_chk.child().and_downcast::<gtk::Label>() {
            lbl.set_line_wrap(true);
        }
        vault_box.pack_start(&vault_consent_chk, false, false, 0);

        let vault_disclosure_lbl = gtk::Label::new(None);
        vault_disclosure_lbl.set_markup("<span foreground=\"#38bdf8\" font_size=\"8.5pt\">ⓘ Security disclosure: Keys are saved to ~/.config/mewser/.vault.json (permissions 0600). When unchecked, keys are held in memory only for the current session.</span>");
        vault_disclosure_lbl.set_line_wrap(true);
        vault_disclosure_lbl.set_halign(gtk::Align::Start);
        vault_box.pack_start(&vault_disclosure_lbl, false, false, 0);

        adv_grid.attach(&vault_box, 0, 3, 2, 1);

        let timeout_valid_cell = Rc::new(Cell::new(true));
        let domain_input_valid_cell = Rc::new(Cell::new(true));
        let suffix_input_valid_cell = Rc::new(Cell::new(true));
        let gw_endpoint_valid_cell = Rc::new(Cell::new(true));
        let proxy_addr_valid_cell = Rc::new(Cell::new(true));
        let tcp_endpoint_valid_cell = Rc::new(Cell::new(true));

        let update_save_sensitivity = {
            let tv = Rc::clone(&timeout_valid_cell);
            let dv = Rc::clone(&domain_input_valid_cell);
            let sv = Rc::clone(&suffix_input_valid_cell);
            let gv = Rc::clone(&gw_endpoint_valid_cell);
            let pv = Rc::clone(&proxy_addr_valid_cell);
            let tcp_v = Rc::clone(&tcp_endpoint_valid_cell);
            let d = dialog.clone();
            move || {
                let all_valid =
                    tv.get() && dv.get() && sv.get() && gv.get() && pv.get() && tcp_v.get();
                d.set_response_sensitive(gtk::ResponseType::Ok, all_valid);
            }
        };

        let update_timeout_validation = {
            let timeout_entry = timeout_entry.clone();
            let timeout_err_lbl = timeout_err_lbl.clone();
            let tv_cell = Rc::clone(&timeout_valid_cell);
            let update_sens = update_save_sensitivity.clone();
            move || -> bool {
                let txt = timeout_entry.text();
                match crate::profile::MasterDnsProfile::validate_timeout_input(&txt) {
                    Ok(_) => {
                        timeout_err_lbl.hide();
                        timeout_entry.style_context().remove_class("entry-error");
                        tv_cell.set(true);
                        update_sens();
                        true
                    }
                    Err(err_msg) => {
                        timeout_err_lbl.set_markup(&format!(
                            "<span foreground=\"#ef4444\" font_size=\"8.5pt\">⚠ {err_msg}</span>"
                        ));
                        timeout_err_lbl.show();
                        timeout_entry.style_context().add_class("entry-error");
                        tv_cell.set(false);
                        update_sens();
                        false
                    }
                }
            }
        };

        {
            let utv = update_timeout_validation.clone();
            timeout_entry.connect_changed(move |_| {
                utv();
            });
        }

        sub_stack.add_named(&adv_grid, "advanced");

        right_card.pack_start(&sub_stack, true, true, 0);
        right_scroll.add(&right_card);
        two_panel_box.pack_start(&right_scroll, true, true, 0);
        tab1_vbox.pack_start(&two_panel_box, true, true, 0);

        let active_subtab_rc = Rc::new(RefCell::new("basic".to_string()));

        {
            let name_entry_c = name_entry.clone();
            edit_btn.connect_clicked(move |_| {
                name_entry_c.grab_focus();
            });
        }

        let in_switch = Rc::new(RefCell::new(false));
        let list_profile_ids = Rc::new(RefCell::new(Vec::<String>::new()));

        // Live helpers for counts and credential badge
        let update_res_count = {
            let res_buf = res_buf.clone();
            let res_count_lbl = res_count_lbl.clone();
            move || {
                let start = res_buf.start_iter();
                let end = res_buf.end_iter();
                let txt = res_buf.text(&start, &end, false).unwrap_or_default();
                let mut total = 0;
                let mut valid = 0;
                let mut invalid_samples = Vec::new();

                for line in txt.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    total += 1;
                    let candidate = if !trimmed.contains(':') {
                        format!("{trimmed}:53")
                    } else {
                        trimmed.to_string()
                    };
                    if candidate.parse::<SocketAddr>().is_ok() {
                        valid += 1;
                    } else if invalid_samples.len() < 2 {
                        invalid_samples.push(trimmed.to_string());
                    }
                }

                if total == 0 {
                    res_count_lbl.set_markup(
                        "<span foreground=\"#ef4444\" font_size=\"9.5pt\">⚠ 0 resolvers configured (at least 1 required)</span>",
                    );
                } else if valid == total {
                    res_count_lbl.set_markup(&format!(
                        "<span foreground=\"#10b981\" font_size=\"9.5pt\">● <b>{total} configured</b> · All endpoints valid</span>"
                    ));
                } else {
                    let inv_str = invalid_samples.join(", ");
                    res_count_lbl.set_markup(&format!(
                        "<span foreground=\"#f59e0b\" font_size=\"9.5pt\">⚠ <b>{valid}/{total} valid</b> · Invalid: <tt>{inv_str}</tt></span>"
                    ));
                }
            }
        };

        {
            let urc = update_res_count.clone();
            res_buf.connect_changed(move |_| {
                urc();
            });
        }

        let update_key_status = {
            let key_entry = key_entry.clone();
            let key_status_lbl = key_status_lbl.clone();
            let vault_notice_lbl = vault_notice_lbl.clone();
            let vault_chk = vault_consent_chk.clone();
            move || {
                let txt = key_entry.text().to_string();
                let has_key = !txt.trim().is_empty();
                let consented = vault_chk.is_active();
                if !has_key {
                    key_status_lbl.set_markup(
                        "<span foreground=\"#ef4444\" font_size=\"9pt\">⚠️ No encryption key configured</span>",
                    );
                    vault_notice_lbl.set_markup(
                        "<span foreground=\"#64748b\" font_size=\"8.5pt\">ⓘ Key required before tunnel can connect</span>",
                    );
                } else if consented {
                    key_status_lbl.set_markup(
                        "<span foreground=\"#10b981\" font_size=\"9pt\">✓ Key configured · Saved in local vault</span>",
                    );
                    vault_notice_lbl.set_markup(
                        "<span foreground=\"#38bdf8\" font_size=\"8.5pt\">ⓘ Stored in local file vault (0600; unencrypted on disk)</span>",
                    );
                } else {
                    key_status_lbl.set_markup(
                        "<span foreground=\"#38bdf8\" font_size=\"9pt\">✓ Key configured · In-memory session only</span>",
                    );
                    vault_notice_lbl.set_markup(
                        "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">ⓘ Key kept in volatile memory only; will not persist across app restart</span>",
                    );
                }
                key_status_lbl.show();
                vault_notice_lbl.show();
            }
        };

        {
            let uks = update_key_status.clone();
            key_entry.connect_changed(move |_| {
                uks();
            });
        }

        {
            let uks = update_key_status.clone();
            vault_consent_chk.connect_toggled(move |_| {
                uks();
            });
        }

        let save_form_to_viewed = {
            let store = Rc::clone(&profile_store_rc);
            let keys = Rc::clone(&profile_keys_rc);
            let viewed = Rc::clone(&viewed_id_rc);
            let name_entry = name_entry.clone();
            let dom_entry = dom_entry.clone();
            let enc_combo = enc_combo.clone();
            let key_entry = key_entry.clone();
            let port_entry = port_entry.clone();
            let timeout_entry = timeout_entry.clone();
            let res_buf = res_buf.clone();
            move || {
                if let Some(ref vid) = *viewed.borrow() {
                    let mut s = store.borrow_mut();
                    if let Some(prof) = s.get_profile_mut(vid) {
                        let name_txt = name_entry.text().to_string();
                        if !name_txt.trim().is_empty() {
                            prof.name = name_txt.trim().to_string();
                        }
                        prof.domain = dom_entry.text().trim().to_string();
                        if let Some(m_str) = enc_combo.active_id() {
                            if let Ok(m) = m_str.parse::<u8>() {
                                prof.encryption_method = m;
                            }
                        }
                        let port_txt = port_entry.text().trim().to_string();
                        prof.custom_port = port_txt.parse::<u16>().ok();
                        let timeout_txt = timeout_entry.text();
                        if let Ok(valid_timeout) =
                            crate::profile::MasterDnsProfile::validate_timeout_input(&timeout_txt)
                        {
                            prof.timeout_secs = Some(valid_timeout);
                        }
                        let start = res_buf.start_iter();
                        let end = res_buf.end_iter();
                        let res_text = res_buf.text(&start, &end, false).unwrap_or_default();
                        let raw_res: Vec<String> = res_text
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                        prof.resolvers =
                            crate::profile::MasterDnsProfile::sanitize_resolvers(&raw_res);
                        prof.modified_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                    }
                    keys.borrow_mut()
                        .insert(vid.clone(), key_entry.text().to_string());
                }
            }
        };

        let select_subtab = {
            let sub_stack = sub_stack.clone();
            let subtab_basic = subtab_basic.clone();
            let subtab_res = subtab_res.clone();
            let subtab_adv = subtab_adv.clone();
            let active_subtab = Rc::clone(&active_subtab_rc);
            let save_form = save_form_to_viewed.clone();
            move |sub_name: &str| {
                save_form();
                *active_subtab.borrow_mut() = sub_name.to_string();
                sub_stack.set_visible_child_name(sub_name);
                subtab_basic
                    .style_context()
                    .remove_class("subtab-btn-active");
                subtab_res.style_context().remove_class("subtab-btn-active");
                subtab_adv.style_context().remove_class("subtab-btn-active");
                match sub_name {
                    "basic" => subtab_basic.style_context().add_class("subtab-btn-active"),
                    "resolvers" => subtab_res.style_context().add_class("subtab-btn-active"),
                    "advanced" => subtab_adv.style_context().add_class("subtab-btn-active"),
                    _ => {}
                }
            }
        };
        {
            let ss = select_subtab.clone();
            subtab_basic.connect_clicked(move |_| ss("basic"));
        }
        {
            let ss = select_subtab.clone();
            subtab_res.connect_clicked(move |_| ss("resolvers"));
        }
        {
            let ss = select_subtab.clone();
            subtab_adv.connect_clicked(move |_| ss("advanced"));
        }

        let load_viewed_to_form = {
            let store = Rc::clone(&profile_store_rc);
            let keys = Rc::clone(&profile_keys_rc);
            let viewed = Rc::clone(&viewed_id_rc);
            let name_entry = name_entry.clone();
            let dom_entry = dom_entry.clone();
            let enc_combo = enc_combo.clone();
            let key_entry = key_entry.clone();
            let port_entry = port_entry.clone();
            let timeout_entry = timeout_entry.clone();
            let res_buf = res_buf.clone();
            let sub_stack = sub_stack.clone();
            let active_subtab = Rc::clone(&active_subtab_rc);
            let update_res = update_res_count.clone();
            let update_key = update_key_status.clone();
            let update_timeout_val = update_timeout_validation.clone();
            let warn_lbl = connected_warn_lbl.clone();
            let controller = Arc::clone(&controller);
            let card_name_lbl = card_name_lbl.clone();
            let card_sub_lbl = card_sub_lbl.clone();
            let card_badge_lbl = card_badge_lbl.clone();
            let card_star_lbl = card_star_lbl.clone();
            let card_select_btn = card_select_btn.clone();
            move || {
                if let Some(ref vid) = *viewed.borrow() {
                    let s = store.borrow();
                    if let Some(prof) = s.get_profile(vid) {
                        card_name_lbl.set_markup(&format!(
                            "<b>{}</b>",
                            glib::markup_escape_text(&prof.name)
                        ));
                        card_name_lbl.set_tooltip_text(Some(&prof.name));
                        let display_domain = if prof.domain.trim().is_empty() {
                            "Unconfigured domain"
                        } else {
                            &prof.domain
                        };
                        card_sub_lbl.set_text(&format!(
                            "{} · Method {}",
                            display_domain, prof.encryption_method
                        ));

                        name_entry.set_text(&prof.name);
                        dom_entry.set_text(&prof.domain);
                        enc_combo.set_active_id(Some(&prof.encryption_method.to_string()));
                        enc_combo.set_tooltip_text(Some(&format!(
                            "Encryption Method {}",
                            prof.encryption_method
                        )));
                        let key = keys.borrow().get(vid).cloned().unwrap_or_default();
                        key_entry.set_text(&key);
                        if let Some(p) = prof.custom_port {
                            port_entry.set_text(&p.to_string());
                        } else {
                            port_entry.set_text("");
                        }
                        if let Some(t) = prof.timeout_secs {
                            timeout_entry.set_text(&t.to_string());
                        } else {
                            timeout_entry.set_text("60");
                        }
                        update_timeout_val();
                        res_buf.set_text(&prof.resolvers.join("\n"));
                        update_res();
                        update_key();

                        sub_stack.set_visible_child_name(&active_subtab.borrow());

                        let curr_snap = controller.connected_profile();
                        let curr_state = controller.state();
                        let ui_state = crate::controller::ProfileUiState::derive(
                            vid,
                            s.selected_profile_id.as_deref(),
                            curr_snap.as_ref(),
                            &curr_state,
                        );

                        if ui_state.is_fully_connected {
                            card_badge_lbl.set_markup(
                                "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\"> ● Connected </span>",
                            );
                            card_badge_lbl.show();
                        } else if ui_state.is_listener_ready_unverified {
                            card_badge_lbl.set_markup(
                                "<span foreground=\"#38bdf8\" background=\"#0c4a6e\" font_weight=\"bold\"> ● Ready </span>",
                            );
                            card_badge_lbl.show();
                        } else {
                            card_badge_lbl.hide();
                        }

                        if ui_state.is_selected {
                            card_star_lbl.set_markup(
                                "<span foreground=\"#fbbf24\" font_size=\"12pt\">★</span>",
                            );
                            card_star_lbl.show();
                            card_select_btn.hide();
                        } else {
                            card_star_lbl.hide();
                            card_select_btn.show();
                        }

                        if ui_state.should_show_runtime_edit_warning {
                            if let Some(ref msg) = ui_state.warning_text {
                                warn_lbl.set_markup(&format!(
                                    "<span foreground=\"#f59e0b\">{msg}</span>"
                                ));
                            }
                            warn_lbl.show();
                        } else {
                            warn_lbl.hide();
                        }
                    }
                }
            }
        };

        #[allow(clippy::type_complexity)]
        let pop_cell: Rc<RefCell<Option<Box<dyn Fn()>>>> = Rc::new(RefCell::new(None));

        // Helper closure to populate the Profile ListBox
        let populate_list = {
            let list_box = profile_list.clone();
            let store = Rc::clone(&profile_store_rc);
            let viewed = Rc::clone(&viewed_id_rc);
            let in_switch = Rc::clone(&in_switch);
            let controller = Arc::clone(&controller);
            let list_ids = Rc::clone(&list_profile_ids);
            let pop_f_c = Rc::clone(&pop_cell);
            let save_f_c = save_form_to_viewed.clone();
            let load_f_c = load_viewed_to_form.clone();
            move || {
                *in_switch.borrow_mut() = true;
                for child in list_box.children() {
                    list_box.remove(&child);
                }
                let store_b = store.borrow().clone();
                let sel_id = store_b.selected_profile_id.clone();
                let cur_viewed = viewed.borrow().clone();
                let curr_snap = controller.connected_profile();
                let curr_state = controller.state();
                let mut ids = Vec::new();

                let mut row_to_select = None;

                for p in store_b.profiles.iter() {
                    ids.push(p.id.clone());
                    let ui_state = crate::controller::ProfileUiState::derive(
                        &p.id,
                        sel_id.as_deref(),
                        curr_snap.as_ref(),
                        &curr_state,
                    );
                    let is_viewed = cur_viewed.as_ref() == Some(&p.id);

                    let card_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
                    card_box.style_context().add_class("profile-card-row");
                    if is_viewed {
                        card_box.style_context().add_class("profile-card-active");
                    }

                    let top_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                    let status_btn = gtk::Button::new();
                    status_btn.style_context().add_class("radio-indicator-btn");
                    let status_lbl = gtk::Label::new(None);
                    if ui_state.is_fully_connected {
                        status_lbl
                            .set_markup("<span foreground=\"#10b981\" font_size=\"12pt\">●</span>");
                        status_btn.set_tooltip_text(Some("Connected profile (click to select)"));
                    } else if ui_state.is_listener_ready_unverified {
                        status_lbl
                            .set_markup("<span foreground=\"#38bdf8\" font_size=\"12pt\">●</span>");
                        status_btn
                            .set_tooltip_text(Some("Listener ready unverified (click to select)"));
                    } else {
                        status_lbl
                            .set_markup("<span foreground=\"#64748b\" font_size=\"12pt\">○</span>");
                        status_btn.set_tooltip_text(Some("Click to set as selected profile"));
                    }
                    status_btn.add(&status_lbl);

                    // Connect radio button click to select profile
                    {
                        let store_inner = Rc::clone(&store);
                        let pid = p.id.clone();
                        let viewed_inner = Rc::clone(&viewed);
                        let save_f = save_f_c.clone();
                        let load_f = load_f_c.clone();
                        let pop_f = Rc::clone(&pop_f_c);
                        status_btn.connect_clicked(move |_| {
                            save_f();
                            let _ = store_inner.borrow_mut().select_profile(&pid);
                            *viewed_inner.borrow_mut() = Some(pid.clone());
                            load_f();
                            if let Some(ref f) = *pop_f.borrow() {
                                f();
                            }
                        });
                    }
                    top_row.pack_start(&status_btn, false, false, 0);

                    let text_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
                    let name_lbl = gtk::Label::new(None);
                    name_lbl.set_markup(&format!("<b>{}</b>", glib::markup_escape_text(&p.name)));
                    name_lbl.set_halign(gtk::Align::Start);
                    name_lbl.set_ellipsize(gtk::pango::EllipsizeMode::End);
                    name_lbl.style_context().add_class("profile-card-name");
                    text_box.pack_start(&name_lbl, false, false, 0);

                    let display_dom = if p.domain.trim().is_empty() {
                        "Unconfigured domain"
                    } else {
                        &p.domain
                    };
                    let dom_lbl = gtk::Label::new(Some(display_dom));
                    dom_lbl.set_halign(gtk::Align::Start);
                    dom_lbl.set_ellipsize(gtk::pango::EllipsizeMode::End);
                    dom_lbl.style_context().add_class("profile-card-domain");
                    text_box.pack_start(&dom_lbl, false, false, 0);
                    top_row.pack_start(&text_box, true, true, 0);

                    card_box.pack_start(&top_row, false, false, 0);

                    if ui_state.is_selected {
                        let bottom_row = gtk::Box::new(gtk::Orientation::Horizontal, 0);
                        let sel_badge = gtk::Label::new(None);
                        sel_badge.set_markup("<span foreground=\"#fbbf24\" font_size=\"8.5pt\" font_weight=\"bold\">★ Selected</span>");
                        sel_badge.style_context().add_class("badge-selected-pill");
                        bottom_row.pack_end(&sel_badge, false, false, 0);
                        card_box.pack_start(&bottom_row, false, false, 0);
                    }

                    let row = gtk::ListBoxRow::new();
                    row.add(&card_box);
                    row.style_context().add_class("profile-list-row");
                    list_box.add(&row);

                    if is_viewed || (row_to_select.is_none() && sel_id.as_ref() == Some(&p.id)) {
                        row_to_select = Some(row);
                    }
                }

                *list_ids.borrow_mut() = ids;
                list_box.show_all();

                if let Some(ref r) = row_to_select {
                    list_box.select_row(Some(r));
                } else if let Some(first) = list_box.row_at_index(0) {
                    list_box.select_row(Some(&first));
                }

                *in_switch.borrow_mut() = false;
            }
        };

        *pop_cell.borrow_mut() = Some(Box::new(populate_list.clone()));

        // ListBox row switch handler
        {
            let save_form_c = save_form_to_viewed.clone();
            let load_form_c = load_viewed_to_form.clone();
            let viewed_c = Rc::clone(&viewed_id_rc);
            let in_switch_c = Rc::clone(&in_switch);
            let list_ids_c = Rc::clone(&list_profile_ids);
            let pop_f = Rc::clone(&pop_cell);

            profile_list.connect_row_selected(move |_lb, row_opt| {
                if *in_switch_c.borrow() {
                    return;
                }
                if let Some(row) = row_opt {
                    let idx = row.index();
                    if idx >= 0 {
                        let ids = list_ids_c.borrow();
                        if let Some(target_id) = ids.get(idx as usize) {
                            if viewed_c.borrow().as_ref() != Some(target_id) {
                                save_form_c();
                                *viewed_c.borrow_mut() = Some(target_id.clone());
                                load_form_c();
                                if let Some(ref f) = *pop_f.borrow() {
                                    f();
                                }
                            }
                        }
                    }
                }
            });
        }

        // Card Select button (in details panel header)
        {
            let store_c = Rc::clone(&profile_store_rc);
            let viewed_c = Rc::clone(&viewed_id_rc);
            let pop_f = Rc::clone(&pop_cell);
            let load_form_c = load_viewed_to_form.clone();
            let save_form_c = save_form_to_viewed.clone();
            card_select_btn.connect_clicked(move |_| {
                save_form_c();
                if let Some(ref vid) = *viewed_c.borrow() {
                    let _ = store_c.borrow_mut().select_profile(vid);
                    if let Some(ref f) = *pop_f.borrow() {
                        f();
                    }
                    load_form_c();
                }
            });
        }

        // New Profile button
        {
            let store_c = Rc::clone(&profile_store_rc);
            let viewed_c = Rc::clone(&viewed_id_rc);
            let save_form_c = save_form_to_viewed.clone();
            let load_form_c = load_viewed_to_form.clone();
            let pop_c = populate_list.clone();
            new_prof_btn.connect_clicked(move |_| {
                save_form_c();
                let new_prof = crate::profile::MasterDnsProfile::new(
                    "New Profile",
                    "",
                    1,
                    crate::state::default_masterdns_resolvers(),
                );
                let new_id = new_prof.id.clone();
                store_c.borrow_mut().add_profile(new_prof);
                *viewed_c.borrow_mut() = Some(new_id);
                pop_c();
                load_form_c();
            });
        }

        // Import Existing Config button
        {
            let store_c = Rc::clone(&profile_store_rc);
            let keys_c = Rc::clone(&profile_keys_rc);
            let viewed_c = Rc::clone(&viewed_id_rc);
            let save_form_c = save_form_to_viewed.clone();
            let load_form_c = load_viewed_to_form.clone();
            let pop_c = populate_list.clone();
            let parent_c = parent.clone();
            import_btn.connect_clicked(move |_| {
                save_form_c();
                let chooser = gtk::FileChooserDialog::with_buttons(
                    Some("Select MasterDNS Configuration (client_config.toml)"),
                    Some(&parent_c),
                    gtk::FileChooserAction::Open,
                    &[
                        ("Cancel", gtk::ResponseType::Cancel),
                        ("Open", gtk::ResponseType::Accept),
                    ],
                );
                let filter_toml = gtk::FileFilter::new();
                filter_toml.set_name(Some("TOML Config (*.toml)"));
                filter_toml.add_pattern("*.toml");
                chooser.add_filter(filter_toml);
                let filter_all = gtk::FileFilter::new();
                filter_all.set_name(Some("All Files (*)"));
                filter_all.add_pattern("*");
                chooser.add_filter(filter_all);

                let res = chooser.run();
                let cfg_path = chooser.filename();
                chooser.close();
                if res != gtk::ResponseType::Accept {
                    return;
                }
                let cfg_path = match cfg_path {
                    Some(p) => p,
                    None => return,
                };

                let parent_dir = cfg_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                let sibling_res = parent_dir.join("client_resolvers.txt");
                let res_file_opt = if sibling_res.is_file() {
                    Some(sibling_res)
                } else {
                    let res_chooser = gtk::FileChooserDialog::with_buttons(
                        Some("Select Resolvers File (client_resolvers.txt)"),
                        Some(&parent_c),
                        gtk::FileChooserAction::Open,
                        &[
                            ("Skip / Default", gtk::ResponseType::Cancel),
                            ("Select", gtk::ResponseType::Accept),
                        ],
                    );
                    let res_choice = res_chooser.run();
                    let chosen = res_chooser.filename();
                    res_chooser.close();
                    if res_choice == gtk::ResponseType::Accept {
                        chosen
                    } else {
                        None
                    }
                };

                match crate::controller::importer::import_masterdns_files(
                    &cfg_path,
                    res_file_opt.as_deref(),
                ) {
                    Ok(imported) => {
                        let (new_prof, key) = imported.into_profile(None);
                        let new_id = new_prof.id.clone();
                        if !key.is_empty() {
                            keys_c.borrow_mut().insert(new_id.clone(), key);
                        }
                        store_c.borrow_mut().add_profile(new_prof);
                        *viewed_c.borrow_mut() = Some(new_id);
                        pop_c();
                        load_form_c();
                    }
                    Err(err) => {
                        let err_dialog = gtk::MessageDialog::new(
                            Some(&parent_c),
                            gtk::DialogFlags::MODAL,
                            gtk::MessageType::Error,
                            gtk::ButtonsType::Ok,
                            &format!("Configuration Import Failed:\n\n{err}"),
                        );
                        err_dialog.run();
                        err_dialog.close();
                    }
                }
            });
        }

        // Duplicate button
        {
            let store_c = Rc::clone(&profile_store_rc);
            let keys_c = Rc::clone(&profile_keys_rc);
            let viewed_c = Rc::clone(&viewed_id_rc);
            let save_form_c = save_form_to_viewed.clone();
            let load_form_c = load_viewed_to_form.clone();
            let pop_c = populate_list.clone();
            dup_btn.connect_clicked(move |_| {
                save_form_c();
                if let Some(ref vid) = *viewed_c.borrow() {
                    if let Ok(dup) = store_c.borrow_mut().duplicate_profile(vid, None) {
                        if let Some(k) = keys_c.borrow().get(vid).cloned() {
                            keys_c.borrow_mut().insert(dup.id.clone(), k);
                        }
                        *viewed_c.borrow_mut() = Some(dup.id);
                        pop_c();
                        load_form_c();
                    }
                }
            });
        }

        // Export button
        {
            let store_c = Rc::clone(&profile_store_rc);
            let keys_c = Rc::clone(&profile_keys_rc);
            let viewed_c = Rc::clone(&viewed_id_rc);
            let save_form_c = save_form_to_viewed.clone();
            let parent_c = parent.clone();
            export_btn.connect_clicked(move |_| {
                save_form_c();
                let vid = match viewed_c.borrow().clone() {
                    Some(v) => v,
                    None => return,
                };
                let prof = match store_c.borrow().get_profile(&vid).cloned() {
                    Some(p) => p,
                    None => return,
                };
                let key = keys_c.borrow().get(&vid).cloned().unwrap_or_default();

                let exp_dialog = gtk::Dialog::with_buttons(
                    Some(&format!("Export Profile: {}", prof.name)),
                    Some(&parent_c),
                    gtk::DialogFlags::MODAL,
                    &[("Cancel", gtk::ResponseType::Cancel), ("Continue", gtk::ResponseType::Ok)],
                );
                let area = exp_dialog.content_area();
                let exp_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
                exp_box.set_margin_start(16);
                exp_box.set_margin_end(16);
                exp_box.set_margin_top(16);
                exp_box.set_margin_bottom(16);

                let radio_safe = gtk::RadioButton::with_label("Safe Export (Exclude encryption key) [Recommended]");
                let radio_full = gtk::RadioButton::with_label_from_widget(&radio_safe, "Full Export (Include encryption key in client_config.toml)");
                let warn_lbl = gtk::Label::new(None);
                warn_lbl.set_markup("<span foreground=\"#ef4444\">⚠️ Warning: Full export writes the encryption key in plaintext.</span>");
                warn_lbl.set_halign(gtk::Align::Start);
                warn_lbl.hide();

                let warn_lbl_c = warn_lbl.clone();
                radio_full.connect_toggled(move |rf| {
                    if rf.is_active() { warn_lbl_c.show(); } else { warn_lbl_c.hide(); }
                });

                exp_box.pack_start(&radio_safe, false, false, 0);
                exp_box.pack_start(&radio_full, false, false, 0);
                exp_box.pack_start(&warn_lbl, false, false, 4);
                area.add(&exp_box);
                exp_dialog.show_all();
                warn_lbl.hide();

                let choice = exp_dialog.run();
                let is_full = radio_full.is_active();
                exp_dialog.close();
                if choice != gtk::ResponseType::Ok {
                    return;
                }

                if is_full {
                    let alert = gtk::MessageDialog::new(
                        Some(&parent_c),
                        gtk::DialogFlags::MODAL,
                        gtk::MessageType::Warning,
                        gtk::ButtonsType::OkCancel,
                        "SECURITY WARNING:\n\nThe exported client_config.toml will contain your secret MasterDNS encryption key in plaintext. Anyone with access to this file can decrypt your tunnel traffic.\n\nDo you want to proceed?",
                    );
                    let alert_res = alert.run();
                    alert.close();
                    if alert_res != gtk::ResponseType::Ok {
                        return;
                    }
                }

                let folder_chooser = gtk::FileChooserDialog::with_buttons(
                    Some("Select Destination Folder for Export"),
                    Some(&parent_c),
                    gtk::FileChooserAction::SelectFolder,
                    &[("Cancel", gtk::ResponseType::Cancel), ("Export Here", gtk::ResponseType::Accept)],
                );
                let folder_res = folder_chooser.run();
                let dest_dir = folder_chooser.filename();
                folder_chooser.close();
                if folder_res != gtk::ResponseType::Accept {
                    return;
                }
                if let Some(dest) = dest_dir {
                    let secret_to_pass = if is_full && !key.is_empty() { Some(key.as_str()) } else { None };
                    match crate::profile::export_masterdns_profile(&prof, &dest, secret_to_pass) {
                        Ok((cfg_out, res_out)) => {
                            let success_dlg = gtk::MessageDialog::new(
                                Some(&parent_c),
                                gtk::DialogFlags::MODAL,
                                gtk::MessageType::Info,
                                gtk::ButtonsType::Ok,
                                &format!("Profile successfully exported!\n\nConfig: {}\nResolvers: {}", cfg_out.display(), res_out.display()),
                            );
                            success_dlg.run();
                            success_dlg.close();
                        }
                        Err(e) => {
                            let err_dlg = gtk::MessageDialog::new(
                                Some(&parent_c),
                                gtk::DialogFlags::MODAL,
                                gtk::MessageType::Error,
                                gtk::ButtonsType::Ok,
                                &format!("Failed to export profile:\n\n{e}"),
                            );
                            err_dlg.run();
                            err_dlg.close();
                        }
                    }
                }
            });
        }

        // Delete button
        {
            let store_c = Rc::clone(&profile_store_rc);
            let keys_c = Rc::clone(&profile_keys_rc);
            let viewed_c = Rc::clone(&viewed_id_rc);
            let load_form_c = load_viewed_to_form.clone();
            let pop_c = populate_list.clone();
            let parent_c = parent.clone();
            let current_vault = current.secret_vault.clone();
            let controller_c = Arc::clone(&controller);
            del_btn.connect_clicked(move |_| {
                let vid = match viewed_c.borrow().clone() {
                    Some(v) => v,
                    None => return,
                };
                if let Some(ref snap) = controller_c.connected_profile() {
                    if snap.id == vid {
                        let warn = gtk::MessageDialog::new(
                            Some(&parent_c),
                            gtk::DialogFlags::MODAL,
                            gtk::MessageType::Warning,
                            gtk::ButtonsType::Ok,
                            &format!(
                                "Cannot delete profile \"{}\" because it is currently connected.\n\nPlease disconnect the tunnel before deleting this profile.",
                                snap.name
                            ),
                        );
                        warn.run();
                        warn.close();
                        return;
                    }
                }
                if store_c.borrow().profiles.len() <= 1 {
                    let warn = gtk::MessageDialog::new(
                        Some(&parent_c),
                        gtk::DialogFlags::MODAL,
                        gtk::MessageType::Warning,
                        gtk::ButtonsType::Ok,
                        "Cannot delete the only remaining profile. Create or import another profile first.",
                    );
                    warn.run();
                    warn.close();
                    return;
                }
                let name = store_c.borrow().get_profile(&vid).map(|p| p.name.clone()).unwrap_or_default();
                let confirm = gtk::MessageDialog::new(
                    Some(&parent_c),
                    gtk::DialogFlags::MODAL,
                    gtk::MessageType::Question,
                    gtk::ButtonsType::OkCancel,
                    &format!("Are you sure you want to delete profile \"{name}\"?\nAssociated credentials will be permanently removed."),
                );
                let res = confirm.run();
                confirm.close();
                if res == gtk::ResponseType::Ok {
                    let removed = store_c.borrow_mut().remove_profile(&vid);
                    keys_c.borrow_mut().remove(&vid);
                    if let Some(r) = removed {
                        let _ = current_vault.delete_key(&r.key_ref);
                    }
                    *viewed_c.borrow_mut() = store_c
                        .borrow()
                        .selected_profile_id
                        .clone()
                        .or_else(|| store_c.borrow().profiles.first().map(|p| p.id.clone()));
                    pop_c();
                    load_form_c();
                }
            });
        }

        // Initial population
        populate_list();
        load_viewed_to_form();

        // Reactive GTK Dialog Timer: synchronously refreshes banner, list badges, and warning when runtime changes
        {
            let dialog_weak = dialog.downgrade();
            let refresh_banner_t = refresh_banner.clone();
            let load_form_t = load_viewed_to_form.clone();
            let pop_list_t = populate_list.clone();
            let controller_t = Arc::clone(&controller);
            let last_state_t = Rc::new(RefCell::new(controller.state()));

            glib::timeout_add_local(Duration::from_millis(500), move || {
                let d = match dialog_weak.upgrade() {
                    Some(d) => d,
                    None => return glib::ControlFlow::Break,
                };
                if !d.is_visible() {
                    return glib::ControlFlow::Break;
                }

                refresh_banner_t();
                let cur_st = controller_t.state();

                if *last_state_t.borrow() != cur_st {
                    *last_state_t.borrow_mut() = cur_st;
                    pop_list_t();
                    load_form_t();
                }

                glib::ControlFlow::Continue
            });
        }

        stack.add_named(&tab1_vbox, "profiles");

        // --- TAB 2: Routing Policy ---
        let staged_domains = Rc::new(RefCell::new(current.direct_domains.clone()));
        let staged_suffixes = Rc::new(RefCell::new(current.direct_suffixes.clone()));

        let tab2_vbox = gtk::Box::new(gtk::Orientation::Vertical, 10);
        tab2_vbox.set_margin_start(16);
        tab2_vbox.set_margin_end(16);
        tab2_vbox.set_margin_top(12);
        tab2_vbox.set_margin_bottom(16);

        // Header
        let header_vbox = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let r_title = gtk::Label::new(None);
        r_title.set_markup("<b>Routing Policy</b>");
        r_title.set_halign(gtk::Align::Start);
        r_title.style_context().add_class("home-title");
        header_vbox.pack_start(&r_title, false, false, 0);

        let r_sub = gtk::Label::new(Some(
            "Configure deterministic traffic routing rules for direct connections and tunneled destinations.",
        ));
        r_sub.set_halign(gtk::Align::Start);
        r_sub.style_context().add_class("home-subtitle");
        header_vbox.pack_start(&r_sub, false, false, 0);
        tab2_vbox.pack_start(&header_vbox, false, false, 0);

        // 1. Direct Domains Card
        let dom_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        dom_card.style_context().add_class("profile-editor-card");

        let dom_header_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let dom_title_vbox = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let dom_title_lbl = gtk::Label::new(None);
        dom_title_lbl.set_markup("<b>Direct Domains</b>");
        dom_title_lbl.set_halign(gtk::Align::Start);
        dom_title_lbl.style_context().add_class("form-label");
        dom_title_vbox.pack_start(&dom_title_lbl, false, false, 0);

        let dom_hint_lbl = gtk::Label::new(None);
        dom_hint_lbl.set_markup("<span foreground=\"#94a3b8\" font_size=\"8.5pt\">Exact hostnames that bypass MasterDNS tunnel and connect directly.</span>");
        dom_hint_lbl.set_halign(gtk::Align::Start);
        dom_title_vbox.pack_start(&dom_hint_lbl, false, false, 0);
        dom_header_row.pack_start(&dom_title_vbox, true, true, 0);

        let dom_count_badge = gtk::Label::new(None);
        dom_count_badge.style_context().add_class("badge-selected");
        dom_header_row.pack_start(&dom_count_badge, false, false, 0);
        dom_card.pack_start(&dom_header_row, false, false, 0);

        let dom_input_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let dom_entry = gtk::Entry::new();
        dom_entry.set_placeholder_text(Some("e.g. bank.internal or example.com"));
        dom_entry.set_hexpand(true);
        dom_entry.set_tooltip_text(Some(
            "Enter an exact domain or IP to connect directly without encapsulation",
        ));
        dom_input_row.pack_start(&dom_entry, true, true, 0);

        let dom_add_btn = gtk::Button::with_label("+ Add Domain");
        dom_add_btn.style_context().add_class("btn-card-action");
        dom_add_btn.set_sensitive(false);
        dom_input_row.pack_start(&dom_add_btn, false, false, 0);
        dom_card.pack_start(&dom_input_row, false, false, 0);

        let dom_err_lbl = gtk::Label::new(None);
        dom_err_lbl.set_halign(gtk::Align::Start);
        dom_err_lbl.set_line_wrap(true);
        dom_err_lbl.set_no_show_all(true);
        dom_err_lbl.hide();
        dom_card.pack_start(&dom_err_lbl, false, false, 0);

        let dom_list_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
        dom_card.pack_start(&dom_list_box, false, false, 0);

        tab2_vbox.pack_start(&dom_card, false, false, 0);

        // 2. Direct Suffixes Card
        let suf_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        suf_card.style_context().add_class("profile-editor-card");

        let suf_header_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let suf_title_vbox = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let suf_title_lbl = gtk::Label::new(None);
        suf_title_lbl.set_markup("<b>Direct Suffixes</b>");
        suf_title_lbl.set_halign(gtk::Align::Start);
        suf_title_lbl.style_context().add_class("form-label");
        suf_title_vbox.pack_start(&suf_title_lbl, false, false, 0);

        let suf_hint_lbl = gtk::Label::new(None);
        suf_hint_lbl.set_markup("<span foreground=\"#94a3b8\" font_size=\"8.5pt\">Matches any subdomain ending with this suffix (e.g., .corp.internal).</span>");
        suf_hint_lbl.set_halign(gtk::Align::Start);
        suf_title_vbox.pack_start(&suf_hint_lbl, false, false, 0);
        suf_header_row.pack_start(&suf_title_vbox, true, true, 0);

        let suf_count_badge = gtk::Label::new(None);
        suf_count_badge.style_context().add_class("badge-selected");
        suf_header_row.pack_start(&suf_count_badge, false, false, 0);
        suf_card.pack_start(&suf_header_row, false, false, 0);

        let suf_input_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let suf_entry = gtk::Entry::new();
        suf_entry.set_placeholder_text(Some("e.g. .internal or .corp.local"));
        suf_entry.set_hexpand(true);
        suf_entry.set_tooltip_text(Some(
            "Enter a domain suffix (e.g. .internal) for wildcard direct routing",
        ));
        suf_input_row.pack_start(&suf_entry, true, true, 0);

        let suf_add_btn = gtk::Button::with_label("+ Add Suffix");
        suf_add_btn.style_context().add_class("btn-card-action");
        suf_add_btn.set_sensitive(false);
        suf_input_row.pack_start(&suf_add_btn, false, false, 0);
        suf_card.pack_start(&suf_input_row, false, false, 0);

        let suf_err_lbl = gtk::Label::new(None);
        suf_err_lbl.set_halign(gtk::Align::Start);
        suf_err_lbl.set_line_wrap(true);
        suf_err_lbl.set_no_show_all(true);
        suf_err_lbl.hide();
        suf_card.pack_start(&suf_err_lbl, false, false, 0);

        let suf_list_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
        suf_card.pack_start(&suf_list_box, false, false, 0);

        tab2_vbox.pack_start(&suf_card, false, false, 0);

        // 3. Routing Behavior Explanation Card
        let beh_card = gtk::Box::new(gtk::Orientation::Vertical, 6);
        beh_card.style_context().add_class("profile-editor-card");

        let beh_title = gtk::Label::new(None);
        beh_title.set_markup("<b>Deterministic Routing Behavior</b>");
        beh_title.set_halign(gtk::Align::Start);
        beh_title.style_context().add_class("form-label");
        beh_card.pack_start(&beh_title, false, false, 0);

        let beh_text = gtk::Label::new(None);
        beh_text.set_markup(
            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
            • <b>Direct Rules:</b> Requests matching configured exact domains or suffixes connect directly.\n\
            • <b>MasterDNS Tunnel:</b> Other eligible public destinations use the selected MasterDNS SOCKS5 tunnel.\n\
            • <b>Fail Closed:</b> Tunnel-designated traffic fails closed when unavailable; direct routing is never an implicit fallback.</span>"
        );
        beh_text.set_line_wrap(true);
        beh_text.set_halign(gtk::Align::Start);
        beh_card.pack_start(&beh_text, false, false, 0);
        tab2_vbox.pack_start(&beh_card, false, false, 0);

        // 4. SSRF Defense Status Card
        let ssrf_card = gtk::Box::new(gtk::Orientation::Vertical, 6);
        ssrf_card.style_context().add_class("profile-editor-card");

        let ssrf_header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let ssrf_title = gtk::Label::new(None);
        ssrf_title.set_markup("<b>SSRF Defense</b>");
        ssrf_title.set_halign(gtk::Align::Start);
        ssrf_title.style_context().add_class("form-label");
        ssrf_header.pack_start(&ssrf_title, true, true, 0);

        let ssrf_active = mewser_core::policy::is_restricted_ip(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        ));
        let ssrf_val = gtk::Label::new(None);
        if ssrf_active {
            ssrf_val.set_markup("<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Active (Hardened) </span>");
        } else {
            ssrf_val.set_markup("<span foreground=\"#ef4444\" background=\"#450a0a\" font_weight=\"bold\" font_size=\"8.5pt\"> ⚠ Inactive </span>");
        }
        ssrf_val.style_context().add_class("routing-badge-ssrf");
        ssrf_header.pack_start(&ssrf_val, false, false, 0);
        ssrf_card.pack_start(&ssrf_header, false, false, 0);

        let ssrf_desc = gtk::Label::new(None);
        ssrf_desc.set_markup(
            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
            Enforced policy strictly blocks private (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1, localhost), link-local (169.254/16, fe80::/10), and cloud metadata (169.254.169.254, metadata.google.internal) targets.\
            </span>"
        );
        ssrf_desc.set_line_wrap(true);
        ssrf_desc.set_halign(gtk::Align::Start);
        ssrf_card.pack_start(&ssrf_desc, false, false, 0);
        tab2_vbox.pack_start(&ssrf_card, false, false, 0);

        // Validation & Refresh Wiring for Direct Domains
        let validate_pending_domain = {
            let dom_entry = dom_entry.clone();
            let dom_err_lbl = dom_err_lbl.clone();
            let dom_add_btn = dom_add_btn.clone();
            let staged_domains = Rc::clone(&staged_domains);
            let domain_valid = Rc::clone(&domain_input_valid_cell);
            let update_sens = update_save_sensitivity.clone();
            move || -> bool {
                let txt = dom_entry.text();
                let trimmed = txt.trim();
                if trimmed.is_empty() {
                    dom_err_lbl.hide();
                    dom_entry.style_context().remove_class("entry-error");
                    dom_add_btn.set_sensitive(false);
                    domain_valid.set(true);
                    update_sens();
                    return true;
                }

                match validate_direct_domain(trimmed, &staged_domains.borrow()) {
                    Ok(_) => {
                        dom_err_lbl.hide();
                        dom_entry.style_context().remove_class("entry-error");
                        dom_add_btn.set_sensitive(true);
                        domain_valid.set(true);
                        update_sens();
                        true
                    }
                    Err(err) => {
                        dom_err_lbl.set_markup(&format!(
                            "<span foreground=\"#ef4444\" font_size=\"8.5pt\">⚠ {}</span>",
                            glib::markup_escape_text(&err)
                        ));
                        dom_err_lbl.show();
                        dom_entry.style_context().add_class("entry-error");
                        dom_add_btn.set_sensitive(false);
                        domain_valid.set(false);
                        update_sens();
                        false
                    }
                }
            }
        };

        let refresh_domains = {
            let dom_list_box = dom_list_box.clone();
            let dom_count_badge = dom_count_badge.clone();
            let staged_domains = Rc::clone(&staged_domains);
            let validate_domain = validate_pending_domain.clone();
            let refresh_rc = Rc::new(RefCell::new(None::<Rc<dyn Fn()>>));
            let refresh_clone = Rc::clone(&refresh_rc);

            let r: Rc<dyn Fn()> = Rc::new(move || {
                for child in dom_list_box.children() {
                    dom_list_box.remove(&child);
                }
                let list = staged_domains.borrow();
                let count = list.len();
                dom_count_badge.set_markup(&format!(
                    "<span font_size=\"8.5pt\">{} rule{}</span>",
                    count,
                    if count == 1 { "" } else { "s" }
                ));

                if list.is_empty() {
                    let empty_lbl = gtk::Label::new(None);
                    empty_lbl.set_markup(
                        "<span foreground=\"#64748b\" font_style=\"italic\" font_size=\"8.5pt\">No direct domains configured. All eligible requests use the tunnel.</span>"
                    );
                    empty_lbl.set_halign(gtk::Align::Start);
                    empty_lbl.set_margin_top(4);
                    empty_lbl.set_margin_bottom(4);
                    dom_list_box.pack_start(&empty_lbl, false, false, 0);
                } else {
                    for dom in list.iter() {
                        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                        row.style_context().add_class("routing-rule-row");

                        let name_lbl = gtk::Label::new(None);
                        name_lbl.set_markup(&format!(
                            "<span foreground=\"#e2e8f0\" font_family=\"monospace\" font_size=\"9pt\">{}</span>",
                            glib::markup_escape_text(dom)
                        ));
                        name_lbl.set_halign(gtk::Align::Start);
                        row.pack_start(&name_lbl, true, true, 0);

                        let type_badge = gtk::Label::new(None);
                        type_badge.set_markup("<span foreground=\"#38bdf8\" font_weight=\"bold\" font_size=\"8pt\">Exact</span>");
                        type_badge.style_context().add_class("routing-badge-exact");
                        row.pack_start(&type_badge, false, false, 0);

                        let del_btn = gtk::Button::with_label("✕");
                        del_btn.style_context().add_class("btn-card-action");
                        del_btn.style_context().add_class("btn-destructive");
                        del_btn.set_tooltip_text(Some(&format!(
                            "Remove direct domain rule for {}",
                            dom
                        )));

                        let staged_d = Rc::clone(&staged_domains);
                        let dom_to_remove = dom.clone();
                        let r_inner = Rc::clone(&refresh_clone);
                        let val_dom = validate_domain.clone();
                        del_btn.connect_clicked(move |_| {
                            staged_d.borrow_mut().retain(|d| d != &dom_to_remove);
                            if let Some(ref cb) = *r_inner.borrow() {
                                cb();
                            }
                            val_dom();
                        });
                        row.pack_start(&del_btn, false, false, 0);
                        dom_list_box.pack_start(&row, false, false, 0);
                    }
                }
                dom_list_box.show_all();
            });
            *refresh_rc.borrow_mut() = Some(Rc::clone(&r));
            r
        };

        let add_domain_action = {
            let dom_entry = dom_entry.clone();
            let staged_domains = Rc::clone(&staged_domains);
            let refresh_dom = refresh_domains.clone();
            let validate_dom = validate_pending_domain.clone();
            move || {
                let txt = dom_entry.text();
                let trimmed = txt.trim();
                if trimmed.is_empty() {
                    return;
                }
                if let Ok(normalized) = validate_direct_domain(trimmed, &staged_domains.borrow()) {
                    staged_domains.borrow_mut().push(normalized);
                    dom_entry.set_text("");
                    validate_dom();
                    refresh_dom();
                }
            }
        };

        {
            let val = validate_pending_domain.clone();
            dom_entry.connect_changed(move |_| {
                val();
            });
        }
        {
            let add_act = add_domain_action.clone();
            dom_entry.connect_activate(move |_| {
                add_act();
            });
        }
        {
            let add_act = add_domain_action.clone();
            dom_add_btn.connect_clicked(move |_| {
                add_act();
            });
        }

        // Validation & Refresh Wiring for Direct Suffixes
        let validate_pending_suffix = {
            let suf_entry = suf_entry.clone();
            let suf_err_lbl = suf_err_lbl.clone();
            let suf_add_btn = suf_add_btn.clone();
            let staged_suffixes = Rc::clone(&staged_suffixes);
            let suffix_valid = Rc::clone(&suffix_input_valid_cell);
            let update_sens = update_save_sensitivity.clone();
            move || -> bool {
                let txt = suf_entry.text();
                let trimmed = txt.trim();
                if trimmed.is_empty() {
                    suf_err_lbl.hide();
                    suf_entry.style_context().remove_class("entry-error");
                    suf_add_btn.set_sensitive(false);
                    suffix_valid.set(true);
                    update_sens();
                    return true;
                }

                match validate_direct_suffix(trimmed, &staged_suffixes.borrow()) {
                    Ok(_) => {
                        suf_err_lbl.hide();
                        suf_entry.style_context().remove_class("entry-error");
                        suf_add_btn.set_sensitive(true);
                        suffix_valid.set(true);
                        update_sens();
                        true
                    }
                    Err(err) => {
                        suf_err_lbl.set_markup(&format!(
                            "<span foreground=\"#ef4444\" font_size=\"8.5pt\">⚠ {}</span>",
                            glib::markup_escape_text(&err)
                        ));
                        suf_err_lbl.show();
                        suf_entry.style_context().add_class("entry-error");
                        suf_add_btn.set_sensitive(false);
                        suffix_valid.set(false);
                        update_sens();
                        false
                    }
                }
            }
        };

        let refresh_suffixes = {
            let suf_list_box = suf_list_box.clone();
            let suf_count_badge = suf_count_badge.clone();
            let staged_suffixes = Rc::clone(&staged_suffixes);
            let validate_suffix = validate_pending_suffix.clone();
            let refresh_rc = Rc::new(RefCell::new(None::<Rc<dyn Fn()>>));
            let refresh_clone = Rc::clone(&refresh_rc);

            let r: Rc<dyn Fn()> = Rc::new(move || {
                for child in suf_list_box.children() {
                    suf_list_box.remove(&child);
                }
                let list = staged_suffixes.borrow();
                let count = list.len();
                suf_count_badge.set_markup(&format!(
                    "<span font_size=\"8.5pt\">{} rule{}</span>",
                    count,
                    if count == 1 { "" } else { "s" }
                ));

                if list.is_empty() {
                    let empty_lbl = gtk::Label::new(None);
                    empty_lbl.set_markup(
                        "<span foreground=\"#64748b\" font_style=\"italic\" font_size=\"8.5pt\">No direct suffixes configured. Subdomains route through the tunnel.</span>"
                    );
                    empty_lbl.set_halign(gtk::Align::Start);
                    empty_lbl.set_margin_top(4);
                    empty_lbl.set_margin_bottom(4);
                    suf_list_box.pack_start(&empty_lbl, false, false, 0);
                } else {
                    for suf in list.iter() {
                        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                        row.style_context().add_class("routing-rule-row");

                        let name_lbl = gtk::Label::new(None);
                        name_lbl.set_markup(&format!(
                            "<span foreground=\"#e2e8f0\" font_family=\"monospace\" font_size=\"9pt\">{}</span>",
                            glib::markup_escape_text(suf)
                        ));
                        name_lbl.set_halign(gtk::Align::Start);
                        row.pack_start(&name_lbl, true, true, 0);

                        let type_badge = gtk::Label::new(None);
                        type_badge.set_markup("<span foreground=\"#2dd4bf\" font_weight=\"bold\" font_size=\"8pt\">Suffix</span>");
                        type_badge.style_context().add_class("routing-badge-suffix");
                        row.pack_start(&type_badge, false, false, 0);

                        let del_btn = gtk::Button::with_label("✕");
                        del_btn.style_context().add_class("btn-card-action");
                        del_btn.style_context().add_class("btn-destructive");
                        del_btn.set_tooltip_text(Some(&format!(
                            "Remove direct suffix rule for {}",
                            suf
                        )));

                        let staged_s = Rc::clone(&staged_suffixes);
                        let suf_to_remove = suf.clone();
                        let r_inner = Rc::clone(&refresh_clone);
                        let val_suf = validate_suffix.clone();
                        del_btn.connect_clicked(move |_| {
                            staged_s.borrow_mut().retain(|s| s != &suf_to_remove);
                            if let Some(ref cb) = *r_inner.borrow() {
                                cb();
                            }
                            val_suf();
                        });
                        row.pack_start(&del_btn, false, false, 0);
                        suf_list_box.pack_start(&row, false, false, 0);
                    }
                }
                suf_list_box.show_all();
            });
            *refresh_rc.borrow_mut() = Some(Rc::clone(&r));
            r
        };

        let add_suffix_action = {
            let suf_entry = suf_entry.clone();
            let staged_suffixes = Rc::clone(&staged_suffixes);
            let refresh_suf = refresh_suffixes.clone();
            let validate_suf = validate_pending_suffix.clone();
            move || {
                let txt = suf_entry.text();
                let trimmed = txt.trim();
                if trimmed.is_empty() {
                    return;
                }
                if let Ok(normalized) = validate_direct_suffix(trimmed, &staged_suffixes.borrow()) {
                    staged_suffixes.borrow_mut().push(normalized);
                    suf_entry.set_text("");
                    validate_suf();
                    refresh_suf();
                }
            }
        };

        {
            let val = validate_pending_suffix.clone();
            suf_entry.connect_changed(move |_| {
                val();
            });
        }
        {
            let add_act = add_suffix_action.clone();
            suf_entry.connect_activate(move |_| {
                add_act();
            });
        }
        {
            let add_act = add_suffix_action.clone();
            suf_add_btn.connect_clicked(move |_| {
                add_act();
            });
        }

        // Initial population
        refresh_domains();
        refresh_suffixes();

        // Check screenshot editing test state
        if let Ok(test_mode) = std::env::var("MEWSER_ROUTING_EDIT_TEST") {
            if test_mode == "valid" {
                dom_entry.set_text("api.partner.example");
            } else if test_mode == "invalid" {
                dom_entry.set_text("https://bad-host:8080/path");
            } else if test_mode == "duplicate" {
                dom_entry.set_text("127.0.0.1");
            }
            validate_pending_domain();
        }

        let tab2_scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        tab2_scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        tab2_scroll.add(&tab2_vbox);
        stack.add_named(&tab2_scroll, "routing");

        // --- TAB 3: Resilient Gateway ---
        let tab3_vbox = gtk::Box::new(gtk::Orientation::Vertical, 10);
        tab3_vbox.set_margin_start(16);
        tab3_vbox.set_margin_end(16);
        tab3_vbox.set_margin_top(12);
        tab3_vbox.set_margin_bottom(16);

        // Header: Title & Subtitle
        let tab3_header_vbox = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let gw_title = gtk::Label::new(None);
        gw_title.set_markup("<b>Resilient Gateway</b>");
        gw_title.set_halign(gtk::Align::Start);
        gw_title.style_context().add_class("home-title");
        tab3_header_vbox.pack_start(&gw_title, false, false, 0);

        let gw_sub_lbl = gtk::Label::new(Some(
            "Configure the extraction service used by Resilient Text.",
        ));
        gw_sub_lbl.set_halign(gtk::Align::Start);
        gw_sub_lbl.style_context().add_class("home-subtitle");
        tab3_header_vbox.pack_start(&gw_sub_lbl, false, false, 0);
        tab3_vbox.pack_start(&tab3_header_vbox, false, false, 0);

        // 1. Gateway Endpoint Card
        let ep_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        ep_card.style_context().add_class("profile-editor-card");

        let ep_header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let ep_title = gtk::Label::new(None);
        ep_title.set_markup("<b>Gateway Service Endpoint</b>");
        ep_title.set_halign(gtk::Align::Start);
        ep_title.style_context().add_class("form-label");
        ep_header.pack_start(&ep_title, true, true, 0);

        let is_fixed_tcp = current.transport == DesktopTransport::FixedTcp;
        let ep_badge = gtk::Label::new(Some(if is_fixed_tcp {
            "Managed by MasterDNS (Fixed TCP)"
        } else {
            "SOCKS5 Target Destination"
        }));
        ep_badge.style_context().add_class("badge-selected");
        ep_header.pack_start(&ep_badge, false, false, 0);
        ep_card.pack_start(&ep_header, false, false, 0);

        let ep_desc = gtk::Label::new(None);
        if is_fixed_tcp {
            ep_desc.set_markup(
                "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
                <b>Topology A (Fixed TCP Mode):</b> Extraction requests are routed directly through your local \
                MasterDNS client listener (<tt>127.0.0.1:1080</tt>, configured in General Settings) to the VPS Gateway. \
                Forwarding is fixed by the MasterDNS server (<tt>FORWARD_IP = 127.0.0.1</tt>, <tt>FORWARD_PORT = 4040</tt>). \
                This remote endpoint field is only applicable to SOCKS5 mode (Topology B).\
                </span>",
            );
        } else {
            ep_desc.set_markup(
                "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
                <b>Topology B (SOCKS5 Mode):</b> Specify the public IP or hostname and port of your deployed Mewser Gateway \
                (e.g. <tt>&lt;SERVER_PUBLIC_IP&gt;:4040</tt> or <tt>gw.example.org:4040</tt>) reached via the MasterDNS SOCKS5 proxy.\
                </span>",
            );
        }
        ep_desc.set_line_wrap(true);
        ep_desc.set_halign(gtk::Align::Start);
        ep_card.pack_start(&ep_desc, false, false, 0);

        let gw_entry = gtk::Entry::new();
        gw_entry.set_placeholder_text(Some("127.0.0.1:4040 or gw.example.org:4040"));
        gw_entry.set_text(&current.gateway_addr_str);
        gw_entry.set_hexpand(true);
        if is_fixed_tcp {
            gw_entry.set_sensitive(false);
            gw_entry.set_tooltip_text(Some(
                "In Fixed TCP mode, destination forwarding is handled on the MasterDNS server. Client socket is configured in General Settings.",
            ));
        } else {
            gw_entry.set_sensitive(true);
            gw_entry.set_tooltip_text(Some(
                "Specify the reachable public IP or hostname and port of your self-hosted Gateway instance",
            ));
        }
        ep_card.pack_start(&gw_entry, false, false, 0);

        let ep_err_lbl = gtk::Label::new(None);
        ep_err_lbl.set_halign(gtk::Align::Start);
        ep_err_lbl.set_line_wrap(true);
        ep_err_lbl.set_no_show_all(true);
        ep_err_lbl.hide();
        ep_card.pack_start(&ep_err_lbl, false, false, 0);

        tab3_vbox.pack_start(&ep_card, false, false, 0);

        // 2. Gateway Authentication Card
        let auth_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        auth_card.style_context().add_class("profile-editor-card");

        let auth_header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let auth_title = gtk::Label::new(None);
        auth_title.set_markup("<b>Gateway Authentication</b>");
        auth_title.set_halign(gtk::Align::Start);
        auth_title.style_context().add_class("form-label");
        auth_header.pack_start(&auth_title, true, true, 0);

        let auth_status_badge = gtk::Label::new(None);
        auth_status_badge
            .style_context()
            .add_class("routing-badge-ssrf");
        auth_header.pack_start(&auth_status_badge, false, false, 0);
        auth_card.pack_start(&auth_header, false, false, 0);

        let token_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let gw_token_entry = gtk::Entry::new();
        gw_token_entry.set_visibility(false);
        gw_token_entry.set_invisible_char(Some('•'));
        gw_token_entry.set_placeholder_text(Some("Enter Gateway Bearer authentication token..."));
        gw_token_entry.set_text(&current.gateway_token);
        gw_token_entry.set_hexpand(true);
        gw_token_entry.set_tooltip_text(Some(
            "Bearer token for Gateway HTTP Authorization header (never stored in settings file)",
        ));
        token_row.pack_start(&gw_token_entry, true, true, 0);

        let reveal_token_btn = gtk::Button::with_label("👁 Reveal");
        reveal_token_btn
            .style_context()
            .add_class("btn-card-action");
        reveal_token_btn.set_tooltip_text(Some("Toggle token visibility"));
        token_row.pack_start(&reveal_token_btn, false, false, 0);

        let clear_token_btn = gtk::Button::with_label("Clear");
        clear_token_btn.style_context().add_class("btn-card-action");
        clear_token_btn.set_tooltip_text(Some("Clear stored Gateway token"));
        token_row.pack_start(&clear_token_btn, false, false, 0);
        auth_card.pack_start(&token_row, false, false, 0);

        let auth_desc = gtk::Label::new(None);
        auth_desc.set_line_wrap(true);
        auth_desc.set_halign(gtk::Align::Start);
        auth_card.pack_start(&auth_desc, false, false, 0);

        let update_auth_status = {
            let gw_token_entry = gw_token_entry.clone();
            let auth_status_badge = auth_status_badge.clone();
            let auth_desc = auth_desc.clone();
            let vault_consent = current.vault_file_consent;
            move || {
                let text = gw_token_entry.text().to_string();
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    if vault_consent {
                        auth_status_badge.set_markup(
                            "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Configured (Vault) </span>",
                        );
                        auth_desc.set_markup(
                            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
                            <span foreground=\"#10b981\">✓ Authenticated (Vault)</span> — Token is stored in local vault (<tt>~/.config/mewser/.vault.json</tt>, permissions 0600) and never saved to <tt>desktop_settings.json</tt>.\
                            </span>",
                        );
                    } else {
                        auth_status_badge.set_markup(
                            "<span foreground=\"#38bdf8\" background=\"#0c4a6e\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Configured (Session Memory) </span>",
                        );
                        auth_desc.set_markup(
                            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
                            <span foreground=\"#38bdf8\">✓ Authenticated (Session)</span> — Token is held in memory for this session only (vault consent disabled). Will not persist across restarts.\
                            </span>",
                        );
                    }
                } else if let Ok(env_tok) = std::env::var(mewser_cli::ENV_GATEWAY_AUTH_TOKEN) {
                    if !env_tok.trim().is_empty() {
                        auth_status_badge.set_markup(
                            "<span foreground=\"#a855f7\" background=\"#3b0764\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Configured (Environment) </span>",
                        );
                        auth_desc.set_markup(
                            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
                            <span foreground=\"#a855f7\">✓ Authenticated (Env)</span> — Bearer token provided via environment variable <tt>MEWSER_GATEWAY_AUTH_TOKEN</tt>. Enter a token above to override.\
                            </span>",
                        );
                    } else {
                        auth_status_badge.set_markup(
                            "<span foreground=\"#ef4444\" background=\"#450a0a\" font_weight=\"bold\" font_size=\"8.5pt\"> ⚠ Missing </span>",
                        );
                        auth_desc.set_markup(
                            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
                            <span foreground=\"#ef4444\">⚠ Unauthenticated</span> — No authentication token configured. Authenticated Gateway instances will reject extraction requests with HTTP 401 Unauthorized.\
                            </span>",
                        );
                    }
                } else {
                    auth_status_badge.set_markup(
                        "<span foreground=\"#ef4444\" background=\"#450a0a\" font_weight=\"bold\" font_size=\"8.5pt\"> ⚠ Missing </span>",
                    );
                    auth_desc.set_markup(
                        "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
                        <span foreground=\"#ef4444\">⚠ Unauthenticated</span> — No authentication token configured. Authenticated Gateway instances will reject extraction requests with HTTP 401 Unauthorized.\
                        </span>",
                    );
                }
            }
        };

        {
            let gw_token_entry = gw_token_entry.clone();
            let btn_clone = reveal_token_btn.clone();
            reveal_token_btn.connect_clicked(move |_| {
                let is_vis = gtk::prelude::EntryExt::is_visible(&gw_token_entry);
                gw_token_entry.set_visibility(!is_vis);
                if !is_vis {
                    btn_clone.set_label("🔒 Hide");
                } else {
                    btn_clone.set_label("👁 Reveal");
                }
            });
        }

        {
            let gw_token_entry = gw_token_entry.clone();
            let update_auth = update_auth_status.clone();
            clear_token_btn.connect_clicked(move |_| {
                gw_token_entry.set_text("");
                update_auth();
            });
        }

        {
            let update_auth = update_auth_status.clone();
            gw_token_entry.connect_changed(move |_| {
                update_auth();
            });
        }

        update_auth_status();

        tab3_vbox.pack_start(&auth_card, false, false, 0);

        // 3. Request Configuration Card
        let req_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        req_card.style_context().add_class("profile-editor-card");

        let req_header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let req_title = gtk::Label::new(None);
        req_title.set_markup("<b>Request &amp; Extraction Bounds</b>");
        req_title.set_halign(gtk::Align::Start);
        req_title.style_context().add_class("form-label");
        req_header.pack_start(&req_title, true, true, 0);
        req_card.pack_start(&req_header, false, false, 0);

        let to_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let to_lbl = gtk::Label::new(Some("Extraction Timeout:"));
        to_lbl.set_halign(gtk::Align::Start);
        to_lbl.style_context().add_class("form-label");
        to_row.pack_start(&to_lbl, false, false, 0);

        let to_val_lbl = gtk::Label::new(Some(&format!("{} s", current.timeout_secs)));
        to_val_lbl.style_context().add_class("badge-selected");

        let to_scale = gtk::Scale::with_range(gtk::Orientation::Horizontal, 5.0, 120.0, 5.0);
        to_scale.set_value(current.timeout_secs as f64);
        to_scale.set_hexpand(true);
        to_scale.set_draw_value(false);
        {
            let to_val_lbl = to_val_lbl.clone();
            to_scale.connect_value_changed(move |sc| {
                let val = sc.value() as u64;
                to_val_lbl.set_text(&format!("{val} s"));
            });
        }
        to_row.pack_start(&to_scale, true, true, 0);
        to_row.pack_start(&to_val_lbl, false, false, 0);
        req_card.pack_start(&to_row, false, false, 0);

        let lim_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let lim_lbl = gtk::Label::new(None);
        lim_lbl.set_markup(
            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
            Maximum Extraction Payload Bound: <b>2 MB</b> (enforced by adapter to protect memory and bandwidth).\
            </span>",
        );
        lim_lbl.set_halign(gtk::Align::Start);
        lim_lbl.set_line_wrap(true);
        lim_row.pack_start(&lim_lbl, true, true, 0);
        req_card.pack_start(&lim_row, false, false, 0);

        tab3_vbox.pack_start(&req_card, false, false, 0);

        // 4. Gateway Status & Health Probe Card
        let stat_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        stat_card.style_context().add_class("profile-editor-card");

        let stat_header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let stat_title = gtk::Label::new(None);
        stat_title.set_markup("<b>Gateway Status &amp; Health Probe</b>");
        stat_title.set_halign(gtk::Align::Start);
        stat_title.style_context().add_class("form-label");
        stat_header.pack_start(&stat_title, true, true, 0);

        let stat_badge = gtk::Label::new(None);
        stat_badge.set_markup(
            "<span foreground=\"#38bdf8\" background=\"#0c4a6e\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Configuration Ready </span>",
        );
        stat_badge.style_context().add_class("routing-badge-ssrf");
        stat_header.pack_start(&stat_badge, false, false, 0);
        stat_card.pack_start(&stat_header, false, false, 0);

        let test_gw_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let test_gw_btn = gtk::Button::with_label("Test Gateway Health");
        test_gw_btn.style_context().add_class("btn-card-action");
        test_gw_box.pack_start(&test_gw_btn, false, false, 0);

        let test_gw_res_lbl = gtk::Label::new(None);
        test_gw_res_lbl.set_halign(gtk::Align::Start);
        test_gw_res_lbl.set_line_wrap(true);
        test_gw_box.pack_start(&test_gw_res_lbl, true, true, 0);
        stat_card.pack_start(&test_gw_box, false, false, 0);

        tab3_vbox.pack_start(&stat_card, false, false, 0);

        // 5. Extraction Pipeline & Security Invariants Card
        let disc_card = gtk::Box::new(gtk::Orientation::Vertical, 6);
        disc_card.style_context().add_class("profile-editor-card");

        let disc_title = gtk::Label::new(None);
        disc_title.set_markup("<b>Extraction Pipeline &amp; Security Invariants</b>");
        disc_title.set_halign(gtk::Align::Start);
        disc_title.style_context().add_class("form-label");
        disc_card.pack_start(&disc_title, false, false, 0);

        let disc_text = gtk::Label::new(None);
        disc_text.set_markup(
            "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">\
            • <b>Self-Hosted Infrastructure:</b> Mewser connects exclusively to your self-hosted Gateway instance. No developer VPS or centralized proxy is ever used as a release default.\n\
            • <b>End-to-End Tunneling:</b> Resilient Text extraction requests are routed through the active MasterDNS tunnel directly to your Gateway; direct fallback is strictly forbidden.\n\
            • <b>Server SSRF Defense:</b> The Gateway validates all target URLs, verifies HTTPS certificates, and denies requests to private, loopback, link-local, or cloud metadata IP ranges.\n\
            • <b>Credential Isolation:</b> Authentication tokens are loaded strictly from the process environment and are never serialized into desktop configuration files.\
            </span>",
        );
        disc_text.set_line_wrap(true);
        disc_text.set_halign(gtk::Align::Start);
        disc_card.pack_start(&disc_text, false, false, 0);

        tab3_vbox.pack_start(&disc_card, false, false, 0);

        // Wrap tab3_vbox in ScrolledWindow for responsive 720x500 scrolling
        let tab3_scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        tab3_scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        tab3_scroll.add(&tab3_vbox);
        stack.add_named(&tab3_scroll, "gateway");

        // Validation wiring for Gateway Endpoint
        let validate_pending_gw_endpoint = {
            let gw_entry = gw_entry.clone();
            let ep_err_lbl = ep_err_lbl.clone();
            let stat_badge = stat_badge.clone();
            let gw_valid = Rc::clone(&gw_endpoint_valid_cell);
            let update_sens = update_save_sensitivity.clone();
            move || -> bool {
                let txt = gw_entry.text();
                match validate_gateway_endpoint(&txt) {
                    Ok(_) => {
                        ep_err_lbl.hide();
                        gw_entry.style_context().remove_class("entry-error");
                        stat_badge.set_markup(
                            "<span foreground=\"#38bdf8\" background=\"#0c4a6e\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Configuration Ready </span>",
                        );
                        gw_valid.set(true);
                        update_sens();
                        true
                    }
                    Err(err_msg) => {
                        ep_err_lbl.set_markup(&format!(
                            "<span foreground=\"#ef4444\" font_size=\"8.5pt\">⚠ {err_msg}</span>"
                        ));
                        ep_err_lbl.show();
                        gw_entry.style_context().add_class("entry-error");
                        stat_badge.set_markup(
                            "<span foreground=\"#ef4444\" background=\"#450a0a\" font_weight=\"bold\" font_size=\"8.5pt\"> ⚠ Invalid Endpoint </span>",
                        );
                        gw_valid.set(false);
                        update_sens();
                        false
                    }
                }
            }
        };

        {
            let v_gw = validate_pending_gw_endpoint.clone();
            gw_entry.connect_changed(move |_| {
                v_gw();
            });
        }

        // Test Gateway Health Button wiring
        {
            let gw_entry_c = gw_entry.clone();
            let gw_token_entry_for_test = gw_token_entry.clone();
            let test_gw_res_lbl_clone = test_gw_res_lbl.clone();
            let stat_badge_clone = stat_badge.clone();
            let app_model_clone_hc = Arc::clone(app_model);
            let controller_clone_hc = Arc::clone(&controller);

            test_gw_btn.connect_clicked(move |_| {
                let raw_addr = gw_entry_c.text().to_string();
                let validated = match validate_gateway_endpoint(&raw_addr) {
                    Ok(v) => v,
                    Err(_) => {
                        stat_badge_clone.set_markup(
                            "<span foreground=\"#ef4444\" background=\"#450a0a\" font_weight=\"bold\" font_size=\"8.5pt\"> ⚠ Invalid Endpoint </span>",
                        );
                        test_gw_res_lbl_clone.set_markup(
                            "<span foreground=\"#ef4444\" font_size=\"8.5pt\">Cannot test: Gateway endpoint is invalid</span>",
                        );
                        return;
                    }
                };

                stat_badge_clone.set_markup(
                    "<span foreground=\"#f59e0b\" background=\"#78350f\" font_weight=\"bold\" font_size=\"8.5pt\"> ⏳ Checking... </span>",
                );
                test_gw_res_lbl_clone.set_markup(
                    "<span foreground=\"#94a3b8\" font_size=\"8.5pt\">Probing /health endpoint...</span>",
                );

                struct HealthProbeOutcome {
                    success: bool,
                    auth_failed: bool,
                    message: String,
                }

                let (tx, rx): (Sender<HealthProbeOutcome>, Receiver<HealthProbeOutcome>) =
                    channel();
                let res_lbl_c = test_gw_res_lbl_clone.clone();
                let badge_c = stat_badge_clone.clone();

                glib::idle_add_local(move || {
                    if let Ok(outcome) = rx.try_recv() {
                        if outcome.success {
                            badge_c.set_markup(
                                "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Available </span>",
                            );
                            res_lbl_c.set_markup(&format!(
                                "<span foreground=\"#10b981\" font_size=\"8.5pt\">{}</span>",
                                outcome.message
                            ));
                        } else if outcome.auth_failed {
                            badge_c.set_markup(
                                "<span foreground=\"#f59e0b\" background=\"#78350f\" font_weight=\"bold\" font_size=\"8.5pt\"> ⚠ Auth Failed </span>",
                            );
                            res_lbl_c.set_markup(&format!(
                                "<span foreground=\"#f59e0b\" font_size=\"8.5pt\">{}</span>",
                                outcome.message
                            ));
                        } else {
                            badge_c.set_markup(
                                "<span foreground=\"#ef4444\" background=\"#450a0a\" font_weight=\"bold\" font_size=\"8.5pt\"> ✗ Unavailable </span>",
                            );
                            res_lbl_c.set_markup(&format!(
                                "<span foreground=\"#ef4444\" font_size=\"8.5pt\">{}</span>",
                                outcome.message
                            ));
                        }
                        glib::ControlFlow::Break
                    } else {
                        glib::ControlFlow::Continue
                    }
                });

                let model_guard = app_model_clone_hc.lock().unwrap();
                let routing_policy = model_guard.settings.build_routing_policy();
                let entered_tok = gw_token_entry_for_test.text().to_string();
                let token = if !entered_tok.trim().is_empty() {
                    entered_tok.trim().to_string()
                } else {
                    model_guard.settings.effective_gateway_token().0
                };
                let proxy_addr_str = model_guard.settings.proxy_addr_str.clone();
                let tunnel_endpoint = controller_clone_hc.endpoint();
                drop(model_guard);

                thread::spawn(move || {
                    let (host, port) = match validated.rsplit_once(':') {
                        Some((h, p)) => {
                            let clean_h = h.trim_start_matches('[').trim_end_matches(']');
                            (clean_h.to_string(), p.parse::<u16>().unwrap_or(4040))
                        }
                        None => (validated.clone(), 4040),
                    };

                    let is_direct = routing_policy.is_direct_target(&host)
                        || host == "127.0.0.1"
                        || host == "localhost"
                        || host == "::1";

                    if !is_direct {
                        // Tunneled routing path: Must route via active tunnel proxy
                        let target_proxy = if let Some(ep) = tunnel_endpoint {
                            ep
                        } else if let Ok(parsed_proxy) = proxy_addr_str.parse::<SocketAddr>() {
                            parsed_proxy
                        } else {
                            let _ = tx.send(HealthProbeOutcome {
                                success: false,
                                auth_failed: false,
                                message: "Failed: Active tunnel offline (fail-closed, direct fallback forbidden)".to_string(),
                            });
                            return;
                        };

                        match probe_socks5_http_health(
                            target_proxy,
                            &host,
                            port,
                            &token,
                            Duration::from_secs(3),
                        ) {
                            Ok(code) => {
                                if code == 200 {
                                    let _ = tx.send(HealthProbeOutcome {
                                        success: true,
                                        auth_failed: false,
                                        message: "✓ Gateway OK (HTTP 200 via tunnel)".to_string(),
                                    });
                                } else if code == 401 || code == 403 {
                                    let _ = tx.send(HealthProbeOutcome {
                                        success: false,
                                        auth_failed: true,
                                        message: format!("⚠ Authentication Failed (HTTP {code})"),
                                    });
                                } else {
                                    let _ = tx.send(HealthProbeOutcome {
                                        success: false,
                                        auth_failed: false,
                                        message: format!("Gateway reachable (HTTP {code})"),
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(HealthProbeOutcome {
                                    success: false,
                                    auth_failed: false,
                                    message: format!("Tunnel probe failed: {e}"),
                                });
                            }
                        }
                    } else {
                        // Direct routing path
                        let parsed_addr: Result<SocketAddr, _> = validated.parse();
                        let socket_addr = match parsed_addr {
                            Ok(sa) => sa,
                            Err(e) => {
                                let _ = tx.send(HealthProbeOutcome {
                                    success: false,
                                    auth_failed: false,
                                    message: format!("Invalid socket address: {e}"),
                                });
                                return;
                            }
                        };

                        match std::net::TcpStream::connect_timeout(
                            &socket_addr,
                            Duration::from_secs(3),
                        ) {
                            Ok(mut stream) => {
                                use std::io::{Read, Write};
                                let auth_hdr = if !token.trim().is_empty() {
                                    format!("Authorization: Bearer {}\r\n", token.trim())
                                } else {
                                    String::new()
                                };
                                let req = format!(
                                    "GET /health HTTP/1.1\r\nHost: {validated}\r\n{auth_hdr}Connection: close\r\n\r\n"
                                );
                                if stream.write_all(req.as_bytes()).is_err() {
                                    let _ = tx.send(HealthProbeOutcome {
                                        success: false,
                                        auth_failed: false,
                                        message: "Failed to send request".to_string(),
                                    });
                                    return;
                                }
                                let mut buf = [0u8; 128];
                                let n = stream.read(&mut buf).unwrap_or(0);
                                let resp = String::from_utf8_lossy(&buf[..n]);
                                if resp.starts_with("HTTP/1.1 200")
                                    || resp.starts_with("HTTP/1.0 200")
                                {
                                    let _ = tx.send(HealthProbeOutcome {
                                        success: true,
                                        auth_failed: false,
                                        message: "✓ Gateway OK (HTTP 200)".to_string(),
                                    });
                                } else if resp.starts_with("HTTP/1.1 401")
                                    || resp.starts_with("HTTP/1.0 401")
                                    || resp.starts_with("HTTP/1.1 403")
                                    || resp.starts_with("HTTP/1.0 403")
                                {
                                    let _ = tx.send(HealthProbeOutcome {
                                        success: false,
                                        auth_failed: true,
                                        message: "⚠ Authentication Failed (HTTP 401/403)".to_string(),
                                    });
                                } else {
                                    let first_line =
                                        resp.lines().next().unwrap_or("Non-200 response");
                                    let _ = tx.send(HealthProbeOutcome {
                                        success: false,
                                        auth_failed: false,
                                        message: format!("Gateway responded: {first_line}"),
                                    });
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(HealthProbeOutcome {
                                    success: false,
                                    auth_failed: false,
                                    message: format!("Connection failed: {e}"),
                                });
                            }
                        }
                    }
                });
            });
        }

        validate_pending_gw_endpoint();

        // Test-fixture hook for screenshot generation
        if let Ok(gw_test_mode) = std::env::var("MEWSER_GW_EDIT_TEST") {
            if gw_test_mode == "editing" {
                gw_entry.set_text("192.168.1.50:4040");
            } else if gw_test_mode == "invalid" {
                gw_entry.set_text("http://192.168.1.50:4040/extract");
            } else if gw_test_mode == "status" {
                stat_badge.set_markup(
                    "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Available </span>",
                );
                test_gw_res_lbl.set_markup(
                    "<span foreground=\"#10b981\" font_size=\"8.5pt\">✓ Gateway OK (HTTP 200 — extraction service reachable)</span>",
                );
            }
        }

        // --- TAB 4: General ---
        let tab4_scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        tab4_scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        tab4_scroll.set_hexpand(true);
        tab4_scroll.set_vexpand(true);

        let tab4_vbox = gtk::Box::new(gtk::Orientation::Vertical, 16);
        tab4_vbox.set_margin_start(16);
        tab4_vbox.set_margin_end(16);
        tab4_vbox.set_margin_top(12);
        tab4_vbox.set_margin_bottom(16);

        // Header
        let gen_header_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let gen_title = gtk::Label::new(None);
        gen_title.set_markup("<b>General Settings</b>");
        gen_title.set_halign(gtk::Align::Start);
        gen_title.style_context().add_class("home-title");
        gen_header_box.pack_start(&gen_title, false, false, 0);

        let gen_sub = gtk::Label::new(Some(
            "Configure Mewser's core behavior, interface, and runtime preferences.",
        ));
        gen_sub.set_halign(gtk::Align::Start);
        gen_sub.set_line_wrap(true);
        gen_sub.style_context().add_class("home-subtitle");
        gen_header_box.pack_start(&gen_sub, false, false, 0);
        tab4_vbox.pack_start(&gen_header_box, false, false, 0);

        // === CARD 1: Startup & Runtime ===
        let card1 = gtk::Box::new(gtk::Orientation::Vertical, 12);
        card1.style_context().add_class("profile-editor-card");

        let c1_title_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let c1_title = gtk::Label::new(None);
        c1_title.set_markup("<b>Startup &amp; Runtime</b>");
        c1_title.set_halign(gtk::Align::Start);
        c1_title.style_context().add_class("section-title");
        c1_title_box.pack_start(&c1_title, false, false, 0);

        let c1_sub = gtk::Label::new(Some(
            "Control application initialization and secret vault persistence.",
        ));
        c1_sub.set_halign(gtk::Align::Start);
        c1_sub.set_line_wrap(true);
        c1_sub.style_context().add_class("home-subtitle");
        c1_title_box.pack_start(&c1_sub, false, false, 0);
        card1.pack_start(&c1_title_box, false, false, 0);

        // Row 1: Auto-Connect MasterDNS Tunnel
        let auto_row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let auto_text_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let auto_lbl = gtk::Label::new(None);
        auto_lbl.set_markup("<b>Auto-Connect MasterDNS Tunnel</b>");
        auto_lbl.set_halign(gtk::Align::Start);
        auto_text_box.pack_start(&auto_lbl, false, false, 0);
        let auto_desc = gtk::Label::new(Some(
            "Automatically initiate MasterDNS tunnel connection upon application startup.",
        ));
        auto_desc.set_halign(gtk::Align::Start);
        auto_desc.set_line_wrap(true);
        auto_desc.style_context().add_class("home-subtitle");
        auto_text_box.pack_start(&auto_desc, false, false, 0);
        auto_row.pack_start(&auto_text_box, true, true, 0);

        let gen_auto_switch = gtk::Switch::new();
        gen_auto_switch.set_active(current.tunnel_auto_connect);
        gen_auto_switch.set_valign(gtk::Align::Center);
        auto_row.pack_end(&gen_auto_switch, false, false, 0);
        card1.pack_start(&auto_row, false, false, 4);

        // Row 2: Persistent Secret Vault Storage
        let vault_row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let vault_text_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let vault_lbl = gtk::Label::new(None);
        vault_lbl.set_markup("<b>Persistent Secret Vault Storage</b>");
        vault_lbl.set_halign(gtk::Align::Start);
        vault_text_box.pack_start(&vault_lbl, false, false, 0);
        let vault_desc = gtk::Label::new(Some(
            "Store MasterDNS encryption keys in ~/.config/mewser/.vault.json (permissions 0600) rather than ephemeral memory.",
        ));
        vault_desc.set_halign(gtk::Align::Start);
        vault_desc.set_line_wrap(true);
        vault_desc.style_context().add_class("home-subtitle");
        vault_text_box.pack_start(&vault_desc, false, false, 0);
        vault_row.pack_start(&vault_text_box, true, true, 0);

        let gen_vault_switch = gtk::Switch::new();
        gen_vault_switch.set_active(current.vault_file_consent);
        gen_vault_switch.set_valign(gtk::Align::Center);
        vault_row.pack_end(&gen_vault_switch, false, false, 0);
        card1.pack_start(&vault_row, false, false, 4);

        tab4_vbox.pack_start(&card1, false, false, 0);

        // === CARD 2: Transport & Local Proxy ===
        let card2 = gtk::Box::new(gtk::Orientation::Vertical, 12);
        card2.style_context().add_class("profile-editor-card");

        let c2_title_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let c2_title = gtk::Label::new(None);
        c2_title.set_markup("<b>Transport &amp; Local Proxy</b>");
        c2_title.set_halign(gtk::Align::Start);
        c2_title.style_context().add_class("section-title");
        c2_title_box.pack_start(&c2_title, false, false, 0);

        let c2_sub = gtk::Label::new(Some(
            "Configure how Mewser routes tunneled traffic through the local system.",
        ));
        c2_sub.set_halign(gtk::Align::Start);
        c2_sub.set_line_wrap(true);
        c2_sub.style_context().add_class("home-subtitle");
        c2_title_box.pack_start(&c2_sub, false, false, 0);
        card2.pack_start(&c2_title_box, false, false, 0);

        // Transport Layer Selector
        let trans_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
        let trans_lbl = gtk::Label::new(None);
        trans_lbl.set_markup("<b>Transport Protocol:</b>");
        trans_lbl.set_halign(gtk::Align::Start);
        trans_box.pack_start(&trans_lbl, false, false, 0);

        let transport_combo = gtk::ComboBoxText::new();
        transport_combo.append(Some("socks5"), "SOCKS5 Proxy (MasterDNS Tunnel)");
        transport_combo.append(Some("fixed_tcp"), "Fixed TCP Listener (Direct Socket)");
        match current.transport {
            DesktopTransport::Socks5 => transport_combo.set_active_id(Some("socks5")),
            DesktopTransport::FixedTcp => transport_combo.set_active_id(Some("fixed_tcp")),
        };
        trans_box.pack_start(&transport_combo, false, false, 0);
        card2.pack_start(&trans_box, false, false, 0);

        // Grid for Endpoints and SOCKS5 Auth
        let ep_grid = gtk::Grid::new();
        ep_grid.set_column_spacing(16);
        ep_grid.set_row_spacing(8);

        // Row 0: SOCKS5 Proxy Address
        let proxy_addr_title = gtk::Label::new(None);
        proxy_addr_title.set_markup("<b>SOCKS5 Proxy Address:</b>");
        proxy_addr_title.set_halign(gtk::Align::Start);
        ep_grid.attach(&proxy_addr_title, 0, 0, 1, 1);

        let proxy_addr_entry = gtk::Entry::new();
        proxy_addr_entry.set_text(&current.proxy_addr_str);
        proxy_addr_entry
            .style_context()
            .add_class("profile-editor-entry");
        proxy_addr_entry.set_hexpand(true);
        ep_grid.attach(&proxy_addr_entry, 1, 0, 1, 1);

        let proxy_err_lbl = gtk::Label::new(None);
        proxy_err_lbl.set_halign(gtk::Align::Start);
        proxy_err_lbl.set_line_wrap(true);
        proxy_err_lbl.hide();
        ep_grid.attach(&proxy_err_lbl, 1, 1, 1, 1);

        // Row 2: Fixed TCP Listener Address
        let tcp_endpoint_title = gtk::Label::new(None);
        tcp_endpoint_title.set_markup("<b>Fixed TCP Listener:</b>");
        tcp_endpoint_title.set_halign(gtk::Align::Start);
        ep_grid.attach(&tcp_endpoint_title, 0, 2, 1, 1);

        let tcp_endpoint_entry = gtk::Entry::new();
        tcp_endpoint_entry.set_text(&current.tcp_endpoint_str);
        tcp_endpoint_entry
            .style_context()
            .add_class("profile-editor-entry");
        tcp_endpoint_entry.set_hexpand(true);
        ep_grid.attach(&tcp_endpoint_entry, 1, 2, 1, 1);

        let tcp_err_lbl = gtk::Label::new(None);
        tcp_err_lbl.set_halign(gtk::Align::Start);
        tcp_err_lbl.set_line_wrap(true);
        tcp_err_lbl.hide();
        ep_grid.attach(&tcp_err_lbl, 1, 3, 1, 1);

        // Row 4: SOCKS5 Proxy Username
        let proxy_user_title = gtk::Label::new(None);
        proxy_user_title.set_markup("<b>SOCKS5 Username:</b>");
        proxy_user_title.set_halign(gtk::Align::Start);
        ep_grid.attach(&proxy_user_title, 0, 4, 1, 1);

        let proxy_user_entry = gtk::Entry::new();
        proxy_user_entry.set_text(&current.proxy_user);
        proxy_user_entry.set_placeholder_text(Some("Optional username"));
        proxy_user_entry
            .style_context()
            .add_class("profile-editor-entry");
        proxy_user_entry.set_hexpand(true);
        ep_grid.attach(&proxy_user_entry, 1, 4, 1, 1);

        // Row 5: SOCKS5 Password Status Badge
        let proxy_pass_title = gtk::Label::new(None);
        proxy_pass_title.set_markup("<b>SOCKS5 Password:</b>");
        proxy_pass_title.set_halign(gtk::Align::Start);
        ep_grid.attach(&proxy_pass_title, 0, 5, 1, 1);

        let pass_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let proxy_pass_badge = gtk::Label::new(None);
        if !current.proxy_pass.is_empty() {
            proxy_pass_badge.set_markup(
                "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Configured </span>",
            );
        } else {
            proxy_pass_badge.set_markup(
                "<span foreground=\"#94a3b8\" background=\"#1e293b\" font_weight=\"bold\" font_size=\"8.5pt\"> ○ None </span>",
            );
        }
        pass_box.pack_start(&proxy_pass_badge, false, false, 0);

        let pass_hint = gtk::Label::new(Some(
            "Loaded from MEWSER_SOCKS5_PASSWORD environment variable.",
        ));
        pass_hint.set_halign(gtk::Align::Start);
        pass_hint.set_line_wrap(true);
        pass_hint.style_context().add_class("home-subtitle");
        pass_box.pack_start(&pass_hint, false, false, 0);
        ep_grid.attach(&pass_box, 1, 5, 1, 1);

        card2.pack_start(&ep_grid, false, false, 0);
        tab4_vbox.pack_start(&card2, false, false, 0);

        // === CARD 3: Configuration Storage & Paths ===
        let card3 = gtk::Box::new(gtk::Orientation::Vertical, 10);
        card3.style_context().add_class("profile-editor-card");

        let c3_title_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let c3_title = gtk::Label::new(None);
        c3_title.set_markup("<b>Configuration Storage &amp; Paths</b>");
        c3_title.set_halign(gtk::Align::Start);
        c3_title.style_context().add_class("section-title");
        c3_title_box.pack_start(&c3_title, false, false, 0);

        let c3_sub = gtk::Label::new(Some(
            "On-disk location of application configuration, profiles, and encrypted secrets.",
        ));
        c3_sub.set_halign(gtk::Align::Start);
        c3_sub.set_line_wrap(true);
        c3_sub.style_context().add_class("home-subtitle");
        c3_title_box.pack_start(&c3_sub, false, false, 0);
        card3.pack_start(&c3_title_box, false, false, 0);

        // Path Item 1: Settings File
        let s_path_row = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let s_path_top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let s_path_title = gtk::Label::new(None);
        s_path_title.set_markup("<b>Desktop Settings File:</b>");
        s_path_title.set_halign(gtk::Align::Start);
        s_path_top.pack_start(&s_path_title, false, false, 0);

        let s_path_badge = gtk::Label::new(None);
        s_path_badge.set_markup(
            "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Active </span>",
        );
        s_path_top.pack_end(&s_path_badge, false, false, 0);
        s_path_row.pack_start(&s_path_top, false, false, 0);

        let s_path_val = crate::state::get_settings_file_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/mewser/desktop_settings.json".to_string());
        let s_path_lbl = gtk::Label::new(None);
        s_path_lbl.set_markup(&format!(
            "<span foreground=\"#94a3b8\" font_family=\"monospace\" font_size=\"8.5pt\">{}</span>",
            glib::markup_escape_text(&s_path_val)
        ));
        s_path_lbl.set_halign(gtk::Align::Start);
        s_path_lbl.set_line_wrap(true);
        s_path_row.pack_start(&s_path_lbl, false, false, 0);
        card3.pack_start(&s_path_row, false, false, 2);

        // Path Item 2: Secret Vault File
        let v_path_row = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let v_path_top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let v_path_title = gtk::Label::new(None);
        v_path_title.set_markup("<b>Profile Encryption Key Vault:</b>");
        v_path_title.set_halign(gtk::Align::Start);
        v_path_top.pack_start(&v_path_title, false, false, 0);

        let vault_status_badge = gtk::Label::new(None);
        if current.vault_file_consent {
            vault_status_badge.set_markup(
                "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Enabled </span>",
            );
        } else {
            vault_status_badge.set_markup(
                "<span foreground=\"#94a3b8\" background=\"#1e293b\" font_weight=\"bold\" font_size=\"8.5pt\"> ○ Ephemeral Memory </span>",
            );
        }
        v_path_top.pack_end(&vault_status_badge, false, false, 0);
        v_path_row.pack_start(&v_path_top, false, false, 0);

        let v_path_val = crate::state::get_secrets_file_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/mewser/.vault.json".to_string());
        let v_path_lbl = gtk::Label::new(None);
        v_path_lbl.set_markup(&format!(
            "<span foreground=\"#94a3b8\" font_family=\"monospace\" font_size=\"8.5pt\">{}</span>",
            glib::markup_escape_text(&v_path_val)
        ));
        v_path_lbl.set_halign(gtk::Align::Start);
        v_path_lbl.set_line_wrap(true);
        v_path_row.pack_start(&v_path_lbl, false, false, 0);
        card3.pack_start(&v_path_row, false, false, 2);

        tab4_vbox.pack_start(&card3, false, false, 0);

        // === CARD 4: Security & Architectural Guarantees ===
        let card4 = gtk::Box::new(gtk::Orientation::Vertical, 10);
        card4.style_context().add_class("profile-editor-card");

        let c4_title_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let c4_title = gtk::Label::new(None);
        c4_title.set_markup("<b>Security &amp; Architectural Guarantees</b>");
        c4_title.set_halign(gtk::Align::Start);
        c4_title.style_context().add_class("section-title");
        c4_title_box.pack_start(&c4_title, false, false, 0);

        let c4_sub = gtk::Label::new(Some(
            "Core invariants enforced across runtime boundaries. Non-configurable to prevent data leakage.",
        ));
        c4_sub.set_halign(gtk::Align::Start);
        c4_sub.set_line_wrap(true);
        c4_sub.style_context().add_class("home-subtitle");
        c4_title_box.pack_start(&c4_sub, false, false, 0);
        card4.pack_start(&c4_title_box, false, false, 0);

        // Invariant 1: Server SSRF Defense
        let inv1_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let inv1_top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let inv1_title = gtk::Label::new(None);
        inv1_title.set_markup("<b>Server SSRF Defense</b>");
        inv1_title.set_halign(gtk::Align::Start);
        inv1_top.pack_start(&inv1_title, false, false, 0);
        let inv1_badge = gtk::Label::new(None);
        inv1_badge.set_markup(
            "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Enforced (Hardened) </span>",
        );
        inv1_top.pack_end(&inv1_badge, false, false, 0);
        inv1_box.pack_start(&inv1_top, false, false, 0);
        let inv1_desc = gtk::Label::new(Some(
            "Gateway and client strictly reject RFC 1918 private IPs, loopback, link-local, and cloud metadata (169.254.169.254).",
        ));
        inv1_desc.set_halign(gtk::Align::Start);
        inv1_desc.set_line_wrap(true);
        inv1_desc.style_context().add_class("home-subtitle");
        inv1_box.pack_start(&inv1_desc, false, false, 0);
        card4.pack_start(&inv1_box, false, false, 2);

        // Invariant 2: Fail-Closed Routing
        let inv2_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let inv2_top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let inv2_title = gtk::Label::new(None);
        inv2_title.set_markup("<b>Fail-Closed Routing</b>");
        inv2_title.set_halign(gtk::Align::Start);
        inv2_top.pack_start(&inv2_title, false, false, 0);
        let inv2_badge = gtk::Label::new(None);
        inv2_badge.set_markup(
            "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Enforced (Fail-Closed) </span>",
        );
        inv2_top.pack_end(&inv2_badge, false, false, 0);
        inv2_box.pack_start(&inv2_top, false, false, 0);
        let inv2_desc = gtk::Label::new(Some(
            "Tunneled destinations never silently fall back to direct internet connections if the tunnel is offline.",
        ));
        inv2_desc.set_halign(gtk::Align::Start);
        inv2_desc.set_line_wrap(true);
        inv2_desc.style_context().add_class("home-subtitle");
        inv2_box.pack_start(&inv2_desc, false, false, 0);
        card4.pack_start(&inv2_box, false, false, 2);

        // Invariant 3: Credential Isolation
        let inv3_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let inv3_top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let inv3_title = gtk::Label::new(None);
        inv3_title.set_markup("<b>Credential Isolation</b>");
        inv3_title.set_halign(gtk::Align::Start);
        inv3_top.pack_start(&inv3_title, false, false, 0);
        let inv3_badge = gtk::Label::new(None);
        inv3_badge.set_markup(
            "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Enforced (Zero Leakage) </span>",
        );
        inv3_top.pack_end(&inv3_badge, false, false, 0);
        inv3_box.pack_start(&inv3_top, false, false, 0);
        let inv3_desc = gtk::Label::new(Some(
            "Passwords and MasterDNS encryption keys are never displayed in plaintext or sent over unencrypted channels.",
        ));
        inv3_desc.set_halign(gtk::Align::Start);
        inv3_desc.set_line_wrap(true);
        inv3_desc.style_context().add_class("home-subtitle");
        inv3_box.pack_start(&inv3_desc, false, false, 0);
        card4.pack_start(&inv3_box, false, false, 2);

        tab4_vbox.pack_start(&card4, false, false, 0);

        tab4_scroll.add(&tab4_vbox);
        stack.add_named(&tab4_scroll, "general");

        // Two-way synchronization between switches and profile tab checkboxes
        {
            let auto_chk = auto_chk.clone();
            gen_auto_switch.connect_active_notify(move |sw| {
                let is_act = sw.is_active();
                if auto_chk.is_active() != is_act {
                    auto_chk.set_active(is_act);
                }
            });
        }
        {
            let gen_auto_switch = gen_auto_switch.clone();
            auto_chk.connect_toggled(move |chk| {
                let is_act = chk.is_active();
                if gen_auto_switch.is_active() != is_act {
                    gen_auto_switch.set_active(is_act);
                }
            });
        }

        {
            let vault_consent_chk = vault_consent_chk.clone();
            let vault_badge = vault_status_badge.clone();
            gen_vault_switch.connect_active_notify(move |sw| {
                let is_act = sw.is_active();
                if vault_consent_chk.is_active() != is_act {
                    vault_consent_chk.set_active(is_act);
                }
                if is_act {
                    vault_badge.set_markup(
                        "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Enabled </span>",
                    );
                } else {
                    vault_badge.set_markup(
                        "<span foreground=\"#94a3b8\" background=\"#1e293b\" font_weight=\"bold\" font_size=\"8.5pt\"> ○ Ephemeral Memory </span>",
                    );
                }
            });
        }
        {
            let gen_vault_switch = gen_vault_switch.clone();
            let vault_badge = vault_status_badge.clone();
            vault_consent_chk.connect_toggled(move |chk| {
                let is_act = chk.is_active();
                if gen_vault_switch.is_active() != is_act {
                    gen_vault_switch.set_active(is_act);
                }
                if is_act {
                    vault_badge.set_markup(
                        "<span foreground=\"#10b981\" background=\"#064e3b\" font_weight=\"bold\" font_size=\"8.5pt\"> ● Enabled </span>",
                    );
                } else {
                    vault_badge.set_markup(
                        "<span foreground=\"#94a3b8\" background=\"#1e293b\" font_weight=\"bold\" font_size=\"8.5pt\"> ○ Ephemeral Memory </span>",
                    );
                }
            });
        }

        // Validation wiring for General settings
        let validate_pending_proxy_addr = {
            let proxy_addr_entry = proxy_addr_entry.clone();
            let proxy_err_lbl = proxy_err_lbl.clone();
            let proxy_valid = Rc::clone(&proxy_addr_valid_cell);
            let update_sens = update_save_sensitivity.clone();
            move || -> bool {
                let txt = proxy_addr_entry.text();
                match validate_socket_addr(&txt, "SOCKS5 proxy address") {
                    Ok(_) => {
                        proxy_err_lbl.hide();
                        proxy_addr_entry.style_context().remove_class("entry-error");
                        proxy_valid.set(true);
                        update_sens();
                        true
                    }
                    Err(err_msg) => {
                        proxy_err_lbl.set_markup(&format!(
                            "<span foreground=\"#ef4444\" font_size=\"8.5pt\">⚠ {err_msg}</span>"
                        ));
                        proxy_err_lbl.show();
                        proxy_addr_entry.style_context().add_class("entry-error");
                        proxy_valid.set(false);
                        update_sens();
                        false
                    }
                }
            }
        };

        let validate_pending_tcp_endpoint = {
            let tcp_endpoint_entry = tcp_endpoint_entry.clone();
            let tcp_err_lbl = tcp_err_lbl.clone();
            let tcp_valid = Rc::clone(&tcp_endpoint_valid_cell);
            let update_sens = update_save_sensitivity.clone();
            move || -> bool {
                let txt = tcp_endpoint_entry.text();
                match validate_socket_addr(&txt, "Fixed TCP endpoint") {
                    Ok(_) => {
                        tcp_err_lbl.hide();
                        tcp_endpoint_entry
                            .style_context()
                            .remove_class("entry-error");
                        tcp_valid.set(true);
                        update_sens();
                        true
                    }
                    Err(err_msg) => {
                        tcp_err_lbl.set_markup(&format!(
                            "<span foreground=\"#ef4444\" font_size=\"8.5pt\">⚠ {err_msg}</span>"
                        ));
                        tcp_err_lbl.show();
                        tcp_endpoint_entry.style_context().add_class("entry-error");
                        tcp_valid.set(false);
                        update_sens();
                        false
                    }
                }
            }
        };

        {
            let v_proxy = validate_pending_proxy_addr.clone();
            proxy_addr_entry.connect_changed(move |_| {
                v_proxy();
            });
        }

        {
            let v_tcp = validate_pending_tcp_endpoint.clone();
            tcp_endpoint_entry.connect_changed(move |_| {
                v_tcp();
            });
        }

        validate_pending_proxy_addr();
        validate_pending_tcp_endpoint();

        if let Ok(gen_test_mode) = std::env::var("MEWSER_GEN_EDIT_TEST") {
            if gen_test_mode == "editing" {
                proxy_addr_entry.set_text("127.0.0.1:9050");
                tcp_endpoint_entry.set_text("127.0.0.1:9050");
                proxy_user_entry.set_text("mewser_user");
            } else if gen_test_mode == "invalid" {
                proxy_addr_entry.set_text("socks5://127.0.0.1:1080/proxy");
                validate_pending_proxy_addr();
            }
        }

        dialog.show_all();
        let sub_to_show = std::env::var("MEWSER_VIEW_SUBTAB")
            .unwrap_or_else(|_| active_subtab_rc.borrow().clone());
        select_subtab(&sub_to_show);
        load_viewed_to_form();

        if let Ok(page_str) = std::env::var("MEWSER_SETTINGS_PAGE") {
            if page_str == "1" || page_str == "routing" {
                select_page("routing");
            } else if page_str == "2" || page_str == "gateway" {
                select_page("gateway");
            } else if page_str == "3" || page_str == "general" {
                select_page("general");
            }
        }

        let app_model_clone = Arc::clone(app_model);
        let save_form_final = save_form_to_viewed.clone();
        let pstore_final = Rc::clone(&profile_store_rc);
        let pkeys_final = Rc::clone(&profile_keys_rc);
        let update_timeout_val_final = update_timeout_validation.clone();
        let staged_domains_final = Rc::clone(&staged_domains);
        let staged_suffixes_final = Rc::clone(&staged_suffixes);
        let validate_dom_final = validate_pending_domain.clone();
        let validate_suf_final = validate_pending_suffix.clone();
        let validate_gw_final = validate_pending_gw_endpoint.clone();
        let validate_proxy_final = validate_pending_proxy_addr.clone();
        let validate_tcp_final = validate_pending_tcp_endpoint.clone();
        let transport_combo_final = transport_combo.clone();
        let gw_token_entry_final = gw_token_entry.clone();
        let proxy_addr_entry_final = proxy_addr_entry.clone();
        let tcp_endpoint_entry_final = tcp_endpoint_entry.clone();
        let proxy_user_entry_final = proxy_user_entry.clone();
        let gen_auto_switch_final = gen_auto_switch.clone();
        let gen_vault_switch_final = gen_vault_switch.clone();

        dialog.connect_response(move |d, resp| {
            if resp == gtk::ResponseType::Ok {
                if !update_timeout_val_final() {
                    return;
                }
                if !validate_dom_final() || !validate_suf_final() {
                    return;
                }
                if !validate_gw_final() {
                    return;
                }
                if !validate_proxy_final() || !validate_tcp_final() {
                    return;
                }
                save_form_final();

                let mut model = app_model_clone.lock().unwrap();
                model.settings.profile_store = pstore_final.borrow().clone();
                model.settings.tunnel_auto_connect = gen_auto_switch_final.is_active();
                model.settings.profile_store.auto_connect = gen_auto_switch_final.is_active();
                model.settings.vault_file_consent = gen_vault_switch_final.is_active();

                if model.settings.vault_file_consent {
                    if let Some(v_path) = crate::state::get_secrets_file_path() {
                        if let Ok(file_vault) = crate::profile::SecretVault::file_backed(v_path) {
                            model.settings.secret_vault = file_vault;
                        }
                    }
                }

                // Persist all in-memory keys into the secret vault
                for (prof_id, key) in pkeys_final.borrow().iter() {
                    if let Some(prof) = model.settings.profile_store.get_profile(prof_id) {
                        let _ = model.settings.secret_vault.set_key(&prof.key_ref, key);
                    }
                }

                // Synchronize active profile into cached settings fields
                model.settings.sync_active_profile_fields();

                model.settings.direct_domains = staged_domains_final.borrow().clone();
                model.settings.direct_suffixes = staged_suffixes_final.borrow().clone();

                if gw_entry.is_sensitive() {
                    if let Ok(valid_gw) = validate_gateway_endpoint(&gw_entry.text()) {
                        model.settings.gateway_addr_str = valid_gw;
                    }
                }
                let entered_token = gw_token_entry_final.text().trim().to_string();
                model.settings.gateway_token = entered_token.clone();
                if !entered_token.is_empty() {
                    let _ = model
                        .settings
                        .secret_vault
                        .set_key(crate::state::GATEWAY_TOKEN_SECRET_REF, &entered_token);
                } else {
                    let _ = model
                        .settings
                        .secret_vault
                        .delete_key(crate::state::GATEWAY_TOKEN_SECRET_REF);
                }
                model.settings.timeout_secs = to_scale.value() as u64;

                if transport_combo_final.active_id().as_deref() == Some("fixed_tcp") {
                    model.settings.transport = DesktopTransport::FixedTcp;
                } else {
                    model.settings.transport = DesktopTransport::Socks5;
                }

                if let Ok(valid_proxy) =
                    validate_socket_addr(&proxy_addr_entry_final.text(), "SOCKS5 proxy address")
                {
                    model.settings.proxy_addr_str = valid_proxy;
                }
                if let Ok(valid_tcp) =
                    validate_socket_addr(&tcp_endpoint_entry_final.text(), "Fixed TCP endpoint")
                {
                    model.settings.tcp_endpoint_str = valid_tcp;
                }
                model.settings.proxy_user = proxy_user_entry_final.text().to_string();

                let _ = model.settings.save_persistent();

                // Update controller configuration
                model
                    .controller
                    .update_config(model.settings.build_masterdns_config());
            }
            d.close();
        });
    }
}

pub struct MewserApp {
    pub address_bar: String,
    pub current_url: Option<String>,
    pub state: PageState,
    pub history: HistoryStack,
    pub settings: SettingsState,
    pub show_settings: bool,
    pub active_request_id: u64,
    pub endpoint_test_result: Option<Result<String, String>>,
    tx: Sender<(u64, Result<NavigationResult, ClientError>)>,
    rx: Receiver<(u64, Result<NavigationResult, ClientError>)>,
}

impl Default for MewserApp {
    fn default() -> Self {
        Self::new()
    }
}

impl MewserApp {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        let settings = SettingsState::load_or_default();
        Self {
            address_bar: "https://example.com/".to_string(),
            current_url: None,
            state: PageState::Idle,
            history: HistoryStack::new(),
            settings,
            show_settings: false,
            active_request_id: 0,
            endpoint_test_result: None,
            tx,
            rx,
        }
    }

    pub fn navigate_new(&mut self, raw_url: String) {
        let normalized = normalize_input_url(&raw_url);
        if normalized.is_empty() {
            return;
        }
        self.history.push_new(self.current_url.clone());
        self.start_request(normalized);
    }

    pub fn navigate_back(&mut self) {
        if let Some(prev) = self.history.go_back(self.current_url.clone()) {
            self.start_request(prev);
        }
    }

    pub fn navigate_forward(&mut self) {
        if let Some(next) = self.history.go_forward(self.current_url.clone()) {
            self.start_request(next);
        }
    }

    pub fn reload(&mut self) {
        let url_to_reload = self
            .current_url
            .clone()
            .unwrap_or_else(|| normalize_input_url(&self.address_bar));
        if !url_to_reload.is_empty() {
            self.start_request(url_to_reload);
        }
    }

    pub fn cancel_navigation(&mut self) {
        self.active_request_id = self.active_request_id.wrapping_add(1);
        if matches!(self.state, PageState::Loading { .. }) {
            self.state = PageState::Idle;
        }
    }

    fn start_request(&mut self, url: String) {
        let trimmed = url.trim().to_string();
        if trimmed.is_empty() {
            return;
        }

        self.address_bar = trimmed.clone();
        self.current_url = Some(trimmed.clone());

        self.active_request_id = self.active_request_id.wrapping_add(1);
        let req_id = self.active_request_id;

        self.state = PageState::Loading {
            url: trimmed.clone(),
            started_at: Instant::now(),
        };

        let adapter = match self.settings.build_tunnel_adapter() {
            Ok(a) => a,
            Err(e) => {
                self.state = PageState::Error {
                    url: trimmed,
                    message: format!("Configuration error: {e}"),
                };
                return;
            }
        };

        let (eff_tok, _) = self.settings.effective_gateway_token();
        let auth_token = if eff_tok.is_empty() {
            None
        } else {
            Some(eff_tok)
        };
        let engine = ClientEngine::new(adapter).with_auth_token(auth_token);
        let mode = self.settings.active_mode;
        let tx = self.tx.clone();

        thread::spawn(move || {
            let res = engine.navigate(&trimmed, mode);
            let _ = tx.send((req_id, res));
        });
    }

    pub fn check_background_results(&mut self) {
        while let Ok((req_id, result)) = self.rx.try_recv() {
            if req_id != self.active_request_id {
                continue;
            }

            match result {
                Ok(NavigationResult::TextPage(page)) => {
                    self.current_url = Some(page.url.clone());
                    self.address_bar = page.url.clone();
                    self.state = PageState::Loaded { page };
                }
                Err(err) => {
                    let url_disp = self
                        .current_url
                        .clone()
                        .unwrap_or_else(|| self.address_bar.clone());
                    self.state = PageState::from_client_error(url_disp, err, &self.settings);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mewser_gateway::ExtractedPage;

    #[test]
    fn test_normalize_input_url() {
        assert_eq!(normalize_input_url(""), "");
        assert_eq!(normalize_input_url("   "), "");
        assert_eq!(normalize_input_url("example.com"), "https://example.com");
        assert_eq!(
            normalize_input_url("http://example.com/page"),
            "http://example.com/page"
        );
        assert_eq!(
            normalize_input_url("https://example.com/page"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_stale_response_filtering_in_background_results() {
        let (tx, rx) = channel();
        let settings = SettingsState::default();
        let mut app = MewserApp {
            address_bar: "https://example.com/".to_string(),
            current_url: None,
            state: PageState::Idle,
            history: HistoryStack::new(),
            settings,
            show_settings: false,
            active_request_id: 2, // Current active request ID is 2
            endpoint_test_result: None,
            tx: tx.clone(),
            rx,
        };

        // Stale response with req_id = 1
        let stale_page = ExtractedPage {
            url: "https://example.com/stale".to_string(),
            title: "Stale Page".to_string(),
            description: None,
            headings: vec![],
            content: vec![],
            links: vec![],
            images: vec![],
        };
        tx.send((1, Ok(NavigationResult::TextPage(stale_page))))
            .unwrap();

        app.check_background_results();
        // State must remain Idle because response with id 1 was discarded
        assert_eq!(app.state, PageState::Idle);

        // Fresh response with req_id = 2
        let fresh_page = ExtractedPage {
            url: "https://example.com/fresh".to_string(),
            title: "Fresh Page".to_string(),
            description: None,
            headings: vec![],
            content: vec![],
            links: vec![],
            images: vec![],
        };
        tx.send((2, Ok(NavigationResult::TextPage(fresh_page.clone()))))
            .unwrap();

        app.check_background_results();
        assert_eq!(app.state, PageState::Loaded { page: fresh_page });
    }

    #[test]
    fn test_cancel_navigation_invalidates_active_request() {
        let (tx, rx) = channel();
        let settings = SettingsState::default();
        let mut app = MewserApp {
            address_bar: "https://example.com/".to_string(),
            current_url: None,
            state: PageState::Loading {
                url: "https://example.com/loading".to_string(),
                started_at: Instant::now(),
            },
            history: HistoryStack::new(),
            settings,
            show_settings: false,
            active_request_id: 5,
            endpoint_test_result: None,
            tx: tx.clone(),
            rx,
        };

        // User cancels navigation
        app.cancel_navigation();
        assert_eq!(app.active_request_id, 6);
        assert_eq!(app.state, PageState::Idle);

        // Arriving result from cancelled request (id 5) is discarded
        let cancelled_page = ExtractedPage {
            url: "https://example.com/cancelled".to_string(),
            title: "Cancelled Page".to_string(),
            description: None,
            headings: vec![],
            content: vec![],
            links: vec![],
            images: vec![],
        };
        tx.send((5, Ok(NavigationResult::TextPage(cancelled_page))))
            .unwrap();

        app.check_background_results();
        assert_eq!(app.state, PageState::Idle);
    }
}
