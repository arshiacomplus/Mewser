pub mod adapter;
pub mod app;
pub mod controller;
pub mod profile;
pub mod state;

pub use adapter::BrowserEngineAdapter;
pub use app::{
    normalize_input_url, validate_direct_domain, validate_direct_suffix, validate_gateway_endpoint,
    validate_socket_addr, MewserApp, MewserAppModel, TabModel,
};
pub use controller::{
    ConnectedProfileSnapshot, MasterDnsConfig, MasterDnsController, ProfileUiState, TunnelState,
};
pub use profile::{
    export_masterdns_profile, generate_profile_id, FileSecretStore, MasterDnsProfile,
    MemorySecretStore, ProfileSecretStore, ProfileStore, SecretVault,
};
pub use state::{
    DesktopTransport, HistoryStack, PageState, PersistentSettings, ReaderPageMetadata,
    SettingsState,
};
