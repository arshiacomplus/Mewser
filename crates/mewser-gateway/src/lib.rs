pub mod config;
pub mod error;
pub mod extractor;
pub mod fetcher;
pub mod models;
pub mod server;
pub mod ssrf;

pub use config::GatewayConfig;
pub use error::GatewayError;
pub use extractor::extract_page;
pub use fetcher::SafeFetcher;
pub use models::{ContentBlock, ExtractedPage, HeadingItem, ImagePlaceholder, LinkItem};
pub use server::{GatewayServer, GatewayServerHandle};

pub struct Gateway {
    fetcher: SafeFetcher,
    config: GatewayConfig,
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Self {
        let fetcher = SafeFetcher::new(config.clone());
        Self { fetcher, config }
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub fn extract(&self, raw_url: &str) -> Result<ExtractedPage, GatewayError> {
        let (html, final_url) = self.fetcher.fetch(raw_url)?;
        Ok(extract_page(&html, &final_url))
    }
}
