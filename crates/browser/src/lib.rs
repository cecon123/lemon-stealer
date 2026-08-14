//! Port of Go package `browser` (Windows subset).
//!
//! Phase 2: the chromium engine and the Windows platform table are wired —
//! [`discover`] iterates the table and builds [`chromium::Browser`] instances.
//! Phase 0 traits (`Browser` / `KeyManager` / `Archivable`) remain the contract
//! every engine implements (Go `browser/browser.go`, `browser/archive.go`).

pub mod browser_windows;
pub mod chromium;
pub mod consts;
pub mod discover;
pub mod dump;

pub use dump::{Dump, DumpError, HostInfo, Vault, build_dump, read_dump, write_dump};

pub use browser_windows::platform_browsers;

use hbd_core::{BrowserKind, Category, CountResult, ExtractResult, Profile};

use keyring::{MasterKeys, Retrievers};

/// One installation: a UserDataDir holding profiles that (for Chromium) share one
/// master key (Go: `Browser`).
pub trait Browser {
    fn browser_name(&self) -> &str;
    fn user_data_dir(&self) -> &str;
    fn profiles(&self) -> Vec<Profile>;
    fn extract(&self, categories: &[Category]) -> Result<Vec<ExtractResult>, BrowserError>;
    fn count_entries(&self, categories: &[Category]) -> Result<Vec<CountResult>, BrowserError>;
}

/// Implemented by installations accepting external master-key retrievers
/// (Chromium only — Go: `KeyManager`). `browser_key`/`kind` expose the identity a
/// portable dump needs to rebuild the engine off the platform table.
pub trait KeyManager {
    fn set_retrievers(&mut self, retrievers: Retrievers);
    fn export_keys(&self) -> Result<MasterKeys, BrowserError>;
    fn browser_key(&self) -> String;
    fn kind(&self) -> BrowserKind;
}

/// Implemented by installations that can pack the decryption-relevant subset of their
/// profile files for cross-host restore (Go: `Archivable`, `browser/archive.go`).
pub trait Archivable {
    fn browser_key(&self) -> String;
    /// Phase 4: returns the relative file paths (forward slashes, deduped) that make
    /// up one `<browser-key>/` entry of the archive zip.
    fn archive_sources(&self, categories: &[Category]) -> Result<Vec<String>, BrowserError>;
}

/// Combined extraction + key-management surface for the CLI: every supported
/// engine on this Windows-only build implements both, so discovery returns one
/// list that can dump keys and extract (Go: `DiscoverBrowsers` returning the
/// `Browser` interface, with Chromium also satisfying `KeyManager`).
pub trait ManagedBrowser: Browser + KeyManager {}

impl<T: Browser + KeyManager> ManagedBrowser for T {}

/// Opaque browser-layer error (Go surfaces open errors; entry-level failures inside
/// extractors are logged and skipped, never propagated — see R3).
#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl BrowserError {
    pub fn msg(s: impl Into<String>) -> Self {
        BrowserError::Message(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BrowserError>();
    }
}
