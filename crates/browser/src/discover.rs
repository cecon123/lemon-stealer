//! Port of Go package `browser` discovery functions
//! (Go: `browser/browser.go` + `browser/browser_windows.go`).
//!
//! These functions iterate the Windows browser config table and create
//! [`Browser`] / [`KeyManager`] instances for further processing.
//!
//! ## Layering
//!
//! - `core` / `crypto` / `keyring` / `browser` have NO cyclic dependencies.
//! - `discover` lives in `browser` crate; it depends on `core`, `keyring`,
//!   `filemanager`, and `chromium` (for `NewBrowser`).
//! - CLI entry point (`cli`) calls `discover_browsers` / `discover_browsers_with_keys`
//!   then invokes `Extract` / `CountEntries` on returned instances.

use crate::browser_windows::platform_browsers;
use crate::chromium::new_browser;
use crate::{BrowserError, KeyManager, ManagedBrowser};
use hbd_core::BrowserKind;

/// Discovered browser: both the extraction surface (`Browser`) and key
/// management (`KeyManager`).
pub type DiscoveredBrowser = Box<dyn ManagedBrowser + Send + Sync>;

/// Discover all configured browsers on this platform.
///
/// Returns a vector of [`Browser`] trait objects ready for `Extract` /
/// `CountEntries`. Each browser's master keys are initially unavailable
/// (nil tiers) — call `set_retrievers` or use `DiscoverBrowsersWithKeys`
/// to inject them.
///
/// Go parity: `DiscoverBrowsers` (metadata-only; no credential injection).
pub fn discover_browsers() -> Result<Vec<DiscoveredBrowser>, BrowserError> {
    let configs = platform_browsers();
    let mut browsers = Vec::new();

    for cfg in configs {
        // Dispatch per kind — currently only Chromium-family supported
        // (Go: `newBrowser` selects Chromium/YandexOpera/Firefox/Safari;
        //  Windows-only build drops non-Chromium).
        let browser: Option<DiscoveredBrowser> = match cfg.kind {
            BrowserKind::Chromium | BrowserKind::ChromiumYandex | BrowserKind::ChromiumOpera => {
                new_browser(cfg)
                    .ok()
                    .flatten()
                    .map(|b| Box::new(b) as DiscoveredBrowser)
            }
            _ => {
                // Firefox/Safari not in scope for Windows-only build
                None
            }
        };

        if let Some(b) = browser {
            browsers.push(b);
        }
    }
    Ok(browsers)
}

/// Discover all configured browsers and wire per-tier master-key retrievers
/// so that `Extract` can decrypt data (Go: `DiscoverBrowsersWithKeys`).
///
/// The injector closure sets retrievers on each browser before returning.
/// For production use, construct `Retrievers` with DPAPI/ABE retrievers
/// (Phase 3). For test / scaffold purposes, [`Retrievers::default`] or
/// a [`crate::keyring::tests::StaticDummy`] may be passed.
///
/// Signature mirrors Go: `func DiscoverBrowsersWithKeys(opts DiscoverOptions) ([]Browser, error)`
pub fn discover_browsers_with_keys(
    mut injector: impl FnMut(&mut dyn KeyManager),
) -> Result<Vec<DiscoveredBrowser>, BrowserError> {
    let mut browsers = discover_browsers()?;

    for b in &mut browsers {
        injector(b.as_mut());
    }
    Ok(browsers)
}

#[cfg(test)]
mod tests {
    use super::*;

    use keyring::{Retrievers, retriever::StaticDummy};

    #[test]
    fn discover_browsers_has_chromium() {
        let browsers = discover_browsers().unwrap();
        assert!(
            !browsers.is_empty(),
            "at least Chrome/Edge should be discovered"
        );
        let keys = browsers[0].export_keys().unwrap();
        // v10 stays None when no retrievers wired — Go parity.
        assert!(keys.v10.is_none(), "v10 should be None without retrievers");
    }

    #[test]
    fn discover_browsers_with_keys_stub() {
        let browsers = discover_browsers_with_keys(|b| {
            let r = Retrievers {
                v10: Some(Box::new(StaticDummy(Some(vec![1, 2, 3]), None))),
                ..Default::default()
            };
            b.set_retrievers(r);
        })
        .unwrap();
        assert!(!browsers.is_empty());
        let keys = browsers[0].export_keys().unwrap();
        assert!(
            matches!(keys.v10, Some(k) if k == vec![1, 2, 3]),
            "v10 populated via stub"
        );
    }
}
