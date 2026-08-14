//! Port of Go package `chrome` — engine for every Chromium-based browser
//! (plain Chromium, Opera, Yandex variants). The Go files map 1:1:
//!
//! | Go | Rust |
//! |---|---|
//! | `chromium.go` | [`mod.rs`] (this file) |
//! | `profile.go` | [`profile`] |
//! | `source.go` | [`source`] |
//! | `decrypt.go` | [`decrypt`] |
//! | `extract_*.go` | `extract_*.rs` |
//! | `yandex.go` | [`yandex`] |
//! | `utils/sqliteutil` | [`sqliteutil`] |

pub mod decrypt;
pub mod error;
pub mod extract_bookmark;
pub mod extract_cookie;
pub mod extract_creditcard;
pub mod extract_download;
pub mod extract_extension;
pub mod extract_history;
pub mod extract_password;
pub mod extract_storage;
pub mod leveldb;
pub mod leveldb_probe;
pub mod profile;
pub mod source;
pub mod sqliteutil;
pub mod yandex;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use hbd_core::{
    BrowserConfig, BrowserKind, Category, CountResult, ExtractResult, Profile as CoreProfile,
};
use keyring::{Hints, MasterKeys, Retrievers};

use crate::chromium::source::{extractors_for_kind, resolve_source_paths, sources_for_kind};
use crate::{Browser as BrowserTrait, BrowserError, KeyManager};
use filemanager::Session;

/// One Chromium installation: a single UserDataDir holding profiles that share
/// a master key. The key is derived once and reused across profiles (Go: `Browser`).
pub struct Browser {
    cfg: BrowserConfig,
    retrievers: Retrievers,
    #[allow(dead_code)] // read via profile names/loop; the struct owns the listing
    profiles: Vec<Profile>,
    keys: OnceLock<MasterKeys>,
}

/// Discovers the profiles under `cfg.user_data_dir`, or returns `None` if none
/// resolve. Call `set_retrievers` before `extract` to enable decryption.
/// (Go: `NewBrowser`.)
pub fn new_browser(cfg: BrowserConfig) -> Result<Option<Browser>, BrowserError> {
    let sources = sources_for_kind(cfg.kind);
    let extractors = extractors_for_kind(cfg.kind);

    let mut profiles = Vec::new();
    for profile_dir in discover_profiles(&cfg.user_data_dir, &sources) {
        let source_paths = resolve_source_paths(&sources, &profile_dir);
        if source_paths.is_empty() {
            continue;
        }
        profiles.push(Profile {
            profile_dir,
            browser_name: cfg.name.clone(),
            kind: cfg.kind,
            extractors: extractors.clone(),
            source_paths,
        });
    }
    if profiles.is_empty() {
        return Ok(None);
    }
    Ok(Some(Browser {
        cfg,
        retrievers: Retrievers::default(),
        profiles,
        keys: OnceLock::new(),
    }))
}

impl Browser {
    /// Wires the per-tier master-key retrievers (V10/V11/V20) used by `extract` —
    /// unused tiers stay `None` (Go: `SetRetrievers`).
    pub fn set_retrievers(&mut self, r: Retrievers) {
        self.retrievers = r;
    }

    /// Derives the installation's keys, keeping partial results: a v20-only
    /// failure must not discard a usable v10 key (Go: `ExportKeys`).
    #[allow(dead_code)] // trait path uses it indirectly via KeyManager::export_keys
    pub(crate) fn export_keys_impl(&self) -> Result<MasterKeys, MasterKeyError> {
        let session = Session::new()?;
        Self::export_keys_with_hints(&self.retrievers, self.build_hints(&session))
    }

    /// The key-flavored half of `export_keys`, testable without a session.
    fn export_keys_with_hints(
        retrievers: &Retrievers,
        hints: Hints,
    ) -> Result<MasterKeys, MasterKeyError> {
        let (keys, errs) = keyring::masterkeys::new_master_keys_partial(retrievers, hints);
        if errs.is_empty() {
            Ok(keys)
        } else {
            Err(MasterKeyError { keys, errs })
        }
    }

    /// Derives and caches the installation's keys exactly once, so a failure is
    /// warned once — no cross-profile dedup state needed (Go: `masterKeys`).
    fn master_keys(&self) -> &MasterKeys {
        self.keys.get_or_init(|| {
            let (keys, errs) = match self.export_keys_impl() {
                Ok(keys) => (keys, Vec::new()),
                Err(e) => (e.keys, e.errs),
            };
            if !errs.is_empty() {
                let joined = errs
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                log::warn!("{}: master key retrieval: {}", self.cfg.name, joined);
            }
            self.log_key_tiers(&keys);
            keys
        })
    }

    /// Logs which key tiers are available for this installation with their
    /// sizes (Go logs nothing here; added for operator visibility).
    fn log_key_tiers(&self, keys: &MasterKeys) {
        let mut tiers = Vec::new();
        if let Some(k) = keys.v10.as_deref() {
            tiers.push(format!("v10:{}", k.len()));
        }
        if let Some(k) = keys.v11.as_deref() {
            tiers.push(format!("v11:{}", k.len()));
        }
        if let Some(k) = keys.v20.as_deref() {
            tiers.push(format!("v20:{}", k.len()));
        }
        if tiers.is_empty() {
            log::info!("{}: no master keys", self.cfg.name);
        } else {
            log::info!("{}: master keys: {}", self.cfg.name, tiers.join(", "));
        }
    }

    /// Copies Local State into the session temp dir (so Windows DPAPI/ABE
    /// retrievers read it from a process-owned path) and assembles the hints.
    /// Local State sits at the installation root (Go: `buildHints`).
    fn build_hints(&self, session: &Session) -> Hints {
        let mut local_state_path = PathBuf::new();
        let candidate = Path::new(&self.cfg.user_data_dir).join("Local State");
        if candidate.is_file() {
            let dst = session.temp_dir().join("Local State");
            match session.acquire(&candidate, &dst, false) {
                Ok(()) => local_state_path = dst,
                Err(e) => log::debug!("acquire Local State for {}: {}", self.cfg.name, e),
            }
        }

        let abe_key = if self.cfg.windows_abe {
            self.cfg.key.clone()
        } else {
            String::new()
        };
        Hints {
            keychain_label: self.cfg.keychain_label.clone(),
            windows_abe_key: abe_key,
            local_state_path,
        }
    }
}

/// Error from [`Browser::export_keys`] carrying the partial keys that
/// succeeded (Go: `(MasterKeys, error)` — the error joins per-tier failures).
#[derive(Debug)]
pub struct MasterKeyError {
    pub keys: MasterKeys,
    pub errs: Vec<keyring::RetrieverError>,
}

impl From<(MasterKeys, Vec<keyring::RetrieverError>)> for MasterKeyError {
    fn from((keys, errs): (MasterKeys, Vec<keyring::RetrieverError>)) -> Self {
        MasterKeyError { keys, errs }
    }
}

impl From<std::io::Error> for MasterKeyError {
    fn from(e: std::io::Error) -> Self {
        MasterKeyError {
            keys: MasterKeys::default(),
            errs: vec![keyring::RetrieverError::Os(e)],
        }
    }
}

impl std::fmt::Display for MasterKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, e) in self.errs.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for MasterKeyError {}

impl BrowserTrait for Browser {
    fn browser_name(&self) -> &str {
        &self.cfg.name
    }
    fn user_data_dir(&self) -> &str {
        &self.cfg.user_data_dir
    }
    fn profiles(&self) -> Vec<CoreProfile> {
        self.profiles
            .iter()
            .map(|p| CoreProfile {
                name: p.name(),
                dir: p.profile_dir.display().to_string(),
            })
            .collect()
    }
    fn extract(&self, categories: &[Category]) -> Result<Vec<ExtractResult>, BrowserError> {
        let master_keys = self.master_keys().clone();
        let mut results = Vec::with_capacity(self.profiles.len());
        for p in &self.profiles {
            log::debug!("{}: extracting {}", self.cfg.name, p.label());
            let data = p.extract(&master_keys, categories);
            let total: usize = data.passwords.len()
                + data.cookies.len()
                + data.histories.len()
                + data.downloads.len()
                + data.bookmarks.len()
                + data.credit_cards.len()
                + data.extensions.len()
                + data.local_storage.len()
                + data.session_storage.len();
            log::info!("  {}/{}: {} entries", self.cfg.name, p.name(), total);
            results.push(ExtractResult {
                profile: CoreProfile {
                    name: p.name(),
                    dir: p.profile_dir.display().to_string(),
                },
                data,
            });
        }
        Ok(results)
    }
    fn count_entries(&self, categories: &[Category]) -> Result<Vec<CountResult>, BrowserError> {
        let mut results = Vec::with_capacity(self.profiles.len());
        for p in &self.profiles {
            results.push(CountResult {
                profile: CoreProfile {
                    name: p.name(),
                    dir: p.profile_dir.display().to_string(),
                },
                counts: p.count(categories),
            });
        }
        Ok(results)
    }
}

impl KeyManager for Browser {
    fn set_retrievers(&mut self, retrievers: Retrievers) {
        self.retrievers = retrievers;
    }
    fn export_keys(&self) -> Result<MasterKeys, BrowserError> {
        match self.export_keys_impl() {
            Ok(keys) => Ok(keys),
            Err(e) if e.keys.has_any() => {
                // Partial success: keep the usable tiers (Go: warn + partial).
                Ok(e.keys)
            }
            Err(e) => Err(BrowserError::Message(format!("{e}"))),
        }
    }
    fn browser_key(&self) -> String {
        self.cfg.key.clone()
    }
    fn kind(&self) -> BrowserKind {
        self.cfg.kind
    }
}

/// Lists subdirectories of `user_data_dir` that are valid profile directories.
/// A directory counts as a profile if it contains a `Preferences` file, which
/// Chromium creates for every profile (Go: `discoverProfiles`).
pub fn discover_profiles(user_data_dir: &str, sources: &source::Sources) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(user_data_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let entries: Vec<_> = entries.flatten().collect();

    let mut profiles = Vec::new();
    for e in &entries {
        let Ok(file_type) = e.file_type() else {
            continue;
        };
        if !file_type.is_dir() || is_skipped_dir(&e.file_name().to_string_lossy()) {
            continue;
        }
        let dir = Path::new(user_data_dir).join(e.file_name());
        if is_profile_dir(&dir) {
            profiles.push(dir);
        }
    }

    // Flat layout (older Opera): data files directly under userDataDir with no
    // profile subdir. Check the root before the subdir fallback so a stray
    // source-bearing subdir can't suppress root discovery.
    if profiles.is_empty() && has_any_source(sources, user_data_dir) {
        profiles.push(PathBuf::from(user_data_dir));
    }

    // Restored/copied trees may omit the Preferences marker (it is no extraction
    // source). When the marker scan and flat-layout check both find nothing,
    // treat any source-bearing subdir as a profile.
    if profiles.is_empty() {
        for e in &entries {
            let Ok(file_type) = e.file_type() else {
                continue;
            };
            if !file_type.is_dir() || is_skipped_dir(&e.file_name().to_string_lossy()) {
                continue;
            }
            let dir = Path::new(user_data_dir).join(e.file_name());
            if has_any_source(sources, &dir.to_string_lossy()) {
                profiles.push(dir);
            }
        }
    }
    profiles
}

/// `Preferences` — standard Chromium and all major forks; `Preferences_02` —
/// Tencent-based browsers (QQ Browser, Sogou Explorer) (Go: `profileMarkers`).
const PROFILE_MARKERS: [&str; 2] = ["Preferences", "Preferences_02"];

/// Reports whether `dir` is a valid Chromium profile directory
/// (Go: `isProfileDir`).
fn is_profile_dir(dir: &Path) -> bool {
    PROFILE_MARKERS
        .iter()
        .any(|marker| Path::new(dir).join(marker).exists())
}

/// Checks if `dir` contains at least one source file or directory
/// (Go: `hasAnySource`).
fn has_any_source(sources: &source::Sources, dir: &str) -> bool {
    for candidates in sources.values() {
        for sp in candidates {
            if Path::new(dir).join(&sp.rel).exists() {
                return true;
            }
        }
    }
    false
}

/// Returns true for directory names that should never be treated as profiles
/// (Go: `isSkippedDir`).
fn is_skipped_dir(name: &str) -> bool {
    matches!(name, "System Profile" | "Guest Profile" | "Snapshot")
}

pub use crate::chromium::profile::Profile;
