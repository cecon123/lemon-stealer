//! Port of `types/category.go`.
//!
//! `Category` is a browser-agnostic data type: a password is a password regardless of
//! which browser it came from. Kept as a newtype over `i32` (Go: `type Category int`
//! with `iota`) so arbitrary values behave exactly like Go (e.g. `Category(999)`).

use serde::{Deserialize, Serialize};

/// A kind of browser data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Category(i32);

impl Category {
    pub const PASSWORD: Category = Category(0);
    pub const COOKIE: Category = Category(1);
    pub const BOOKMARK: Category = Category(2);
    pub const HISTORY: Category = Category(3);
    pub const DOWNLOAD: Category = Category(4);
    pub const CREDIT_CARD: Category = Category(5);
    pub const EXTENSION: Category = Category(6);
    pub const LOCAL_STORAGE: Category = Category(7);
    pub const SESSION_STORAGE: Category = Category(8);

    /// Returns all supported data categories (Go: `AllCategories`).
    pub const ALL: [Category; 9] = [
        Category::PASSWORD,
        Category::COOKIE,
        Category::BOOKMARK,
        Category::HISTORY,
        Category::DOWNLOAD,
        Category::CREDIT_CARD,
        Category::EXTENSION,
        Category::LOCAL_STORAGE,
        Category::SESSION_STORAGE,
    ];

    /// Returns whether the category contains sensitive data that requires
    /// explicit opt-in to export (Go: `IsSensitive`).
    pub fn is_sensitive(self) -> bool {
        matches!(
            self,
            Category::PASSWORD | Category::COOKIE | Category::CREDIT_CARD
        )
    }

    pub const fn from_i32(v: i32) -> Self {
        Category(v)
    }

    pub const fn to_i32(self) -> i32 {
        self.0
    }
}

impl From<i32> for Category {
    fn from(v: i32) -> Self {
        Category(v)
    }
}

/// Human-readable name of the category (Go: `Category.String()`).
impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Category::PASSWORD => f.write_str(bypass::x!("password", 0x11).as_str()),
            Category::COOKIE => f.write_str(bypass::x!("cookie", 0x22).as_str()),
            Category::BOOKMARK => f.write_str(bypass::x!("bookmark", 0x33).as_str()),
            Category::HISTORY => f.write_str(bypass::x!("history", 0x44).as_str()),
            Category::DOWNLOAD => f.write_str(bypass::x!("download", 0x55).as_str()),
            Category::CREDIT_CARD => f.write_str(bypass::x!("creditcard", 0x66).as_str()),
            Category::EXTENSION => f.write_str(bypass::x!("extension", 0x77).as_str()),
            Category::LOCAL_STORAGE => f.write_str(bypass::x!("localstorage", 0x88).as_str()),
            Category::SESSION_STORAGE => f.write_str(bypass::x!("sessionstorage", 0x99).as_str()),
            _ => f.write_str(bypass::x!("unknown", 0xAA).as_str()),
        }
    }
}

/// Categories that are safe to export by default (Go: `NonSensitiveCategories`).
pub fn non_sensitive_categories() -> Vec<Category> {
    Category::ALL
        .iter()
        .copied()
        .filter(|c| !c.is_sensitive())
        .collect()
}

/// Identifies the browser engine type (Go: `BrowserKind`).
///
/// `Chromium`/`ChromiumYandex`/`ChromiumOpera` are the stable wire forms carried in a
/// keys dump — don't change them lightly. `Firefox`/`Safari` are kept only for
/// `String()` parity with Go; this build never produces them (Windows + Chromium only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserKind {
    Chromium,
    /// Chromium variant with different file names and extract logic.
    ChromiumYandex,
    /// Opera: extensions in "opsettings" key, data in Roaming.
    ChromiumOpera,
    Firefox,
    Safari,
}

/// Canonical lowercase name of the engine kind (Go: `BrowserKind.String()`).
impl std::fmt::Display for BrowserKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BrowserKind::Chromium => "chromium",
            BrowserKind::ChromiumYandex => "chromium-yandex",
            BrowserKind::ChromiumOpera => "chromium-opera",
            BrowserKind::Firefox => "firefox",
            BrowserKind::Safari => "safari",
        })
    }
}

/// Declarative configuration for a browser installation (Go: `BrowserConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserConfig {
    /// Lookup key; doubles as the Windows ABE / winutil table key when `windows_abe` is true.
    pub key: String,
    /// Display name.
    pub name: String,
    /// Engine type.
    pub kind: BrowserKind,
    /// macOS Keychain account / Linux D-Bus Secret Service label; "" = none.
    pub keychain_label: String,
    /// Enable Windows App-Bound Encryption v20 (reflective injection).
    pub windows_abe: bool,
    /// Base browser directory.
    pub user_data_dir: String,
}

/// All extracted browser data with typed slices (Go: `BrowserData`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BrowserData {
    pub passwords: Vec<crate::LoginEntry>,
    pub cookies: Vec<crate::CookieEntry>,
    pub histories: Vec<crate::HistoryEntry>,
    pub downloads: Vec<crate::DownloadEntry>,
    pub bookmarks: Vec<crate::BookmarkEntry>,
    pub credit_cards: Vec<crate::CreditCardEntry>,
    pub extensions: Vec<crate::ExtensionEntry>,
    pub local_storage: Vec<crate::StorageEntry>,
    pub session_storage: Vec<crate::StorageEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of TestCategory_String / TestBrowserKind_String.
    #[test]
    fn category_string_parity() {
        let cases = [
            (Category::PASSWORD, "password"),
            (Category::COOKIE, "cookie"),
            (Category::BOOKMARK, "bookmark"),
            (Category::HISTORY, "history"),
            (Category::DOWNLOAD, "download"),
            (Category::CREDIT_CARD, "creditcard"),
            (Category::EXTENSION, "extension"),
            (Category::LOCAL_STORAGE, "localstorage"),
            (Category::SESSION_STORAGE, "sessionstorage"),
            (Category::from_i32(999), "unknown"),
        ];
        for (cat, want) in cases {
            assert_eq!(want, cat.to_string(), "category {cat:?}");
        }
    }

    #[test]
    fn browser_kind_string_parity() {
        let cases = [
            (BrowserKind::Chromium, "chromium"),
            (BrowserKind::ChromiumYandex, "chromium-yandex"),
            (BrowserKind::ChromiumOpera, "chromium-opera"),
            (BrowserKind::Firefox, "firefox"),
            (BrowserKind::Safari, "safari"),
        ];
        for (kind, want) in cases {
            assert_eq!(want, kind.to_string(), "kind {kind:?}");
        }
    }

    // Port of TestCategory_IsSensitive.
    #[test]
    fn category_is_sensitive() {
        for c in [Category::PASSWORD, Category::COOKIE, Category::CREDIT_CARD] {
            assert!(c.is_sensitive(), "{c} should be sensitive");
        }
        for c in [
            Category::BOOKMARK,
            Category::HISTORY,
            Category::DOWNLOAD,
            Category::EXTENSION,
            Category::LOCAL_STORAGE,
            Category::SESSION_STORAGE,
        ] {
            assert!(!c.is_sensitive(), "{c} should not be sensitive");
        }
    }

    // Port of TestAllCategories / TestNonSensitiveCategories.
    #[test]
    fn all_categories_len_is_9() {
        assert_eq!(9, Category::ALL.len());
    }

    #[test]
    fn non_sensitive_categories_exclude_sensitive() {
        let cats = super::non_sensitive_categories();
        assert_eq!(6, cats.len());
        assert!(cats.iter().all(|c| !c.is_sensitive()));
    }
}
