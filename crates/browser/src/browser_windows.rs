//! Windows browser config table (Go: `browser/browser_windows.go` — gravid port).
//!
//! Firefox is kept in the table for `list_browsers`/`names` parity with Go, but
//! `new_browser` does not dispatch to a Firefox engine (dropped from this build),
//! so it logs a per-install error and skips — exactly like Go's unknown-kind error
//! path.

use hbd_core::{BrowserConfig, BrowserKind};

use crate::consts::*;

/// Home-relative path helper: `homeDir + "/AppData/..."` (forward slashes — Go
/// uses them; Windows APIs accept them).
fn home_path(rel: &str) -> String {
    let home = home_dir().to_string_lossy().to_string();
    format!("{home}{rel}")
}

/// The Windows platform browser table (Go: `platformBrowsers`).
pub fn platform_browsers() -> Vec<BrowserConfig> {
    vec![
        BrowserConfig {
            key: "chrome".into(),
            name: CHROME_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: true,
            user_data_dir: home_path("/AppData/Local/Google/Chrome/User Data"),
        },
        BrowserConfig {
            key: "edge".into(),
            name: EDGE_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: true,
            user_data_dir: home_path("/AppData/Local/Microsoft/Edge/User Data"),
        },
        BrowserConfig {
            key: "chromium".into(),
            name: CHROMIUM_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/Chromium/User Data"),
        },
        BrowserConfig {
            key: "chrome-beta".into(),
            name: CHROME_BETA_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: true,
            user_data_dir: home_path("/AppData/Local/Google/Chrome Beta/User Data"),
        },
        BrowserConfig {
            key: "opera".into(),
            name: OPERA_NAME.into(),
            kind: BrowserKind::ChromiumOpera,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Roaming/Opera Software/Opera Stable"),
        },
        BrowserConfig {
            key: "opera-gx".into(),
            name: OPERA_GX_NAME.into(),
            kind: BrowserKind::ChromiumOpera,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Roaming/Opera Software/Opera GX Stable"),
        },
        BrowserConfig {
            key: "vought".into(),
            name: VOUGHT_NAME.into(),
            kind: BrowserKind::ChromiumOpera,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Roaming/Browser from Vought"),
        },
        BrowserConfig {
            key: "vivaldi".into(),
            name: VIVALDI_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/Vivaldi/User Data"),
        },
        BrowserConfig {
            key: "coccoc".into(),
            name: COCCOC_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: true,
            user_data_dir: home_path("/AppData/Local/CocCoc/Browser/User Data"),
        },
        BrowserConfig {
            key: "brave".into(),
            name: BRAVE_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: true,
            user_data_dir: home_path("/AppData/Local/BraveSoftware/Brave-Browser/User Data"),
        },
        BrowserConfig {
            key: "yandex".into(),
            name: YANDEX_NAME.into(),
            kind: BrowserKind::ChromiumYandex,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/Yandex/YandexBrowser/User Data"),
        },
        BrowserConfig {
            key: "360x".into(),
            name: SPEED360X_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/360ChromeX/Chrome/User Data"),
        },
        BrowserConfig {
            key: "360".into(),
            name: SPEED360_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/360chrome/Chrome/User Data"),
        },
        BrowserConfig {
            key: "qq".into(),
            name: QQ_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/Tencent/QQBrowser/User Data"),
        },
        BrowserConfig {
            key: "dc".into(),
            name: DC_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/DCBrowser/User Data"),
        },
        BrowserConfig {
            key: "sogou".into(),
            name: SOGOU_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Local/Sogou/SogouExplorer/User Data"),
        },
        BrowserConfig {
            key: "arc".into(),
            name: ARC_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path(
                "/AppData/Local/Packages/TheBrowserCompany.Arc_*/LocalCache/Local/Arc/User Data",
            ),
        },
        BrowserConfig {
            key: "duckduckgo".into(),
            name: DUCKDUCKGO_NAME.into(),
            kind: BrowserKind::Chromium,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path(
                "/AppData/Local/Packages/DuckDuckGo.DesktopBrowser_*/LocalState/EBWebView",
            ),
        },
        BrowserConfig {
            key: "firefox".into(),
            name: FIREFOX_NAME.into(),
            kind: BrowserKind::Firefox,
            keychain_label: "".into(),
            windows_abe: false,
            user_data_dir: home_path("/AppData/Roaming/Mozilla/Firefox/Profiles"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of the Windows config-table invariants (browser_windows_test.go):
    // every entry has a key/name/kind and Windows-ABE flags match the Go table.
    #[test]
    fn table_has_all_go_entries_in_order() {
        let table = platform_browsers();
        let keys: Vec<&str> = table.iter().map(|c| c.key.as_str()).collect();
        // Exact Go order (browser_windows.go), Firefox included for parity.
        assert_eq!(
            vec![
                "chrome",
                "edge",
                "chromium",
                "chrome-beta",
                "opera",
                "opera-gx",
                "vought",
                "vivaldi",
                "coccoc",
                "brave",
                "yandex",
                "360x",
                "360",
                "qq",
                "dc",
                "sogou",
                "arc",
                "duckduckgo",
                "firefox",
            ],
            keys
        );
    }

    #[test]
    fn abe_flags_match_go() {
        let table = platform_browsers();
        let abe: Vec<&str> = table
            .iter()
            .filter(|c| c.windows_abe)
            .map(|c| c.key.as_str())
            .collect();
        assert_eq!(
            vec!["chrome", "edge", "chrome-beta", "coccoc", "brave"],
            abe
        );
    }

    #[test]
    fn kinds_match_go() {
        let table = platform_browsers();
        for c in table {
            match c.key.as_str() {
                "opera" | "opera-gx" | "vought" => {
                    assert_eq!(BrowserKind::ChromiumOpera, c.kind, "{}", c.key)
                }
                "yandex" => assert_eq!(BrowserKind::ChromiumYandex, c.kind, "yandex"),
                "firefox" => assert_eq!(BrowserKind::Firefox, c.kind, "firefox"),
                _ => assert_eq!(BrowserKind::Chromium, c.kind, "{}", c.key),
            }
        }
    }
}
