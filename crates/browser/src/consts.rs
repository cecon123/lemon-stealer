//! Display names (Go: `browser/consts.go` — `homeDir` resolved at runtime).

use std::path::PathBuf;

/// Home directory of the current user (Go: `os.UserHomeDir()`).
pub fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub const CHROME_NAME: &str = "Chrome";
pub const CHROME_BETA_NAME: &str = "Chrome Beta";
pub const CHROMIUM_NAME: &str = "Chromium";
pub const EDGE_NAME: &str = "Microsoft Edge";
pub const BRAVE_NAME: &str = "Brave";
pub const OPERA_NAME: &str = "Opera";
pub const OPERA_GX_NAME: &str = "OperaGX";
pub const VOUGHT_NAME: &str = "Browser from Vought";
pub const VIVALDI_NAME: &str = "Vivaldi";
pub const COCCOC_NAME: &str = "CocCoc";
pub const YANDEX_NAME: &str = "Yandex";
pub const FIREFOX_NAME: &str = "Firefox";
pub const SPEED360_NAME: &str = "360 Speed";
pub const SPEED360X_NAME: &str = "360 Speed X";
pub const QQ_NAME: &str = "QQ";
pub const DC_NAME: &str = "DC";
pub const SOGOU_NAME: &str = "Sogou";
pub const ARC_NAME: &str = "Arc";
pub const DUCKDUCKGO_NAME: &str = "DuckDuckGo";
