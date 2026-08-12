//! CLI binary — port of `cmd/hack-browser-data` (Phase 0: full flag surface, stub
//! handlers; wiring lands with Phase 2/3/4).
//!
//! Flag-name/short/alias parity (PLAN R8): `-b -c -f -d -p --zip -v`, `dump` is the
//! default command when no subcommand is given (Go: root copies dump's flags).
//! `--keychain-pw` (macOS-only) is intentionally dropped.

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

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
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("LemonStealer: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> anyhow::Result<()> {
    // Placeholder handlers — each command is wired to its real implementation in the
    // phase that ports it (Phase 2: list/dump discovery; Phase 3: dumpkeys; Phase 4:
    // archive/restore/extractAndWrite).
    match cli.command {
        None => {
            println!(
                "dump (default): -b {} -c {} -f {} -d {} -p {} --zip {}",
                cli.dump.browser,
                cli.dump.category,
                cli.dump.format,
                cli.dump.dir,
                cli.dump.profile_path,
                cli.dump.zip
            );
            println!("  [stub] Phase 2/4: discover + extract + write")
        }
        Some(Command::Dump { args }) => {
            println!(
                "dump: -b {} -c {} -f {} -d {} -p {} --zip {}",
                args.browser, args.category, args.format, args.dir, args.profile_path, args.zip
            );
            println!("  [stub] Phase 2/4: discover + extract + write")
        }
        Some(Command::Dumpkeys { browser, output }) => {
            println!("dumpkeys: -b {browser} -o {output}");
            println!("  [stub] Phase 3: DiscoverBrowsersWithKeys + BuildDump + WriteJSON")
        }
        Some(Command::Archive {
            browser,
            category,
            output,
        }) => {
            println!("archive: -b {browser} -c {category} -o {output}");
            println!("  [stub] Phase 4: Archivable → ZipDir")
        }
        Some(Command::Restore {
            keys,
            data_dir,
            data_zip,
            args,
        }) => {
            println!(
                "restore: --keys {keys} --data-dir {data_dir} --data-zip {data_zip} -b {} -c {} -f {} -d {} --zip {}",
                args.browser, args.category, args.format, args.dir, args.zip
            );
            println!("  [stub] Phase 4: ReadJSON + BuildFromDump + extractAndWrite")
        }
        Some(Command::List { detail }) => {
            println!("list: --detail {detail}");
            println!("  [stub] Phase 2: DiscoverBrowsers + tabwriter")
        }
        Some(Command::Version) => {
            println!("LemonStealer {}", env!("CARGO_PKG_VERSION"));
            println!("  commit: dev");
            println!("  built:  unknown");
        }
    }
    Ok(())
}
