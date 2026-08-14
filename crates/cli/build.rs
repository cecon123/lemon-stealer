//! Build-time version metadata (Go: `debug.ReadBuildInfo` vcs.revision /
//! vcs.time — PORTING.md row 45: build.rs + env variables).
//!
//! Falls back silently to the "none"/"unknown" defaults in `version` when
//! git is unavailable or this isn't a git checkout.

use std::process::Command;

fn main() {
    let commit = git(&["rev-parse", "--short=8", "HEAD"]);
    let date = git(&["log", "-1", "--format=%cI"]);
    if let Some(c) = commit {
        println!("cargo:rustc-env=LEMON_GIT_COMMIT={c}");
    }
    if let Some(d) = date {
        println!("cargo:rustc-env=LEMON_BUILD_DATE={d}");
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.trim().to_string())
}
