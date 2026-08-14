//! Windows browser executable resolution (Go: `utils/winutil/browser_path_windows.go` +
//! `browser_meta_windows.go`, with the low-level calls from `utils/winapi`).
//!
//! Lives in `abi` (not the `browser` crate) because registry/process probing
//! is WinAPI — `browser` must stay `unsafe`-free and `keyring` (which resolves
//! the path for ABE) cannot depend on `browser`. This is the only layering
//! deviation from the Go repo.

use std::ffi::OsStr;
use std::fmt;
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::ProcessStatus::K32EnumProcesses;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, REG_SZ, REG_VALUE_TYPE,
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{Error, HRESULT, PCWSTR, PWSTR};

/// `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<exe>` (Go: same).
const APP_PATHS_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\";

/// Win32 error code → `windows::core::Error` (windows-core 0.62 dropped
/// `Error::from_win32`; HRESULT::from_win32 is the sanctioned conversion).
fn win32_err(code: u32) -> Error {
    Error::from_hresult(HRESULT::from_win32(code))
}

/// Which IElevator dispatch the C payload uses for this browser (Go: `ABEKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbeKind {
    None,
    /// IElevator vtable slot 5 (Chrome, Brave, CocCoc).
    ChromeBase,
    /// IElevator vtable slot 8 (Edge; 3 extra interface methods).
    Edge,
    /// IElevator vtable slot 13 (Avast; extended IElevator).
    Avast,
}

/// Per-browser Windows metadata (Go: `winutil.Entry`, keyed like the config
/// table's `windows_abe` entries).
#[derive(Debug, Clone)]
pub struct BrowserExe {
    pub key: &'static str,
    pub exe_name: &'static str,
    pub install_fallbacks: &'static [&'static str],
    pub kind: AbeKind,
}

/// Authoritative Windows metadata table (Go: `winutil.Table`).
pub const BROWSER_EXE_TABLE: &[BrowserExe] = &[
    BrowserExe {
        key: "chrome",
        exe_name: "chrome.exe",
        install_fallbacks: &[
            r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
            r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
            r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
        ],
        kind: AbeKind::ChromeBase,
    },
    BrowserExe {
        key: "chrome-beta",
        exe_name: "chrome.exe",
        install_fallbacks: &[
            r"%ProgramFiles%\Google\Chrome Beta\Application\chrome.exe",
            r"%ProgramFiles(x86)%\Google\Chrome Beta\Application\chrome.exe",
            r"%LocalAppData%\Google\Chrome Beta\Application\chrome.exe",
        ],
        kind: AbeKind::ChromeBase,
    },
    BrowserExe {
        key: "edge",
        exe_name: "msedge.exe",
        install_fallbacks: &[
            r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
            r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
        ],
        kind: AbeKind::Edge,
    },
    BrowserExe {
        key: "brave",
        exe_name: "brave.exe",
        install_fallbacks: &[
            r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe",
        ],
        kind: AbeKind::ChromeBase,
    },
    BrowserExe {
        key: "coccoc",
        exe_name: "browser.exe",
        install_fallbacks: &[
            r"%ProgramFiles%\CocCoc\Browser\Application\browser.exe",
            r"%ProgramFiles(x86)%\CocCoc\Browser\Application\browser.exe",
            r"%LocalAppData%\CocCoc\Browser\Application\browser.exe",
        ],
        kind: AbeKind::ChromeBase,
    },
];

/// Go: `ErrExecutableNotFound`.
#[derive(Debug)]
pub enum WinpathError {
    NotFound(String),
    ExpandEnv(Error),
    Registry(Error),
    EnumProcesses(Error),
    QueryImage(Error),
}

impl fmt::Display for WinpathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WinpathError::NotFound(detail) => {
                write!(f, "browser executable not found: {detail}")
            }
            WinpathError::ExpandEnv(e) => write!(f, "ExpandEnvironmentStringsW: {e}"),
            WinpathError::Registry(e) => {
                write!(f, "registry App Paths lookup: {e}")
            }
            WinpathError::EnumProcesses(e) => write!(f, "K32EnumProcesses: {e}"),
            WinpathError::QueryImage(e) => write!(f, "QueryFullProcessImageNameW: {e}"),
        }
    }
}

impl std::error::Error for WinpathError {}

/// 4-tier executable resolution (Go: `ExecutablePath`): registry App Paths
/// HKLM → HKCU → running-process probe → expanded install fallbacks.
pub fn executable_path(browser_key: &str) -> Result<String, WinpathError> {
    let Some(entry) = BROWSER_EXE_TABLE.iter().find(|e| e.key == browser_key) else {
        return Err(WinpathError::NotFound(format!(
            "{browser_key:?} (no lookup entry)"
        )));
    };

    if let Ok(p) = app_paths_lookup(entry.exe_name, HKEY_LOCAL_MACHINE) {
        return Ok(p);
    }
    if let Ok(p) = app_paths_lookup(entry.exe_name, HKEY_CURRENT_USER) {
        return Ok(p);
    }
    if let Some(p) = running_process_path(entry.exe_name) {
        return Ok(p);
    }
    for candidate in entry.install_fallbacks {
        let Ok(expanded) = expand_env_string(candidate) else {
            continue;
        };
        if is_file(&expanded) {
            return Ok(expanded);
        }
    }
    Err(WinpathError::NotFound(format!(
        "{browser_key:?} (registry miss, no running process, no fallback match)"
    )))
}

/// `kernel32!ExpandEnvironmentStringsW` (Go uses it instead of os.ExpandEnv:
/// Go stdlib leaves `%VAR%` untouched — verified on Win10 19044 in the Go repo).
///
/// windows-rs 0.62 wraps the two-call size/fill pattern in an optional slice:
/// `None` queries the required length, `Some(buf)` fills it.
pub fn expand_env_string(s: &str) -> Result<String, WinpathError> {
    let wide: Vec<u16> = OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: src is NUL-terminated; None asks for the required length only.
    let size = unsafe { ExpandEnvironmentStringsW(PCWSTR(wide.as_ptr()), None) };
    if size == 0 {
        // SAFETY: advisory error read.
        return Err(WinpathError::ExpandEnv(win32_err(
            unsafe { GetLastError() }.0,
        )));
    }
    let mut buf = vec![0u16; size as usize];
    // SAFETY: buf is exactly size elements; the wrapper slices it to the
    // declared capacity and the OS writes a NUL-terminated result.
    let written = unsafe { ExpandEnvironmentStringsW(PCWSTR(wide.as_ptr()), Some(&mut buf)) };
    if written == 0 {
        // SAFETY: advisory error read.
        return Err(WinpathError::ExpandEnv(win32_err(
            unsafe { GetLastError() }.0,
        )));
    }
    buf.truncate(buf.iter().position(|&c| c == 0).unwrap_or(buf.len()));
    Ok(String::from_utf16_lossy(&buf))
}

/// `App Paths` lookup at `root` reading the default (`""`) value (Go: `appPathsLookup`).
fn app_paths_lookup(exe_name: &str, root: HKEY) -> Result<String, WinpathError> {
    let subkey: Vec<u16> = OsStr::new(&format!("{APP_PATHS_SUBKEY}{exe_name}"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let name: Vec<u16> = std::iter::once(0).collect();

    // SAFETY: subkey is NUL-terminated UTF-16; root is a predefined hive key;
    // KEY_QUERY_VALUE read-only. RegOpenKeyExW does not retain the strings.
    let mut hkey = HKEY(std::ptr::null_mut());
    // RegOpen* return WIN32_ERROR directly in windows-rs 0.62 (not Result).
    let status = unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(subkey.as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &mut hkey,
        )
    };
    if status.0 != 0 {
        return Err(WinpathError::Registry(win32_err(status.0)));
    }
    // SAFETY: hkey is open; must be closed before returning (guard below).
    let _guard = RegKeyGuard(hkey);

    let mut data_type = REG_VALUE_TYPE(0);
    let mut size = 0u32;
    // First probe gets the size with a NULL buffer; some values report it
    // directly with ERROR_SUCCESS, most with ERROR_MORE_DATA (234).
    let first = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut data_type),
            None,
            Some(&mut size),
        )
    };
    if first.0 != 0 && first.0 != 234 {
        return Err(WinpathError::Registry(win32_err(first.0)));
    }

    let mut value_wide = vec![0u16; (size as usize).div_ceil(2) + 1];
    loop {
        // SAFETY: value name "" (NUL) is the default value; the buffer is
        // sized from the OS query result; the call fills bytes and updates
        // size. ERROR_MORE_DATA grows the buffer and retries.
        let r = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut data_type),
                Some(value_wide.as_mut_ptr() as *mut u8),
                Some(&mut size),
            )
        };
        match r.0 {
            0 => break,
            234 => value_wide = vec![0u16; (size as usize).div_ceil(2) + 1],
            other => return Err(WinpathError::Registry(win32_err(other))),
        }
    }
    if data_type != REG_SZ {
        return Err(WinpathError::NotFound(
            "App Paths default not REG_SZ".into(),
        ));
    }
    value_wide.truncate(
        value_wide
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(value_wide.len()),
    );
    let v = unquote(&String::from_utf16_lossy(&value_wide));
    if !is_file(&v) {
        return Err(WinpathError::NotFound(format!(
            "registry path does not exist: {v}"
        )));
    }
    Ok(v.trim_end_matches('\\').to_string())
}

/// Close-on-drop registry key.
struct RegKeyGuard(HKEY);
impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        // SAFETY: RegCloseKey on a key we opened (failure is benign).
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// Scan live processes for `exe_name` (case-insensitive leaf match) and return
/// the full image path of the first hit (Go: `runningProcessPath`).
pub fn running_process_path(exe_name: &str) -> Option<String> {
    let pids = enum_processes().ok()?;
    for pid in pids {
        if pid == 0 {
            continue;
        }
        // SAFETY: OpenProcess read-only query rights; fails silently for
        // protected processes (Skip-Access) — mirrors Go behavior.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let _guard = OwnedRawHandle(h);
        match query_full_process_image_name(h) {
            Some(path) => {
                let leaf = path.rsplit(['\\', '/']).next().unwrap_or("");
                if leaf.eq_ignore_ascii_case(exe_name) {
                    return Some(path);
                }
            }
            None => continue,
        }
    }
    None
}

/// `K32EnumProcesses` with buffer doubling up to 1M entries (Go: `EnumProcesses`).
fn enum_processes() -> Result<Vec<u32>, WinpathError> {
    let mut size = 1024u32;
    loop {
        let mut pids = vec![0u32; size as usize];
        let mut bytes_returned = 0u32;
        let r = unsafe { K32EnumProcesses(pids.as_mut_ptr(), size * 4, &mut bytes_returned) };
        if r.0 == 0 {
            // SAFETY: advisory error read.
            return Err(WinpathError::EnumProcesses(win32_err(
                unsafe { GetLastError() }.0,
            )));
        }
        let n = (bytes_returned / 4) as usize;
        if n < size as usize {
            pids.truncate(n);
            return Ok(pids);
        }
        size *= 2;
        if size > 1 << 20 {
            return Err(WinpathError::EnumProcesses(win32_err(8)));
        }
    }
}

fn query_full_process_image_name(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 32767];
    let mut size = buf.len() as u32;
    // SAFETY: buf is MAX_PATH-ish and size describes it; PROCESS_NAME_WIN32 (0)
    // matches the Go default flag.
    let r = unsafe {
        QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
    };
    if r.is_err() {
        return None;
    }
    buf.truncate(size as usize);
    Some(String::from_utf16_lossy(&buf))
}

struct OwnedRawHandle(HANDLE);
impl Drop for OwnedRawHandle {
    fn drop(&mut self) {
        // SAFETY: CloseHandle on a handle we own.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn unquote(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn is_file(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_matches_go_winutil() {
        let keys: Vec<&str> = BROWSER_EXE_TABLE.iter().map(|e| e.key).collect();
        assert_eq!(
            vec!["chrome", "chrome-beta", "edge", "brave", "coccoc"],
            keys
        );
        assert!(
            BROWSER_EXE_TABLE
                .iter()
                .all(|e| e.exe_name.ends_with(".exe"))
        );
        assert_eq!(
            AbeKind::Edge,
            BROWSER_EXE_TABLE
                .iter()
                .find(|e| e.key == "edge")
                .unwrap()
                .kind
        );
        assert_eq!(
            AbeKind::ChromeBase,
            BROWSER_EXE_TABLE
                .iter()
                .find(|e| e.key == "brave")
                .unwrap()
                .kind
        );
    }

    #[test]
    fn unquote_handles_quoted_and_plain() {
        assert_eq!(r"C:\x", unquote(r#""C:\x""#));
        assert_eq!(r"C:\x", unquote(r"C:\x"));
        assert_eq!("", unquote(""));
    }

    #[test]
    fn expand_env_known_vars() {
        let v = expand_env_string("%ProgramFiles%").unwrap();
        assert!(v.contains("Program Files"), "got {v}");
    }

    #[test]
    fn unknown_browser_key_is_not_found() {
        assert!(matches!(
            executable_path("no-such-browser"),
            Err(WinpathError::NotFound(_))
        ));
    }
}
