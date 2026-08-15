//! Double-click console hiding — port of `cmd/hack-browser-data/main_windows.go`
//! (`configureDoubleClickMode` + `mousetrap.StartedByExplorer` +
//! `utils/winapi/console_windows.go` `HideConsoleWindow`).
//!
//! When launched by double-click from Explorer, our process gets a console that
//! becomes a visible black window. We detect that launch (parent PID's exe is
//! `explorer.exe`) and `ShowWindow(hwnd, SW_HIDE)` it away.
//!
//! Bootstrap without imports: the toolhelp snapshot walk reads only the loader's
//! module list + export directories, and every WinAPI below goes through the
//! [`crate::apitable`] tables — same IAT-reduction contract as the injector.
//!
//! Divergence from Go: mousetrap's `cobra.MousetrapHelpText = ""` is cobra-only
//! (clap has no double-click help guard); we keep just the console-hide half.
//! `GetConsoleWindow` uses `win32.Win32_Foundation.HWND` — the compile-time type
//! adds no import-table entry.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::ToolHelp::{PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD;

use crate::apitable::{kernel32, user32};

/// `SW_HIDE` (0) — hide the console window.
const SW_HIDE: SHOW_WINDOW_CMD = SHOW_WINDOW_CMD(0);

/// `INVALID_HANDLE_VALUE` for toolhelp snapshots (CreateToolhelp32Snapshot).
fn snapshot_ok(h: HANDLE) -> bool {
    !h.0.is_null() && h.0 as usize != usize::MAX
}

/// Full name of the current process's parent, resolved by walking the toolhelp
/// snapshot (Go: `mousetrap.getProcessEntry(syscall.Getppid())`, but we read
/// `th32ParentProcessID` from our own entry instead of a p-pid syscall).
fn parent_process_exe() -> Option<String> {
    let my_pid = std::process::id();
    // SAFETY: CreateToolhelp32Snapshot then Process32FirstW/NextW is the
    // documented walk; every address comes from a resolved export. The handle
    // is closed on every path out of this fn (guard below).
    let k = kernel32();
    let snap = unsafe { (k.create_toolhelp32_snapshot)(TH32CS_SNAPPROCESS, 0) };
    if !snapshot_ok(snap) {
        return None;
    }
    let _guard = OwnedHandle(snap);

    // First pass: find our own entry to get the parent PID.
    let mut parent_pid = None;
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    let mut next = unsafe { (k.process32_first_w)(snap, &mut entry) };
    let mut guard = 0usize;
    while next.as_bool() && guard < 4096 {
        if entry.th32ProcessID == my_pid {
            parent_pid = Some(entry.th32ParentProcessID);
            break;
        }
        // SAFETY: Process32NextW mutates `entry` in place on successive calls.
        next = unsafe { (k.process32_next_w)(snap, &mut entry) };
        guard += 1;
    }
    let parent_pid = parent_pid?;

    // Second pass: find the parent's entry and read its exe file name.
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    let mut next = unsafe { (k.process32_first_w)(snap, &mut entry) };
    let mut guard = 0usize;
    while next.as_bool() && guard < 4096 {
        if entry.th32ProcessID == parent_pid {
            // szExeFile is a NUL-terminated UTF-16 buffer; stop at the NUL.
            let end = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            return Some(String::from_utf16_lossy(&entry.szExeFile[..end]));
        }
        // SAFETY: as above.
        next = unsafe { (k.process32_next_w)(snap, &mut entry) };
        guard += 1;
    }
    None
}

/// Conservative check matching `mousetrap.StartedByExplorer`: true only for a
/// double-click launch from Explorer. Returns false on any failure (Go parity).
pub fn launched_by_explorer() -> bool {
    parent_process_exe().as_deref() == Some("explorer.exe")
}

/// `winapi.HideConsoleWindow`: hide the console attached to this process and
/// report whether it was previously visible.
pub fn hide_console_window() -> bool {
    // SAFETY: GetConsoleWindow has no parameters; returns a HWND or null.
    let hwnd = unsafe { (kernel32().get_console_window)() };
    if hwnd.0.is_null() {
        return false;
    }
    // SAFETY: ShowWindow on our own (validated non-null) console window.
    let prev = unsafe { (user32().show_window)(hwnd, SW_HIDE) };
    prev.as_bool()
}

/// `configureDoubleClickMode`: hide the console iff launched by Explorer
/// (double-click), otherwise leave the terminal's console alone.
pub fn configure_double_click_mode() {
    if launched_by_explorer() {
        hide_console_window();
    }
}

/// Closes a toolhelp snapshot handle on drop.
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: CloseHandle on the snapshot we own (failure is benign).
        unsafe {
            let _ = (kernel32().close_handle)(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launched_explorer_is_boolean() {
        // Should never panic or trap; explorer.exe parent → true.
        let _ = launched_by_explorer();
        let _ = hide_console_window();
        configure_double_click_mode();
    }

    #[test]
    fn parent_snapshot_walk_is_bounded() {
        // The two snapshot walks must terminate within the guard regardless of
        // system process count.
        let had_parent = parent_process_exe().is_some();
        // We're guaranteed a parent on Windows (even if pid 4 services).
        assert!(had_parent);
    }
}
