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
pub mod dpapi;
#[cfg(windows)]
pub use dpapi::decrypt_dpapi;

/// Errors produced by the WinAPI surface (all variants carry the raw OS error).
#[derive(Debug, thiserror::Error)]
pub enum AbiError {
    /// Go: `CryptUnprotectData: %w` (dpapi_windows.go).
    #[error("CryptUnprotectData: {0}")]
    CryptUnprotectData(windows::core::Error),
    /// Go: `LocalFree` is called without error checking, but a failure here means
    /// the freed pointer is gone while the failure itself is only observable via
    /// the returned handle — treated as fatal for the operation.
    #[error("LocalFree: {0}")]
    LocalFree(windows::core::Error),
}
