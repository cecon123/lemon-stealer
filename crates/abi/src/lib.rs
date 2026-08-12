//! `abi` — the ONLY crate allowed to touch WinAPI / `unsafe` (PLAN.md R4).
//!
//! Scope (all phases):
//! - DPAPI: `CryptUnprotectData` (crypt32) — Phase 3
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
//!
//! Until the first Windows-specific phase, this crate stays empty on purpose.
