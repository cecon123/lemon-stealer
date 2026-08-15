//! Runtime-resolved WinAPI table (Wave 2: IAT reduction).
//!
//! Every function the injector touches is resolved at runtime from the
//! loader's module list + each module's export directory via [`crate::resolve`]
//! — so none of these names appear in our own import table. The table is
//! resolved once per process and reused.
//!
//! The fn-pointer signatures are the raw export ABIs (callers check `BOOL`,
//! like the `windows` 0.62 wrapper bodies do with `.ok()`). The struct/string
//! types (`HANDLE`, `PCWSTR`, `STARTUPINFOW`, …) are `windows` crate type
//! aliases — compile-time only, adding no import-table entries.
//!
//! ABI notes (kept here because they sit under `fn(...) -> BOOL`):
//! - `CreateProcessW`/`CreateRemoteThread` take `*const c_void` for their
//!   SECURITY_ATTRIBUTES slots: a plain pointer at this ABI level, and we pass
//!   `None` anyway.
//! - `lpcommandline` is `PWSTR` (mutable) as `link!` declares it; we keep the
//!   `Option<PWSTR>` to mirror the crate wrapper we replaced.

use std::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::{HANDLE, WAIT_EVENT, WIN32_ERROR};
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE};
use windows::Win32::System::Threading::{
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::resolve::{api, hash_bytes, hash_mod_bytes};

type ThreadRoutine = unsafe extern "system" fn(*mut c_void) -> u32;

/// Exact raw-ABI kernel32 export set used by the injector.
pub struct Kernel32 {
    /// `CloseHandle(hobject) -> BOOL`
    pub close_handle: unsafe extern "system" fn(HANDLE) -> BOOL,
    /// `GetLastError() -> WIN32_ERROR`
    pub get_last_error: unsafe extern "system" fn() -> WIN32_ERROR,
    /// `ReadProcessMemory(h, base, buf, len, &written) -> BOOL`
    pub read_process_memory:
        unsafe extern "system" fn(HANDLE, *const c_void, *mut c_void, usize, *mut usize) -> BOOL,
    /// `WriteProcessMemory(h, base, src, len, &written) -> BOOL`
    pub write_process_memory:
        unsafe extern "system" fn(HANDLE, *const c_void, *const c_void, usize, *mut usize) -> BOOL,
    /// `VirtualAllocEx(h, addr, size, type, prot) -> *mut c_void` (NULL on fail)
    pub virtual_alloc_ex: unsafe extern "system" fn(
        HANDLE,
        *const c_void,
        usize,
        VIRTUAL_ALLOCATION_TYPE,
        PAGE_PROTECTION_FLAGS,
    ) -> *mut c_void,
    /// `CreateProcessW(...) -> BOOL`
    #[allow(clippy::type_complexity)]
    pub create_process_w: unsafe extern "system" fn(
        PCWSTR,
        PWSTR,
        *const c_void,
        *const c_void,
        BOOL,
        PROCESS_CREATION_FLAGS,
        *const c_void,
        PCWSTR,
        *const STARTUPINFOW,
        *mut PROCESS_INFORMATION,
    ) -> BOOL,
    /// `CreateRemoteThread(h, attrs, stack, start, param, flags, &tid) -> HANDLE` (NULL on fail)
    pub create_remote_thread: unsafe extern "system" fn(
        HANDLE,
        *const c_void,
        usize,
        ThreadRoutine,
        *const c_void,
        u32,
        *mut u32,
    ) -> HANDLE,
    /// `ResumeThread(h) -> u32`
    pub resume_thread: unsafe extern "system" fn(HANDLE) -> u32,
    /// `TerminateProcess(h, code) -> BOOL`
    pub terminate_process: unsafe extern "system" fn(HANDLE, u32) -> BOOL,
    /// `WaitForSingleObject(h, ms) -> WAIT_EVENT`
    pub wait_for_single_object: unsafe extern "system" fn(HANDLE, u32) -> WAIT_EVENT,
    /// `GetExitCodeProcess(h, &code) -> BOOL`
    pub get_exit_code_process: unsafe extern "system" fn(HANDLE, *mut u32) -> BOOL,
}

/// Resolved-at-first-use kernel32 table.
pub static KERNEL32: OnceLock<Kernel32> = OnceLock::new();

fn load() -> Result<Kernel32, &'static str> {
    // All exports live in kernel32; a failed resolve reports the export name.
    fn addr(name: &str) -> Option<usize> {
        let m = hash_mod_bytes(b"kernel32.dll");
        api(m, hash_bytes(name.as_bytes()))
    }
    macro_rules! resolve {
        ($e:literal) => {{
            match addr($e) {
                Some(a) => a,
                None => return Err($e),
            }
        }};
    }

    // SAFETY: each `addr` is the verified code address of a kernel32 export
    // (kernel32 is loaded in every Windows process; the module hash is fixed
    // and case-folded, the export name hash is exact). transmute is the
    // sanctioned usize→fn-ptr bridge on x86-64; the signatures match the raw
    // `windows` 0.62 `link!` ABIs for the same exports.
    unsafe {
        Ok(Kernel32 {
            close_handle: std::mem::transmute::<usize, unsafe extern "system" fn(HANDLE) -> BOOL>(
                resolve!("CloseHandle"),
            ),
            get_last_error: std::mem::transmute::<usize, unsafe extern "system" fn() -> WIN32_ERROR>(
                resolve!("GetLastError"),
            ),
            read_process_memory: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HANDLE,
                    *const c_void,
                    *mut c_void,
                    usize,
                    *mut usize,
                ) -> BOOL,
            >(resolve!("ReadProcessMemory")),
            write_process_memory: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HANDLE,
                    *const c_void,
                    *const c_void,
                    usize,
                    *mut usize,
                ) -> BOOL,
            >(resolve!("WriteProcessMemory")),
            virtual_alloc_ex: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HANDLE,
                    *const c_void,
                    usize,
                    VIRTUAL_ALLOCATION_TYPE,
                    PAGE_PROTECTION_FLAGS,
                ) -> *mut c_void,
            >(resolve!("VirtualAllocEx")),
            create_process_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    PCWSTR,
                    PWSTR,
                    *const c_void,
                    *const c_void,
                    BOOL,
                    PROCESS_CREATION_FLAGS,
                    *const c_void,
                    PCWSTR,
                    *const STARTUPINFOW,
                    *mut PROCESS_INFORMATION,
                ) -> BOOL,
            >(resolve!("CreateProcessW")),
            create_remote_thread: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HANDLE,
                    *const c_void,
                    usize,
                    ThreadRoutine,
                    *const c_void,
                    u32,
                    *mut u32,
                ) -> HANDLE,
            >(resolve!("CreateRemoteThread")),
            resume_thread: std::mem::transmute::<usize, unsafe extern "system" fn(HANDLE) -> u32>(
                resolve!("ResumeThread"),
            ),
            terminate_process: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HANDLE, u32) -> BOOL,
            >(resolve!("TerminateProcess")),
            wait_for_single_object: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HANDLE, u32) -> WAIT_EVENT,
            >(resolve!("WaitForSingleObject")),
            get_exit_code_process: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HANDLE, *mut u32) -> BOOL,
            >(resolve!("GetExitCodeProcess")),
        })
    }
}

/// Resolve the table once (idempotent across threads).
///
/// Safer than returning the raw `Result`: either we've already resolved the
/// whole table or the first caller caches the resolution error forever. The
/// first failure aborts the injector anyway, so a panic with a precise message
/// is the honest surface.
pub fn kernel32() -> &'static Kernel32 {
    KERNEL32.get_or_init(|| match load() {
        Ok(t) => t,
        Err(name) => panic!("apitable: failed to resolve kernel32!{name}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_resolves_close_handle_nonzero() {
        let k = kernel32();
        assert_ne!(k.close_handle as usize, 0);
        assert_ne!(k.get_last_error as usize, 0);
    }
}
