//! Pre-resolved import patching (Go: `patchPreresolvedImports` in
//! `utils/injector/reflective_windows.go`).
//!
//! Writes five raw function addresses into the payload's DOS stub at the
//! scratch region offsets (`crate::payload::IMP_*_OFFSET`) so Bootstrap skips
//! PEB.Ldr traversal. Validity relies on KnownDlls + session-consistent ASLR:
//! kernel32 and ntdll share addresses across processes spawned in the same
//! boot session.

use std::ffi::CString;
use std::fmt;

use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::PCSTR;

use crate::payload;

/// Patch failure — all variants carry enough context to tell a corrupt payload
/// from a broken toolchain.
#[derive(Debug)]
pub enum PatchError {
    TooSmall(usize),
    MissingImport(&'static str),
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::TooSmall(len) => {
                write!(
                    f,
                    "injector: payload too small for pre-resolved import patch ({len})"
                )
            }
            PatchError::MissingImport(name) => {
                write!(f, "injector: failed to resolve pre-resolved import {name}")
            }
        }
    }
}

impl std::error::Error for PatchError {}

/// Raw address of an export inside a system DLL, resolved in OUR process — the
/// same value Bootstrap uses inside the target (KnownDlls ASLR; Go: `winapi.Addr*`).
/// Doesn't declare the export types; GetProcAddress returns the address value.
fn module_export_addr(module_name: &[u8], export: &[u8]) -> Option<usize> {
    let name_c = CString::new(export).ok()?;
    // SAFETY: module_name is a static, NUL-terminated DLL name ("kernel32.dll"
    // / "ntdll.dll" — both are loaded in every Windows process). GetModuleHandleA
    // returns the handle or fails; the handle is valid for the process lifetime.
    let hmod = unsafe { GetModuleHandleA(PCSTR(module_name.as_ptr().cast())) }.ok()?;
    if hmod.is_invalid() {
        return None;
    }
    // SAFETY: GetProcAddress returns a pointer to the export or NULL; both are
    // stable for the process lifetime. Only the address VALUE is used (the
    // pointee is never touched from our process). FARPROC is Option<fn> in
    // windows-rs 0.62 — map it to a raw address (None → unresolved).
    let addr = unsafe { GetProcAddress(hmod, PCSTR(name_c.as_ptr().cast())) };
    addr.map(|f| f as usize)
}

/// Port of `patchPreresolvedImports`: copy `payload` and write the five
/// function pointers (Go: `AddrLoadLibraryA` … `AddrNtFlushInstructionCache`).
pub fn patch_preresolved_imports(payload: &[u8]) -> Result<Vec<u8>, PatchError> {
    let need = payload::IMP_NTFLUSHIC_OFFSET + 8;
    if payload.len() < need {
        return Err(PatchError::TooSmall(payload.len()));
    }

    const SPECS: [(&[u8], &str); 5] = [
        (b"kernel32.dll\0", "LoadLibraryA"),
        (b"kernel32.dll\0", "GetProcAddress"),
        (b"kernel32.dll\0", "VirtualAlloc"),
        (b"kernel32.dll\0", "VirtualProtect"),
        (b"ntdll.dll\0", "NtFlushInstructionCache"),
    ];
    let mut addrs = [0usize; 5];
    for (i, (module, export)) in SPECS.iter().enumerate() {
        let Some(addr) = module_export_addr(module, export.as_bytes()) else {
            return Err(PatchError::MissingImport(export));
        };
        addrs[i] = addr;
    }

    let mut patched = payload.to_vec();
    let offsets = [
        payload::IMP_LOADLIBRARYA_OFFSET,
        payload::IMP_GETPROCADDRESS_OFFSET,
        payload::IMP_VIRTUALALLOC_OFFSET,
        payload::IMP_VIRTUALPROTECT_OFFSET,
        payload::IMP_NTFLUSHIC_OFFSET,
    ];
    for (off, addr) in offsets.iter().zip(addrs.iter()) {
        patched[*off..*off + 8].copy_from_slice(&addr.to_le_bytes());
    }
    Ok(patched)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::payload::PAYLOAD_AMD64;

    #[test]
    fn resolved_addresses_are_nonzero_in_this_process() {
        // The ASLR/KnownDlls contract is machine-local; on the dev box these
        // five addresses must resolve before anything is spawned.
        for (name, exp) in [
            (b"kernel32.dll\0".as_slice(), "LoadLibraryA".as_bytes()),
            (b"kernel32.dll\0".as_slice(), "GetProcAddress".as_bytes()),
            (b"kernel32.dll\0".as_slice(), "VirtualAlloc".as_bytes()),
            (b"kernel32.dll\0".as_slice(), "VirtualProtect".as_bytes()),
            (
                b"ntdll.dll\0".as_slice(),
                "NtFlushInstructionCache".as_bytes(),
            ),
        ] {
            let addr = module_export_addr(name, exp);
            assert!(addr.is_some() && addr.unwrap() != 0, "{exp:?} unresolved");
        }
    }

    #[test]
    fn patched_payload_has_five_nonzero_pointers() {
        let patched = patch_preresolved_imports(PAYLOAD_AMD64).unwrap();
        for off in [
            payload::IMP_LOADLIBRARYA_OFFSET,
            payload::IMP_GETPROCADDRESS_OFFSET,
            payload::IMP_VIRTUALALLOC_OFFSET,
            payload::IMP_VIRTUALPROTECT_OFFSET,
            payload::IMP_NTFLUSHIC_OFFSET,
        ] {
            let v = u64::from_le_bytes(patched[off..off + 8].try_into().unwrap());
            assert!(v != 0, "slot {off:#x} patched with a real address");
        }
    }

    #[test]
    fn tiny_payload_rejected() {
        assert!(matches!(
            patch_preresolved_imports(&[0u8; 0x40]),
            Err(PatchError::TooSmall(_))
        ));
    }
}
