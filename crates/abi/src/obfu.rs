//! XOR string payloads for runtime materialization (IAT-reduction adjunct).
//!
//! DLL names that must exist as real UTF-16 in memory for a `LoadLibraryW`
//! call (`apitable`) are the only strings the wave-2 hash trick can't fold
//! away: the wide buffer is a runtime argument, so the plaintext literal
//! stays in `.rdata`. This module re-embeds the same byte literals XOR-mangled
//! at const-eval and reveals them (NUL-terminated UTF-16) at call time — the
//! plain DLL name never lands in the image.
//!
//! Honest scope: XOR is *static-signature* reduction, not crypto. One sweep
//! with a known key recovers it. It kills cheap `strings`/YARA hits on the
//! DLL-name surface; it does not beat reversing.

/// XOR `src` at compile time — the mangled output is what lands in the image.
pub const fn enc<const N: usize>(src: &[u8], key: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = src[i] ^ key;
        i += 1;
    }
    out
}

/// Inverse of [`enc`] (XOR is its own inverse).
pub const fn dec<const N: usize>(buf: &[u8; N], key: u8) -> [u8; N] {
    enc::<N>(buf, key)
}

/// Reveal an ASCII const blob as a NUL-terminated UTF-16 buffer — exactly the
/// argument `LoadLibraryW` expects. ASCII-only by contract (module names).
pub fn dec_wide<const N: usize>(buf: &[u8; N], key: u8) -> Vec<u16> {
    let clear = dec(buf, key);
    clear
        .iter()
        .map(|&b| b as u16)
        .chain(std::iter::once(0))
        .collect()
}

/// Reveal an ASCII const blob as a `String` (no terminating NUL).
pub fn dec_str<const N: usize>(buf: &[u8; N], key: u8) -> String {
    let clear = dec(buf, key);
    String::from_utf8_lossy(&clear).into_owned()
}

/// Const-encrypt a string literal into an opaque `[u8; N]`, decrypt it at
/// runtime to a `String`. Use where a byte string must be materialized at
/// runtime (paths, format fragments) so the plaintext never lands in `.rdata`.
///
/// ```rust
/// let s: String = abi::xs!(r"System32\ntdll.dll", 0x57);
/// assert_eq!(&s, r"System32\ntdll.dll");
/// ```
#[macro_export]
macro_rules! xs {
    ($lit:literal, $key:expr) => {{
        const N: usize = $lit.len();
        const BUF: [u8; N] = $crate::obfu::enc::<N>($lit.as_bytes(), $key);
        $crate::obfu::dec_str::<N>(&BUF, $key)
    }};
}

/// Const-encrypt a string literal into an opaque `[u8; N]`, decrypt it at
/// runtime to a `Vec<u16>` (NUL-terminated). Use where a module name must be
/// passed as a real UTF-16 pointer.
///
/// ```rust
/// let wide: Vec<u16> = abi::xwide!("winhttp.dll", 0xAB);
/// let ascii: Vec<u8> = wide[..wide.len() - 1].iter().map(|&w| w as u8).collect();
/// assert_eq!(&ascii[..], b"winhttp.dll");
/// assert_eq!(wide.last(), Some(&0));
/// ```
#[macro_export]
macro_rules! xwide {
    ($lit:literal, $key:expr) => {{
        const N: usize = $lit.len();
        const BUF: [u8; N] = $crate::obfu::enc::<N>($lit.as_bytes(), $key);
        $crate::obfu::dec_wide::<N>(&BUF, $key)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xwide_round_trips_nul_terminated() {
        let wide = crate::xwide!("winhttp.dll", 0xAB);
        let ascii: Vec<u8> = wide.iter().take(wide.len() - 1).map(|&w| w as u8).collect();
        assert_eq!(&ascii[..], b"winhttp.dll");
        assert_eq!(wide.last(), Some(&0));
    }

    #[test]
    fn encrypted_blob_never_contains_plaintext() {
        const N: usize = 11;
        const SRC: &[u8] = b"crypt32.dll";
        const BUF: [u8; N] = enc::<N>(SRC, 0xC4);
        assert!(
            BUF.iter().all(|&b| b != b'c' && b != b'y'),
            "no plain chars"
        );
        assert_eq!(&dec::<N>(&BUF, 0xC4), b"crypt32.dll");
    }
}
