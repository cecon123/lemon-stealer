//! Port of `crypto/errors.go`.

/// Sentinel errors for crypto operations (Go: `errors.go`).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Go: `ciphertext too short`.
    #[error("ciphertext too short")]
    ShortCiphertext,
    /// Go: `ciphertext is not a multiple of the block size`.
    #[error("ciphertext is not a multiple of the block size")]
    InvalidBlockSize,
    /// Go: `IV length must equal block size`.
    #[error("IV length must equal block size")]
    InvalidIvLength,
    /// Go: `invalid PKCS5 padding`.
    #[error("invalid PKCS5 padding")]
    InvalidPadding,
    /// Go: `nonce length must equal GCM nonce size`.
    #[error("nonce length must equal GCM nonce size")]
    InvalidNonceLen,
    /// Go: `unsupported IV length`.
    #[error("unsupported IV length")]
    UnsupportedIvLen,
    /// Go: `failed to decode ASN1 data` (Firefox-only — kept for parity, unused here).
    #[error("failed to decode ASN1 data")]
    DecodeAsn1,
    /// Go: `DPAPI not supported on this platform` (darwin/linux stubs).
    #[error("DPAPI not supported on this platform")]
    DpapiNotSupported,
    /// AES-GCM authentication failure (Go surfaces the raw `cipher.AEAD` error).
    #[error("authentication failed")]
    AeadAuthFailed,
    /// Invalid AES key length (Go: `aes.NewCipher` error).
    #[error("invalid AES key length {0}")]
    InvalidKeyLength(usize),
    /// Go: `yandex: v10 marker not found in local_encryptor_data`.
    #[error("yandex: v10 marker not found in local_encryptor_data")]
    YandexMarkerNotFound,
    /// Go: `yandex: encrypted intermediate key truncated`.
    #[error("yandex: encrypted intermediate key truncated")]
    YandexBlobShort,
    /// Go: `yandex: invalid protobuf signature on decrypted key`.
    #[error("yandex: invalid protobuf signature on decrypted key")]
    YandexBadSignature,
    /// Go: `yandex: decrypted intermediate key shorter than 32 bytes`.
    #[error("yandex: decrypted intermediate key shorter than 32 bytes")]
    YandexKeyTooShort,
    /// Windows-only DPAPI failure, wrapped from `abi::dpapi` (Go surfaces the raw
    /// `CryptUnprotectData: ...` error from winapi).
    #[error("dpapi: {0}")]
    Dpapi(String),
}
