//! The Digium phone application-server protocol, independent of Asterisk.
//!
//! Everything here is pure Rust so it can be unit tested with `cargo test
//! -p dpma-proto`.  The Asterisk side lives in `res_dpma_rs`.
//!
//! Cryptography uses the RustCrypto crates, and certificates are decoded
//! with `x509-cert` ([`cert`] documents what phone certificate
//! verification checks).
//!
//! The official DPMA logs from inside several of the functions ported here.
//! Those messages go to the [`log`] crate, so they appear wherever the
//! application's logger puts them.

pub mod cert;
pub mod client;
pub mod crypto;
pub mod documents;
pub mod errors;
pub mod framing;
pub mod headers;
pub mod json;
pub mod message;
pub mod types;
pub mod uri;
pub mod xml;

mod cbuf;
mod rsakey;

/// Errors from this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Invalid input.
    Invalid(String),
    /// A cryptographic operation failed; the text is what the official DPMA
    /// logs (format string filled in, no trailing newline).
    Crypto(String),
}

impl ProtoError {
    /// The bare message, without the variant prefix of `Display`.
    pub fn message(&self) -> &str {
        match self {
            ProtoError::Invalid(s) | ProtoError::Crypto(s) => s,
        }
    }
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Invalid(s) => write!(f, "invalid: {}", s),
            ProtoError::Crypto(s) => write!(f, "crypto: {}", s),
        }
    }
}

impl std::error::Error for ProtoError {}

pub type Result<T> = std::result::Result<T, ProtoError>;

/// Log a message that the official DPMA logs, as a warning.  The message
/// can carry bytes from a phone that are not UTF-8, which are replaced.
pub(crate) fn warn(msg: &[u8]) {
    log::warn!("{}", String::from_utf8_lossy(msg.trim_ascii_end()));
}

/// Log a message that the official DPMA logs only when debugging.
pub(crate) fn debug(msg: &[u8]) {
    log::debug!("{}", String::from_utf8_lossy(msg.trim_ascii_end()));
}
