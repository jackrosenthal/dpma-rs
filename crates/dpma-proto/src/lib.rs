//! The Digium phone application-server protocol, independent of Asterisk.
//!
//! Everything here is pure Rust (plus OpenSSL) so it can be unit tested
//! with `cargo test -p dpma-proto`.  The Asterisk side (ast_msg handling,
//! sessions, dialplan routing) lives in `res_digium_phone`.
//!
//! Owner: package P1 "proto" (wave 1).  See dev/notes/port-plan.md.

pub mod cert;
pub mod crypto;
pub mod errors;
pub mod framing;
pub mod headers;
pub mod json;
pub mod types;
pub mod uri;
pub mod xml;

/// Errors from this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Not implemented yet (skeleton).
    NotImplemented,
    /// Invalid input (bad hex, bad base64, wrong length, ...).
    Invalid(String),
    /// An OpenSSL operation failed; the text is the OpenSSL error string.
    Crypto(String),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::NotImplemented => write!(f, "not implemented"),
            ProtoError::Invalid(s) => write!(f, "invalid: {}", s),
            ProtoError::Crypto(s) => write!(f, "crypto: {}", s),
        }
    }
}

impl std::error::Error for ProtoError {}

pub type Result<T> = std::result::Result<T, ProtoError>;
