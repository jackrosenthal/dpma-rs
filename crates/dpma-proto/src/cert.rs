//! Phone certificate verification (`load_castore`, `session_verify_cert`,
//! `session_load_rsa_key`).
//!
//! The CA store is built from the user-supplied `phone_ca_file` PEM bundle
//! (the original embeds three CA certificates; they must never be copied
//! into this project).
//!
//! Owner: P1 "proto" (wave 1).

use crate::{ProtoError, Result};
use openssl::pkey::{PKey, Public};

/// The trusted CA certificates phones are verified against.
pub struct CaStore {
    _private: (),
}

impl CaStore {
    /// Build a store from a PEM bundle (every certificate in it).
    pub fn from_pem(_pem: &[u8]) -> Result<CaStore> {
        Err(ProtoError::NotImplemented)
    }

    /// Number of certificates loaded.
    pub fn len(&self) -> usize {
        0
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A phone certificate that passed verification.
pub struct VerifiedClient {
    /// The certificate that was verified (its key encrypts the common
    /// password).
    pub certificate: openssl::x509::X509,
    pub public_key: PKey<Public>,
    /// Serial number of the intermediate certificate (chain form only);
    /// a non-zero value makes the server send
    /// `X-Digium-AppServer-Handshake-Version: 1`.
    pub intermediate_serial: Option<i64>,
    /// True for the legacy single-certificate form.
    pub legacy: bool,
}

/// Why verification failed; the text is what the original logs.
#[derive(Debug, Clone)]
pub enum CertError {
    Unreadable(String),
    WrongChainLength(usize),
    NoSerial(String),
    Context(String),
    Verify(String),
}

/// Verify the PEM certificate(s) a phone sent in its Handshake body.
///
/// One certificate: the legacy form, verified directly against `store`.
/// Otherwise exactly three: the first is ignored (it is the legacy
/// certificate for older servers), the second is the intermediate (its
/// serial is reported), and the last is the phone certificate, verified
/// with the second and third as untrusted chain.  Validity-period errors
/// (`X509_V_ERR_CERT_NOT_YET_VALID`, `X509_V_ERR_CERT_HAS_EXPIRED`) are
/// ignored.  Use security level 0 so 512-bit keys and SHA-1 signatures
/// verify as they do under the original's OpenSSL 1.1.
pub fn verify_client_chain(_store: &CaStore, _pem: &str) -> std::result::Result<VerifiedClient, CertError> {
    Err(CertError::Context("not implemented".into()))
}

/// Load a phone public key saved in AstDB (`session_load_rsa_key`):
/// PEM RSA public key, at least 512 bits.
pub fn load_public_key(_pem: &str) -> Result<PKey<Public>> {
    Err(ProtoError::NotImplemented)
}

/// PEM encoding of a public key, as stored in `DigiumPhoneSessions`.
pub fn public_key_pem(_key: &PKey<Public>) -> Result<String> {
    Err(ProtoError::NotImplemented)
}
