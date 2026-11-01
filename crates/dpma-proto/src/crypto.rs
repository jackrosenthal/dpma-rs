//! Message encryption (phone_crypto.c) and the handshake common password.
//!
//! * Cipher: AES-128-CBC with PKCS#7 padding.
//! * Key and IV: `EVP_BytesToKey(aes-128-cbc, SHA-1, salt, password,
//!   count = 1)`.
//! * Password: the 40 random bytes ("common password") chosen by the
//!   server during the handshake and sent to the phone RSA-encrypted
//!   (PKCS#1 v1.5) with the phone certificate's public key, base64 encoded,
//!   in `X-Digium-AppServer-Password`.
//! * Salt: 8 random bytes per outgoing message, sent as 16 uppercase hex
//!   digits in `X-Digium-AppServer-Message-Salt`.
//! * Ciphertext: base64 (Asterisk `ast_base64encode`, no line breaks).
//!
//! Owner: P1 "proto" (wave 1).

use crate::{ProtoError, Result};

/// Length of the common password generated at handshake time.
pub const COMMON_PASSWORD_LEN: usize = 40;
/// Length of a message salt.
pub const SALT_LEN: usize = 8;

/// Generate a new common password (`RAND_bytes(40)`).
pub fn new_common_password() -> Result<Vec<u8>> {
    Err(ProtoError::NotImplemented)
}

/// Generate a new message salt (`RAND_bytes(8)`).
pub fn new_salt() -> Result<[u8; SALT_LEN]> {
    Err(ProtoError::NotImplemented)
}

/// Salt as sent on the wire: `%02X` for each byte.
pub fn salt_to_hex(salt: &[u8; SALT_LEN]) -> String {
    salt.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Parse a wire salt (`set_hex`): at most 16 hex digits, either case;
/// shorter strings are zero filled on the right.
pub fn salt_from_hex(_hex: &str) -> Result<[u8; SALT_LEN]> {
    Err(ProtoError::NotImplemented)
}

/// `EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, password, 1)`;
/// returns (key, iv).
pub fn derive_key_iv(_password: &[u8], _salt: &[u8; SALT_LEN]) -> ([u8; 16], [u8; 16]) {
    ([0; 16], [0; 16])
}

/// Streaming encryptor matching `init_encryption` / `encrypt_data` /
/// `encrypt_final`: one CBC stream per outgoing message, fed chunk by
/// chunk; each chunk's output is base64 encoded separately.
pub struct Encryptor {
    _private: (),
}

impl Encryptor {
    /// Start a stream with `password` and `salt`.
    pub fn new(_password: &[u8], _salt: &[u8; SALT_LEN]) -> Result<Encryptor> {
        Err(ProtoError::NotImplemented)
    }

    /// Encrypt more plaintext; returns the ciphertext produced so far
    /// (whole blocks only).
    pub fn update(&mut self, _plain: &[u8]) -> Result<Vec<u8>> {
        Err(ProtoError::NotImplemented)
    }

    /// Finish the stream (padding block).
    pub fn finish(self) -> Result<Vec<u8>> {
        Err(ProtoError::NotImplemented)
    }
}

/// `decrypt_msg_field`: base64 decode `field` and decrypt it with
/// `password` and the hex `salt`.  Used for message bodies (all chunks'
/// base64 concatenated first) and for the encrypted header fields
/// (password, config password, config token).
pub fn decrypt_field(_password: &[u8], _salt_hex: &str, _field_b64: &str) -> Result<Vec<u8>> {
    Err(ProtoError::NotImplemented)
}

/// Encrypt a header value for sending (`FUN_001490b0`): returns base64 of
/// the AES-128-CBC ciphertext under `password`/`salt`.
pub fn encrypt_field(_password: &[u8], _salt: &[u8; SALT_LEN], _plain: &[u8]) -> Result<String> {
    Err(ProtoError::NotImplemented)
}

/// RSA (PKCS#1 v1.5) encrypt the common password with the phone's public
/// key and base64 encode it (`phone_msg_set_common_password`).
pub fn encrypt_common_password(
    _phone_key: &openssl::pkey::PKey<openssl::pkey::Public>,
    _password: &[u8],
) -> Result<String> {
    Err(ProtoError::NotImplemented)
}

/// `ast_base64encode` (no line breaks).
pub fn base64_encode(_data: &[u8]) -> String {
    String::new()
}

/// `ast_base64decode`: decoding stops at the first character outside the
/// base64 alphabet (including `=`); never fails.
pub fn base64_decode(_text: &str) -> Vec<u8> {
    Vec::new()
}
