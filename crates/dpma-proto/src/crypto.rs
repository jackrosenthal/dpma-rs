//! Message encryption (phone_crypto.c) and the handshake common password.
//!
//! * Cipher: AES-128-CBC with PKCS#7 padding.
//! * Key and IV: `EVP_BytesToKey(aes-128-cbc, SHA-1, salt, password,
//!   count = 1)` (the EVP_MD at 0x5bd8a0 is NID 64, SHA-1).
//! * Password: the 40 random bytes ("common password") chosen by the
//!   server during the handshake and sent to the phone RSA-encrypted
//!   (PKCS#1 v1.5) with the phone certificate's public key, base64 encoded,
//!   in `X-Digium-AppServer-Password`.
//! * Salt: 8 random bytes per outgoing message, sent as 16 uppercase hex
//!   digits in `X-Digium-AppServer-Message-Salt`.
//! * Ciphertext: base64 (Asterisk `ast_base64encode`, no line breaks).
//!
//! Every encryption (each header field and each message body) starts a
//! fresh CBC stream from the same key and IV; a message body is one stream
//! across all of its chunks (see `framing`).
//!
//! The functions log what the original logs (through the crate's log
//! hook) and return the same text in [`ProtoError::Crypto`].

use crate::cbuf::c_bytes;
use crate::{LogLevel, ProtoError, Result};
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::symm::{Cipher, Crypter, Mode};

/// Length of the common password generated at handshake time.
pub const COMMON_PASSWORD_LEN: usize = 40;
/// Length of a message salt.
pub const SALT_LEN: usize = 8;
/// AES block size.
pub const BLOCK_LEN: usize = 16;
/// Size of the buffers the original base64 encodes ciphertext into
/// (`send_encrypt_hdr_helper` and the body chunks): at most 0x514
/// characters are produced.
pub const CIPHERTEXT_B64_BUF: usize = 0x515;
/// Size of the buffer the RSA-encrypted common password is base64 encoded
/// into (`phone_msg_set_common_password`).
pub const COMMON_PASSWORD_B64_BUF: usize = 0x3ff;
/// Size of the buffers incoming header fields (password, config password,
/// config token) are decrypted into (`incoming_check_finalize`).
pub const HEADER_FIELD_BUF: usize = 0x80;

fn log_dpma(line: u32, func: &str, msg: &str) {
    crate::log(LogLevel::Dpma, "phone_crypto.c", line, func, msg);
}

/// `log_ssl` (FUN_001511c0): log `fmt` (which contains one `%s`) with the
/// OpenSSL error queue, and return the logged text without its newline.
fn log_ssl(fmt: &str, err: &ErrorStack) -> ProtoError {
    // ERR_print_errors() prints one line per queued error.
    let mut errs = String::new();
    for e in err.errors() {
        errs.push_str(&e.to_string());
        errs.push('\n');
    }
    let text = fmt.replacen("%s", &errs, 1);
    log_dpma(0x50, "log_ssl", &text);
    ProtoError::Crypto(text.trim_end_matches('\n').to_string())
}

/// Log a fixed phone_crypto.c message and return it as an error.
fn fail(line: u32, func: &str, msg: &str) -> ProtoError {
    log_dpma(line, func, &format!("{}\n", msg));
    ProtoError::Crypto(msg.to_string())
}

/// Generate a new common password (`RAND_bytes(40)`).
pub fn new_common_password() -> Result<Vec<u8>> {
    let mut buf = vec![0u8; COMMON_PASSWORD_LEN];
    openssl::rand::rand_bytes(&mut buf).map_err(|e| ProtoError::Crypto(e.to_string()))?;
    Ok(buf)
}

/// Generate a new message salt (FUN_00151840, `RAND_bytes(8)`).
pub fn new_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    openssl::rand::rand_bytes(&mut salt)
        .map_err(|e| log_ssl("RAND_bytes returned failure: %s\n", &e))?;
    Ok(salt)
}

/// Salt as sent on the wire: `%02X` for each byte.
pub fn salt_to_hex(salt: &[u8; SALT_LEN]) -> String {
    salt.iter().map(|b| format!("{:02X}", b)).collect()
}

/// `set_hex` (FUN_001512b0): fill `out` from at most `2 * out.len()` hex
/// digits (either case).  `out` is zeroed first and filled from the left,
/// a nibble per digit, so short (and odd-length) strings leave the rest
/// zero: "A" gives `A0 00 ...`.  On an invalid digit `out` keeps what was
/// filled so far, as in the original.
pub fn set_hex(hex: &str, out: &mut [u8]) -> Result<()> {
    let digits = c_bytes(hex.as_bytes());
    if digits.len() > out.len() * 2 {
        log_dpma(0x18, "set_hex", "hex string is too long\n");
        return Err(ProtoError::Invalid("hex string is too long".into()));
    }
    out.iter_mut().for_each(|b| *b = 0);
    for (i, &c) in digits.iter().enumerate() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            _ => {
                let msg = format!("Invalid character in hex string '{}'", c as char);
                log_dpma(0x2b, "set_hex", &format!("{}\n", msg));
                return Err(ProtoError::Invalid(msg));
            }
        };
        if i % 2 == 0 {
            out[i / 2] = v << 4;
        } else {
            out[i / 2] |= v;
        }
    }
    Ok(())
}

/// Parse a wire salt (`set_hex` with 8 bytes): at most 16 hex digits,
/// either case; shorter strings are zero filled on the right.
pub fn salt_from_hex(hex: &str) -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    set_hex(hex, &mut salt)?;
    Ok(salt)
}

/// `EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, password, 1)`;
/// returns (key, iv).  With one iteration this is
/// `D1 = SHA1(password || salt)`, `D2 = SHA1(D1 || password || salt)`,
/// key = `D1[0..16]`, iv = `D1[16..20] || D2[0..12]`.
pub fn derive_key_iv(password: &[u8], salt: &[u8; SALT_LEN]) -> ([u8; 16], [u8; 16]) {
    let mut h = openssl::sha::Sha1::new();
    h.update(password);
    h.update(salt);
    let d1 = h.finish();
    let mut h = openssl::sha::Sha1::new();
    h.update(&d1);
    h.update(password);
    h.update(salt);
    let d2 = h.finish();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&d1[..16]);
    iv[..4].copy_from_slice(&d1[16..20]);
    iv[4..].copy_from_slice(&d2[..12]);
    (key, iv)
}

fn crypter(mode: Mode, password: &[u8], salt: &[u8; SALT_LEN]) -> std::result::Result<Crypter, ErrorStack> {
    let (key, iv) = derive_key_iv(password, salt);
    Crypter::new(Cipher::aes_128_cbc(), mode, &key, Some(&iv))
}

/// Streaming encryptor matching `init_encryption` / `encrypt_data` /
/// `encrypt_final`: one CBC stream per outgoing message, fed chunk by
/// chunk; each chunk's output is base64 encoded separately.
pub struct Encryptor {
    crypter: Crypter,
}

impl Encryptor {
    /// Start a stream with `password` and `salt` (`init_encryption`,
    /// FUN_001515c0).  Fails without a password, as the original does.
    pub fn new(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Encryptor> {
        if password.is_empty() {
            return Err(fail(0x98, "init_encryption", "Unable to initialize encryption without common pass"));
        }
        let crypter = crypter(Mode::Encrypt, password, salt)
            .map_err(|e| log_ssl("Failed to initialize encryption: %s\n", &e))?;
        Ok(Encryptor { crypter })
    }

    /// Encrypt more plaintext (`encrypt_data`); returns the ciphertext
    /// produced so far (whole blocks only).
    pub fn update(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; plain.len() + BLOCK_LEN];
        let n = self
            .crypter
            .update(plain, &mut out)
            .map_err(|e| log_ssl("EncryptUpdate returned failure: %s\n", &e))?;
        out.truncate(n);
        Ok(out)
    }

    /// Finish the stream (`encrypt_final`): the last, padded block.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        let mut out = vec![0u8; BLOCK_LEN];
        let n = self
            .crypter
            .finalize(&mut out)
            .map_err(|e| log_ssl("EncryptFinal returned failure: %s\n", &e))?;
        out.truncate(n);
        Ok(out)
    }
}

/// Encrypt `plain` as one stream (update and final).
pub fn encrypt(password: &[u8], salt: &[u8; SALT_LEN], plain: &[u8]) -> Result<Vec<u8>> {
    let mut enc = Encryptor::new(password, salt)?;
    let mut out = enc.update(plain)?;
    out.extend(enc.finish()?);
    Ok(out)
}

/// Decrypt `cipher` as one stream (FUN_001513e0, FUN_00151520,
/// FUN_00151560).  Unlike encryption, an empty password is accepted.
pub fn decrypt(password: &[u8], salt: &[u8; SALT_LEN], cipher: &[u8]) -> Result<Vec<u8>> {
    let mut c = crypter(Mode::Decrypt, password, salt)
        .map_err(|e| log_ssl("Failed to initialize decryption: %s\n", &e))?;
    let mut out = vec![0u8; cipher.len() + BLOCK_LEN];
    let n = c.update(cipher, &mut out).map_err(|e| log_ssl("DecryptUpdate failed: %s\n", &e))?;
    let m = c.finalize(&mut out[n..]).map_err(|e| log_ssl("DecryptFinal failed: %s\n", &e))?;
    out.truncate(n + m);
    Ok(out)
}

/// `decrypt_msg_field` (FUN_00151870) with an output buffer of `buf_len`
/// bytes: base64 decode at most `buf_len - 1` bytes of `field_b64` (as
/// `ast_base64decode` does), then decrypt with `password` and the hex
/// `salt`.  Returns the plaintext bytes; the original uses them as a C
/// string (see [`c_str`]).
pub fn decrypt_field_limited(password: &[u8], salt_hex: &str, field_b64: &str, buf_len: usize) -> Result<Vec<u8>> {
    if field_b64.is_empty() {
        return Err(fail(0xf4, "decrypt_msg_field", "Unable to decrypt null field"));
    }
    if salt_hex.is_empty() {
        return Err(fail(0xfb, "decrypt_msg_field", "Unable to decrypt with no salt"));
    }
    let cipher = base64_decode_max(field_b64, buf_len.saturating_sub(1));
    let salt = salt_from_hex(salt_hex)?;
    decrypt(password, &salt, &cipher)
}

/// `decrypt_msg_field` without a size limit.
pub fn decrypt_field(password: &[u8], salt_hex: &str, field_b64: &str) -> Result<Vec<u8>> {
    decrypt_field_limited(password, salt_hex, field_b64, usize::MAX)
}

/// Decrypt the concatenated body of a reassembled incoming message the way
/// `incoming_check_finalize` does: an empty body stays empty (no
/// decryption), otherwise `decrypt_msg_field` with a buffer of the body's
/// length, and the result is cut at its first NUL (`ast_str_set("%s")`).
pub fn decrypt_body(password: &[u8], salt_hex: &str, body: &str) -> Result<Vec<u8>> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let plain = decrypt_field_limited(password, salt_hex, body, body.len())?;
    Ok(c_str(&plain).to_vec())
}

/// Decrypt an incoming `Password`, `ConfigPassword`, or `Config-Token`
/// header the way `incoming_check_finalize` does (0x80-byte buffer, cut
/// at the first NUL).
pub fn decrypt_header_field(password: &[u8], salt_hex: &str, field_b64: &str) -> Result<Vec<u8>> {
    let plain = decrypt_field_limited(password, salt_hex, field_b64, HEADER_FIELD_BUF)?;
    Ok(c_str(&plain).to_vec())
}

/// Encrypt a header value for sending (`send_encrypt_hdr_helper`,
/// FUN_001490b0): base64 of the AES-128-CBC ciphertext under
/// `password`/`salt`, in a 0x515-byte buffer.
pub fn encrypt_field(password: &[u8], salt: &[u8; SALT_LEN], plain: &[u8]) -> Result<String> {
    let cipher = encrypt(password, salt, plain)?;
    Ok(base64_encode_max(&cipher, CIPHERTEXT_B64_BUF))
}

/// The part of `bytes` before the first NUL, which is all the original
/// sees of a decrypted C string.
pub fn c_str(bytes: &[u8]) -> &[u8] {
    c_bytes(bytes)
}

/// RSA (PKCS#1 v1.5) encrypt the common password with the phone's public
/// key and base64 encode it (`phone_msg_set_common_password`,
/// FUN_0014bb00).  Keys that are not RSA fail with the original's text.
pub fn encrypt_common_password(phone_key: &PKey<Public>, password: &[u8]) -> Result<String> {
    let rsa = phone_key.rsa().map_err(|_| {
        let msg = "failed to get rsa during common password generation";
        crate::log(LogLevel::Dpma, "phone_message.c", 0x3b4, "phone_msg_set_common_password", &format!("{}\n", msg));
        ProtoError::Crypto(msg.into())
    })?;
    let mut out = vec![0u8; rsa.size() as usize];
    let n = rsa
        .public_encrypt(password, &mut out, Padding::PKCS1)
        .map_err(|e| ProtoError::Crypto(e.to_string()))?;
    out.truncate(n);
    Ok(base64_encode_max(&out, COMMON_PASSWORD_B64_BUF))
}

/// The phone's side of the handshake: recover the common password from
/// `X-Digium-AppServer-Password` with the phone's private key.
pub fn decrypt_common_password(phone_key: &PKey<Private>, password_b64: &str) -> Result<Vec<u8>> {
    let rsa = phone_key.rsa().map_err(|e| ProtoError::Crypto(e.to_string()))?;
    let cipher = base64_decode(password_b64);
    let mut out = vec![0u8; rsa.size() as usize];
    let n = rsa
        .private_decrypt(&cipher, &mut out, Padding::PKCS1)
        .map_err(|e| ProtoError::Crypto(e.to_string()))?;
    out.truncate(n);
    Ok(out)
}

/// `ast_base64encode` (no line breaks).
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// `ast_base64encode(dst, src, len, max)`: like [`base64_encode`] but into
/// a buffer of `max` bytes, so at most `max - 1` characters, whole groups
/// of four only (the final group is dropped when it does not fit).
pub fn base64_encode_max(data: &[u8], max: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let max = max.saturating_sub(1);
    let mut out = Vec::new();
    let mut byte: u32 = 0;
    let mut bits = 0;
    let mut cntin = 0;
    while cntin < data.len() && out.len() < max {
        byte = (byte << 8) | u32::from(data[cntin]);
        bits += 8;
        cntin += 1;
        if bits == 24 && out.len() + 4 <= max {
            out.push(ALPHABET[((byte >> 18) & 0x3f) as usize]);
            out.push(ALPHABET[((byte >> 12) & 0x3f) as usize]);
            out.push(ALPHABET[((byte >> 6) & 0x3f) as usize]);
            out.push(ALPHABET[(byte & 0x3f) as usize]);
            bits = 0;
            byte = 0;
        }
    }
    if bits != 0 && out.len() + 4 <= max {
        byte <<= 24 - bits;
        out.push(ALPHABET[((byte >> 18) & 0x3f) as usize]);
        out.push(ALPHABET[((byte >> 12) & 0x3f) as usize]);
        if bits == 16 {
            out.push(ALPHABET[((byte >> 6) & 0x3f) as usize]);
        } else {
            out.push(b'=');
        }
        out.push(b'=');
    }
    // Only ASCII from the alphabet was pushed.
    String::from_utf8(out).unwrap_or_default()
}

/// `ast_base64decode` without a size limit.
pub fn base64_decode(text: &str) -> Vec<u8> {
    base64_decode_max(text, usize::MAX)
}

/// `ast_base64decode(dst, src, max)`: decoding stops at the first `=` or
/// NUL or after `max` bytes; it never fails.  Characters outside the
/// alphabet are *not* skipped: Asterisk's table maps them to -1, which the
/// decoder masks to 63 (as if they were `/`).  (Bytes 0x80 and above index
/// before the table in Asterisk, which is undefined; they are treated like
/// the other non-alphabet characters here.)  Leftover bits are dropped.
pub fn base64_decode_max(text: &str, max: usize) -> Vec<u8> {
    fn value(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            _ => 63,
        }
    }
    let mut out = Vec::new();
    let mut byte: u32 = 0;
    let mut bits = 0;
    for &c in text.as_bytes() {
        if c == 0 || c == b'=' || out.len() >= max {
            break;
        }
        byte = (byte << 6) | value(c);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((byte >> bits) & 0xff) as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlog;

    const PASS40: &[u8] = b"test-common-password-0123456789abcdefghi";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn key_iv_known_answer() {
        // Computed independently with Python hashlib:
        // d1 = sha1(pw + salt); d2 = sha1(d1 + pw + salt)
        // key = d1[:16]; iv = d1[16:20] + d2[:12]
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let (key, iv) = derive_key_iv(PASS40, &salt);
        assert_eq!(hex(&key), "9322be0248c5e61def028c2cb3de0a5c");
        assert_eq!(hex(&iv), "4d1e73291b82fe60abf2f19dfc4237f4");
    }

    #[test]
    fn key_iv_matches_evp_bytes_to_key() {
        let salt = [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3];
        for pw in [&b""[..], b"x", PASS40, &[0u8; 40][..]] {
            let kv = openssl::pkcs5::bytes_to_key(
                Cipher::aes_128_cbc(),
                openssl::hash::MessageDigest::sha1(),
                pw,
                Some(&salt),
                1,
            )
            .unwrap();
            let (key, iv) = derive_key_iv(pw, &salt);
            assert_eq!(kv.key, key.to_vec());
            assert_eq!(kv.iv.unwrap(), iv.to_vec());
        }
    }

    #[test]
    fn encrypt_known_answer() {
        // Computed independently with the OpenSSL command line, whose
        // legacy key derivation is the same EVP_BytesToKey call:
        //   printf 'Hello, phone!' | openssl enc -aes-128-cbc -md sha1 \
        //     -S 0102030405060708 -pass pass:<PASS40> | base64
        // (`-P` prints the key and IV of `key_iv_known_answer`).
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let b64 = encrypt_field(PASS40, &salt, b"Hello, phone!").unwrap();
        assert_eq!(b64, "GS9WsQejwMVM/QGEVE8Ijw==");
        let plain = decrypt_field(PASS40, "0102030405060708", &b64).unwrap();
        assert_eq!(plain, b"Hello, phone!");
    }

    #[test]
    fn chunked_equals_one_shot() {
        let salt = [9, 8, 7, 6, 5, 4, 3, 2];
        let body: Vec<u8> = (0..2000u32).map(|i| (i * 7 % 251) as u8).collect();
        let one = encrypt(PASS40, &salt, &body).unwrap();
        for sizes in [vec![1usize], vec![15, 16, 17], vec![420, 420, 420], vec![900], vec![3, 1000, 5]] {
            let mut enc = Encryptor::new(PASS40, &salt).unwrap();
            let mut out = Vec::new();
            let mut pos = 0;
            let mut k = 0;
            while pos < body.len() {
                let n = sizes[k % sizes.len()].min(body.len() - pos);
                let part = enc.update(&body[pos..pos + n]).unwrap();
                assert_eq!(part.len() % BLOCK_LEN, 0);
                out.extend(part);
                pos += n;
                k += 1;
            }
            out.extend(enc.finish().unwrap());
            assert_eq!(out, one, "sizes {:?}", sizes);
        }
        assert_eq!(decrypt(PASS40, &salt, &one).unwrap(), body);
    }

    #[test]
    fn padding_lengths() {
        let salt = [0; 8];
        for n in 0..40 {
            let c = encrypt(PASS40, &salt, &vec![b'a'; n]).unwrap();
            assert_eq!(c.len(), (n / 16 + 1) * 16, "plaintext {}", n);
        }
    }

    #[test]
    fn field_round_trips() {
        let salt = new_salt().unwrap();
        let hexsalt = salt_to_hex(&salt);
        assert_eq!(hexsalt.len(), 16);
        assert!(hexsalt.chars().all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)));
        for v in ["", "1234", "secret pin", &"x".repeat(111)] {
            let b64 = encrypt_field(PASS40, &salt, v.as_bytes()).unwrap();
            assert!(!b64.contains('\n'));
            assert_eq!(decrypt_header_field(PASS40, &hexsalt, &b64).unwrap(), v.as_bytes());
            assert_eq!(decrypt_header_field(PASS40, &hexsalt.to_lowercase(), &b64).unwrap(), v.as_bytes());
        }
        // 112 bytes of plaintext need 128 bytes of ciphertext, more than
        // the 0x80-byte buffer's 127 decoded bytes: the original fails.
        let b64 = encrypt_field(PASS40, &salt, "x".repeat(112).as_bytes()).unwrap();
        assert!(decrypt_header_field(PASS40, &hexsalt, &b64).is_err());
        assert_eq!(decrypt_field(PASS40, &hexsalt, &b64).unwrap(), "x".repeat(112).as_bytes());
    }

    #[test]
    fn decrypt_cuts_at_nul() {
        let salt = [5; 8];
        let b64 = encrypt_field(PASS40, &salt, b"abc\0def").unwrap();
        assert_eq!(decrypt_field(PASS40, "0505050505050505", &b64).unwrap(), b"abc\0def");
        assert_eq!(decrypt_header_field(PASS40, "0505050505050505", &b64).unwrap(), b"abc");
        assert_eq!(decrypt_body(PASS40, "0505050505050505", &b64).unwrap(), b"abc");
        assert_eq!(decrypt_body(PASS40, "0505050505050505", "").unwrap(), b"");
    }

    #[test]
    fn decrypt_errors_and_logs() {
        let (r, logs) = testlog::capture(|| decrypt_field(PASS40, "00", ""));
        assert_eq!(r.unwrap_err().message(), "Unable to decrypt null field");
        assert_eq!(logs, vec!["Unable to decrypt null field\n"]);
        let (r, logs) = testlog::capture(|| decrypt_field(PASS40, "", "AAAA"));
        assert_eq!(r.unwrap_err().message(), "Unable to decrypt with no salt");
        assert_eq!(logs, vec!["Unable to decrypt with no salt\n"]);
        let (r, logs) = testlog::capture(|| decrypt_field(PASS40, "0011223344556677889", "AAAA"));
        assert!(r.is_err());
        assert_eq!(logs, vec!["hex string is too long\n"]);
        // Wrong key: bad padding at DecryptFinal.
        let b64 = encrypt_field(PASS40, &[1; 8], b"hello").unwrap();
        let (r, logs) = testlog::capture(|| decrypt_field(b"other", "0101010101010101", &b64));
        assert!(r.unwrap_err().message().starts_with("DecryptFinal failed: "));
        assert_eq!(logs.len(), 1);
        assert!(logs[0].starts_with("DecryptFinal failed: error:"));
        // Not a whole number of blocks.
        let (r, _) = testlog::capture(|| decrypt_field(PASS40, "0101010101010101", "AAAA"));
        assert!(r.unwrap_err().message().starts_with("DecryptFinal failed: "));
        // Decryption with an empty password works; encryption does not.
        let c = {
            let (key, iv) = derive_key_iv(b"", &[2; 8]);
            openssl::symm::encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), b"empty").unwrap()
        };
        assert_eq!(decrypt(b"", &[2; 8], &c).unwrap(), b"empty");
        let (r, logs) = testlog::capture(|| encrypt_field(b"", &[2; 8], b"x"));
        assert_eq!(r.unwrap_err().message(), "Unable to initialize encryption without common pass");
        assert_eq!(logs, vec!["Unable to initialize encryption without common pass\n"]);
    }

    #[test]
    fn salt_hex_parsing() {
        assert_eq!(salt_from_hex("0123456789ABCDEF").unwrap(), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(salt_from_hex("0123456789abcdef").unwrap(), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(salt_from_hex("aBcD").unwrap(), [0xab, 0xcd, 0, 0, 0, 0, 0, 0]);
        assert_eq!(salt_from_hex("A").unwrap(), [0xa0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(salt_from_hex("123").unwrap(), [0x12, 0x30, 0, 0, 0, 0, 0, 0]);
        assert_eq!(salt_from_hex("").unwrap(), [0; 8]);
        assert!(salt_from_hex("0123456789ABCDEF0").is_err());
        let (r, logs) = testlog::capture(|| salt_from_hex("12G4"));
        assert_eq!(r.unwrap_err().message(), "Invalid character in hex string 'G'");
        assert_eq!(logs, vec!["Invalid character in hex string 'G'\n"]);
        assert!(salt_from_hex("12 4").is_err());
        assert!(salt_from_hex("0x12").is_err());
        for _ in 0..20 {
            let s = new_salt().unwrap();
            assert_eq!(salt_from_hex(&salt_to_hex(&s)).unwrap(), s);
        }
    }

    #[test]
    fn base64_matches_asterisk() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..data.len() {
            assert_eq!(base64_encode_max(&data[..n], usize::MAX), base64_encode(&data[..n]));
            assert_eq!(base64_decode(&base64_encode(&data[..n])), &data[..n]);
        }
        // Truncation: max 9 leaves room for 8 characters.
        assert_eq!(base64_encode_max(b"foobarbaz", 9), "Zm9vYmFy");
        assert_eq!(base64_encode_max(b"foobar", 8), "Zm9v");
        assert_eq!(base64_encode_max(b"fo", 4), "");
        assert_eq!(base64_encode_max(b"fo", 5), "Zm8=");
        // Decoding stops at '=' (so concatenated padded strings lose
        // everything after the first padding) and at max.
        assert_eq!(base64_decode("Zg==Zm9v"), b"f");
        assert_eq!(base64_decode_max("Zm9vYmFy", 4), b"foob");
        // Non-alphabet characters count as 63 ('/').
        assert_eq!(base64_decode("Zm9v\nYmFy"), base64_decode("Zm9v/YmFy"));
        assert_eq!(base64_decode("Zm9v YmFy"), base64_decode("Zm9v/YmFy"));
        assert_eq!(base64_decode("Zm9"), b"fo");
    }

    #[test]
    fn rsa_common_password() {
        for bits in [512, 1024, 2048] {
            let key = openssl::rsa::Rsa::generate(bits).unwrap();
            let private = PKey::from_rsa(key.clone()).unwrap();
            let public = PKey::public_key_from_pem(&private.public_key_to_pem().unwrap()).unwrap();
            let pass = new_common_password().unwrap();
            assert_eq!(pass.len(), COMMON_PASSWORD_LEN);
            let b64 = encrypt_common_password(&public, &pass).unwrap();
            assert_eq!(base64_decode(&b64).len(), bits as usize / 8);
            assert_eq!(decrypt_common_password(&private, &b64).unwrap(), pass);
        }
        let ec = openssl::ec::EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap();
        let ec = PKey::from_ec_key(ec).unwrap();
        let ec = PKey::public_key_from_pem(&ec.public_key_to_pem().unwrap()).unwrap();
        let (r, logs) = testlog::capture(|| encrypt_common_password(&ec, b"x"));
        assert_eq!(r.unwrap_err().message(), "failed to get rsa during common password generation");
        assert_eq!(logs, vec!["failed to get rsa during common password generation\n"]);
    }
}
