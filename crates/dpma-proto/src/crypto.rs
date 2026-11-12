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
//! The functions log what the official DPMA logs (through the crate's log
//! hook) and return the same text in [`ProtoError::Crypto`].

use crate::cbuf::c_bytes;
use crate::{ProtoError, Result};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use dpma_bytes::bformat;

pub use crate::cert::PublicKey;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Length of the common password generated at handshake time.
pub const COMMON_PASSWORD_LEN: usize = 40;
/// Length of a message salt.
pub const SALT_LEN: usize = 8;
/// AES block size.
pub const BLOCK_LEN: usize = 16;
/// Size of the buffers the official DPMA base64 encodes ciphertext into
/// (`send_encrypt_hdr_helper` and the body chunks): at most 0x514
/// characters are produced.
pub const CIPHERTEXT_B64_BUF: usize = 0x515;
/// Size of the buffer the RSA-encrypted common password is base64 encoded
/// into (`phone_msg_set_common_password`).
pub const COMMON_PASSWORD_B64_BUF: usize = 0x3ff;
/// Size of the buffers incoming header fields are decrypted into
/// (`incoming_check_finalize`).
pub const HEADER_FIELD_BUF: usize = 0x80;

/// Log `msg` and return it as an error.
fn fail(msg: &str) -> ProtoError {
    crate::warn(msg.as_bytes());
    ProtoError::Crypto(msg.to_string())
}

/// Fill `buf` from the operating system's random source.
pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf)
        .map_err(|e| ProtoError::Crypto(format!("random number generation failed: {}", e)))
}

/// Generate a new common password: 40 random bytes.
pub fn new_common_password() -> Result<Vec<u8>> {
    let mut buf = vec![0u8; COMMON_PASSWORD_LEN];
    random_bytes(&mut buf)?;
    Ok(buf)
}

/// Generate a new message salt (FUN_00151840): 8 random bytes.
pub fn new_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt).map_err(|e| fail(e.message()))?;
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
/// filled so far, as in the official DPMA.
pub fn set_hex(hex: impl AsRef<[u8]>, out: &mut [u8]) -> Result<()> {
    let digits = c_bytes(hex.as_ref());
    if digits.len() > out.len() * 2 {
        crate::warn(b"hex string is too long");
        return Err(ProtoError::Invalid("hex string is too long".into()));
    }
    out.iter_mut().for_each(|b| *b = 0);
    for (i, &c) in digits.iter().enumerate() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            _ => {
                crate::warn(&bformat!("Invalid character in hex string '{}'", [c]));
                let msg = format!(
                    "Invalid character in hex string '{}'",
                    String::from_utf8_lossy(&[c])
                );
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
pub fn salt_from_hex(hex: impl AsRef<[u8]>) -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    set_hex(hex, &mut salt)?;
    Ok(salt)
}

/// `EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, password, 1)`;
/// returns (key, iv).  With one iteration this is
/// `D1 = SHA1(password || salt)`, `D2 = SHA1(D1 || password || salt)`,
/// key = `D1[0..16]`, iv = `D1[16..20] || D2[0..12]`.
pub fn derive_key_iv(password: &[u8], salt: &[u8; SALT_LEN]) -> ([u8; 16], [u8; 16]) {
    use sha1::{Digest, Sha1};
    let d1 = Sha1::new()
        .chain_update(password)
        .chain_update(salt)
        .finalize();
    let d2 = Sha1::new()
        .chain_update(d1)
        .chain_update(password)
        .chain_update(salt)
        .finalize();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&d1[..16]);
    iv[..4].copy_from_slice(&d1[16..20]);
    iv[4..].copy_from_slice(&d2[..12]);
    (key, iv)
}

/// Streaming encryptor matching `init_encryption` / `encrypt_data` /
/// `encrypt_final` (`EVP_EncryptUpdate` and `EVP_EncryptFinal_ex` with
/// AES-128-CBC): one CBC stream per outgoing message, fed chunk by chunk;
/// each chunk's output is base64 encoded separately.
pub struct Encryptor {
    cipher: Aes128CbcEnc,
    /// Plaintext not yet making a whole block.
    buf: Vec<u8>,
}

impl Encryptor {
    /// Start a stream with `password` and `salt` (`init_encryption`,
    /// FUN_001515c0).  Fails without a password, as the official DPMA does.
    pub fn new(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Encryptor> {
        if password.is_empty() {
            return Err(fail("Unable to initialize encryption without common pass"));
        }
        let (key, iv) = derive_key_iv(password, salt);
        Ok(Encryptor {
            cipher: Aes128CbcEnc::new(&key.into(), &iv.into()),
            buf: Vec::with_capacity(BLOCK_LEN),
        })
    }

    /// Encrypt more plaintext (`encrypt_data`); returns the ciphertext
    /// produced so far (whole blocks only).
    pub fn update(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        self.buf.extend_from_slice(plain);
        let whole = self.buf.len() / BLOCK_LEN * BLOCK_LEN;
        let mut out: Vec<u8> = self.buf.drain(..whole).collect();
        for block in out.as_chunks_mut::<BLOCK_LEN>().0 {
            self.cipher.encrypt_block_mut(block.into());
        }
        Ok(out)
    }

    /// Finish the stream (`encrypt_final`): the last block, PKCS#7 padded.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        let n = BLOCK_LEN - self.buf.len();
        let mut block = std::mem::take(&mut self.buf);
        block.resize(BLOCK_LEN, n as u8);
        self.cipher.encrypt_block_mut(block.as_mut_slice().into());
        Ok(block)
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
/// FUN_00151560: `EVP_DecryptUpdate` and `EVP_DecryptFinal_ex`).  Unlike
/// encryption, an empty password is accepted.  A ciphertext that is not a
/// whole number of blocks, or whose last block's padding is wrong, fails.
pub fn decrypt(password: &[u8], salt: &[u8; SALT_LEN], cipher: &[u8]) -> Result<Vec<u8>> {
    let (key, iv) = derive_key_iv(password, salt);
    let mut dec = Aes128CbcDec::new(&key.into(), &iv.into());
    let final_error = |msg: &str| Err(fail(&format!("DecryptFinal failed: {}", msg)));
    if cipher.is_empty() || !cipher.len().is_multiple_of(BLOCK_LEN) {
        return final_error("ciphertext is not a whole number of blocks");
    }
    let mut out = cipher.to_vec();
    for block in out.as_chunks_mut::<BLOCK_LEN>().0 {
        dec.decrypt_block_mut(block.into());
    }
    let n = usize::from(out[out.len() - 1]);
    if n == 0 || n > BLOCK_LEN {
        return final_error("bad padding");
    }
    if out[out.len() - n..].iter().any(|&b| usize::from(b) != n) {
        return final_error("bad padding");
    }
    out.truncate(out.len() - n);
    Ok(out)
}

/// `decrypt_msg_field` (FUN_00151870) with an output buffer of `buf_len`
/// bytes: base64 decode at most `buf_len - 1` bytes of `field_b64` (as
/// `ast_base64decode` does), then decrypt with `password` and the hex
/// `salt`.  Returns the plaintext bytes; the official DPMA uses them as a C
/// string (see [`c_str`]).
pub fn decrypt_field_limited(
    password: &[u8],
    salt_hex: impl AsRef<[u8]>,
    field_b64: impl AsRef<[u8]>,
    buf_len: usize,
) -> Result<Vec<u8>> {
    let (salt_hex, field_b64) = (salt_hex.as_ref(), field_b64.as_ref());
    if field_b64.is_empty() {
        return Err(fail("Unable to decrypt null field"));
    }
    if salt_hex.is_empty() {
        return Err(fail("Unable to decrypt with no salt"));
    }
    let cipher = base64_decode_max(field_b64, buf_len.saturating_sub(1));
    let salt = salt_from_hex(salt_hex)?;
    decrypt(password, &salt, &cipher)
}

/// `decrypt_msg_field` without a size limit.
pub fn decrypt_field(
    password: &[u8],
    salt_hex: impl AsRef<[u8]>,
    field_b64: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    decrypt_field_limited(password, salt_hex, field_b64, usize::MAX)
}

/// Decrypt the concatenated body of a reassembled incoming message the way
/// `incoming_check_finalize` does: an empty body stays empty (no
/// decryption), otherwise `decrypt_msg_field` with a buffer of the body's
/// length, and the result is cut at its first NUL (`ast_str_set("%s")`).
pub fn decrypt_body(
    password: &[u8],
    salt_hex: impl AsRef<[u8]>,
    body: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let body = body.as_ref();
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let plain = decrypt_field_limited(password, salt_hex, body, body.len())?;
    Ok(c_str(&plain).to_vec())
}

/// Decrypt an incoming `Password`, `ConfigPassword`, or `Config-Token`
/// header the way `incoming_check_finalize` does (0x80-byte buffer, cut
/// at the first NUL).
pub fn decrypt_header_field(
    password: &[u8],
    salt_hex: impl AsRef<[u8]>,
    field_b64: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
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

/// The part of `bytes` before the first NUL, which is all the official DPMA
/// sees of a decrypted C string.
pub fn c_str(bytes: &[u8]) -> &[u8] {
    c_bytes(bytes)
}

/// RSA (PKCS#1 v1.5) encrypt the common password with the phone's public
/// key and base64 encode it (`phone_msg_set_common_password`,
/// FUN_0014bb00).  Keys that are not RSA, and keys that are too small for
/// the password, fail.
pub fn encrypt_common_password(phone_key: &PublicKey, password: &[u8]) -> Result<String> {
    let rsa = phone_key.rsa().ok_or_else(|| {
        let msg = "failed to get rsa during common password generation";
        fail(msg)
    })?;
    let cipher = rsa.encrypt_pkcs1(password)?;
    Ok(base64_encode_max(&cipher, COMMON_PASSWORD_B64_BUF))
}

/// The phone's side of the handshake: recover the common password from
/// `X-Digium-AppServer-Password` with the phone's private key.
pub fn decrypt_common_password(
    phone_key: &rsa::RsaPrivateKey,
    password_b64: impl AsRef<[u8]>,
) -> Result<Vec<u8>> {
    let cipher = base64_decode(password_b64);
    phone_key
        .decrypt(rsa::Pkcs1v15Encrypt, &cipher)
        .map_err(|e| ProtoError::Crypto(e.to_string()))
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
pub fn base64_decode(text: impl AsRef<[u8]>) -> Vec<u8> {
    base64_decode_max(text, usize::MAX)
}

/// `ast_base64decode(dst, src, max)`: decoding stops at the first `=` or
/// NUL or after `max` bytes; it never fails.  Characters outside the
/// alphabet are *not* skipped: Asterisk's table maps them to -1, which the
/// decoder masks to 63 (as if they were `/`).  (Bytes 0x80 and above index
/// before the table in Asterisk, which is undefined; they are treated like
/// the other non-alphabet characters here.)  Leftover bits are dropped.
pub fn base64_decode_max(text: impl AsRef<[u8]>, max: usize) -> Vec<u8> {
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
    for &c in text.as_ref() {
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
    use aes::cipher::BlockEncryptMut;

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
        // Vectors computed independently with Python's hashlib.
        let salt = [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3];
        for (pw, key, iv) in [
            (
                &b""[..],
                "0c0ce7ebb26cfa99db7453b9b6ade790",
                "56a295afed30229d36a83ab2ee30053a",
            ),
            (
                b"x",
                "4550242d5427b4c2337d8c369bb81872",
                "024862b878f89b159cb774df0d882a58",
            ),
            (
                PASS40,
                "6827f349714e1b6dc214a73053ba0747",
                "11e7ef5ed87ba5589e6d8db8aaabf0dd",
            ),
            (
                &[0u8; 40],
                "3481c862e50320674099ad9a63a8d573",
                "18f26043d6a2ab8b5fa14854e77c1b0f",
            ),
        ] {
            let (k, i) = derive_key_iv(pw, &salt);
            assert_eq!((hex(&k), hex(&i)), (key.to_string(), iv.to_string()));
        }
    }

    #[test]
    fn encrypt_known_answer() {
        // A fixed vector computed independently of this code: AES-128-CBC
        // of "Hello, phone!" with PKCS#7 padding under the key and IV of
        // `key_iv_known_answer`, base64 encoded.
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
        for sizes in [
            vec![1usize],
            vec![15, 16, 17],
            vec![420, 420, 420],
            vec![900],
            vec![3, 1000, 5],
        ] {
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
        assert!(hexsalt
            .chars()
            .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)));
        for v in ["", "1234", "secret pin", &"x".repeat(111)] {
            let b64 = encrypt_field(PASS40, &salt, v.as_bytes()).unwrap();
            assert!(!b64.contains('\n'));
            assert_eq!(
                decrypt_header_field(PASS40, &hexsalt, &b64).unwrap(),
                v.as_bytes()
            );
            assert_eq!(
                decrypt_header_field(PASS40, hexsalt.to_lowercase(), &b64).unwrap(),
                v.as_bytes()
            );
        }
        // 112 bytes of plaintext need 128 bytes of ciphertext, more than
        // the 0x80-byte buffer's 127 decoded bytes: the official DPMA
        // fails.
        let b64 = encrypt_field(PASS40, &salt, "x".repeat(112).as_bytes()).unwrap();
        assert!(decrypt_header_field(PASS40, &hexsalt, &b64).is_err());
        assert_eq!(
            decrypt_field(PASS40, &hexsalt, &b64).unwrap(),
            "x".repeat(112).as_bytes()
        );
    }

    #[test]
    fn decrypt_cuts_at_nul() {
        let salt = [5; 8];
        let b64 = encrypt_field(PASS40, &salt, b"abc\0def").unwrap();
        assert_eq!(
            decrypt_field(PASS40, "0505050505050505", &b64).unwrap(),
            b"abc\0def"
        );
        assert_eq!(
            decrypt_header_field(PASS40, "0505050505050505", &b64).unwrap(),
            b"abc"
        );
        assert_eq!(
            decrypt_body(PASS40, "0505050505050505", &b64).unwrap(),
            b"abc"
        );
        assert_eq!(decrypt_body(PASS40, "0505050505050505", "").unwrap(), b"");
    }

    #[test]
    fn decrypt_failures() {
        // No data, no salt, and a salt that is too long.
        assert!(decrypt_field(PASS40, "00", "").is_err());
        assert!(decrypt_field(PASS40, "", "AAAA").is_err());
        assert!(decrypt_field(PASS40, "0011223344556677889", "AAAA").is_err());
        // The wrong password leaves bad padding.
        let b64 = encrypt_field(PASS40, &[1; 8], b"hello").unwrap();
        assert!(decrypt_field(b"other", "0101010101010101", &b64).is_err());
        // Not a whole number of blocks, and no data at all.
        for field in ["AAAA", "===="] {
            assert!(decrypt_field(PASS40, "0101010101010101", field).is_err());
        }
        // The padding of the last block: bytes that disagree, and a length
        // over 16 or of 0, are refused; valid padding is removed.
        let raw = |last: &[u8]| {
            let (key, iv) = derive_key_iv(PASS40, &[3; 8]);
            let mut block = [0u8; 16];
            block[16 - last.len()..].copy_from_slice(last);
            let mut enc = Aes128CbcEnc::new(&key.into(), &iv.into());
            enc.encrypt_block_mut((&mut block).into());
            block.to_vec()
        };
        for last in [&[2u8, 3][..], &[17], &[0]] {
            assert!(decrypt(PASS40, &[3; 8], &raw(last)).is_err());
        }
        assert_eq!(decrypt(PASS40, &[3; 8], &raw(&[2, 2])).unwrap(), [0u8; 14]);
        // Decryption with an empty password works; encryption does not.
        let c = {
            let (key, iv) = derive_key_iv(b"", &[2; 8]);
            let mut block = *b"empty\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
            let mut enc = Aes128CbcEnc::new(&key.into(), &iv.into());
            enc.encrypt_block_mut((&mut block).into());
            block
        };
        assert_eq!(decrypt(b"", &[2; 8], &c).unwrap(), b"empty");
        assert!(encrypt_field(b"", &[2; 8], b"x").is_err());
    }

    #[test]
    fn salt_hex_parsing() {
        assert_eq!(
            salt_from_hex("0123456789ABCDEF").unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(
            salt_from_hex("0123456789abcdef").unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(
            salt_from_hex("aBcD").unwrap(),
            [0xab, 0xcd, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(salt_from_hex("A").unwrap(), [0xa0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            salt_from_hex("123").unwrap(),
            [0x12, 0x30, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(salt_from_hex("").unwrap(), [0; 8]);
        assert!(salt_from_hex("0123456789ABCDEF0").is_err());
        assert!(salt_from_hex("12G4").is_err());
        assert!(salt_from_hex("12 4").is_err());
        assert!(salt_from_hex("0x12").is_err());
        for _ in 0..20 {
            let s = new_salt().unwrap();
            assert_eq!(salt_from_hex(salt_to_hex(&s)).unwrap(), s);
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
            assert_eq!(
                base64_encode_max(&data[..n], usize::MAX),
                base64_encode(&data[..n])
            );
            assert_eq!(base64_decode(base64_encode(&data[..n])), &data[..n]);
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
        use rand::SeedableRng;
        use rsa::traits::PublicKeyParts;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
        for bits in [512, 1024, 2048] {
            let private = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
            let public = PublicKey::Rsa(crate::rsakey::RsaKey::from_be_bytes(
                &private.n().to_bytes_be(),
                &private.e().to_bytes_be(),
            ));
            let pass = new_common_password().unwrap();
            assert_eq!(pass.len(), COMMON_PASSWORD_LEN);
            let b64 = encrypt_common_password(&public, &pass).unwrap();
            assert_eq!(base64_decode(&b64).len(), bits / 8);
            assert_eq!(decrypt_common_password(&private, &b64).unwrap(), pass);
            // Each encryption pads with fresh random octets.
            assert_ne!(encrypt_common_password(&public, &pass).unwrap(), b64);
        }
        // A key that is not RSA.
        assert!(encrypt_common_password(&PublicKey::Other, b"x").is_err());
    }
}
