//! The phone side of the protocol's cryptography (`phone_crypto.c`),
//! written independently of the module with RustCrypto crates.

use std::path::Path;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use sha1::{Digest, Sha1};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// AES block size in bytes.
pub const BLOCK: usize = 16;

/// `EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, password, 1)`:
/// `D1 = SHA1(password + salt)`, `D2 = SHA1(D1 + password + salt)`, key
/// = `D1[0..16]`, IV = `D1[16..20] + D2[0..12]`.
pub fn evp_bytes_to_key(password: &[u8], salt: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut out = Vec::with_capacity(40);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < 32 {
        let mut h = Sha1::new();
        h.update(&prev);
        h.update(password);
        h.update(salt);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&out[..16]);
    iv.copy_from_slice(&out[16..32]);
    (key, iv)
}

/// One AES-128-CBC stream with PKCS#7 padding, as the official DPMA's
/// `init_encryption`, `encrypt_data`, and `encrypt_final`: [`update`]
/// returns whole blocks only, [`finish`] the rest with the padding.
///
/// [`update`]: StreamEncryptor::update
/// [`finish`]: StreamEncryptor::finish
pub struct StreamEncryptor {
    enc: Aes128CbcEnc,
    pending: Vec<u8>,
}

impl StreamEncryptor {
    /// A stream keyed from the common password and the salt.
    pub fn new(password: &[u8], salt: &[u8]) -> Self {
        let (key, iv) = evp_bytes_to_key(password, salt);
        StreamEncryptor {
            enc: Aes128CbcEnc::new(&key.into(), &iv.into()),
            pending: Vec::new(),
        }
    }

    /// Feeds `data`; returns the ciphertext of every block completed so
    /// far (a multiple of 16 bytes, possibly empty).
    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        let whole = self.pending.len() / BLOCK * BLOCK;
        let mut out: Vec<u8> = self.pending.drain(..whole).collect();
        self.encrypt_in_place(&mut out);
        out
    }

    /// Pads what is left (PKCS#7) and returns its ciphertext: one block.
    pub fn finish(mut self) -> Vec<u8> {
        let mut last = std::mem::take(&mut self.pending);
        let pad = BLOCK - last.len() % BLOCK;
        last.extend(std::iter::repeat_n(pad as u8, pad));
        self.encrypt_in_place(&mut last);
        last
    }

    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        for block in data.as_chunks_mut::<BLOCK>().0 {
            self.enc.encrypt_block_mut(block.into());
        }
    }
}

/// Encrypts `plain` as one stream (the whole body or one header field).
pub fn encrypt(password: &[u8], salt: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut e = StreamEncryptor::new(password, salt);
    let mut out = e.update(plain);
    out.extend(e.finish());
    out
}

/// Decrypts one stream and removes the PKCS#7 padding.
pub fn decrypt(password: &[u8], salt: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(BLOCK) {
        bail!("ciphertext length {} is not a multiple of 16", data.len());
    }
    let (key, iv) = evp_bytes_to_key(password, salt);
    Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| anyhow!("bad padding after decryption (wrong key or salt?)"))
}

/// `ast_base64encode`: standard alphabet, `=` padding, no line breaks.
pub fn b64encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Strict base64 decoding (whitespace at either end ignored), as the
/// simulator reads the server's chunks.
pub fn b64decode_strict(text: &[u8]) -> Result<Vec<u8>> {
    let t = text.trim_ascii();
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|e| {
            let head = &t[..t.len().min(40)];
            anyhow!("invalid base64 {:?}: {}", bstr::BStr::new(head), e)
        })
}

/// Asterisk's `ast_base64decode`, quirks included: it stops at NUL or
/// `=` (or after `max_len` bytes), maps every byte outside the alphabet
/// to 63, and drops leftover bits.
pub fn ast_base64decode(text: &[u8], max_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte: u32 = 0;
    let mut bits = 0;
    for &ch in text {
        if ch == 0 || ch == b'=' || out.len() >= max_len {
            break;
        }
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            _ => 63,
        };
        byte = (byte << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((byte >> bits) as u8);
        }
    }
    out
}

/// A salt as the module sends it: 16 uppercase hex digits.
pub fn salt_hex(salt: &[u8]) -> String {
    hex::encode_upper(salt)
}

/// The official DPMA's `set_hex` with a size of 8: at most 16 hex digits,
/// either case, the rest zero filled.
pub fn set_hex(text: &[u8]) -> Result<[u8; 8]> {
    if text.len() > 16 {
        bail!("hex string is too long");
    }
    let mut out = [0u8; 8];
    for (i, &ch) in text.iter().enumerate() {
        let v = (ch as char).to_digit(16).ok_or_else(|| {
            anyhow!(
                "Invalid character in hex string '{}'",
                bstr::BStr::new(&[ch])
            )
        })? as u8;
        if i % 2 == 0 {
            out[i / 2] = v << 4;
        } else {
            out[i / 2] |= v;
        }
    }
    Ok(out)
}

/// A header field (`send_encrypt_hdr_helper`): its own CBC stream with
/// the message's key and IV, base64 encoded.
pub fn encrypt_field(password: &[u8], salt: &[u8], value: &[u8]) -> String {
    b64encode(&encrypt(password, salt, value))
}

/// Decrypts a header field encrypted with [`encrypt_field`].
pub fn decrypt_field(password: &[u8], salt: &[u8], text: &[u8]) -> Result<Vec<u8>> {
    decrypt(password, salt, &b64decode_strict(text)?)
}

/// Reads an RSA private key in PEM, PKCS#1 (`RSA PRIVATE KEY`) or PKCS#8
/// (`PRIVATE KEY`).
pub fn parse_private_key_pem(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
        .map_err(|e| anyhow!("unreadable RSA private key: {e}"))
}

/// Reads an RSA private key file (see [`parse_private_key_pem`]).
pub fn load_private_key(path: &Path) -> Result<RsaPrivateKey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_private_key_pem(&text).with_context(|| path.display().to_string())
}

/// `X-Digium-AppServer-Password` of a HandshakeResponse: base64 of the
/// 40-byte common password, RSA PKCS#1 v1.5 encrypted to the phone key.
pub fn rsa_decrypt_common_password(key: &RsaPrivateKey, text: &[u8]) -> Result<Vec<u8>> {
    let data = b64decode_strict(text)?;
    key.decrypt(Pkcs1v15Encrypt, &data)
        .map_err(|e| anyhow!("cannot decrypt the common password: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_equals_one_shot() {
        let pw = [7u8; 40];
        let salt = [1u8; 8];
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let whole = encrypt(&pw, &salt, &data);
        let mut e = StreamEncryptor::new(&pw, &salt);
        let mut got = Vec::new();
        for piece in data.chunks(37) {
            let c = e.update(piece);
            assert_eq!(c.len() % BLOCK, 0);
            got.extend(c);
        }
        got.extend(e.finish());
        assert_eq!(got, whole);
        assert_eq!(decrypt(&pw, &salt, &whole).unwrap(), data);
    }
}
