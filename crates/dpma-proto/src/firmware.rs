//! Firmware images (`.eff` files): what identifies one.
//!
//! An `.eff` file is a 100-byte plaintext label, then OpenSSL "Salted__"
//! AES-256-CBC ciphertext (key and IV from `EVP_BytesToKey` with MD5, one
//! round, over the passphrase every phone holds) of four 100-byte text
//! fields followed by the update itself.  The update starts with a 160-byte
//! header that carries the CRC and size of its two components, the kernel
//! and the root file system.
//!
//! Those four numbers identify the image: a phone records them for the
//! image it runs, so a server that states them in a `<firmware>` entry
//! lets the phone see that it already has the image without fetching it.

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use md5::{Digest, Md5};
use std::io::Read;

/// The passphrase of firmware images (the phones' `/etc/otapassphrase`).
const PASSPHRASE: &[u8; 255] = b"*\xac7\xf5\x9e1\xb0\xde\xef\xfb1\xf4N`V#\x82\xa1%\xb6$)\xd9\x12\xc3\xb3\xc4\x89\xbd1O\xb4\xac|\xcf\xb0\"k\x92\xf5\x14K'T\x8e \x8c\xe2\x89\xe9\x03#>\x84\x0e0\x11,~\xd8\xdc#3~}\xb9m&\xad\x18|~J#G)j\x17\x8e\xe0\x07\xa3\xb7k\xa7\xa6BF0@?MEv\xad\xa24\xc4 \x06-t\xf2\xb8q\xf8\xb9\x8d \x16\x1a\xa5}\x18\xdc\x03)\xc3\xb0\x03\x03]q\x0f\xbaI<\xf3\xf4Q\xb2\xfb\xe3\xf1\x8e(\xc5\xa2\xfdX\xf8\xb1\xb7\x17\x9cL \xca0\xf0:\x07\xd80\xb9\x97\x06\x17\x89\x01\x03v\xc5\x1c\xc0\xb2\xed-\xff\xd9\x15_+\xe1}\x9d\x95&~\xe4\xdc\xcd\x061Uf\x90 VR\xa0 \xd6\xcf\xec\x1eP\xcf\xdaU\xe0\xa1\x14\xe7t\\N\x06\x1b\xab\xf5\xe7\x1f\x85\x9f\xd05\xa3\xd1QY\xe1\x10\xe9\xcc\xdf_d\x87\xcf\xa4\x9c5$\xbdq_\xdb\xee\x1a\x07^\xeb\xc7G\x90\xdc{\xa1\x88\xef=\xb6Wq";

const LABEL_LEN: usize = 100;
const INNER_LEN: usize = 400;
const UPDATE_HEADER_LEN: usize = 160;
const MAGIC_TEXT: &[u8] = b"Digium Phone Firmware\0";
const UPDATE_MAGIC: u32 = 0x7d9f_8001;

/// The CRC of the phones' updater: reflected CRC-32 (polynomial
/// 0xEDB88320) from 0xffffffff, without the final inversion.
fn crc(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    c
}

fn be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The checksums and sizes that identify a firmware image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageChecksum {
    pub kernel_crc: u32,
    pub kernel_size: u32,
    pub rootfs_crc: u32,
    pub rootfs_size: u32,
}

impl ImageChecksum {
    /// Read them from the start of an `.eff` file (its first 676 bytes).
    /// `None` when `file` is not a firmware image for a kernel and root
    /// file system, or its header is damaged.  The components themselves
    /// are not read.
    pub fn read(mut file: impl Read) -> Option<ImageChecksum> {
        let mut head = [0u8; LABEL_LEN + 16];
        file.read_exact(&mut head).ok()?;
        if &head[LABEL_LEN..LABEL_LEN + 8] != b"Salted__" {
            return None;
        }
        let salt = &head[LABEL_LEN + 8..];

        // EVP_BytesToKey(MD5, one round): 32 bytes of key, 16 of IV.
        let mut derived = [0u8; 48];
        let mut prev: Option<[u8; 16]> = None;
        for chunk in derived.chunks_mut(16) {
            let mut h = Md5::new();
            if let Some(p) = prev {
                h.update(p);
            }
            h.update(PASSPHRASE);
            h.update(salt);
            let d: [u8; 16] = h.finalize().into();
            chunk.copy_from_slice(&d);
            prev = Some(d);
        }

        let mut buf = [0u8; INNER_LEN + UPDATE_HEADER_LEN];
        file.read_exact(&mut buf).ok()?;
        cbc::Decryptor::<aes::Aes256>::new_from_slices(&derived[..32], &derived[32..])
            .ok()?
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .ok()?;
        if !buf.starts_with(MAGIC_TEXT) {
            return None;
        }

        // The update header: magic, type (0: kernel and root file system),
        // the CRC of those two, then the component header and its CRC.
        // The CRCs are over the integers in little-endian order.
        let u = &buf[INNER_LEN..];
        if be(&u[0..4]) != UPDATE_MAGIC || be(&u[4..8]) != 0 {
            return None;
        }
        let sum = ImageChecksum {
            kernel_crc: be(&u[12..16]),
            kernel_size: be(&u[16..20]),
            rootfs_crc: be(&u[20..24]),
            rootfs_size: be(&u[24..28]),
        };
        let mut covered = Vec::with_capacity(144);
        for v in [
            sum.kernel_crc,
            sum.kernel_size,
            sum.rootfs_crc,
            sum.rootfs_size,
        ] {
            covered.extend_from_slice(&v.to_le_bytes());
        }
        covered.extend_from_slice(&u[28..156]);
        (crc(&covered) == be(&u[156..160])).then_some(sum)
    }
}

/// The value of a `<firmware>` entry's `checksum` attribute:
/// `<kernel CRC>-<kernel size>-<rootfs CRC>-<rootfs size>`, the CRCs as
/// eight lowercase hexadecimal digits and the sizes in decimal bytes.
impl std::fmt::Display for ImageChecksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08x}-{}-{:08x}-{}",
            self.kernel_crc, self.kernel_size, self.rootfs_crc, self.rootfs_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncryptMut;

    /// The first 676 bytes of an image with the given update header.
    fn image(update_header: &[u8; UPDATE_HEADER_LEN]) -> Vec<u8> {
        let salt = *b"saltsalt";
        let mut derived = [0u8; 48];
        let mut prev: Option<[u8; 16]> = None;
        for chunk in derived.chunks_mut(16) {
            let mut h = Md5::new();
            if let Some(p) = prev {
                h.update(p);
            }
            h.update(PASSPHRASE);
            h.update(salt);
            let d: [u8; 16] = h.finalize().into();
            chunk.copy_from_slice(&d);
            prev = Some(d);
        }
        let mut plain = [0u8; INNER_LEN + UPDATE_HEADER_LEN];
        plain[..21].copy_from_slice(b"Digium Phone Firmware");
        plain[100] = b'1';
        plain[200..203].copy_from_slice(b"D60");
        plain[300..306].copy_from_slice(b"9_9_99");
        plain[INNER_LEN..].copy_from_slice(update_header);
        let len = plain.len();
        cbc::Encryptor::<aes::Aes256>::new_from_slices(&derived[..32], &derived[32..])
            .unwrap()
            .encrypt_padded_mut::<NoPadding>(&mut plain, len)
            .unwrap();
        let mut out = vec![0u8; LABEL_LEN];
        out[..10].copy_from_slice(b"D60 9_9_99");
        out.extend_from_slice(b"Salted__");
        out.extend_from_slice(&salt);
        out.extend_from_slice(&plain);
        out
    }

    fn update_header(sum: ImageChecksum) -> [u8; UPDATE_HEADER_LEN] {
        let mut u = [0u8; UPDATE_HEADER_LEN];
        u[0..4].copy_from_slice(&UPDATE_MAGIC.to_be_bytes());
        u[12..16].copy_from_slice(&sum.kernel_crc.to_be_bytes());
        u[16..20].copy_from_slice(&sum.kernel_size.to_be_bytes());
        u[20..24].copy_from_slice(&sum.rootfs_crc.to_be_bytes());
        u[24..28].copy_from_slice(&sum.rootfs_size.to_be_bytes());
        u[28..52].copy_from_slice(b"Tue Oct 27 13:05:08 2026");
        u[92..108].copy_from_slice(b"9_9_99_D60_fw.bin"[..16].as_ref());
        let mut covered = Vec::new();
        for v in [
            sum.kernel_crc,
            sum.kernel_size,
            sum.rootfs_crc,
            sum.rootfs_size,
        ] {
            covered.extend_from_slice(&v.to_le_bytes());
        }
        covered.extend_from_slice(&u[28..156]);
        u[156..160].copy_from_slice(&crc(&covered).to_be_bytes());
        u
    }

    const SUM: ImageChecksum = ImageChecksum {
        kernel_crc: 0x0a1b_2c3d,
        kernel_size: 1_500_000,
        rootfs_crc: 0xffff_ffff,
        rootfs_size: 39_321_600,
    };

    #[test]
    fn crc_is_the_updaters() {
        // CRC-32 of "123456789" is 0xcbf43926; without the final inversion
        // it is the complement.
        assert_eq!(crc(b"123456789"), !0xcbf4_3926);
    }

    #[test]
    fn reads_an_image_and_formats_the_attribute() {
        let sum = ImageChecksum::read(&image(&update_header(SUM))[..]).unwrap();
        assert_eq!(sum, SUM);
        assert_eq!(sum.to_string(), "0a1b2c3d-1500000-ffffffff-39321600");
    }

    #[test]
    fn refuses_what_is_not_an_image() {
        let good = image(&update_header(SUM));
        assert!(
            ImageChecksum::read(&good[..good.len() - 1]).is_none(),
            "short"
        );
        assert!(ImageChecksum::read(&b"not firmware"[..]).is_none());
        let mut unsalted = good.clone();
        unsalted[100] = b'X';
        assert!(ImageChecksum::read(&unsalted[..]).is_none());
        // Another passphrase's ciphertext does not decrypt to the magic.
        let mut other = good.clone();
        other[110] ^= 1;
        assert!(ImageChecksum::read(&other[..]).is_none());
        // A damaged component header.
        let mut u = update_header(SUM);
        u[13] ^= 1;
        assert!(ImageChecksum::read(&image(&u)[..]).is_none());
        // A bootstrap update (type 1).
        let mut u = update_header(SUM);
        u[7] = 1;
        assert!(ImageChecksum::read(&image(&u)[..]).is_none());
    }

    /// With `DPMA_TEST_EFF` naming a real image and `DPMA_TEST_EFF_SUM` its
    /// expected attribute, check a vendor file.
    #[test]
    fn reads_a_vendor_image_when_given_one() {
        let (Ok(path), Ok(want)) = (
            std::env::var("DPMA_TEST_EFF"),
            std::env::var("DPMA_TEST_EFF_SUM"),
        ) else {
            return;
        };
        let sum = ImageChecksum::read(std::fs::File::open(path).unwrap()).unwrap();
        assert_eq!(sum.to_string(), want);
    }
}
