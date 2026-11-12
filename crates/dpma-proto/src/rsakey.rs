//! RSA public keys, and PKCS#1 v1.5 encryption of the common password to
//! a phone's key.

use crate::{ProtoError, Result};
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};

/// An RSA public key (modulus and exponent, as decoded: any values).
#[derive(Clone, PartialEq, Eq)]
pub struct RsaKey {
    key: RsaPublicKey,
}

impl std::fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaKey({} bits)", self.bits())
    }
}

impl RsaKey {
    /// A key from big-endian modulus and exponent octets (leading zeros
    /// allowed, as `BN_bin2bn` reads them).
    pub fn from_be_bytes(n: &[u8], e: &[u8]) -> RsaKey {
        RsaKey {
            key: RsaPublicKey::new_unchecked(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)),
        }
    }

    /// The modulus, big endian, without leading zeros.
    pub fn n(&self) -> Vec<u8> {
        trimmed(&self.key.n().to_bytes_be())
    }

    /// The public exponent, big endian, without leading zeros.
    pub fn e(&self) -> Vec<u8> {
        trimmed(&self.key.e().to_bytes_be())
    }

    /// The length of the modulus in bits.
    pub fn bits(&self) -> usize {
        self.key.n().bits()
    }

    /// The modulus length in octets.
    pub fn size(&self) -> usize {
        self.bits().div_ceil(8)
    }

    /// PKCS#1 v1.5 (type 2) encryption of `from`.  Fails when the key is
    /// unusable or `from` is too long for it.
    pub(crate) fn encrypt_pkcs1(&self, from: &[u8]) -> Result<Vec<u8>> {
        self.key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, from)
            .map_err(|e| ProtoError::Crypto(e.to_string()))
    }
}

fn trimmed(b: &[u8]) -> Vec<u8> {
    let skip = b.iter().take_while(|&&x| x == 0).count();
    b[skip..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unusable_keys_are_refused() {
        // Keys decoded from a certificate can have any values, and
        // encrypting to one must fail without panicking.
        for (n, e) in [
            (&[0x0b][..], &[0x11][..]),
            (&[0xc0; 64], &[1, 0, 1]),
            (&[][..], &[3][..]),
            (&[1][..], &[3][..]),
            (&[0xc1; 50], &[][..]),
        ] {
            let _ = RsaKey::from_be_bytes(n, e).encrypt_pkcs1(b"x");
        }
    }

    #[test]
    fn message_length_limit() {
        // PKCS#1 v1.5 needs 11 octets of padding: 39 fit a 50-octet key.
        let k = RsaKey::from_be_bytes(&[0xc1; 50], &[0x03]);
        assert!(k.encrypt_pkcs1(&[1; 40]).is_err());
        assert_eq!(k.encrypt_pkcs1(&[1; 39]).unwrap().len(), 50);
    }

    #[test]
    fn key_parts() {
        let k = RsaKey::from_be_bytes(&[0, 0, 1, 0], &[3]);
        assert_eq!((k.n(), k.e(), k.size()), (vec![1, 0], vec![3], 2));
    }
}
