//! RSA public keys and PKCS#1 v1.5 encryption of the common password to
//! a phone's key, with the checks OpenSSL 1.1.1t makes
//! (`crypto/rsa/rsa_ossl.c`, `rsa_pk1.c`) and its error texts.
//!
//! The modular exponentiation is the `rsa` crate's (its `hazmat`
//! primitive on an unchecked key); the key checks and the padding are
//! 1.1.1t's, which accept keys the `rsa` crate's own checks would refuse
//! (any exponent below the modulus, moduli up to 16384 bits) and refuse
//! even moduli (1.1.1t's Montgomery arithmetic cannot use them).

use crate::errstack::{self, Errs, LIB_BN, LIB_RSA};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};

/// `OPENSSL_RSA_MAX_MODULUS_BITS`.
const MAX_MODULUS_BITS: usize = 16384;
/// `OPENSSL_RSA_SMALL_MODULUS_BITS`.
const SMALL_MODULUS_BITS: usize = 3072;
/// `OPENSSL_RSA_MAX_PUBEXP_BITS`.
const MAX_PUBEXP_BITS: usize = 64;
/// `RSA_PKCS1_PADDING_SIZE`.
const PKCS1_PADDING_SIZE: usize = 11;

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
        RsaKey { key: RsaPublicKey::new_unchecked(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)) }
    }

    /// The modulus, big endian, without leading zeros.
    pub fn n(&self) -> Vec<u8> {
        trimmed(&self.key.n().to_bytes_be())
    }

    /// The public exponent, big endian, without leading zeros.
    pub fn e(&self) -> Vec<u8> {
        trimmed(&self.key.e().to_bytes_be())
    }

    /// `BN_num_bits(n)`.
    pub fn bits(&self) -> usize {
        self.key.n().bits()
    }

    /// `RSA_size`: the modulus length in octets.
    pub fn size(&self) -> usize {
        self.bits().div_ceil(8)
    }

    /// The checks `rsa_ossl_public_encrypt` and `rsa_ossl_public_decrypt`
    /// make before using the key; the reason code of the first that fails.
    fn check(&self) -> Result<(), u32> {
        let (n, e) = (self.key.n(), self.key.e());
        if n.bits() > MAX_MODULUS_BITS {
            return Err(errstack::rsa::R_MODULUS_TOO_LARGE);
        }
        if n <= e {
            return Err(errstack::rsa::R_BAD_E_VALUE);
        }
        if n.bits() > SMALL_MODULUS_BITS && e.bits() > MAX_PUBEXP_BITS {
            return Err(errstack::rsa::R_BAD_E_VALUE);
        }
        Ok(())
    }

    /// `m^e mod n`, left-padded to [`Self::size`] octets; None for an even
    /// modulus (`BN_MONT_CTX_set` fails).
    fn public_op(&self, m: &BigUint) -> Option<Vec<u8>> {
        let odd = self.key.n().to_bytes_be().last().is_some_and(|b| b & 1 == 1);
        if !odd {
            return None;
        }
        let c = rsa::hazmat::rsa_encrypt(&self.key, m).ok()?;
        let bytes = c.to_bytes_be();
        let mut out = vec![0u8; self.size().saturating_sub(bytes.len())];
        out.extend(trimmed(&bytes));
        Some(out)
    }

    /// `RSA_public_encrypt(len, from, to, rsa, RSA_PKCS1_PADDING)`: PKCS#1
    /// v1.5 type 2 padding with random non-zero octets.  None, with
    /// 1.1.1t's error recorded, when the key cannot be used or `from` is
    /// too long for it.
    pub(crate) fn encrypt_pkcs1(&self, from: &[u8], errs: &mut Errs) -> Option<Vec<u8>> {
        const RSA_OSSL: &str = "crypto/rsa/rsa_ossl.c";
        if let Err(r) = self.check() {
            let line = if r == errstack::rsa::R_MODULUS_TOO_LARGE { 77 } else { 82 };
            errs.put(LIB_RSA, errstack::rsa::F_RSA_OSSL_PUBLIC_ENCRYPT, r, RSA_OSSL, line);
            return None;
        }
        let num = self.size();
        if num < PKCS1_PADDING_SIZE || from.len() > num - PKCS1_PADDING_SIZE {
            errs.put(
                LIB_RSA,
                errstack::rsa::F_RSA_PADDING_ADD_PKCS1_TYPE_2,
                errstack::rsa::R_DATA_TOO_LARGE_FOR_KEY_SIZE,
                "crypto/rsa/rsa_pk1.c",
                124,
            );
            return None;
        }
        let mut em = vec![0u8, 2];
        let mut ps = vec![0u8; num - 3 - from.len()];
        crate::crypto::random_bytes(&mut ps, errs).ok()?;
        for b in ps.iter_mut() {
            while *b == 0 {
                let mut one = [0u8];
                crate::crypto::random_bytes(&mut one, errs).ok()?;
                *b = one[0];
            }
        }
        em.extend(ps);
        em.push(0);
        em.extend_from_slice(from);
        match self.public_op(&BigUint::from_bytes_be(&em)) {
            Some(c) => Some(c),
            None => {
                errs.put(LIB_BN, errstack::bn::F_BN_MOD_INVERSE, errstack::bn::R_NO_INVERSE, "crypto/bn/bn_gcd.c", 532);
                None
            }
        }
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
    fn key_checks() {
        // The first error of a failed encryption.
        let error = |k: &RsaKey, from: &[u8]| {
            let mut errs = Errs::new();
            assert!(k.encrypt_pkcs1(from, &mut errs).is_none());
            errstack::error_string(errs.peek())
        };
        // e >= n, and an even modulus.
        assert_eq!(
            error(&RsaKey::from_be_bytes(&[0x0b], &[0x11]), b"x"),
            "error:04068065:rsa routines:rsa_ossl_public_encrypt:bad e value"
        );
        let even = RsaKey::from_be_bytes(&[0xc0; 64], &[0x01, 0x00, 0x01]);
        assert_eq!(error(&even, b"x"), "error:0306E06C:bignum routines:BN_mod_inverse:no inverse");
        // Too much data for the key.
        let k = RsaKey::from_be_bytes(&[0xc1; 50], &[0x03]);
        assert_eq!(
            error(&k, &[1; 40]),
            "error:0406D06E:rsa routines:RSA_padding_add_PKCS1_type_2:data too large for key size"
        );
        assert_eq!(k.encrypt_pkcs1(&[1; 39], &mut Errs::new()).unwrap().len(), 50);
        assert_eq!(k.size(), 50);
        assert_eq!(RsaKey::from_be_bytes(&[0, 0, 1, 0], &[3]).n(), [1, 0]);
    }
}
