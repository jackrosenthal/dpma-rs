//! A throwaway PKI for the verifier tests, made with x509-cert's
//! certificate builder (nothing from the official DPMA's binary).  Keys are
//! generated from fixed seeds and cached; certificates are made per test.
//! Signatures are made with the `rsa` crate's PKCS#1 v1.5 signer.

use rsa::pkcs1v15::Signature;
use rsa::signature::Keypair;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Any, OctetString};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, ObjectIdentifier,
    SubjectPublicKeyInfoOwned,
};
use x509_cert::time::{Time, Validity};

/// An RSA key from a fixed seed (cached: generating keys is slow).
pub fn key(bits: usize, seed: u64) -> RsaPrivateKey {
    static KEYS: OnceLock<Mutex<HashMap<(usize, u64), RsaPrivateKey>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(k) = keys.lock().unwrap().get(&(bits, seed)) {
        return k.clone();
    }
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed * 7919 + bits as u64);
    let k = RsaPrivateKey::new(&mut rng, bits).unwrap();
    keys.lock().unwrap().insert((bits, seed), k.clone());
    k
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// The `<hash>WithRSAEncryption` OID.
    fn oid(self) -> &'static str {
        match self {
            Hash::Sha1 => "1.2.840.113549.1.1.5",
            Hash::Sha224 => "1.2.840.113549.1.1.14",
            Hash::Sha256 => "1.2.840.113549.1.1.11",
            Hash::Sha384 => "1.2.840.113549.1.1.12",
            Hash::Sha512 => "1.2.840.113549.1.1.13",
        }
    }
}

/// PKCS#1 v1.5 signature of `msg`.
pub fn sign(key: &RsaPrivateKey, hash: Hash, msg: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    let (scheme, digest) = match hash {
        Hash::Sha1 => (
            Pkcs1v15Sign::new::<sha1::Sha1>(),
            sha1::Sha1::digest(msg).to_vec(),
        ),
        Hash::Sha224 => (
            Pkcs1v15Sign::new::<sha2::Sha224>(),
            sha2::Sha224::digest(msg).to_vec(),
        ),
        Hash::Sha256 => (
            Pkcs1v15Sign::new::<sha2::Sha256>(),
            sha2::Sha256::digest(msg).to_vec(),
        ),
        Hash::Sha384 => (
            Pkcs1v15Sign::new::<sha2::Sha384>(),
            sha2::Sha384::digest(msg).to_vec(),
        ),
        Hash::Sha512 => (
            Pkcs1v15Sign::new::<sha2::Sha512>(),
            sha2::Sha512::digest(msg).to_vec(),
        ),
    };
    key.sign(scheme, &digest).unwrap()
}

/// A signer for x509-cert's builder with any algorithm identifier.
pub struct TestSigner {
    key: RsaPrivateKey,
    hash: Hash,
    alg: AlgorithmIdentifierOwned,
}

impl Keypair for TestSigner {
    type VerifyingKey = RsaPublicKey;
    fn verifying_key(&self) -> RsaPublicKey {
        self.key.to_public_key()
    }
}

impl DynSignatureAlgorithmIdentifier for TestSigner {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(self.alg.clone())
    }
}

impl rsa::signature::Signer<Signature> for TestSigner {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, rsa::signature::Error> {
        Signature::try_from(sign(&self.key, self.hash, msg).as_slice())
    }
}

/// An extension given as its parts (x509-cert's builder takes typed
/// extensions; this passes any).
struct Raw(Extension);

impl x509_cert::der::oid::AssociatedOid for Raw {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4");
}

impl Encode for Raw {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        self.0.encoded_len()
    }
    fn encode(&self, w: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        self.0.encode(w)
    }
}

impl AsExtension for Raw {
    fn critical(&self, _: &Name, _: &[Extension]) -> bool {
        self.0.critical
    }
    fn to_extension(&self, _: &Name, _: &[Extension]) -> Result<Extension, x509_cert::der::Error> {
        Ok(self.0.clone())
    }
}

/// An extension from its OID, criticality, and value.
pub fn ext<T: Encode>(oid: &str, critical: bool, value: &T) -> Extension {
    Extension {
        extn_id: ObjectIdentifier::new_unwrap(oid),
        critical,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

pub fn basic_constraints(ca: bool, path_len: Option<u8>) -> Extension {
    ext(
        "2.5.29.19",
        true,
        &BasicConstraints {
            ca,
            path_len_constraint: path_len,
        },
    )
}

pub fn key_usage(usages: impl Into<x509_cert::der::flagset::FlagSet<KeyUsages>>) -> Extension {
    ext("2.5.29.15", true, &KeyUsage(usages.into()))
}

pub fn ca_extensions() -> Vec<Extension> {
    vec![
        basic_constraints(true, None),
        key_usage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
    ]
}

pub fn subject_key_id(id: &[u8]) -> Extension {
    ext("2.5.29.14", false, &OctetString::new(id).unwrap())
}

pub fn authority_key_id(id: &[u8]) -> Extension {
    let akid = AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(id).unwrap()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    ext("2.5.29.35", false, &akid)
}

/// UTCTime (or GeneralizedTime from 2050) at midnight of a date.
pub fn time(y: u16, m: u8, d: u8) -> Time {
    let dt = x509_cert::der::DateTime::new(y, m, d, 0, 0, 0).unwrap();
    if y < 2050 {
        Time::UtcTime(x509_cert::der::asn1::UtcTime::from_date_time(dt).unwrap())
    } else {
        Time::GeneralTime(x509_cert::der::asn1::GeneralizedTime::from_date_time(dt))
    }
}

/// A certificate made by [`Spec::issue`], and its key.
#[derive(Clone)]
pub struct Issued {
    pub der: Vec<u8>,
    pub key: RsaPrivateKey,
    pub name: Name,
}

impl Issued {
    pub fn pem(&self) -> String {
        pem_of(&self.der)
    }
}

/// A `CERTIFICATE` PEM block of any octets.
pub fn pem_of(der: &[u8]) -> String {
    x509_cert::der::pem::encode_string("CERTIFICATE", x509_cert::der::pem::LineEnding::LF, der)
        .unwrap()
}

/// PEM text of several certificates.
pub fn pem(certs: &[&Issued]) -> String {
    certs.iter().map(|c| c.pem()).collect()
}

/// What a certificate should be.
pub struct Spec {
    pub subject: String,
    pub key: RsaPrivateKey,
    pub serial: SerialNumber,
    pub not_before: Time,
    pub not_after: Time,
    pub hash: Hash,
    /// The signature algorithm OID, when not the hash's PKCS#1 one.
    pub sig_oid: Option<&'static str>,
    pub extensions: Vec<Extension>,
}

impl Spec {
    /// A certificate for `subject` with a 1024-bit key from `seed`, valid
    /// 2025 to 2035, SHA-256, no extensions.
    pub fn new(subject: &str, seed: u64) -> Spec {
        Spec {
            subject: subject.to_string(),
            key: key(1024, seed),
            serial: SerialNumber::from(seed),
            not_before: time(2025, 1, 1),
            not_after: time(2035, 1, 1),
            hash: Hash::Sha256,
            sig_oid: None,
            extensions: Vec::new(),
        }
    }

    pub fn ca(mut self) -> Spec {
        self.extensions.extend(ca_extensions());
        self
    }

    pub fn ext(mut self, e: Extension) -> Spec {
        self.extensions.push(e);
        self
    }

    pub fn serial(mut self, s: u64) -> Spec {
        self.serial = SerialNumber::from(s);
        self
    }

    /// A serial number given as its DER INTEGER content (for negative
    /// ones).
    pub fn serial_der(mut self, content: &[u8]) -> Spec {
        let mut der = vec![0x02, content.len() as u8];
        der.extend_from_slice(content);
        self.serial = SerialNumber::from_der(&der).unwrap();
        self
    }

    pub fn bits(mut self, bits: usize, seed: u64) -> Spec {
        self.key = key(bits, seed);
        self
    }

    pub fn hash(mut self, h: Hash) -> Spec {
        self.hash = h;
        self
    }

    pub fn validity(mut self, from: Time, to: Time) -> Spec {
        self.not_before = from;
        self.not_after = to;
        self
    }

    /// Issue the certificate, signed by `issuer` (self-signed when None).
    /// Without extensions the builder makes a v1 certificate.
    pub fn issue(self, issuer: Option<&Issued>) -> Issued {
        let subject = Name::from_str(&self.subject).unwrap();
        let signing_key = issuer
            .map(|i| i.key.clone())
            .unwrap_or_else(|| self.key.clone());
        let oid = self.sig_oid.unwrap_or(self.hash.oid());
        let signer = TestSigner {
            key: signing_key,
            hash: self.hash,
            alg: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(oid),
                parameters: Some(Any::null()),
            },
        };
        let spki = SubjectPublicKeyInfoOwned::from_key(self.key.to_public_key()).unwrap();
        let profile = Profile::Manual {
            issuer: issuer.map(|i| i.name.clone()),
        };
        let validity = Validity {
            not_before: self.not_before,
            not_after: self.not_after,
        };
        let mut b = CertificateBuilder::new(
            profile,
            self.serial,
            validity,
            subject.clone(),
            spki,
            &signer,
        )
        .unwrap();
        for e in self.extensions {
            b.add_extension(&Raw(e)).unwrap();
        }
        let cert = b.build::<Signature>().unwrap();
        Issued {
            der: cert.to_der().unwrap(),
            key: self.key,
            name: subject,
        }
    }
}

/// Header and content lengths of the definite-length TLV at `b`.
fn tlv(b: &[u8]) -> (usize, usize) {
    if b[1] < 0x80 {
        return (2, usize::from(b[1]));
    }
    let n = usize::from(b[1] & 0x7f);
    (
        2 + n,
        b[2..2 + n]
            .iter()
            .fold(0, |l, &x| (l << 8) | usize::from(x)),
    )
}

/// Ranges of the signed part, the outer signature algorithm, and the
/// signature octets (after the unused-bits octet) of a DER certificate.
pub fn parts(
    der: &[u8],
) -> (
    std::ops::Range<usize>,
    std::ops::Range<usize>,
    std::ops::Range<usize>,
) {
    let (h, _) = tlv(der);
    let (th, tl) = tlv(&der[h..]);
    let tbs = h..h + th + tl;
    let (ah, al) = tlv(&der[tbs.end..]);
    let alg = tbs.end..tbs.end + ah + al;
    let (sh, sl) = tlv(&der[alg.end..]);
    (tbs, alg.clone(), alg.end + sh + 1..alg.end + sh + sl)
}

/// Replace the first occurrence of `from` with `to` (same length).
pub fn patch(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let i = der
        .windows(from.len())
        .position(|w| w == from)
        .expect("pattern not found");
    let mut out = der.to_vec();
    out[i..i + to.len()].copy_from_slice(to);
    out
}

/// Sign the signed part again (after a patch that kept its length).
pub fn resign(der: &[u8], key: &RsaPrivateKey, hash: Hash) -> Vec<u8> {
    let (tbs, _, sig) = parts(der);
    let s = sign(key, hash, &der[tbs]);
    let mut out = der.to_vec();
    out[sig].copy_from_slice(&s);
    out
}
