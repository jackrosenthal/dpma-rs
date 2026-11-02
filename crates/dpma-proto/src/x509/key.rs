//! Public keys in certificates (`X509_PUBKEY`) and the signature
//! algorithms OpenSSL 1.1.1t knows (`crypto/objects/obj_xref.h`).

use super::asn1::{self, AStr, Item, Tmpl, Val, V_ANY, V_INTEGER, V_OBJECT, V_SEQUENCE};
use crate::errstack::Errs;
use crate::rsakey::RsaKey;

pub(crate) const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// X.500's `rsa` (2.5.8.1.1), an alias of rsaEncryption in 1.1.1t.
const OID_RSA: &[u8] = &[0x55, 0x08, 0x01, 0x01];
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

/// `EVP_PKEY` types (their NIDs).
pub(crate) const NID_RSA: u32 = 6;
pub(crate) const NID_RSA_PSS: u32 = 912;
const NID_DSA: u32 = 116;
const NID_EC: u32 = 408;
const NID_DH: u32 = 28;
const NID_DHX: u32 = 920;
const NID_X25519: u32 = 1034;
const NID_X448: u32 = 1035;
const NID_ED25519: u32 = 1087;
const NID_ED448: u32 = 1088;

/// The key types 1.1.1t decodes, by key algorithm OID, with their
/// `EVP_PKEY` type (aliases resolved).
const KEY_TYPES: &[(&[u8], u32)] = &[
    (OID_RSA_ENCRYPTION, NID_RSA),
    (OID_RSA, NID_RSA),
    (OID_RSASSA_PSS, NID_RSA_PSS),
    (&[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01], NID_DSA),
    (&[0x2b, 0x0e, 0x03, 0x02, 0x0c], NID_DSA),
    (&[0x2b, 0x0e, 0x03, 0x02, 0x0d], NID_DSA),
    (&[0x2b, 0x0e, 0x03, 0x02, 0x1b], NID_DSA),
    (&[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03], NID_DSA),
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], NID_EC),
    (&[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d], NID_EC),
    (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01], NID_DH),
    (&[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01], NID_DHX),
    (&[0x2b, 0x65, 0x6e], NID_X25519),
    (&[0x2b, 0x65, 0x6f], NID_X448),
    (&[0x2b, 0x65, 0x70], NID_ED25519),
    (&[0x2b, 0x65, 0x71], NID_ED448),
];

/// A public key that decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// rsaEncryption (or its X.500 alias).
    Rsa(RsaKey),
    /// RSASSA-PSS.
    RsaPss(RsaKey),
    /// Another key type 1.1.1t supports (DSA, EC, DH, X25519, X448,
    /// Ed25519, Ed448), by its `EVP_PKEY` type.  Its content is not
    /// decoded (see the module documentation of [`crate::cert`]).
    Other(u32),
}

impl PublicKey {
    /// `EVP_PKEY_get0_RSA`: the RSA key of an RSA or RSASSA-PSS key.
    pub fn rsa(&self) -> Option<&RsaKey> {
        match self {
            PublicKey::Rsa(k) | PublicKey::RsaPss(k) => Some(k),
            PublicKey::Other(_) => None,
        }
    }

    /// `EVP_PKEY_base_id`.
    pub(crate) fn base_id(&self) -> u32 {
        match self {
            PublicKey::Rsa(_) => NID_RSA,
            PublicKey::RsaPss(_) => NID_RSA_PSS,
            PublicKey::Other(t) => *t,
        }
    }
}

static BIGNUM: Item = Item::Prim { utype: V_INTEGER, bignum: true };
static RSA_PUBLIC_KEY: Item = Item::Seq(&[Tmpl::new(&BIGNUM), Tmpl::new(&BIGNUM)]);
static OBJECT: Item = Item::Prim { utype: V_OBJECT, bignum: false };
static ANY: Item = Item::Prim { utype: V_ANY, bignum: false };
static INTEGER: Item = Item::Prim { utype: V_INTEGER, bignum: false };
/// `X509_ALGOR`.
pub(crate) static ALGOR: Item = Item::Seq(&[Tmpl::new(&OBJECT), Tmpl::new(&ANY).opt()]);
static RSA_PSS_PARAMS: Item = Item::Seq(&[
    Tmpl::new(&ALGOR).exp(0).opt(),
    Tmpl::new(&ALGOR).exp(1).opt(),
    Tmpl::new(&INTEGER).exp(2).opt(),
    Tmpl::new(&INTEGER).exp(3).opt(),
]);

/// An `X509_ALGOR`: the algorithm OID and its parameters (an ANY).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Algor {
    pub oid: Vec<u8>,
    pub params: Option<Val>,
}

impl Algor {
    pub fn from_val(v: &Val) -> Algor {
        Algor { oid: v.field(0).and_then(Val::as_obj).unwrap_or_default().to_vec(), params: v.field(1).cloned() }
    }

    /// `X509_ALGOR_cmp(a, b) == 0`.
    pub fn same(&self, other: &Algor) -> bool {
        if self.oid != other.oid {
            return false;
        }
        match (&self.params, &other.params) {
            (None, None) => true,
            (Some(Val::Any(ta, a)), Some(Val::Any(tb, b))) => ta == tb && type_value_eq(a, b),
            _ => false,
        }
    }
}

/// `ASN1_TYPE_cmp(a, b) == 0` for values of the same type: strings compare
/// type, length, and data (not a BIT STRING's unused bits).
fn type_value_eq(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Str(x), Val::Str(y)) => x.ty == y.ty && x.data == y.data,
        _ => a == b,
    }
}

static BIT_STRING: Item = Item::Prim { utype: super::asn1::V_BIT_STRING, bignum: false };
static PUBKEY: Item = Item::Seq(&[Tmpl::new(&ALGOR), Tmpl::new(&BIT_STRING)]);

/// `d2i_PUBKEY`: a DER `SubjectPublicKeyInfo` and its key, if 1.1.1t can
/// decode them.
pub(crate) fn d2i_pubkey(der: &[u8], errs: &mut Errs) -> Option<PublicKey> {
    let v = asn1::d2i(der, &PUBKEY, errs)?;
    decode(&Algor::from_val(v.field(0)?), v.field(1)?.as_str()?)
}

/// `x509_pubkey_decode`: the key, if 1.1.1t can decode it.
pub(crate) fn decode(alg: &Algor, bits: &AStr) -> Option<PublicKey> {
    let (_, ty) = KEY_TYPES.iter().find(|(oid, _)| *oid == alg.oid.as_slice())?;
    match *ty {
        NID_RSA | NID_RSA_PSS => {
            // rsa_pub_decode: d2i_RSAPublicKey of the BIT STRING's octets,
            // then rsa_param_decode.
            let v = asn1::d2i(&bits.data, &RSA_PUBLIC_KEY, &mut Errs::new())?;
            let (Some(Val::Bn(n)), Some(Val::Bn(e))) = (v.field(0), v.field(1)) else {
                return None;
            };
            let key = RsaKey::from_be_bytes(n, e);
            if *ty == NID_RSA {
                return Some(PublicKey::Rsa(key));
            }
            pss_params_ok(alg).then_some(PublicKey::RsaPss(key))
        }
        t => Some(PublicKey::Other(t)),
    }
}

/// `rsa_param_decode` for an RSASSA-PSS key: no parameters, or a SEQUENCE
/// that decodes as `RSA_PSS_PARAMS` whose mask generation function, if
/// present, is MGF1 with an `X509_ALGOR` parameter.
fn pss_params_ok(alg: &Algor) -> bool {
    let Some(params) = &alg.params else { return true };
    let unpack = |p: &Val, item: &Item| match p {
        Val::Any(V_SEQUENCE, s) => match &**s {
            Val::Str(raw) => asn1::d2i(&raw.data, item, &mut Errs::new()),
            _ => None,
        },
        _ => None,
    };
    let Some(pss) = unpack(params, &RSA_PSS_PARAMS) else { return false };
    match pss.field(1) {
        None => true,
        Some(mgf) => {
            let mgf = Algor::from_val(mgf);
            mgf.oid == OID_MGF1 && mgf.params.as_ref().and_then(|p| unpack(p, &ALGOR)).is_some()
        }
    }
}

/// Digests of the signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Md {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    /// Digests 1.1.1t has but this verifier does not implement (MD4,
    /// MDC2, RIPEMD-160, SHA-3).
    Unimplemented,
    /// Digests 1.1.1t does not have (MD2, disabled in its default build,
    /// and SHA-0, removed in 1.1.0).
    Unavailable,
    /// No digest: the key type's own verification (RSASSA-PSS, Ed25519,
    /// Ed448, ECDSA with unspecified digests).
    KeyType,
}

/// One entry of 1.1.1t's signature algorithm table: OID, digest, and the
/// `EVP_PKEY` type of the signing key.
pub(crate) struct SigAlg {
    pub md: Md,
    pub pkey: u32,
}

/// `OBJ_find_sigid_algs` (the table `sigoid_srt`, without the GOST and
/// ECDH entries, whose key types 1.1.1t cannot verify without an
/// engine).
pub(crate) fn sig_alg(oid: &[u8]) -> Option<SigAlg> {
    const PKCS1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    const OIW: &[u8] = &[0x2b, 0x0e, 0x03, 0x02];
    const NIST_SIG: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    const X962_SIG: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04];
    let rsa = |md| Some(SigAlg { md, pkey: NID_RSA });
    let dsa = |md| Some(SigAlg { md, pkey: NID_DSA });
    let ec = |md| Some(SigAlg { md, pkey: NID_EC });
    if let Some(last) = oid.strip_prefix(PKCS1) {
        return match last {
            [0x02] => rsa(Md::Unavailable),
            [0x03] => rsa(Md::Unimplemented),
            [0x04] => rsa(Md::Md5),
            [0x05] => rsa(Md::Sha1),
            [0x0a] => rsa(Md::KeyType),
            [0x0b] => rsa(Md::Sha256),
            [0x0c] => rsa(Md::Sha384),
            [0x0d] => rsa(Md::Sha512),
            [0x0e] => rsa(Md::Sha224),
            _ => None,
        };
    }
    if let Some(last) = oid.strip_prefix(OIW) {
        return match last {
            [0x03] => rsa(Md::Md5),
            [0x0f] => rsa(Md::Unavailable),
            [0x1d] => rsa(Md::Sha1),
            [0x0d] => dsa(Md::Unavailable),
            [0x1b] => dsa(Md::Sha1),
            _ => None,
        };
    }
    if let Some(last) = oid.strip_prefix(NIST_SIG) {
        return match last {
            [0x01] => dsa(Md::Sha224),
            [0x02] => dsa(Md::Sha256),
            [0x0d..=0x10] => rsa(Md::Unimplemented),
            _ => None,
        };
    }
    if let Some(last) = oid.strip_prefix(X962_SIG) {
        return match last {
            [0x01] => ec(Md::Sha1),
            [0x02] | [0x03] => ec(Md::KeyType),
            [0x03, 0x01] => ec(Md::Sha224),
            [0x03, 0x02] => ec(Md::Sha256),
            [0x03, 0x03] => ec(Md::Sha384),
            [0x03, 0x04] => ec(Md::Sha512),
            _ => None,
        };
    }
    match oid {
        [0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03] => dsa(Md::Sha1),
        [0x55, 0x08, 0x03, 0x64] => rsa(Md::Unimplemented),
        [0x2b, 0x24, 0x03, 0x03, 0x01, 0x02] => rsa(Md::Unimplemented),
        [0x2b, 0x65, 0x70] => Some(SigAlg { md: Md::KeyType, pkey: NID_ED25519 }),
        [0x2b, 0x65, 0x71] => Some(SigAlg { md: Md::KeyType, pkey: NID_ED448 }),
        _ => None,
    }
}

/// `check_sig_alg_match(pkey, subject)`: does the key's type match the
/// subject's (inner) signature algorithm?  Err holds the `X509_V_ERR_*`.
pub(crate) fn check_sig_alg_match(key: Option<&PublicKey>, tbs_sig_oid: &[u8]) -> Result<(), i32> {
    use super::verify::{
        X509_V_ERR_NO_ISSUER_PUBLIC_KEY, X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH,
        X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM,
    };
    let key = key.ok_or(X509_V_ERR_NO_ISSUER_PUBLIC_KEY)?;
    // An RSASSA-PSS key signs as rsaEncryption (its sigoid_srt entry).
    let pkey_sig_nid = match key.base_id() {
        NID_RSA_PSS => NID_RSA,
        b => b,
    };
    let alg = sig_alg(tbs_sig_oid).ok_or(X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM)?;
    if pkey_sig_nid != alg.pkey {
        return Err(X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH);
    }
    Ok(())
}

/// The `DigestInfo` prefix `encode_pkcs1` puts before a digest.
pub(crate) fn digest_info(md: Md, tbs: &[u8]) -> Option<Vec<u8>> {
    use sha1::Digest;
    let (prefix, digest): (&[u8], Vec<u8>) = match md {
        Md::Md5 => (
            &[0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10],
            md5::Md5::digest(tbs).to_vec(),
        ),
        Md::Sha1 => (
            &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14],
            sha1::Sha1::digest(tbs).to_vec(),
        ),
        Md::Sha224 => (&nist(0x2d, 0x04, 0x1c), sha2::Sha224::digest(tbs).to_vec()),
        Md::Sha256 => (&nist(0x31, 0x01, 0x20), sha2::Sha256::digest(tbs).to_vec()),
        Md::Sha384 => (&nist(0x41, 0x02, 0x30), sha2::Sha384::digest(tbs).to_vec()),
        Md::Sha512 => (&nist(0x51, 0x03, 0x40), sha2::Sha512::digest(tbs).to_vec()),
        _ => return None,
    };
    let mut out = prefix.to_vec();
    out.extend(digest);
    Some(out)
}

/// The DigestInfo prefix of a NIST hash (2.16.840.1.101.3.4.2.`n`).
const fn nist(total: u8, n: u8, len: u8) -> [u8; 19] {
    [0x30, total, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, n, 0x05, 0x00, 0x04, len]
}
