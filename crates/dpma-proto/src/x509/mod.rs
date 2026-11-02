//! X.509 certificates as the original's OpenSSL 1.1.1t reads and verifies
//! them: the decoder (`asn1`, `name`, `ext`, `key`), the PEM reader
//! (`pem`), and chain verification (`verify`, `ncons`).
//!
//! These follow 1.1.1t's source (`crypto/asn1`, `crypto/pem`,
//! `crypto/x509`, `crypto/x509v3`) step by step, so that the module accepts
//! exactly the phone certificates the original accepts and logs the same
//! error texts.  [`crate::cert`] documents what is checked and what is
//! left out.

pub(crate) mod asn1;
pub(crate) mod ext;
pub(crate) mod key;
pub(crate) mod name;
pub(crate) mod ncons;
pub(crate) mod pem;
pub(crate) mod verify;

use asn1::{AInt, AStr, Item, Tmpl, Val, B_TIME, V_BIT_STRING, V_BOOLEAN, V_INTEGER, V_OBJECT, V_OCTET_STRING};
use ext::{ExInfo, Extension, EXFLAG_INVALID, EXFLAG_SI, EXFLAG_SS};
use key::{Algor, PublicKey, ALGOR};
use name::Name;

use crate::errstack::Errs;

static OBJECT: Item = Item::Prim { utype: V_OBJECT, bignum: false };
static INTEGER: Item = Item::Prim { utype: V_INTEGER, bignum: false };
static BIT_STRING: Item = Item::Prim { utype: V_BIT_STRING, bignum: false };
static OCTET_STRING: Item = Item::Prim { utype: V_OCTET_STRING, bignum: false };
static BOOLEAN: Item = Item::Prim { utype: V_BOOLEAN, bignum: false };
static TIME: Item = Item::MString(B_TIME);
static NAME: Item = Item::Name;
static VAL: Item = Item::Seq(&[Tmpl::new(&TIME), Tmpl::new(&TIME)]);
static PUBKEY: Item = Item::Seq(&[Tmpl::new(&ALGOR), Tmpl::new(&BIT_STRING)]);
static EXTENSION: Item = Item::Seq(&[Tmpl::new(&OBJECT), Tmpl::new(&BOOLEAN).opt(), Tmpl::new(&OCTET_STRING)]);
static CINF: Item = Item::Seq(&[
    Tmpl::new(&INTEGER).exp(0).opt(),
    Tmpl::new(&INTEGER),
    Tmpl::new(&ALGOR),
    Tmpl::new(&NAME),
    Tmpl::new(&VAL),
    Tmpl::new(&NAME),
    Tmpl::new(&PUBKEY),
    Tmpl::new(&BIT_STRING).imp(1).opt(),
    Tmpl::new(&BIT_STRING).imp(2).opt(),
    Tmpl::new(&EXTENSION).exp(3).seq_of().opt(),
]);
/// `X509`.
static X509: Item = Item::Seq(&[Tmpl::new(&CINF), Tmpl::new(&ALGOR), Tmpl::new(&BIT_STRING)]);

/// A decoded certificate, with what 1.1.1t caches about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The encoding the certificate was decoded from (trailing data
    /// excluded).
    der: Vec<u8>,
    /// The signed part (`TBSCertificate`) as it came (`cert_info.enc`).
    tbs: (usize, usize),
    pub(crate) version: Option<AInt>,
    pub(crate) serial: AInt,
    /// The signature algorithm inside the signed part.
    pub(crate) tbs_alg: Algor,
    pub(crate) issuer: Name,
    pub(crate) not_before: AStr,
    pub(crate) not_after: AStr,
    pub(crate) subject: Name,
    pub(crate) key: Option<PublicKey>,
    pub(crate) sig_alg: Algor,
    pub(crate) signature: AStr,
    pub(crate) ex: ExInfo,
}

impl Certificate {
    /// `d2i_X509`: decode a certificate from the start of `der` (trailing
    /// data is ignored, as in 1.1.1t), recording 1.1.1t's errors.
    pub(crate) fn d2i(der: &[u8], errs: &mut Errs) -> Option<Certificate> {
        let v = asn1::d2i(der, &X509, errs)?;
        let (start, end) = v.span()?;
        let cinf = v.field(0)?;
        let tbs = cinf.span()?;
        let name = |i| match cinf.field(i) {
            Some(Val::Name(n)) => Some(n.clone()),
            _ => None,
        };
        let validity = cinf.field(4)?;
        let pubkey = cinf.field(6)?;
        let spki_alg = Algor::from_val(pubkey.field(0)?);
        let spki_bits = pubkey.field(1)?.as_str()?;
        let exts: Vec<Extension> = cinf
            .field(9)
            .map(Val::as_list)
            .unwrap_or_default()
            .iter()
            .map(|e| Extension {
                oid: e.field(0).and_then(Val::as_obj).unwrap_or_default().to_vec(),
                critical: match e.field(1) {
                    Some(Val::Bool(b)) => Some(*b),
                    _ => None,
                },
                value: e.field(2).and_then(Val::as_str).map(|s| s.data.clone()).unwrap_or_default(),
            })
            .collect();
        let version = cinf.field(0).and_then(Val::as_int).cloned();
        let serial = cinf.field(1)?.as_int()?.clone();
        let issuer = name(3)?;
        let subject = name(5)?;
        let key = key::decode(&spki_alg, spki_bits);
        let tbs_alg = Algor::from_val(cinf.field(2)?);
        let mut ex = ext::cache(&ext::CacheInput {
            v1: version.as_ref().map(AInt::get).unwrap_or(0) == 0,
            exts: &exts,
            subject: &subject,
            issuer: &issuer,
        });
        // A self-issued certificate is self-signed if its AKID matches it
        // and its key type matches its signature algorithm.
        if ex.flags & EXFLAG_SI != 0
            && ext::check_akid(ex.akid.as_ref(), ex.skid.as_deref(), &serial, &issuer).is_ok()
            && key::check_sig_alg_match(key.as_ref(), &tbs_alg.oid).is_ok()
        {
            ex.flags |= EXFLAG_SS;
        }
        Some(Certificate {
            der: der[start..end].to_vec(),
            tbs: (tbs.0 - start, tbs.1 - start),
            version,
            serial,
            tbs_alg,
            issuer,
            not_before: validity.field(0)?.as_str()?.clone(),
            not_after: validity.field(1)?.as_str()?.clone(),
            subject,
            key,
            sig_alg: Algor::from_val(v.field(1)?),
            signature: v.field(2)?.as_str()?.clone(),
            ex,
        })
    }

    /// The certificate's encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The signed part as it came.
    pub(crate) fn tbs(&self) -> &[u8] {
        &self.der[self.tbs.0..self.tbs.1]
    }

    /// Its public key, if 1.1.1t can decode it (`X509_get0_pubkey`).
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.key.as_ref()
    }

    /// The serial number as the original reads it:
    /// `strtoll(BN_bn2dec(serial))`.
    pub fn serial_i64(&self) -> i64 {
        self.serial.to_i64_saturating()
    }

    /// `EXFLAG_INVALID`.
    pub(crate) fn invalid(&self) -> bool {
        self.ex.flags & EXFLAG_INVALID != 0
    }

    /// `X509_cmp(a, b) == 0`: the same signed part, signature algorithm,
    /// and signature (1.1.1t compares a hash of the re-encoded certificate
    /// and the signed part as it came).
    pub(crate) fn same(&self, other: &Certificate) -> bool {
        self.tbs() == other.tbs()
            && self.sig_alg == other.sig_alg
            && self.signature.data == other.signature.data
            && (self.signature.data.is_empty() || self.signature.bits_left == other.signature.bits_left)
    }
}
