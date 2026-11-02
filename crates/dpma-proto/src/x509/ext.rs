//! The certificate extensions OpenSSL 1.1.1t looks at, and what it caches
//! from them (`x509v3_cache_extensions` in `crypto/x509v3/v3_purp.c`).
//!
//! 1.1.1t decodes basicConstraints, proxyCertInfo, keyUsage,
//! extendedKeyUsage, nsCertType, subjectKeyIdentifier,
//! authorityKeyIdentifier, subjectAltName, nameConstraints,
//! cRLDistributionPoints, and the two RFC 3779 extensions.  When one of
//! them occurs twice or does not decode (with the templates below, which
//! are 1.1.1t's), the certificate is flagged `EXFLAG_INVALID`; an invalid
//! certificate is never taken as anyone's issuer or subject in a chain, nor
//! as self-signed or trusted (see `verify`).

use super::asn1::{self, AInt, AStr, Item, Tmpl, Val, B_DIRECTORYSTRING, V_ANY, V_BIT_STRING, V_BOOLEAN, V_IA5STRING, V_INTEGER, V_NULL, V_OBJECT, V_OCTET_STRING, V_SEQUENCE};
use super::name::{Name, NAME_ENTRY};
use crate::errstack::Errs;

static OBJECT: Item = Item::Prim { utype: V_OBJECT, bignum: false };
static INTEGER: Item = Item::Prim { utype: V_INTEGER, bignum: false };
static BIT_STRING: Item = Item::Prim { utype: V_BIT_STRING, bignum: false };
static OCTET_STRING: Item = Item::Prim { utype: V_OCTET_STRING, bignum: false };
static BOOLEAN: Item = Item::Prim { utype: V_BOOLEAN, bignum: false };
static NULL: Item = Item::Prim { utype: V_NULL, bignum: false };
static IA5STRING: Item = Item::Prim { utype: V_IA5STRING, bignum: false };
static ANY: Item = Item::Prim { utype: V_ANY, bignum: false };
/// `ASN1_SEQUENCE` (kept encoded).
static SEQUENCE: Item = Item::Prim { utype: V_SEQUENCE, bignum: false };
static DIRECTORYSTRING: Item = Item::MString(B_DIRECTORYSTRING);
static NAME: Item = Item::Name;

/// `BASIC_CONSTRAINTS` (`ca` is an `ASN1_FBOOLEAN`, which decodes as a
/// BOOLEAN).
pub(crate) static BASIC_CONSTRAINTS: Item = Item::Seq(&[Tmpl::new(&BOOLEAN).opt(), Tmpl::new(&INTEGER).opt()]);
static PROXY_POLICY: Item = Item::Seq(&[Tmpl::new(&OBJECT), Tmpl::new(&OCTET_STRING).opt()]);
pub(crate) static PROXY_CERT_INFO: Item = Item::Seq(&[Tmpl::new(&INTEGER).opt(), Tmpl::new(&PROXY_POLICY)]);
pub(crate) static EXTENDED_KEY_USAGE: Item = Item::Template(&Tmpl::new(&OBJECT).seq_of());
static OTHERNAME: Item = Item::Seq(&[Tmpl::new(&OBJECT), Tmpl::new(&ANY).exp(0)]);
static EDIPARTYNAME: Item =
    Item::Seq(&[Tmpl::new(&DIRECTORYSTRING).exp(0).opt(), Tmpl::new(&DIRECTORYSTRING).exp(1)]);
/// `GENERAL_NAME`; the alternative's index is its `GEN_*` type.
pub(crate) static GENERAL_NAME: Item = Item::Choice(&[
    Tmpl::new(&OTHERNAME).imp(0),
    Tmpl::new(&IA5STRING).imp(1),
    Tmpl::new(&IA5STRING).imp(2),
    Tmpl::new(&SEQUENCE).imp(3),
    Tmpl::new(&NAME).exp(4),
    Tmpl::new(&EDIPARTYNAME).imp(5),
    Tmpl::new(&IA5STRING).imp(6),
    Tmpl::new(&OCTET_STRING).imp(7),
    Tmpl::new(&OBJECT).imp(8),
]);
pub(crate) static GENERAL_NAMES: Item = Item::Template(&Tmpl::new(&GENERAL_NAME).seq_of());
pub(crate) static AUTHORITY_KEYID: Item = Item::Seq(&[
    Tmpl::new(&OCTET_STRING).imp(0).opt(),
    Tmpl::new(&GENERAL_NAME).imp(1).seq_of().opt(),
    Tmpl::new(&INTEGER).imp(2).opt(),
]);
static GENERAL_SUBTREE: Item =
    Item::Seq(&[Tmpl::new(&GENERAL_NAME), Tmpl::new(&INTEGER).imp(0).opt(), Tmpl::new(&INTEGER).imp(1).opt()]);
pub(crate) static NAME_CONSTRAINTS: Item = Item::Seq(&[
    Tmpl::new(&GENERAL_SUBTREE).imp(0).seq_of().opt(),
    Tmpl::new(&GENERAL_SUBTREE).imp(1).seq_of().opt(),
]);
static DIST_POINT_NAME: Item =
    Item::Choice(&[Tmpl::new(&GENERAL_NAME).imp(0).seq_of(), Tmpl::new(&NAME_ENTRY).imp(1).set_of()]);
static DIST_POINT: Item = Item::Seq(&[
    Tmpl::new(&DIST_POINT_NAME).exp(0).opt(),
    Tmpl::new(&BIT_STRING).imp(1).opt(),
    Tmpl::new(&GENERAL_NAME).imp(2).seq_of().opt(),
]);
pub(crate) static CRL_DIST_POINTS: Item = Item::Template(&Tmpl::new(&DIST_POINT).seq_of());
static IP_ADDRESS_RANGE: Item = Item::Seq(&[Tmpl::new(&BIT_STRING), Tmpl::new(&BIT_STRING)]);
static IP_ADDRESS_OR_RANGE: Item = Item::Choice(&[Tmpl::new(&BIT_STRING), Tmpl::new(&IP_ADDRESS_RANGE)]);
static IP_ADDRESS_CHOICE: Item = Item::Choice(&[Tmpl::new(&NULL), Tmpl::new(&IP_ADDRESS_OR_RANGE).seq_of()]);
static IP_ADDRESS_FAMILY: Item = Item::Seq(&[Tmpl::new(&OCTET_STRING), Tmpl::new(&IP_ADDRESS_CHOICE)]);
pub(crate) static IP_ADDR_BLOCKS: Item = Item::Template(&Tmpl::new(&IP_ADDRESS_FAMILY).seq_of());
static AS_RANGE: Item = Item::Seq(&[Tmpl::new(&INTEGER), Tmpl::new(&INTEGER)]);
static AS_ID_OR_RANGE: Item = Item::Choice(&[Tmpl::new(&INTEGER), Tmpl::new(&AS_RANGE)]);
static AS_IDENTIFIER_CHOICE: Item = Item::Choice(&[Tmpl::new(&NULL), Tmpl::new(&AS_ID_OR_RANGE).seq_of()]);
pub(crate) static AS_IDENTIFIERS: Item = Item::Seq(&[
    Tmpl::new(&AS_IDENTIFIER_CHOICE).exp(0).opt(),
    Tmpl::new(&AS_IDENTIFIER_CHOICE).exp(1).opt(),
]);

/// Extension OIDs (content octets).
pub(crate) mod oid {
    pub const NETSCAPE_CERT_TYPE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01];
    pub const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    pub const ISSUER_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x12];
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    pub const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
    pub const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
    pub const CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
    pub const POLICY_MAPPINGS: &[u8] = &[0x55, 0x1d, 0x21];
    pub const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
    pub const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    pub const INHIBIT_ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x36];
    pub const SBGP_IP_ADDR_BLOCK: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07];
    pub const SBGP_AUTONOMOUS_SYS_NUM: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x08];
    pub const PROXY_CERT_INFO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0e];
}

/// `X509_supported_extension`: the extensions the verifier handles; a
/// critical extension not in this list makes the certificate unusable
/// (`X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION`).
const SUPPORTED: &[&[u8]] = &[
    oid::NETSCAPE_CERT_TYPE,
    oid::KEY_USAGE,
    oid::SUBJECT_ALT_NAME,
    oid::BASIC_CONSTRAINTS,
    oid::CERTIFICATE_POLICIES,
    oid::CRL_DISTRIBUTION_POINTS,
    oid::EXT_KEY_USAGE,
    oid::SBGP_IP_ADDR_BLOCK,
    oid::SBGP_AUTONOMOUS_SYS_NUM,
    oid::POLICY_CONSTRAINTS,
    oid::PROXY_CERT_INFO,
    oid::NAME_CONSTRAINTS,
    oid::POLICY_MAPPINGS,
    oid::INHIBIT_ANY_POLICY,
];

pub(crate) const EXFLAG_BCONS: u32 = 0x1;
pub(crate) const EXFLAG_KUSAGE: u32 = 0x2;
pub(crate) const EXFLAG_XKUSAGE: u32 = 0x4;
pub(crate) const EXFLAG_NSCERT: u32 = 0x8;
pub(crate) const EXFLAG_CA: u32 = 0x10;
pub(crate) const EXFLAG_SI: u32 = 0x20;
pub(crate) const EXFLAG_V1: u32 = 0x40;
pub(crate) const EXFLAG_INVALID: u32 = 0x80;
pub(crate) const EXFLAG_CRITICAL: u32 = 0x200;
pub(crate) const EXFLAG_PROXY: u32 = 0x400;
pub(crate) const EXFLAG_SS: u32 = 0x2000;

pub(crate) const KU_DIGITAL_SIGNATURE: u32 = 0x0080;
pub(crate) const KU_KEY_CERT_SIGN: u32 = 0x0004;
pub(crate) const NS_ANY_CA: u32 = 0x07;

/// One extension as decoded (`X509_EXTENSION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Extension {
    pub oid: Vec<u8>,
    /// The BOOLEAN's octet as it came, if present; the extension is
    /// critical when it is present and not zero.
    pub critical: Option<u8>,
    pub value: Vec<u8>,
}

impl Extension {
    pub fn is_critical(&self) -> bool {
        self.critical.is_some_and(|c| c != 0)
    }
}

/// A `GENERAL_NAME`: its type (`GEN_OTHERNAME` 0 to `GEN_RID` 8) and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenName {
    pub kind: usize,
    pub value: GenValue,
}

pub(crate) const GEN_EMAIL: usize = 1;
pub(crate) const GEN_DNS: usize = 2;
pub(crate) const GEN_DIRNAME: usize = 4;
pub(crate) const GEN_URI: usize = 6;
pub(crate) const GEN_IPADD: usize = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GenValue {
    /// rfc822Name, dNSName, URI, and iPAddress.
    Str(AStr),
    DirName(Name),
    /// otherName, x400Address, ediPartyName, registeredID.
    Other,
}

fn gen_name(v: &Val) -> Option<GenName> {
    let Val::Choice(kind, inner) = v else { return None };
    let value = match &**inner {
        Val::Str(s) if [GEN_EMAIL, GEN_DNS, GEN_URI, GEN_IPADD].contains(kind) => GenValue::Str(s.clone()),
        Val::Name(n) => GenValue::DirName(n.clone()),
        _ => GenValue::Other,
    };
    Some(GenName { kind: *kind, value })
}

fn gen_names(v: &Val) -> Vec<GenName> {
    v.as_list().iter().filter_map(gen_name).collect()
}

/// `AUTHORITY_KEYID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Akid {
    pub keyid: Option<Vec<u8>>,
    pub issuer: Option<Vec<GenName>>,
    pub serial: Option<AInt>,
}

/// A `GENERAL_SUBTREE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Subtree {
    pub base: GenName,
    /// Whether minimum or maximum is present (1.1.1t does not support
    /// them).
    pub minmax: bool,
}

/// `NAME_CONSTRAINTS`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct NameConstraints {
    pub permitted: Vec<Subtree>,
    pub excluded: Vec<Subtree>,
}

fn subtrees(v: Option<&Val>) -> Vec<Subtree> {
    v.map(Val::as_list)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| {
            Some(Subtree { base: gen_name(s.field(0)?)?, minmax: s.field(1).is_some() || s.field(2).is_some() })
        })
        .collect()
}

/// What `x509v3_cache_extensions` computes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExInfo {
    pub flags: u32,
    pub kusage: u32,
    pub nscert: u32,
    pub pathlen: i64,
    pub pcpathlen: i64,
    pub skid: Option<Vec<u8>>,
    pub akid: Option<Akid>,
    pub altname: Option<Vec<GenName>>,
    pub nc: Option<NameConstraints>,
    /// The certificate has a (decodable) RFC 3779 extension.
    pub rfc3779: bool,
}

/// What `X509V3_get_d2i` found for one extension type.
enum Found {
    Absent,
    /// Present more than once, or does not decode.
    Invalid,
    Ok(Val),
}

fn get_d2i(exts: &[Extension], oid: &[u8], item: &Item) -> Found {
    let mut it = exts.iter().filter(|e| e.oid == oid);
    let Some(ext) = it.next() else { return Found::Absent };
    if it.next().is_some() {
        return Found::Invalid;
    }
    // The errors of a failed decode stay on 1.1.1t's queue; nothing reads
    // them back.
    match asn1::d2i(&ext.value, item, &mut Errs::new()) {
        Some(v) => Found::Ok(v),
        None => Found::Invalid,
    }
}

/// The parts of a certificate `x509v3_cache_extensions` needs besides the
/// extensions.
pub(crate) struct CacheInput<'a> {
    /// `X509_get_version() == 0`.
    pub v1: bool,
    pub exts: &'a [Extension],
    pub subject: &'a Name,
    pub issuer: &'a Name,
}

/// `x509v3_cache_extensions`, except for the self-signed test, which
/// needs the key ([`super::Cert`] adds it).
pub(crate) fn cache(c: &CacheInput) -> ExInfo {
    let mut x = ExInfo {
        flags: 0,
        kusage: 0,
        nscert: 0,
        pathlen: -1,
        pcpathlen: -1,
        skid: None,
        akid: None,
        altname: None,
        nc: None,
        rfc3779: false,
    };
    if c.v1 {
        x.flags |= EXFLAG_V1;
    }
    match get_d2i(c.exts, oid::BASIC_CONSTRAINTS, &BASIC_CONSTRAINTS) {
        Found::Ok(bs) => {
            let ca = matches!(bs.field(0), Some(Val::Bool(b)) if *b != 0);
            if ca {
                x.flags |= EXFLAG_CA;
            }
            match bs.field(1).and_then(Val::as_int) {
                Some(p) if p.neg => {
                    x.flags |= EXFLAG_INVALID;
                    x.pathlen = 0;
                }
                Some(p) => {
                    x.pathlen = p.get();
                    if !ca && x.pathlen != 0 {
                        x.flags |= EXFLAG_INVALID;
                        x.pathlen = 0;
                    }
                }
                None => x.pathlen = -1,
            }
            x.flags |= EXFLAG_BCONS;
        }
        Found::Invalid => x.flags |= EXFLAG_INVALID,
        Found::Absent => {}
    }
    match get_d2i(c.exts, oid::PROXY_CERT_INFO, &PROXY_CERT_INFO) {
        Found::Ok(pci) => {
            if x.flags & EXFLAG_CA != 0
                || c.exts.iter().any(|e| e.oid == oid::SUBJECT_ALT_NAME || e.oid == oid::ISSUER_ALT_NAME)
            {
                x.flags |= EXFLAG_INVALID;
            }
            x.pcpathlen = pci.field(0).and_then(Val::as_int).map(AInt::get).unwrap_or(-1);
            x.flags |= EXFLAG_PROXY;
        }
        Found::Invalid => x.flags |= EXFLAG_INVALID,
        Found::Absent => {}
    }
    match get_d2i(c.exts, oid::KEY_USAGE, &BIT_STRING) {
        Found::Ok(Val::Str(u)) => {
            x.kusage = u.data.first().map(|&b| u32::from(b)).unwrap_or(0)
                | u.data.get(1).map(|&b| u32::from(b) << 8).unwrap_or(0);
            x.flags |= EXFLAG_KUSAGE;
        }
        Found::Absent => {}
        _ => x.flags |= EXFLAG_INVALID,
    }
    match get_d2i(c.exts, oid::EXT_KEY_USAGE, &EXTENDED_KEY_USAGE) {
        Found::Ok(_) => x.flags |= EXFLAG_XKUSAGE,
        Found::Invalid => x.flags |= EXFLAG_INVALID,
        Found::Absent => {}
    }
    match get_d2i(c.exts, oid::NETSCAPE_CERT_TYPE, &BIT_STRING) {
        Found::Ok(Val::Str(ns)) => {
            x.nscert = ns.data.first().map(|&b| u32::from(b)).unwrap_or(0);
            x.flags |= EXFLAG_NSCERT;
        }
        Found::Absent => {}
        _ => x.flags |= EXFLAG_INVALID,
    }
    match get_d2i(c.exts, oid::SUBJECT_KEY_IDENTIFIER, &OCTET_STRING) {
        Found::Ok(Val::Str(s)) => x.skid = Some(s.data),
        Found::Absent => {}
        _ => x.flags |= EXFLAG_INVALID,
    }
    match get_d2i(c.exts, oid::AUTHORITY_KEY_IDENTIFIER, &AUTHORITY_KEYID) {
        Found::Ok(a) => {
            x.akid = Some(Akid {
                keyid: a.field(0).and_then(Val::as_str).map(|s| s.data.clone()),
                issuer: a.field(1).map(gen_names),
                serial: a.field(2).and_then(Val::as_int).cloned(),
            })
        }
        Found::Invalid => x.flags |= EXFLAG_INVALID,
        Found::Absent => {}
    }
    if c.subject.eq_canon(c.issuer) {
        x.flags |= EXFLAG_SI;
    }
    match get_d2i(c.exts, oid::SUBJECT_ALT_NAME, &GENERAL_NAMES) {
        Found::Ok(v) => x.altname = Some(gen_names(&v)),
        Found::Invalid => x.flags |= EXFLAG_INVALID,
        Found::Absent => {}
    }
    match get_d2i(c.exts, oid::NAME_CONSTRAINTS, &NAME_CONSTRAINTS) {
        Found::Ok(v) => x.nc = Some(NameConstraints { permitted: subtrees(v.field(0)), excluded: subtrees(v.field(1)) }),
        Found::Invalid => x.flags |= EXFLAG_INVALID,
        Found::Absent => {}
    }
    match get_d2i(c.exts, oid::CRL_DISTRIBUTION_POINTS, &CRL_DIST_POINTS) {
        Found::Ok(v) => {
            if !v.as_list().iter().all(|dp| setup_dp(dp, c.issuer)) {
                x.flags |= EXFLAG_INVALID;
            }
        }
        Found::Invalid => x.flags |= EXFLAG_INVALID,
        Found::Absent => {}
    }
    for (o, item) in [(oid::SBGP_IP_ADDR_BLOCK, &IP_ADDR_BLOCKS), (oid::SBGP_AUTONOMOUS_SYS_NUM, &AS_IDENTIFIERS)] {
        match get_d2i(c.exts, o, item) {
            Found::Ok(_) => x.rfc3779 = true,
            Found::Invalid => x.flags |= EXFLAG_INVALID,
            Found::Absent => {}
        }
    }
    if c.exts.iter().any(|e| e.is_critical() && !SUPPORTED.contains(&e.oid.as_slice())) {
        x.flags |= EXFLAG_CRITICAL;
    }
    x
}

/// `setup_dp`: a distribution point named relative to its CRL issuer gets
/// its full name built (`DIST_POINT_set_dpname`), which fails when the
/// relative part's values cannot be canonicalized.
fn setup_dp(dp: &Val, issuer: &Name) -> bool {
    let Some(Val::Choice(1, frag)) = dp.field(0) else {
        return true;
    };
    let iname = dp
        .field(2)
        .map(gen_names)
        .unwrap_or_default()
        .into_iter()
        .find_map(|g| match g.value {
            GenValue::DirName(n) if g.kind == GEN_DIRNAME => Some(n),
            _ => None,
        })
        .unwrap_or_else(|| issuer.clone());
    let mut entries = iname.entries.clone();
    for ne in frag.as_list() {
        let (Some(oid), Some(value)) = (ne.field(0).and_then(Val::as_obj), ne.field(1).and_then(Val::as_str)) else {
            return false;
        };
        // X509_NAME_add_entry(..., -1, ...) appends each entry as an RDN of
        // its own.
        let set = entries.last().map(|e| e.set + 1).unwrap_or(0);
        entries.push(super::name::Entry { set, oid: oid.to_vec(), value: value.clone() });
    }
    Name::from_entries(entries, &mut Errs::new()).is_some()
}

/// `X509_check_akid(issuer, akid)`: Ok, or the `X509_V_ERR_*` mismatch.
pub(crate) fn check_akid(
    akid: Option<&Akid>,
    issuer_skid: Option<&[u8]>,
    issuer_serial: &AInt,
    issuer_issuer: &Name,
) -> Result<(), i32> {
    let Some(akid) = akid else { return Ok(()) };
    if let (Some(k), Some(s)) = (&akid.keyid, issuer_skid) {
        if k.as_slice() != s {
            return Err(super::verify::X509_V_ERR_AKID_SKID_MISMATCH);
        }
    }
    if let Some(serial) = &akid.serial {
        if serial != issuer_serial {
            return Err(super::verify::X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
        }
    }
    if let Some(gens) = &akid.issuer {
        let dirname = gens.iter().find_map(|g| match &g.value {
            GenValue::DirName(n) if g.kind == GEN_DIRNAME => Some(n),
            _ => None,
        });
        if let Some(n) = dirname {
            if !n.eq_canon(issuer_issuer) {
                return Err(super::verify::X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::asn1::der_tlv;
    use super::*;

    fn ext(oid: &[u8], critical: Option<u8>, value: Vec<u8>) -> Extension {
        Extension { oid: oid.to_vec(), critical, value }
    }

    fn info(exts: &[Extension]) -> ExInfo {
        let name = Name { entries: vec![], der: vec![], canon: vec![1] };
        let other = Name { entries: vec![], der: vec![], canon: vec![2] };
        cache(&CacheInput { v1: false, exts, subject: &name, issuer: &other })
    }

    #[test]
    fn basic_constraints() {
        let bc = |content: &[u8]| ext(oid::BASIC_CONSTRAINTS, None, der_tlv(true, 0, 16, content));
        let x = info(&[bc(&[0x01, 0x01, 0xff])]);
        assert_eq!(x.flags, EXFLAG_BCONS | EXFLAG_CA);
        assert_eq!(x.pathlen, -1);
        // Any non-zero octet is TRUE; trailing data after the value is not
        // looked at.
        let mut v = der_tlv(true, 0, 16, &[0x01, 0x01, 0x01, 0x02, 0x01, 0x03]);
        v.extend([0xde, 0xad]);
        let x = info(&[ext(oid::BASIC_CONSTRAINTS, None, v)]);
        assert_eq!((x.flags, x.pathlen), (EXFLAG_BCONS | EXFLAG_CA, 3));
        // CA:FALSE with a path length, a negative path length, and two
        // basicConstraints are invalid.
        assert_ne!(info(&[bc(&[0x02, 0x01, 0x01])]).flags & EXFLAG_INVALID, 0);
        assert_eq!(info(&[bc(&[0x02, 0x01, 0x00])]).flags, EXFLAG_BCONS);
        assert_ne!(info(&[bc(&[0x01, 0x01, 0xff, 0x02, 0x01, 0xff])]).flags & EXFLAG_INVALID, 0);
        assert_ne!(info(&[bc(&[]), bc(&[])]).flags & EXFLAG_INVALID, 0);
        assert_ne!(info(&[ext(oid::BASIC_CONSTRAINTS, None, vec![0x04, 0x00])]).flags & EXFLAG_INVALID, 0);
    }

    #[test]
    fn key_usage_and_critical() {
        let ku = ext(oid::KEY_USAGE, Some(0xff), vec![0x03, 0x02, 0x01, 0x86]);
        let x = info(&[ku]);
        assert_eq!(x.flags, EXFLAG_KUSAGE);
        assert_eq!(x.kusage, 0x86);
        let unknown = ext(&[0x2a, 0x03], Some(0x01), vec![0x05, 0x00]);
        assert_eq!(info(std::slice::from_ref(&unknown)).flags, EXFLAG_CRITICAL);
        let not_critical = Extension { critical: Some(0), ..unknown };
        assert_eq!(info(&[not_critical]).flags, 0);
        // A bad subjectAltName makes the certificate invalid.
        assert_ne!(info(&[ext(oid::SUBJECT_ALT_NAME, None, vec![0x30, 0x02, 0x82, 0x05])]).flags & EXFLAG_INVALID, 0);
        let san = der_tlv(true, 0, 16, &der_tlv(false, 0x80, 2, b"phone.example"));
        let x = info(&[ext(oid::SUBJECT_ALT_NAME, None, san)]);
        assert_eq!(x.flags, 0);
        assert_eq!(x.altname.unwrap()[0].kind, GEN_DNS);
    }
}
