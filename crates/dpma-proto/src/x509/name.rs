//! `X509_NAME` as OpenSSL 1.1.1t decodes and compares it
//! (`crypto/x509/x_name.c`, `X509_NAME_cmp`).
//!
//! Names are compared by their canonical encoding, not their bytes: each
//! attribute value of a string type that 1.1.1t canonicalizes is converted
//! to UTF-8, leading and trailing white space is removed, runs of white
//! space become one space, and ASCII letters are lowered; the values are
//! then DER encoded as UTF8Strings, each RDN as a sorted SET, without the
//! outer SEQUENCE.  So `CN=Digium  Root` in a PrintableString matches
//! `cn=digium root` in a UTF8String.  A value that cannot be converted (a
//! UTF8String that is not valid UTF-8) makes the whole name, and so the
//! certificate, undecodable.

use super::asn1::{
    der_tlv, tag2bit, AStr, Dec, Item, Tmpl, Val, B_BMPSTRING, B_IA5STRING, B_PRINTABLE, B_PRINTABLESTRING,
    B_T61STRING, B_UNIVERSALSTRING, B_UTF8STRING, B_VISIBLESTRING, CLASS_UNIVERSAL, V_BIT_STRING, V_OBJECT,
    V_OTHER, V_SEQUENCE, V_SET, V_UTF8STRING,
};
use crate::errstack::{asn1 as e, Errs, LIB_ASN1, R_NESTED_ASN1_ERROR};

static OBJECT: Item = Item::Prim { utype: V_OBJECT, bignum: false };
static PRINTABLE: Item = Item::MString(B_PRINTABLE);
/// `X509_NAME_ENTRY`.
pub(crate) static NAME_ENTRY: Item = Item::Seq(&[Tmpl::new(&OBJECT), Tmpl::new(&PRINTABLE)]);
static NAME_ENTRIES: Item = Item::Template(&Tmpl::new(&NAME_ENTRY).set_of());
static NAME_INTERNAL: Item = Item::Template(&Tmpl::new(&NAME_ENTRIES).seq_of());

/// `ASN1_MASK_CANON`: the string types that are canonicalized.
const MASK_CANON: u32 =
    B_UTF8STRING | B_BMPSTRING | B_UNIVERSALSTRING | B_PRINTABLESTRING | B_T61STRING | B_IA5STRING | B_VISIBLESTRING;

/// One attribute of a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Index of the RDN (SET) the attribute is in.
    pub set: usize,
    /// The attribute type's OID content octets.
    pub oid: Vec<u8>,
    pub value: AStr,
}

/// A decoded name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Name {
    pub entries: Vec<Entry>,
    /// The encoding as it came.
    pub der: Vec<u8>,
    /// The canonical encoding (`canon_enc`); empty for a name without
    /// attributes.
    pub canon: Vec<u8>,
}

impl Name {
    /// `X509_NAME_cmp(a, b) == 0`.
    pub fn eq_canon(&self, other: &Name) -> bool {
        self.canon == other.canon
    }

    /// Build a name from entries (`X509_NAME_add_entry` and the re-encode
    /// `i2d_X509_NAME` does), as `DIST_POINT_set_dpname` does.
    pub fn from_entries(entries: Vec<Entry>, errs: &mut Errs) -> Option<Name> {
        let canon = canon(&entries, errs)?;
        Some(Name { entries, der: Vec::new(), canon })
    }
}

/// `x509_name_ex_d2i`.
pub(crate) fn d2i(d: &mut Dec, pos: &mut usize, len: usize, tag: i64, aclass: u8, opt: bool) -> Result<Option<Val>, ()> {
    let len = len.min(1024 * 1024);
    let q = *pos;
    let mut p = *pos;
    // ASN1_item_ex_d2i starts a new nesting count.
    let internal = match d.item_d2i(&NAME_INTERNAL, &mut p, len, tag, aclass, opt, 0)? {
        None => return Ok(None),
        Some(v) => v,
    };
    let mut entries = Vec::new();
    for (i, rdn) in internal.as_list().iter().enumerate() {
        for ent in rdn.as_list() {
            let oid = ent.field(0).and_then(Val::as_obj).unwrap_or_default().to_vec();
            let Some(value) = ent.field(1).and_then(Val::as_str).cloned() else {
                return Err(());
            };
            entries.push(Entry { set: i, oid, value });
        }
    }
    let Some(canon) = canon(&entries, d.errs) else {
        d.errs.put(LIB_ASN1, e::F_X509_NAME_EX_D2I, R_NESTED_ASN1_ERROR, "crypto/x509/x_name.c", 206);
        return Err(());
    };
    let der = d.buf[q..p].to_vec();
    *pos = p;
    Ok(Some(Val::Name(Name { entries, der, canon })))
}

/// `x509_name_canon`: None when a value cannot be canonicalized.
fn canon(entries: &[Entry], errs: &mut Errs) -> Option<Vec<u8>> {
    if entries.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut set: Option<usize> = None;
    let mut group: Vec<Vec<u8>> = Vec::new();
    for ent in entries {
        if set != Some(ent.set) {
            if set.is_some() {
                out.extend(der_set_of(std::mem::take(&mut group)));
            }
            set = Some(ent.set);
        }
        let value = string_canon(&ent.value, errs)?;
        let mut content = der_tlv(false, CLASS_UNIVERSAL, V_OBJECT as u32, &ent.oid);
        content.extend(i2d_string(&value));
        group.push(der_tlv(true, CLASS_UNIVERSAL, V_SEQUENCE as u32, &content));
    }
    out.extend(der_set_of(group));
    Some(out)
}

/// DER of a SET OF: the elements sorted by their encodings (`der_cmp`).
fn der_set_of(mut elems: Vec<Vec<u8>>) -> Vec<u8> {
    elems.sort();
    der_tlv(true, CLASS_UNIVERSAL, V_SET as u32, &elems.concat())
}

/// The DER an `ASN1_PRINTABLE` value is written as.
pub(crate) fn i2d_string(s: &AStr) -> Vec<u8> {
    if s.ty == V_SEQUENCE || s.ty == V_SET || s.ty == V_OTHER {
        return s.data.clone();
    }
    if s.ty == V_BIT_STRING {
        // i2c_ASN1_BIT_STRING keeps the decoded unused-bits count, except
        // that an empty string has none.
        let bits = if s.data.is_empty() { 0 } else { s.bits_left };
        let mut c = vec![bits];
        c.extend_from_slice(&s.data);
        return der_tlv(false, CLASS_UNIVERSAL, V_BIT_STRING as u32, &c);
    }
    der_tlv(false, CLASS_UNIVERSAL, s.ty as u32, &s.data)
}

/// `asn1_string_canon`.
fn string_canon(s: &AStr, errs: &mut Errs) -> Option<AStr> {
    if tag2bit(i64::from(s.ty)) & MASK_CANON == 0 {
        return Some(s.clone());
    }
    let utf8 = to_utf8(s, errs)?;
    // ossl_isspace: space, \t, \n, \v, \f, \r.
    let space = |c: u8| c == b' ' || (0x09..=0x0d).contains(&c);
    let mut from: &[u8] = &utf8;
    while let Some((&c, rest)) = from.split_first() {
        if !space(c) {
            break;
        }
        from = rest;
    }
    while let Some((&c, rest)) = from.split_last() {
        if !space(c) {
            break;
        }
        from = rest;
    }
    let mut out = Vec::with_capacity(from.len());
    let mut i = 0;
    while i < from.len() {
        let c = from[i];
        if c >= 0x80 {
            out.push(c);
            i += 1;
        } else if space(c) {
            out.push(b' ');
            while i < from.len() && space(from[i]) {
                i += 1;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            i += 1;
        }
    }
    Some(AStr { ty: V_UTF8STRING, data: out, bits_left: 0 })
}

/// `ASN1_STRING_to_UTF8`; None (with 1.1.1t's error recorded) when the
/// value cannot be converted.
pub(crate) fn to_utf8(s: &AStr, errs: &mut Errs) -> Option<Vec<u8>> {
    // tag2nbyte: how each string type is read.
    enum Form {
        Utf8,
        Asc,
        Bmp,
        Univ,
    }
    let form = match s.ty {
        12 => Form::Utf8,
        18 | 19 | 20 | 22 | 23 | 24 | 26 => Form::Asc,
        28 => Form::Univ,
        30 => Form::Bmp,
        _ => return None,
    };
    let fail = |errs: &mut Errs, r, line| {
        errs.put(LIB_ASN1, e::F_ASN1_MBSTRING_NCOPY, r, "crypto/asn1/a_mbstr.c", line);
        None
    };
    let d = &s.data;
    let mut out = Vec::with_capacity(d.len());
    match form {
        Form::Utf8 => {
            let mut p = 0;
            while p < d.len() {
                match utf8_getc(&d[p..]) {
                    Some((_, n)) => p += n,
                    None => return fail(errs, e::R_INVALID_UTF8STRING, 85),
                }
            }
            out.extend_from_slice(d);
        }
        Form::Asc => d.iter().for_each(|&c| utf8_putc(&mut out, u32::from(c))),
        Form::Bmp => {
            if d.len() & 1 != 0 {
                return fail(errs, e::R_INVALID_BMPSTRING_LENGTH, 64);
            }
            d.chunks(2).for_each(|c| utf8_putc(&mut out, u32::from(c[0]) << 8 | u32::from(c[1])));
        }
        Form::Univ => {
            if d.len() & 3 != 0 {
                return fail(errs, e::R_INVALID_UNIVERSALSTRING_LENGTH, 73);
            }
            d.chunks(4).for_each(|c| utf8_putc(&mut out, u32::from_be_bytes([c[0], c[1], c[2], c[3]])));
        }
    }
    Some(out)
}

/// `UTF8_getc`: one character (value and length), or None for invalid
/// UTF-8 (1.1.1t accepts the old 5- and 6-octet forms and surrogates, and
/// rejects overlong forms).
fn utf8_getc(s: &[u8]) -> Option<(u32, usize)> {
    let c = s[0];
    let (n, init, min) = match c {
        _ if c & 0x80 == 0 => return Some((u32::from(c), 1)),
        _ if c & 0xe0 == 0xc0 => (2, u32::from(c & 0x1f), 0x80),
        _ if c & 0xf0 == 0xe0 => (3, u32::from(c & 0x0f), 0x800),
        _ if c & 0xf8 == 0xf0 => (4, u32::from(c & 0x07), 0x10000),
        _ if c & 0xfc == 0xf8 => (5, u32::from(c & 0x03), 0x200000),
        _ if c & 0xfe == 0xfc => (6, u32::from(c & 0x01), 0x4000000),
        _ => return None,
    };
    if s.len() < n || s[1..n].iter().any(|&b| b & 0xc0 != 0x80) {
        return None;
    }
    let v = s[1..n].iter().fold(init, |v, &b| (v << 6) | u32::from(b & 0x3f));
    (v >= min).then_some((v, n))
}

/// `UTF8_putc` (up to six octets; the top bit of a 32-bit value is lost,
/// as in 1.1.1t).
pub(crate) fn utf8_putc(out: &mut Vec<u8>, v: u32) {
    let (n, lead): (u32, u8) = match v {
        0..=0x7f => {
            out.push(v as u8);
            return;
        }
        0x80..=0x7ff => (2, 0xc0),
        0x800..=0xffff => (3, 0xe0),
        0x10000..=0x1fffff => (4, 0xf0),
        0x200000..=0x3ffffff => (5, 0xf8),
        _ => (6, 0xfc),
    };
    let lead_bits = [0, 0, 0x1f, 0x0f, 0x07, 0x03, 0x01][n as usize];
    out.push(lead | ((v >> (6 * (n - 1))) & lead_bits) as u8);
    for i in (0..n - 1).rev() {
        out.push(0x80 | ((v >> (6 * i)) & 0x3f) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::super::asn1::{d2i as item_d2i, der_tlv};
    use super::*;

    static NAME: Item = Item::Name;

    /// A name of (set, oid, tag, value) attributes.
    fn name(attrs: &[(usize, &[u8], u8, &[u8])]) -> Vec<u8> {
        let mut sets: Vec<Vec<u8>> = Vec::new();
        for (set, oid, tag, value) in attrs {
            let mut c = der_tlv(false, 0, 6, oid);
            c.extend(der_tlv(false, 0, u32::from(*tag), value));
            if sets.len() <= *set {
                sets.push(Vec::new());
            }
            sets[*set].extend(der_tlv(true, 0, 16, &c));
        }
        let rdns: Vec<u8> = sets.iter().flat_map(|s| der_tlv(true, 0, 17, s)).collect();
        der_tlv(true, 0, 16, &rdns)
    }

    fn decode(der: &[u8]) -> Option<Name> {
        match item_d2i(der, &NAME, &mut Errs::new()) {
            Some(Val::Name(n)) => Some(n),
            _ => None,
        }
    }

    const CN: &[u8] = &[0x55, 0x04, 0x03];
    const O: &[u8] = &[0x55, 0x04, 0x0a];

    #[test]
    fn canonical_comparison() {
        let a = decode(&name(&[(0, CN, 19, b"  Digium   Root ")])).unwrap();
        let b = decode(&name(&[(0, CN, 12, b"digium root")])).unwrap();
        assert!(a.eq_canon(&b));
        let bmp: Vec<u8> = "DIGIUM ROOT".encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        let c = decode(&name(&[(0, CN, 30, &bmp)])).unwrap();
        assert!(a.eq_canon(&c));
        // NumericString is not canonicalized; a different attribute type
        // or order differs.
        let n1 = decode(&name(&[(0, CN, 18, b"1 2")])).unwrap();
        let n2 = decode(&name(&[(0, CN, 18, b"1  2")])).unwrap();
        assert!(!n1.eq_canon(&n2));
        let d = decode(&name(&[(0, O, 19, b"Digium Root")])).unwrap();
        assert!(!a.eq_canon(&d));
        // Multi-valued RDNs compare regardless of their order.
        let m1 = decode(&name(&[(0, CN, 19, b"x"), (0, O, 19, b"y")])).unwrap();
        let m2 = decode(&name(&[(0, O, 19, b"Y"), (0, CN, 12, b"X")])).unwrap();
        assert!(m1.eq_canon(&m2));
        let s1 = decode(&name(&[(0, CN, 19, b"x"), (1, O, 19, b"y")])).unwrap();
        assert!(!m1.eq_canon(&s1));
        // Latin-1 in a T61String equals the same text in UTF-8.
        let t = decode(&name(&[(0, CN, 20, b"Jos\xe9")])).unwrap();
        let u = decode(&name(&[(0, CN, 12, "jos\u{e9}".as_bytes())])).unwrap();
        assert!(t.eq_canon(&u));
        // An empty name equals another empty name.
        let e1 = decode(&[0x30, 0x00]).unwrap();
        let e2 = decode(&[0x30, 0x02, 0x31, 0x00]).unwrap();
        assert!(e1.canon.is_empty() && e1.eq_canon(&e2));
    }

    #[test]
    fn rejected_values() {
        // Invalid UTF-8 (overlong) in a UTF8String.
        assert!(decode(&name(&[(0, CN, 12, b"\xc0\x80")])).is_none());
        let mut errs = Errs::new();
        assert!(item_d2i(&name(&[(0, CN, 12, b"\xff")]), &NAME, &mut errs).is_none());
        assert_eq!(
            crate::errstack::error_string(errs.peek()),
            "error:0D07A086:asn1 encoding routines:ASN1_mbstring_ncopy:invalid utf8string"
        );
        // A BMPString of odd length, a tag outside the mask, a value that
        // is not universal.
        assert!(decode(&name(&[(0, CN, 30, b"abc")])).is_none());
        assert!(decode(&name(&[(0, CN, 2, b"\x01")])).is_none());
        let mut bad = name(&[(0, CN, 19, b"x")]);
        let n = bad.len();
        bad[n - 3] = 0x80;
        assert!(decode(&bad).is_none());
        // Accepted: 5-octet UTF-8, surrogates, SEQUENCE and BIT STRING
        // values, an unknown universal type.
        assert!(decode(&name(&[(0, CN, 12, b"\xf8\x88\x80\x80\x80")])).is_some());
        assert!(decode(&name(&[(0, CN, 12, b"\xed\xa0\x80")])).is_some());
        assert!(decode(&name(&[(0, CN, 3, b"\x00\x01")])).is_some());
        assert!(decode(&name(&[(0, CN, 9, b"\x01")])).is_some());
    }

    #[test]
    fn utf8_round_trip() {
        for v in [0u32, 0x7f, 0x80, 0x7ff, 0x800, 0xffff, 0x10000, 0x1fffff, 0x200000, 0x3ffffff, 0x4000000, 0x7fffffff] {
            let mut out = Vec::new();
            utf8_putc(&mut out, v);
            assert_eq!(utf8_getc(&out), Some((v, out.len())), "{:x}", v);
        }
    }
}
