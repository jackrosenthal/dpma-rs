//! The template decoder of OpenSSL 1.1.1t (`crypto/asn1/tasn_dec.c`), for
//! the templates the certificate code needs.
//!
//! 1.1.1t decodes BER, not only DER: lengths may be indefinite or use more
//! octets than needed, strings may be constructed, booleans may hold any
//! non-zero octet, and the parts it does not interpret (an ANY that is a
//! SEQUENCE, an x400Address) are kept as they came.  It also checks some
//! things DER decoders often do not: that an OPTIONAL ANY is the last field
//! of its SEQUENCE, that a multi-string's tag is in its mask, the padding
//! of INTEGERs, the unused-bits octet of BIT STRINGs, the encoding of
//! OBJECT IDENTIFIERs, and the lengths of NULL, BOOLEAN, BMPString, and
//! UniversalString contents.  This decoder takes the same paths in the
//! same order and records the same errors (see [`crate::errstack`]), so it
//! accepts and rejects exactly what 1.1.1t's `d2i` functions do and its
//! first error is the one 1.1.1t reports.
//!
//! The only part left out is the decoder's cache of the last header read
//! (`ASN1_TLC`), which saves work but changes no result.

use super::name::{self, Name};
use crate::errstack::{asn1 as e, Errs, LIB_ASN1, R_NESTED_ASN1_ERROR};

const TASN_DEC: &str = "crypto/asn1/tasn_dec.c";

pub(crate) const V_BOOLEAN: i32 = 1;
pub(crate) const V_INTEGER: i32 = 2;
pub(crate) const V_BIT_STRING: i32 = 3;
pub(crate) const V_OCTET_STRING: i32 = 4;
pub(crate) const V_NULL: i32 = 5;
pub(crate) const V_OBJECT: i32 = 6;
pub(crate) const V_ENUMERATED: i32 = 10;
pub(crate) const V_UTF8STRING: i32 = 12;
pub(crate) const V_SEQUENCE: i32 = 16;
pub(crate) const V_SET: i32 = 17;
pub(crate) const V_IA5STRING: i32 = 22;
pub(crate) const V_UTCTIME: i32 = 23;
pub(crate) const V_GENERALIZEDTIME: i32 = 24;
pub(crate) const V_UNIVERSALSTRING: i32 = 28;
pub(crate) const V_BMPSTRING: i32 = 30;
/// `V_ASN1_OTHER`: an ANY whose tag is not of the universal class.
pub(crate) const V_OTHER: i32 = -3;
/// `V_ASN1_ANY`.
pub(crate) const V_ANY: i32 = -4;

pub(crate) const CLASS_UNIVERSAL: u8 = 0x00;
pub(crate) const CLASS_CONTEXT: u8 = 0x80;

pub(crate) const B_NUMERICSTRING: u32 = 0x0001;
pub(crate) const B_PRINTABLESTRING: u32 = 0x0002;
pub(crate) const B_T61STRING: u32 = 0x0004;
pub(crate) const B_VIDEOTEXSTRING: u32 = 0x0008;
pub(crate) const B_IA5STRING: u32 = 0x0010;
pub(crate) const B_GRAPHICSTRING: u32 = 0x0020;
pub(crate) const B_VISIBLESTRING: u32 = 0x0040;
pub(crate) const B_GENERALSTRING: u32 = 0x0080;
pub(crate) const B_UNIVERSALSTRING: u32 = 0x0100;
pub(crate) const B_OCTET_STRING: u32 = 0x0200;
pub(crate) const B_BIT_STRING: u32 = 0x0400;
pub(crate) const B_BMPSTRING: u32 = 0x0800;
pub(crate) const B_UNKNOWN: u32 = 0x1000;
pub(crate) const B_UTF8STRING: u32 = 0x2000;
pub(crate) const B_UTCTIME: u32 = 0x4000;
pub(crate) const B_GENERALIZEDTIME: u32 = 0x8000;
pub(crate) const B_SEQUENCE: u32 = 0x10000;

/// `B_ASN1_PRINTABLE`, the mask of `ASN1_PRINTABLE` (name attribute values).
pub(crate) const B_PRINTABLE: u32 = B_NUMERICSTRING
    | B_PRINTABLESTRING
    | B_T61STRING
    | B_IA5STRING
    | B_BIT_STRING
    | B_UNIVERSALSTRING
    | B_BMPSTRING
    | B_UTF8STRING
    | B_SEQUENCE
    | B_UNKNOWN;
/// `B_ASN1_TIME`.
pub(crate) const B_TIME: u32 = B_UTCTIME | B_GENERALIZEDTIME;
/// `B_ASN1_DIRECTORYSTRING`.
pub(crate) const B_DIRECTORYSTRING: u32 =
    B_PRINTABLESTRING | B_T61STRING | B_BMPSTRING | B_UNIVERSALSTRING | B_UTF8STRING;

/// `ASN1_tag2bit`.
pub(crate) fn tag2bit(tag: i64) -> u32 {
    const TABLE: [u32; 31] = [
        0,
        0,
        0,
        B_BIT_STRING,
        B_OCTET_STRING,
        0,
        0,
        B_UNKNOWN,
        B_UNKNOWN,
        B_UNKNOWN,
        B_UNKNOWN,
        B_UNKNOWN,
        B_UTF8STRING,
        B_UNKNOWN,
        B_UNKNOWN,
        B_UNKNOWN,
        B_SEQUENCE,
        0,
        B_NUMERICSTRING,
        B_PRINTABLESTRING,
        B_T61STRING,
        B_VIDEOTEXSTRING,
        B_IA5STRING,
        B_UTCTIME,
        B_GENERALIZEDTIME,
        B_GRAPHICSTRING,
        B_VISIBLESTRING,
        B_GENERALSTRING,
        B_UNIVERSALSTRING,
        B_UNKNOWN,
        B_BMPSTRING,
    ];
    usize::try_from(tag).ok().and_then(|t| TABLE.get(t).copied()).unwrap_or(0)
}

/// An `ASN1_ITEM`.
pub(crate) enum Item {
    /// A primitive type (`utype` is a `V_ASN1_*` tag, or [`V_ANY`]).
    /// `bignum` is the `BIGNUM` type (`x_bignum.c`), whose content is
    /// taken as an unsigned magnitude without further checks.
    Prim { utype: i32, bignum: bool },
    /// A multi-string (`ASN1_ITYPE_MSTRING`) with its `B_ASN1_*` mask.
    MString(u32),
    /// A SEQUENCE.
    Seq(&'static [Tmpl]),
    /// A CHOICE.
    Choice(&'static [Tmpl]),
    /// An item that is one template (`ASN1_ITEM_TEMPLATE`).
    Template(&'static Tmpl),
    /// `X509_NAME` (`x509_name_ex_d2i`).
    Name,
}

/// How a template is tagged (always context-specific here).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tag {
    None,
    Implicit(u32),
    Explicit(u32),
}

/// SET OF and SEQUENCE OF.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sk {
    None,
    SeqOf,
    SetOf,
}

/// An `ASN1_TEMPLATE`.
pub(crate) struct Tmpl {
    pub opt: bool,
    pub sk: Sk,
    pub tag: Tag,
    pub item: &'static Item,
}

impl Tmpl {
    pub const fn new(item: &'static Item) -> Tmpl {
        Tmpl { opt: false, sk: Sk::None, tag: Tag::None, item }
    }
    pub const fn opt(self) -> Tmpl {
        Tmpl { opt: true, ..self }
    }
    pub const fn imp(self, t: u32) -> Tmpl {
        Tmpl { tag: Tag::Implicit(t), ..self }
    }
    pub const fn exp(self, t: u32) -> Tmpl {
        Tmpl { tag: Tag::Explicit(t), ..self }
    }
    pub const fn seq_of(self) -> Tmpl {
        Tmpl { sk: Sk::SeqOf, ..self }
    }
    pub const fn set_of(self) -> Tmpl {
        Tmpl { sk: Sk::SetOf, ..self }
    }
}

/// An `ASN1_STRING` as decoded: `ty` is the type (`V_ASN1_*`; for
/// SEQUENCE, SET, and [`V_OTHER`] the data is the whole encoding), and
/// `bits_left` is the unused-bits count of a BIT STRING
/// (`ASN1_STRING_FLAG_BITS_LEFT`), whose last data octet has those bits
/// cleared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AStr {
    pub ty: i32,
    pub data: Vec<u8>,
    pub bits_left: u8,
}

/// An `ASN1_INTEGER` or `ASN1_ENUMERATED`: its sign and magnitude (big
/// endian, as `c2i_ibuf` stores it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AInt {
    pub neg: bool,
    pub mag: Vec<u8>,
}

impl AInt {
    /// `ASN1_INTEGER_get`: the value as a `long`, or -1 when it does not
    /// fit (1.1.1t's error result).
    pub fn get(&self) -> i64 {
        let mag: &[u8] = &self.mag;
        if mag.len() > 8 {
            return -1;
        }
        let r = mag.iter().fold(0u64, |r, &b| (r << 8) | u64::from(b));
        if self.neg {
            if r <= i64::MAX as u64 {
                -(r as i64)
            } else if r == 1u64 << 63 {
                i64::MIN
            } else {
                -1
            }
        } else if r <= i64::MAX as u64 {
            r as i64
        } else {
            -1
        }
    }

    /// `strtoll(BN_bn2dec(ASN1_INTEGER_to_BN(...)))`: the value, saturated
    /// to the `long long` range as `strtoll` saturates.
    pub fn to_i64_saturating(&self) -> i64 {
        let mut mag: &[u8] = &self.mag;
        while mag.first() == Some(&0) {
            mag = &mag[1..];
        }
        if mag.len() > 8 {
            return if self.neg { i64::MIN } else { i64::MAX };
        }
        let r = mag.iter().fold(0u64, |r, &b| (r << 8) | u64::from(b));
        match (self.neg, r) {
            (false, r) if r > i64::MAX as u64 => i64::MAX,
            (false, r) => r as i64,
            (true, r) if r >= 1u64 << 63 => i64::MIN,
            (true, r) => -(r as i64),
        }
    }
}

/// A decoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Val {
    Str(AStr),
    Int(AInt),
    /// A `BIGNUM`'s content octets.
    Bn(Vec<u8>),
    /// An OBJECT IDENTIFIER's content octets.
    Obj(Vec<u8>),
    /// A BOOLEAN's content octet (`ASN1_BOOLEAN` keeps it as it came).
    Bool(u8),
    Null,
    /// An ANY: its type and value (`ASN1_TYPE`).
    Any(i32, Box<Val>),
    /// A SEQUENCE: its fields (None when an OPTIONAL one is absent) and the
    /// range of the input it was decoded from (`asn1_enc_save`).
    Seq(Vec<Option<Val>>, (usize, usize)),
    /// SET OF and SEQUENCE OF.
    List(Vec<Val>),
    /// A CHOICE: the alternative and its value.
    Choice(usize, Box<Val>),
    Name(Name),
}

impl Val {
    pub fn field(&self, i: usize) -> Option<&Val> {
        match self {
            Val::Seq(f, _) => f.get(i).and_then(|v| v.as_ref()),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&AStr> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<&AInt> {
        match self {
            Val::Int(i) => Some(i),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&[u8]> {
        match self {
            Val::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn as_list(&self) -> &[Val] {
        match self {
            Val::List(l) => l,
            _ => &[],
        }
    }
    pub fn span(&self) -> Option<(usize, usize)> {
        match self {
            Val::Seq(_, s) => Some(*s),
            _ => None,
        }
    }
}

/// A header read by `asn1_check_tlen`.
struct Hdr {
    /// Content length (for the indefinite form, what is left of the data).
    len: usize,
    tag: i64,
    class: u8,
    inf: bool,
    cst: bool,
}

type Res<T> = Result<T, ()>;

/// `ASN1_item_d2i(NULL, &p, len, it)`: decode one `item` from the start of
/// `buf`.  Trailing data is not an error (1.1.1t does not look at it).
/// Spans in the result are offsets into `buf`.
pub(crate) fn d2i(buf: &[u8], item: &Item, errs: &mut Errs) -> Option<Val> {
    let mut d = Dec { buf, errs };
    let mut pos = 0;
    match d.item_d2i(item, &mut pos, buf.len(), -1, 0, false, 0) {
        Ok(Some(v)) => Some(v),
        _ => None,
    }
}

pub(crate) struct Dec<'a, 'e> {
    pub buf: &'a [u8],
    pub errs: &'e mut Errs,
}

impl Dec<'_, '_> {
    fn err(&mut self, func: u32, reason: u32, line: u32) {
        self.errs.put(LIB_ASN1, func, reason, TASN_DEC, line);
    }

    /// `asn1_item_embed_d2i`.  Ok(None) is 1.1.1t's -1 (an absent
    /// OPTIONAL item), Err its 0.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn item_d2i(
        &mut self,
        item: &Item,
        pos: &mut usize,
        len: usize,
        tag: i64,
        aclass: u8,
        opt: bool,
        depth: u32,
    ) -> Res<Option<Val>> {
        let depth = depth + 1;
        if depth > 30 {
            self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_NESTED_TOO_DEEP, 160);
            return Err(());
        }
        match item {
            Item::Template(tt) => {
                if tag != -1 || opt {
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE, 174);
                    return Err(());
                }
                self.template_ex_d2i(tt, pos, len, opt, depth)
            }
            Item::Prim { .. } => self.prim_d2i(item, pos, len, tag, aclass, opt),
            Item::MString(mask) => {
                if tag != -1 {
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_BAD_TEMPLATE, 190);
                    return Err(());
                }
                let mut p = *pos;
                let hdr = match self.check_tlen(&mut p, len, -1, 0, true) {
                    Ok(Some(h)) => h,
                    _ => {
                        self.err(e::F_ASN1_ITEM_EMBED_D2I, R_NESTED_ASN1_ERROR, 199);
                        return Err(());
                    }
                };
                if hdr.class != CLASS_UNIVERSAL {
                    if opt {
                        return Ok(None);
                    }
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_MSTRING_NOT_UNIVERSAL, 208);
                    return Err(());
                }
                if tag2bit(hdr.tag) & mask == 0 {
                    if opt {
                        return Ok(None);
                    }
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_MSTRING_WRONG_TAG, 217);
                    return Err(());
                }
                self.prim_d2i(item, pos, len, hdr.tag, 0, false)
            }
            Item::Name => name::d2i(self, pos, len, tag, aclass, opt),
            Item::Choice(alts) => {
                if tag != -1 {
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_BAD_TEMPLATE, 233);
                    return Err(());
                }
                let mut p = *pos;
                for (i, tt) in alts.iter().enumerate() {
                    match self.template_ex_d2i(tt, &mut p, len, true, depth) {
                        Ok(None) => continue,
                        Ok(Some(v)) => {
                            *pos = p;
                            return Ok(Some(Val::Choice(i, Box::new(v))));
                        }
                        Err(()) => {
                            self.err(e::F_ASN1_ITEM_EMBED_D2I, R_NESTED_ASN1_ERROR, 272);
                            return Err(());
                        }
                    }
                }
                if opt {
                    return Ok(None);
                }
                self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_NO_MATCHING_CHOICE_TYPE, 284);
                Err(())
            }
            Item::Seq(fields) => {
                let mut p = *pos;
                let (tag, aclass) = if tag == -1 { (i64::from(V_SEQUENCE), CLASS_UNIVERSAL) } else { (tag, aclass) };
                let hdr = match self.check_tlen(&mut p, len, tag, aclass, opt) {
                    Err(()) => {
                        self.err(e::F_ASN1_ITEM_EMBED_D2I, R_NESTED_ASN1_ERROR, 309);
                        return Err(());
                    }
                    Ok(None) => return Ok(None),
                    Ok(Some(h)) => h,
                };
                let mut len = hdr.len;
                let mut seq_eoc = hdr.inf;
                let seq_nolen = seq_eoc;
                if !hdr.cst {
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_SEQUENCE_NOT_CONSTRUCTED, 321);
                    return Err(());
                }
                let mut out: Vec<Option<Val>> = vec![None; fields.len()];
                let mut i = 0;
                while i < fields.len() {
                    let tt = &fields[i];
                    if len == 0 {
                        break;
                    }
                    let q = p;
                    if self.check_eoc(&mut p, len) {
                        if !seq_eoc {
                            self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_UNEXPECTED_EOC, 360);
                            return Err(());
                        }
                        len -= p - q;
                        seq_eoc = false;
                        break;
                    }
                    // The last field cannot be omitted while data is left.
                    let isopt = if i == fields.len() - 1 { false } else { tt.opt };
                    match self.template_ex_d2i(tt, &mut p, len, isopt, depth)? {
                        None => {}
                        Some(v) => {
                            out[i] = Some(v);
                            len -= p - q;
                        }
                    }
                    i += 1;
                }
                if seq_eoc && !self.check_eoc(&mut p, len) {
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_MISSING_EOC, 400);
                    return Err(());
                }
                if !seq_nolen && len != 0 {
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_SEQUENCE_LENGTH_MISMATCH, 405);
                    return Err(());
                }
                if fields[i..].iter().any(|tt| !tt.opt) {
                    self.err(e::F_ASN1_ITEM_EMBED_D2I, e::R_FIELD_MISSING, 425);
                    return Err(());
                }
                let span = (*pos, p);
                *pos = p;
                Ok(Some(Val::Seq(out, span)))
            }
        }
    }

    /// `asn1_template_ex_d2i`: the EXPLICIT tag, if any.
    fn template_ex_d2i(&mut self, tt: &Tmpl, pos: &mut usize, inlen: usize, opt: bool, depth: u32) -> Res<Option<Val>> {
        let Tag::Explicit(t) = tt.tag else {
            return self.template_noexp_d2i(tt, pos, inlen, opt, depth);
        };
        let mut p = *pos;
        let hdr = match self.check_tlen(&mut p, inlen, i64::from(t), CLASS_CONTEXT, opt) {
            Err(()) => {
                self.err(e::F_ASN1_TEMPLATE_EX_D2I, R_NESTED_ASN1_ERROR, 484);
                return Err(());
            }
            Ok(None) => return Ok(None),
            Ok(Some(h)) => h,
        };
        let q = p;
        if !hdr.cst {
            self.err(e::F_ASN1_TEMPLATE_EX_D2I, e::R_EXPLICIT_TAG_NOT_CONSTRUCTED, 489);
            return Err(());
        }
        let v = match self.template_noexp_d2i(tt, &mut p, hdr.len, false, depth) {
            Err(()) => {
                self.err(e::F_ASN1_TEMPLATE_EX_D2I, R_NESTED_ASN1_ERROR, 496);
                return Err(());
            }
            Ok(v) => v,
        };
        let len = hdr.len - (p - q);
        if hdr.inf {
            if !self.check_eoc(&mut p, len) {
                self.err(e::F_ASN1_TEMPLATE_EX_D2I, e::R_MISSING_EOC, 504);
                return Err(());
            }
        } else if len != 0 {
            self.err(e::F_ASN1_TEMPLATE_EX_D2I, e::R_EXPLICIT_LENGTH_MISMATCH, 512);
            return Err(());
        }
        *pos = p;
        Ok(v)
    }

    /// `asn1_template_noexp_d2i`: SET OF, SEQUENCE OF, IMPLICIT tags.
    fn template_noexp_d2i(&mut self, tt: &Tmpl, pos: &mut usize, len: usize, opt: bool, depth: u32) -> Res<Option<Val>> {
        let mut p = *pos;
        let v = if tt.sk != Sk::None {
            let (sktag, skclass) = match tt.tag {
                Tag::Implicit(t) => (i64::from(t), CLASS_CONTEXT),
                _ if tt.sk == Sk::SetOf => (i64::from(V_SET), CLASS_UNIVERSAL),
                _ => (i64::from(V_SEQUENCE), CLASS_UNIVERSAL),
            };
            let hdr = match self.check_tlen(&mut p, len, sktag, skclass, opt) {
                Err(()) => {
                    self.err(e::F_ASN1_TEMPLATE_NOEXP_D2I, R_NESTED_ASN1_ERROR, 572);
                    return Err(());
                }
                Ok(None) => return Ok(None),
                Ok(Some(h)) => h,
            };
            let mut len = hdr.len;
            let mut sk_eoc = hdr.inf;
            let mut items = Vec::new();
            while len > 0 {
                let q = p;
                if self.check_eoc(&mut p, len) {
                    if !sk_eoc {
                        self.err(e::F_ASN1_TEMPLATE_NOEXP_D2I, e::R_UNEXPECTED_EOC, 602);
                        return Err(());
                    }
                    sk_eoc = false;
                    break;
                }
                match self.item_d2i(tt.item, &mut p, len, -1, 0, false, depth) {
                    Ok(Some(v)) => items.push(v),
                    _ => {
                        self.err(e::F_ASN1_TEMPLATE_NOEXP_D2I, R_NESTED_ASN1_ERROR, 614);
                        return Err(());
                    }
                }
                len -= p - q;
            }
            if sk_eoc {
                self.err(e::F_ASN1_TEMPLATE_NOEXP_D2I, e::R_MISSING_EOC, 628);
                return Err(());
            }
            Val::List(items)
        } else {
            let (tag, class, line) = match tt.tag {
                Tag::Implicit(t) => (i64::from(t), CLASS_CONTEXT, 637),
                _ => (-1, 0, 646),
            };
            match self.item_d2i(tt.item, &mut p, len, tag, class, opt, depth) {
                Err(()) => {
                    self.err(e::F_ASN1_TEMPLATE_NOEXP_D2I, R_NESTED_ASN1_ERROR, line);
                    return Err(());
                }
                Ok(None) => return Ok(None),
                Ok(Some(v)) => v,
            }
        };
        *pos = p;
        Ok(Some(v))
    }

    /// `asn1_d2i_ex_primitive`.
    fn prim_d2i(&mut self, item: &Item, pos: &mut usize, inlen: usize, tag: i64, aclass: u8, opt: bool) -> Res<Option<Val>> {
        let (mut utype, mut tag, mut aclass) = match item {
            Item::MString(_) => (tag, -1, aclass),
            Item::Prim { utype, .. } => (i64::from(*utype), tag, aclass),
            _ => return Err(()),
        };
        if utype == i64::from(V_ANY) {
            if tag >= 0 {
                self.err(e::F_ASN1_D2I_EX_PRIMITIVE, e::R_ILLEGAL_TAGGED_ANY, 686);
                return Err(());
            }
            if opt {
                self.err(e::F_ASN1_D2I_EX_PRIMITIVE, e::R_ILLEGAL_OPTIONAL_ANY, 690);
                return Err(());
            }
            let mut p = *pos;
            let hdr = match self.check_tlen(&mut p, inlen, -1, 0, false) {
                Ok(Some(h)) => h,
                _ => {
                    self.err(e::F_ASN1_D2I_EX_PRIMITIVE, R_NESTED_ASN1_ERROR, 698);
                    return Err(());
                }
            };
            utype = if hdr.class != CLASS_UNIVERSAL { i64::from(V_OTHER) } else { hdr.tag };
        }
        if tag == -1 {
            tag = utype;
            aclass = CLASS_UNIVERSAL;
        }
        let mut p = *pos;
        let hdr = match self.check_tlen(&mut p, inlen, tag, aclass, opt) {
            Err(()) => {
                self.err(e::F_ASN1_D2I_EX_PRIMITIVE, R_NESTED_ASN1_ERROR, 713);
                return Err(());
            }
            Ok(None) => return Ok(None),
            Ok(Some(h)) => h,
        };
        let cont: Vec<u8>;
        if utype == i64::from(V_SEQUENCE) || utype == i64::from(V_SET) || utype == i64::from(V_OTHER) {
            // Kept in encoded form, header included.
            if utype != i64::from(V_OTHER) && !hdr.cst {
                self.err(e::F_ASN1_D2I_EX_PRIMITIVE, e::R_TYPE_NOT_CONSTRUCTED, 730);
                return Err(());
            }
            let start = *pos;
            if hdr.inf {
                self.find_end(&mut p, hdr.len, true)?;
            } else {
                p += hdr.len;
            }
            cont = self.buf[start..p].to_vec();
        } else if hdr.cst {
            if [V_NULL, V_BOOLEAN, V_OBJECT, V_INTEGER, V_ENUMERATED].iter().any(|&t| i64::from(t) == utype) {
                self.err(e::F_ASN1_D2I_EX_PRIMITIVE, e::R_TYPE_NOT_PRIMITIVE, 749);
                return Err(());
            }
            let mut b = Vec::new();
            self.collect(&mut b, &mut p, hdr.len, hdr.inf, 0)?;
            cont = b;
        } else {
            cont = self.buf[p..p + hdr.len].to_vec();
            p += hdr.len;
        }
        let v = self.ex_c2i(cont, utype, item)?;
        *pos = p;
        Ok(Some(v))
    }

    /// `asn1_ex_c2i`.
    fn ex_c2i(&mut self, cont: Vec<u8>, utype: i64, item: &Item) -> Res<Val> {
        if let Item::Prim { bignum: true, .. } = item {
            return Ok(Val::Bn(cont));
        }
        let any = matches!(item, Item::Prim { utype: V_ANY, .. });
        let Ok(ty) = i32::try_from(utype) else {
            // Universal tags that do not fit an int cannot be read by
            // ASN1_get_object.
            return Err(());
        };
        let v = match ty {
            V_OBJECT => Val::Obj(c2i_object(self.errs, cont)?),
            V_NULL => {
                if !cont.is_empty() {
                    self.err(e::F_ASN1_EX_C2I, e::R_NULL_IS_WRONG_LENGTH, 829);
                    return Err(());
                }
                Val::Null
            }
            V_BOOLEAN => {
                if cont.len() != 1 {
                    self.err(e::F_ASN1_EX_C2I, e::R_BOOLEAN_IS_WRONG_LENGTH, 837);
                    return Err(());
                }
                Val::Bool(cont[0])
            }
            V_BIT_STRING => Val::Str(c2i_bit_string(self.errs, &cont)?),
            V_INTEGER | V_ENUMERATED => Val::Int(c2i_integer(self.errs, &cont)?),
            _ => {
                if ty == V_BMPSTRING && cont.len() & 1 != 0 {
                    self.err(e::F_ASN1_EX_C2I, e::R_BMPSTRING_IS_WRONG_LENGTH, 879);
                    return Err(());
                }
                if ty == V_UNIVERSALSTRING && cont.len() & 3 != 0 {
                    self.err(e::F_ASN1_EX_C2I, e::R_UNIVERSALSTRING_IS_WRONG_LENGTH, 883);
                    return Err(());
                }
                Val::Str(AStr { ty, data: cont, bits_left: 0 })
            }
        };
        Ok(if any { Val::Any(ty, Box::new(v)) } else { v })
    }

    /// `asn1_find_end`.
    fn find_end(&mut self, pos: &mut usize, mut len: usize, inf: bool) -> Res<()> {
        if !inf {
            *pos += len;
            return Ok(());
        }
        let mut expected_eoc: u32 = 1;
        let mut p = *pos;
        while len > 0 {
            if self.check_eoc(&mut p, len) {
                expected_eoc -= 1;
                if expected_eoc == 0 {
                    break;
                }
                len -= 2;
                continue;
            }
            let q = p;
            let hdr = match self.check_tlen(&mut p, len, -1, 0, false) {
                Ok(Some(h)) => h,
                _ => {
                    self.err(e::F_ASN1_FIND_END, R_NESTED_ASN1_ERROR, 965);
                    return Err(());
                }
            };
            if hdr.inf {
                if expected_eoc == u32::MAX {
                    self.err(e::F_ASN1_FIND_END, R_NESTED_ASN1_ERROR, 970);
                    return Err(());
                }
                expected_eoc += 1;
            } else {
                p += hdr.len;
            }
            len -= p - q;
        }
        if expected_eoc != 0 {
            self.err(e::F_ASN1_FIND_END, e::R_MISSING_EOC, 980);
            return Err(());
        }
        *pos = p;
        Ok(())
    }

    /// `asn1_collect`: the content of a constructed string.  The inner
    /// tags are not checked (1.1.1t passes -1 for them).
    fn collect(&mut self, out: &mut Vec<u8>, pos: &mut usize, mut len: usize, inf: bool, depth: u32) -> Res<()> {
        let mut p = *pos;
        let mut inf = inf;
        while len > 0 {
            let q = p;
            if self.check_eoc(&mut p, len) {
                if !inf {
                    self.err(e::F_ASN1_COLLECT, e::R_UNEXPECTED_EOC, 1027);
                    return Err(());
                }
                inf = false;
                break;
            }
            let hdr = match self.check_tlen(&mut p, len, -1, CLASS_UNIVERSAL, false) {
                Ok(Some(h)) => h,
                _ => {
                    self.err(e::F_ASN1_COLLECT, R_NESTED_ASN1_ERROR, 1036);
                    return Err(());
                }
            };
            if hdr.cst {
                if depth >= 5 {
                    self.err(e::F_ASN1_COLLECT, e::R_NESTED_ASN1_STRING, 1043);
                    return Err(());
                }
                self.collect(out, &mut p, hdr.len, hdr.inf, depth + 1)?;
            } else if hdr.len > 0 {
                out.extend_from_slice(&self.buf[p..p + hdr.len]);
                p += hdr.len;
            }
            len -= p - q;
        }
        if inf {
            self.err(e::F_ASN1_COLLECT, e::R_MISSING_EOC, 1053);
            return Err(());
        }
        *pos = p;
        Ok(())
    }

    /// `asn1_check_eoc`.
    fn check_eoc(&self, p: &mut usize, len: usize) -> bool {
        if len < 2 {
            return false;
        }
        if self.buf[*p] == 0 && self.buf[*p + 1] == 0 {
            *p += 2;
            return true;
        }
        false
    }

    /// `asn1_check_tlen`: read a header and, when `exptag` is not -1, check
    /// its tag and class (Ok(None) when they differ and `opt` is set).
    fn check_tlen(&mut self, p: &mut usize, len: usize, exptag: i64, expclass: u8, opt: bool) -> Res<Option<Hdr>> {
        let q = *p;
        let mut pp = *p;
        let (ret, plen, ptag, pclass) = self.get_object(&mut pp, len);
        if ret & 0x80 != 0 {
            self.err(e::F_ASN1_CHECK_TLEN, e::R_BAD_OBJECT_HEADER, 1137);
            return Err(());
        }
        if exptag >= 0 && (exptag != ptag || expclass != pclass) {
            if opt {
                return Ok(None);
            }
            self.err(e::F_ASN1_CHECK_TLEN, e::R_WRONG_TAG, 1149);
            return Err(());
        }
        let inf = ret & 1 != 0;
        let plen = if inf { len - (pp - q) } else { plen };
        *p = pp;
        Ok(Some(Hdr { len: plen, tag: ptag, class: pclass, inf, cst: ret & 0x20 != 0 }))
    }

    /// `ASN1_get_object` (with `asn1_get_length`): returns 1.1.1t's flags
    /// (0x20 constructed, 0x01 indefinite, 0x80 error), the length, the
    /// tag, and the class.
    fn get_object(&mut self, pos: &mut usize, omax: usize) -> (u32, usize, i64, u8) {
        let b = self.buf;
        let start = *pos;
        let mut p = start;
        let mut max = omax;
        let fail = |s: &mut Self| {
            s.errs.put(LIB_ASN1, e::F_ASN1_GET_OBJECT, e::R_HEADER_TOO_LONG, "crypto/asn1/asn1_lib.c", 101);
            (0x80, 0, 0, 0)
        };
        if max == 0 {
            return fail(self);
        }
        let ret = u32::from(b[p] & 0x20);
        let class = b[p] & 0xc0;
        let low = b[p] & 0x1f;
        let tag: i64;
        if low == 0x1f {
            p += 1;
            max -= 1;
            if max == 0 {
                return fail(self);
            }
            let mut l: i64 = 0;
            while b[p] & 0x80 != 0 {
                l = (l << 7) | i64::from(b[p] & 0x7f);
                p += 1;
                max -= 1;
                if max == 0 {
                    return fail(self);
                }
                if l > i64::from(i32::MAX >> 7) {
                    return fail(self);
                }
            }
            l = (l << 7) | i64::from(b[p] & 0x7f);
            p += 1;
            tag = l;
            max -= 1;
            if max == 0 {
                return fail(self);
            }
        } else {
            tag = i64::from(low);
            p += 1;
            max -= 1;
            if max == 0 {
                return fail(self);
            }
        }
        // asn1_get_length
        if max < 1 {
            return fail(self);
        }
        max -= 1;
        let inf;
        let length: u64;
        if b[p] == 0x80 {
            inf = 1;
            p += 1;
            length = 0;
        } else {
            inf = 0;
            let mut i = usize::from(b[p] & 0x7f);
            let long_form = b[p] & 0x80 != 0;
            p += 1;
            if long_form {
                if max < i + 1 {
                    return fail(self);
                }
                while i > 0 && b[p] == 0 {
                    p += 1;
                    i -= 1;
                }
                if i > 8 {
                    return fail(self);
                }
                let mut r: u64 = 0;
                while i > 0 {
                    r = (r << 8) | u64::from(b[p]);
                    p += 1;
                    i -= 1;
                }
                if r > i64::MAX as u64 {
                    return fail(self);
                }
                length = r;
            } else {
                length = i as u64;
            }
        }
        if inf != 0 && ret & 0x20 == 0 {
            return fail(self);
        }
        let mut ret = ret;
        let avail = (omax - (p - start)) as u64;
        let mut plen = length as usize;
        if length > avail {
            self.errs.put(LIB_ASN1, e::F_ASN1_GET_OBJECT, e::R_TOO_LONG, "crypto/asn1/asn1_lib.c", 91);
            ret |= 0x80;
            plen = 0;
        }
        *pos = p;
        (ret | inf, plen, tag, class)
    }
}

/// `c2i_ASN1_OBJECT`: content octets of an OBJECT IDENTIFIER.
pub(crate) fn c2i_object(errs: &mut Errs, cont: Vec<u8>) -> Res<Vec<u8>> {
    if cont.is_empty() || cont[cont.len() - 1] & 0x80 != 0 {
        errs.put(LIB_ASN1, e::F_C2I_ASN1_OBJECT, e::R_INVALID_OBJECT_ENCODING, "crypto/asn1/a_object.c", 254);
        return Err(());
    }
    for i in 0..cont.len() {
        if cont[i] == 0x80 && (i == 0 || cont[i - 1] & 0x80 == 0) {
            errs.put(LIB_ASN1, e::F_C2I_ASN1_OBJECT, e::R_INVALID_OBJECT_ENCODING, "crypto/asn1/a_object.c", 284);
            return Err(());
        }
    }
    Ok(cont)
}

/// `c2i_ASN1_BIT_STRING`.
pub(crate) fn c2i_bit_string(errs: &mut Errs, cont: &[u8]) -> Res<AStr> {
    let fail = |errs: &mut Errs, r| {
        errs.put(LIB_ASN1, e::F_C2I_ASN1_BIT_STRING, r, "crypto/asn1/a_bitstr.c", 137);
        Err(())
    };
    if cont.is_empty() {
        return fail(errs, e::R_STRING_TOO_SHORT);
    }
    if cont.len() > i32::MAX as usize {
        return fail(errs, e::R_STRING_TOO_LONG);
    }
    let bits = cont[0];
    if bits > 7 {
        return fail(errs, e::R_INVALID_BIT_STRING_BITS_LEFT);
    }
    let mut data = cont[1..].to_vec();
    if let Some(last) = data.last_mut() {
        *last &= 0xffu8 << bits;
    }
    Ok(AStr { ty: V_BIT_STRING, data, bits_left: bits })
}

/// `c2i_ASN1_INTEGER` (`c2i_ibuf`): reject empty content and redundant
/// padding; keep the sign and the magnitude.
pub(crate) fn c2i_integer(errs: &mut Errs, p: &[u8]) -> Res<AInt> {
    if p.is_empty() {
        errs.put(LIB_ASN1, e::F_C2I_IBUF, e::R_ILLEGAL_ZERO_CONTENT, "crypto/asn1/a_int.c", 154);
        return Err(());
    }
    let neg = p[0] & 0x80 != 0;
    if p.len() == 1 {
        let m = if neg { (p[0] ^ 0xff).wrapping_add(1) } else { p[0] };
        return Ok(AInt { neg, mag: vec![m] });
    }
    let pad = if p[0] == 0 {
        true
    } else if p[0] == 0xff {
        // "One less minimal negative": padded only if any other octet is
        // non-zero.
        p[1..].iter().any(|&b| b != 0)
    } else {
        false
    };
    if pad && neg == (p[1] & 0x80 != 0) {
        errs.put(LIB_ASN1, e::F_C2I_IBUF, e::R_ILLEGAL_PADDING, "crypto/asn1/a_int.c", 187);
        return Err(());
    }
    let src = if pad { &p[1..] } else { p };
    let mag = if neg {
        // ~value + 1
        let mut out = vec![0u8; src.len()];
        let mut carry: u32 = 1;
        for i in (0..src.len()).rev() {
            carry += u32::from(src[i] ^ 0xff);
            out[i] = carry as u8;
            carry >>= 8;
        }
        out
    } else {
        src.to_vec()
    };
    Ok(AInt { neg, mag })
}

/// Minimal DER of a header (`ASN1_put_object` with a definite length).
pub(crate) fn der_header(out: &mut Vec<u8>, constructed: bool, class: u8, tag: u32, len: usize) {
    let c = if constructed { 0x20 } else { 0 } | (class & 0xc0);
    if tag < 31 {
        out.push(c | tag as u8);
    } else {
        out.push(c | 0x1f);
        let mut groups = Vec::new();
        let mut t = tag;
        while t > 0 {
            groups.push((t & 0x7f) as u8);
            t >>= 7;
        }
        for (i, g) in groups.iter().enumerate().rev() {
            out.push(if i > 0 { g | 0x80 } else { *g });
        }
    }
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// A DER TLV.
pub(crate) fn der_tlv(constructed: bool, class: u8, tag: u32, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    der_header(&mut out, constructed, class, tag, content.len());
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errstack::error_string;

    static INTEGER: Item = Item::Prim { utype: V_INTEGER, bignum: false };
    static OBJECT: Item = Item::Prim { utype: V_OBJECT, bignum: false };
    static ANY: Item = Item::Prim { utype: V_ANY, bignum: false };
    static OCTETS: Item = Item::Prim { utype: V_OCTET_STRING, bignum: false };
    static PAIR: Item = Item::Seq(&[Tmpl::new(&OBJECT), Tmpl::new(&ANY).opt()]);
    static EXPLICIT: Item = Item::Seq(&[Tmpl::new(&INTEGER).exp(0).opt(), Tmpl::new(&INTEGER)]);

    fn first_error(buf: &[u8], item: &Item) -> String {
        let mut errs = Errs::new();
        assert!(d2i(buf, item, &mut errs).is_none());
        error_string(errs.peek())
    }

    #[test]
    fn integers() {
        let mut errs = Errs::new();
        for (enc, neg, mag) in [
            (&[0x00][..], false, &[0x00][..]),
            (&[0x7f], false, &[0x7f]),
            (&[0x00, 0x80], false, &[0x80]),
            (&[0xff], true, &[0x01]),
            (&[0x80], true, &[0x80]),
            (&[0xff, 0x00], true, &[0x01, 0x00]),
            (&[0xff, 0x7f], true, &[0x81]),
        ] {
            let i = c2i_integer(&mut errs, enc).unwrap();
            assert_eq!((i.neg, &i.mag[..]), (neg, mag), "{:02x?}", enc);
        }
        assert!(errs.0.is_empty());
        assert!(c2i_integer(&mut errs, &[0x00, 0x7f]).is_err());
        assert!(c2i_integer(&mut errs, &[0xff, 0x80]).is_err());
        assert!(c2i_integer(&mut errs, &[]).is_err());
        assert_eq!(error_string(errs.get()), "error:0D0E20DD:asn1 encoding routines:c2i_ibuf:illegal padding");
        assert_eq!(AInt { neg: true, mag: vec![5] }.get(), -5);
        assert_eq!(AInt { neg: false, mag: vec![1; 9] }.get(), -1);
        assert_eq!(AInt { neg: false, mag: vec![1; 9] }.to_i64_saturating(), i64::MAX);
        assert_eq!(AInt { neg: true, mag: vec![1; 9] }.to_i64_saturating(), i64::MIN);
    }

    #[test]
    fn ber_forms_accepted() {
        // Long-form length with leading zero octets, and the indefinite
        // form with an end-of-contents marker.
        let v = d2i(&[0x30, 0x82, 0x00, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04], &PAIR, &mut Errs::new()).unwrap();
        assert_eq!(v.field(0).unwrap().as_obj().unwrap(), &[0x2a, 0x03, 0x04]);
        assert!(v.field(1).is_none());
        let v = d2i(&[0x30, 0x80, 0x06, 0x01, 0x2a, 0x05, 0x00, 0x00, 0x00], &PAIR, &mut Errs::new()).unwrap();
        assert_eq!(v.field(1), Some(&Val::Any(V_NULL, Box::new(Val::Null))));
        // A constructed OCTET STRING is collected.
        let v = d2i(&[0x24, 0x80, 0x04, 0x01, 0x61, 0x04, 0x02, 0x62, 0x63, 0x00, 0x00], &OCTETS, &mut Errs::new()).unwrap();
        assert_eq!(v.as_str().unwrap().data, b"abc");
        // Trailing data after the item is ignored.
        assert!(d2i(&[0x02, 0x01, 0x05, 0xff, 0xff], &INTEGER, &mut Errs::new()).is_some());
    }

    #[test]
    fn first_errors() {
        assert_eq!(first_error(&[0, 0, 0], &PAIR), "error:0D0680A8:asn1 encoding routines:asn1_check_tlen:wrong tag");
        assert_eq!(first_error(&[0x30, 0x05, 0x06], &PAIR), "error:0D07209B:asn1 encoding routines:ASN1_get_object:too long");
        assert_eq!(first_error(&[0x30], &PAIR), "error:0D07207B:asn1 encoding routines:ASN1_get_object:header too long");
        // The 1.1.1t quirk: a long-form length must leave one more octet.
        assert_eq!(first_error(&[0x04, 0x81, 0x00], &OCTETS), "error:0D07207B:asn1 encoding routines:ASN1_get_object:header too long");
        assert!(d2i(&[0x04, 0x81, 0x00, 0x00], &OCTETS, &mut Errs::new()).is_some());
        assert_eq!(
            first_error(&[0x30, 0x05, 0x06, 0x01, 0x2a, 0x05, 0x01], &PAIR),
            "error:0D07209B:asn1 encoding routines:ASN1_get_object:too long"
        );
        assert_eq!(
            first_error(&[0x30, 0x06, 0x06, 0x01, 0x2a, 0x05, 0x01, 0x00], &PAIR),
            "error:0D0CC090:asn1 encoding routines:asn1_ex_c2i:null is wrong length"
        );
        assert_eq!(
            first_error(&[0x30, 0x04, 0x06, 0x02, 0x80, 0x01], &PAIR),
            "error:0D0C40D8:asn1 encoding routines:c2i_ASN1_OBJECT:invalid object encoding"
        );
        assert_eq!(
            first_error(&[0x30, 0x05, 0x06, 0x01, 0x2a, 0x00, 0x00], &PAIR),
            "error:0D07809F:asn1 encoding routines:asn1_item_embed_d2i:unexpected eoc"
        );
        assert_eq!(
            first_error(&[0x30, 0x06, 0x06, 0x01, 0x2a, 0x05, 0x00, 0x05], &PAIR),
            "error:0D078094:asn1 encoding routines:asn1_item_embed_d2i:sequence length mismatch"
        );
        // A primitive SEQUENCE tag matches, then fails the constructed check.
        assert_eq!(
            first_error(&[0x10, 0x00], &PAIR),
            "error:0D078095:asn1 encoding routines:asn1_item_embed_d2i:sequence not constructed"
        );
        assert_eq!(
            first_error(&[0xa0, 0x03, 0x02, 0x01, 0x01], &EXPLICIT),
            "error:0D0680A8:asn1 encoding routines:asn1_check_tlen:wrong tag"
        );
        assert_eq!(
            first_error(&[0x30, 0x08, 0xa0, 0x04, 0x02, 0x01, 0x01, 0x00, 0x02, 0x01, 0x01], &EXPLICIT),
            "error:0D084077:asn1 encoding routines:asn1_template_ex_d2i:explicit length mismatch"
        );
        assert_eq!(
            first_error(&[0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x01], &EXPLICIT),
            "error:0D078079:asn1 encoding routines:asn1_item_embed_d2i:field missing"
        );
        // Without the OPTIONAL first field, the last one is read.
        assert!(d2i(&[0x30, 0x03, 0x02, 0x01, 0x01], &EXPLICIT, &mut Errs::new()).is_some());
    }

    #[test]
    fn der_helpers() {
        assert_eq!(der_tlv(false, 0, 2, &[5]), [2, 1, 5]);
        assert_eq!(der_tlv(true, 0, 16, &[0; 200])[..3], [0x30, 0x81, 200]);
        assert_eq!(der_tlv(true, 0x80, 31, &[])[..], [0xbf, 0x1f, 0]);
    }
}
