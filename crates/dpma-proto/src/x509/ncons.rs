//! Name constraints as OpenSSL 1.1.1t checks them
//! (`crypto/x509v3/v3_ncons.c`): `NAME_CONSTRAINTS_check` and
//! `NAME_CONSTRAINTS_check_CN`.

use super::asn1::{AStr, V_IA5STRING};
use super::ext::{GenName, GenValue, NameConstraints, Subtree, GEN_DIRNAME, GEN_DNS, GEN_EMAIL, GEN_IPADD, GEN_URI};
use super::name::{self, Name};
use super::verify::{
    X509_V_ERR_EXCLUDED_VIOLATION, X509_V_ERR_OUT_OF_MEM, X509_V_ERR_PERMITTED_VIOLATION, X509_V_ERR_SUBTREE_MINMAX,
    X509_V_ERR_UNSPECIFIED, X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE, X509_V_ERR_UNSUPPORTED_NAME_SYNTAX, X509_V_OK,
};
use super::Certificate;
use crate::errstack::Errs;

/// pkcs9 emailAddress (1.2.840.113549.1.9.1).
const OID_EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
/// commonName (2.5.4.3).
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// Does the certificate have a dNSName in its subjectAltName?
pub(crate) fn has_dns_san(x: &Certificate) -> bool {
    x.ex.altname.as_ref().is_some_and(|a| a.iter().any(|g| g.kind == GEN_DNS))
}

/// `NAME_CONSTRAINTS_check`: the subject (as a directoryName and its
/// emailAddress attributes) and every subjectAltName entry.
pub(crate) fn check(x: &Certificate, nc: &NameConstraints) -> i32 {
    let nm = &x.subject;
    let names = nm.entries.len() + x.ex.altname.as_ref().map(Vec::len).unwrap_or(0);
    let constraints = nc.permitted.len() + nc.excluded.len();
    if names > 0 && constraints > (1 << 20) / names {
        return X509_V_ERR_UNSPECIFIED;
    }
    if !nm.entries.is_empty() {
        let r = nc_match(&GenName { kind: GEN_DIRNAME, value: GenValue::DirName(nm.clone()) }, nc);
        if r != X509_V_OK {
            return r;
        }
        for e in nm.entries.iter().filter(|e| e.oid == OID_EMAIL_ADDRESS) {
            if e.value.ty != V_IA5STRING {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            }
            let r = nc_match(&GenName { kind: GEN_EMAIL, value: GenValue::Str(e.value.clone()) }, nc);
            if r != X509_V_OK {
                return r;
            }
        }
    }
    for g in x.ex.altname.iter().flatten() {
        let r = nc_match(g, nc);
        if r != X509_V_OK {
            return r;
        }
    }
    X509_V_OK
}

/// `NAME_CONSTRAINTS_check_CN`: commonNames that look like host names are
/// checked as dNSNames.
pub(crate) fn check_cn(x: &Certificate, nc: &NameConstraints) -> i32 {
    for e in x.subject.entries.iter().filter(|e| e.oid == OID_COMMON_NAME) {
        let id = match cn2dnsid(&e.value) {
            Ok(id) => id,
            Err(r) => return r,
        };
        if id.is_empty() {
            continue;
        }
        let dns = AStr { ty: V_IA5STRING, data: id, bits_left: 0 };
        let r = nc_match(&GenName { kind: GEN_DNS, value: GenValue::Str(dns) }, nc);
        if r != X509_V_OK {
            return r;
        }
    }
    X509_V_OK
}

/// `cn2dnsid`: the commonName as a DNS name if it looks like one (two or
/// more labels), else empty.
fn cn2dnsid(cn: &AStr) -> Result<Vec<u8>, i32> {
    let Some(mut v) = name::to_utf8(cn, &mut Errs::new()) else {
        return Err(X509_V_ERR_OUT_OF_MEM);
    };
    while v.last() == Some(&0) {
        v.pop();
    }
    if v.contains(&0) {
        return Err(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
    }
    let n = v.len();
    let mut isdnsname = false;
    for i in 0..n {
        let c = v[i];
        if c.is_ascii_alphanumeric() || c == b'_' {
            continue;
        }
        if i > 0 && i < n - 1 {
            if c == b'-' {
                continue;
            }
            if c == b'.' && v[i + 1] != b'.' && v[i - 1] != b'-' && v[i + 1] != b'-' {
                isdnsname = true;
                continue;
            }
        }
        isdnsname = false;
        break;
    }
    Ok(if isdnsname { v } else { Vec::new() })
}

/// `nc_match`.
fn nc_match(gen: &GenName, nc: &NameConstraints) -> i32 {
    let mut matched = 0;
    for sub in nc.permitted.iter().filter(|s: &&Subtree| s.base.kind == gen.kind) {
        if sub.minmax {
            return X509_V_ERR_SUBTREE_MINMAX;
        }
        if matched == 2 {
            continue;
        }
        if matched == 0 {
            matched = 1;
        }
        match match_single(gen, &sub.base) {
            X509_V_OK => matched = 2,
            X509_V_ERR_PERMITTED_VIOLATION => {}
            r => return r,
        }
    }
    if matched == 1 {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    for sub in nc.excluded.iter().filter(|s: &&Subtree| s.base.kind == gen.kind) {
        if sub.minmax {
            return X509_V_ERR_SUBTREE_MINMAX;
        }
        match match_single(gen, &sub.base) {
            X509_V_OK => return X509_V_ERR_EXCLUDED_VIOLATION,
            X509_V_ERR_PERMITTED_VIOLATION => {}
            r => return r,
        }
    }
    X509_V_OK
}

/// `nc_match_single`.
fn match_single(gen: &GenName, base: &GenName) -> i32 {
    match (&gen.value, &base.value) {
        (GenValue::DirName(n), GenValue::DirName(b)) if base.kind == GEN_DIRNAME => nc_dn(n, b),
        (GenValue::Str(g), GenValue::Str(b)) => match base.kind {
            GEN_DNS => nc_dns(&g.data, &b.data),
            GEN_EMAIL => nc_email(&g.data, &b.data),
            GEN_URI => nc_uri(&g.data, &b.data),
            GEN_IPADD => nc_ip(&g.data, &b.data),
            _ => X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
        },
        _ => X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
    }
}

/// `ia5ncasecmp(a, b, n) == 0`.
fn ia5_eq_ic(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

/// `nc_dn`: the subtree's canonical encoding is a prefix of the name's.
fn nc_dn(nm: &Name, base: &Name) -> i32 {
    if nm.canon.starts_with(&base.canon) {
        X509_V_OK
    } else {
        X509_V_ERR_PERMITTED_VIOLATION
    }
}

/// `nc_dns`.
fn nc_dns(dns: &[u8], base: &[u8]) -> i32 {
    if base.is_empty() {
        return X509_V_OK;
    }
    if dns.len() < base.len() {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    let off = dns.len() - base.len();
    if off > 0 && base[0] != b'.' && dns[off - 1] != b'.' {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    if !ia5_eq_ic(base, &dns[off..]) {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    X509_V_OK
}

/// `nc_email`.
fn nc_email(eml: &[u8], base: &[u8]) -> i32 {
    let Some(emlat) = eml.iter().rposition(|&c| c == b'@') else {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    };
    let baseat = base.iter().rposition(|&c| c == b'@');
    // An initial '.' matches the right-hand side.
    if baseat.is_none() && base.first() == Some(&b'.') {
        if eml.len() > base.len() && ia5_eq_ic(base, &eml[eml.len() - base.len()..]) {
            return X509_V_OK;
        }
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    let mut basehost = base;
    if let Some(baseat) = baseat {
        if baseat != 0 {
            if baseat != emlat {
                return X509_V_ERR_PERMITTED_VIOLATION;
            }
            if base[..baseat].contains(&0) || eml[..emlat].contains(&0) {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            }
            // The local part is case sensitive.
            if base[..baseat] != eml[..emlat] {
                return X509_V_ERR_PERMITTED_VIOLATION;
            }
        }
        basehost = &base[baseat + 1..];
    }
    if !ia5_eq_ic(basehost, &eml[emlat + 1..]) {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    X509_V_OK
}

/// `nc_uri`.
fn nc_uri(uri: &[u8], base: &[u8]) -> i32 {
    let Some(p) = uri.iter().position(|&c| c == b':') else {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    };
    if uri.len() - p < 3 || uri[p + 1] != b'/' || uri[p + 2] != b'/' {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    let host = &uri[p + 3..];
    let hostlen = host
        .iter()
        .position(|&c| c == b':')
        .or_else(|| host.iter().position(|&c| c == b'/'))
        .unwrap_or(host.len());
    if hostlen == 0 {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    let host = &host[..hostlen];
    if base.first() == Some(&b'.') {
        if hostlen > base.len() && ia5_eq_ic(&host[hostlen - base.len()..], base) {
            return X509_V_OK;
        }
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    if !ia5_eq_ic(host, base) {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    X509_V_OK
}

/// `nc_ip`.
fn nc_ip(ip: &[u8], base: &[u8]) -> i32 {
    if !(ip.len() == 4 || ip.len() == 16) || !(base.len() == 8 || base.len() == 32) {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    if ip.len() * 2 != base.len() {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    let mask = &base[ip.len()..];
    if ip.iter().zip(base).zip(mask).any(|((h, b), m)| h & m != b & m) {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    X509_V_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_rules() {
        assert_eq!(nc_dns(b"phone.example.com", b"example.com"), X509_V_OK);
        assert_eq!(nc_dns(b"phone.example.com", b".example.com"), X509_V_OK);
        assert_eq!(nc_dns(b"badexample.com", b"example.com"), X509_V_ERR_PERMITTED_VIOLATION);
        assert_eq!(nc_dns(b"EXAMPLE.COM", b"example.com"), X509_V_OK);
        assert_eq!(nc_email(b"a@Example.com", b"example.com"), X509_V_OK);
        assert_eq!(nc_email(b"a@x.example.com", b".example.com"), X509_V_OK);
        assert_eq!(nc_email(b"A@example.com", b"a@example.com"), X509_V_ERR_PERMITTED_VIOLATION);
        assert_eq!(nc_email(b"example.com", b"example.com"), X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
        assert_eq!(nc_uri(b"https://phone.example.com:443/x", b".example.com"), X509_V_OK);
        assert_eq!(nc_uri(b"https://example.com/x", b"example.com"), X509_V_OK);
        assert_eq!(nc_uri(b"example.com", b"example.com"), X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);
        assert_eq!(nc_ip(&[10, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]), X509_V_OK);
        assert_eq!(nc_ip(&[11, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]), X509_V_ERR_PERMITTED_VIOLATION);
        let cn = |s: &str| cn2dnsid(&AStr { ty: 12, data: s.as_bytes().to_vec(), bits_left: 0 });
        assert_eq!(cn("phone.example.com").unwrap(), b"phone.example.com");
        assert!(cn("000fd3000001").unwrap().is_empty());
        assert!(cn("a..b").unwrap().is_empty());
        assert_eq!(cn2dnsid(&AStr { ty: 3, data: vec![], bits_left: 0 }), Err(X509_V_ERR_OUT_OF_MEM));
    }
}
