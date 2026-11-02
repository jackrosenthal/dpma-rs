//! `X509_verify_cert` of OpenSSL 1.1.1t (`crypto/x509/x509_vfy.c`) as the
//! original calls it: a store built with `X509_STORE_add_cert` and no
//! flags, the default verification parameters (`X509_V_FLAG_TRUSTED_FIRST`,
//! depth 100, no purpose, the default trust, no security level), and the
//! verify callback FUN_00148210, which ignores
//! `X509_V_ERR_CERT_NOT_YET_VALID` and `X509_V_ERR_CERT_HAS_EXPIRED`.
//!
//! See [`crate::cert`] for the list of checks.

use super::ext::{
    EXFLAG_BCONS, EXFLAG_CA, EXFLAG_CRITICAL, EXFLAG_KUSAGE, EXFLAG_NSCERT, EXFLAG_PROXY, EXFLAG_SI, EXFLAG_SS,
    EXFLAG_V1, KU_DIGITAL_SIGNATURE, KU_KEY_CERT_SIGN, NS_ANY_CA,
};
use super::key::{self, Md, PublicKey};
use super::{asn1, ext, ncons, Certificate};

pub(crate) const X509_V_OK: i32 = 0;
pub(crate) const X509_V_ERR_UNSPECIFIED: i32 = 1;
pub(crate) const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: i32 = 2;
pub(crate) const X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: i32 = 6;
pub(crate) const X509_V_ERR_CERT_SIGNATURE_FAILURE: i32 = 7;
pub(crate) const X509_V_ERR_CERT_NOT_YET_VALID: i32 = 9;
pub(crate) const X509_V_ERR_CERT_HAS_EXPIRED: i32 = 10;
pub(crate) const X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: i32 = 13;
pub(crate) const X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: i32 = 14;
pub(crate) const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: i32 = 18;
pub(crate) const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: i32 = 19;
pub(crate) const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: i32 = 20;
pub(crate) const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: i32 = 21;
pub(crate) const X509_V_ERR_CERT_CHAIN_TOO_LONG: i32 = 22;
pub(crate) const X509_V_ERR_INVALID_CA: i32 = 24;
pub(crate) const X509_V_ERR_PATH_LENGTH_EXCEEDED: i32 = 25;
pub(crate) const X509_V_ERR_AKID_SKID_MISMATCH: i32 = 30;
pub(crate) const X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: i32 = 31;
pub(crate) const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: i32 = 32;
pub(crate) const X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: i32 = 34;
pub(crate) const X509_V_ERR_INVALID_NON_CA: i32 = 37;
pub(crate) const X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: i32 = 39;
pub(crate) const X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: i32 = 40;
pub(crate) const X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: i32 = 45;
pub(crate) const X509_V_ERR_PERMITTED_VIOLATION: i32 = 47;
pub(crate) const X509_V_ERR_EXCLUDED_VIOLATION: i32 = 48;
pub(crate) const X509_V_ERR_SUBTREE_MINMAX: i32 = 49;
pub(crate) const X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: i32 = 51;
pub(crate) const X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: i32 = 53;
pub(crate) const X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH: i32 = 76;
pub(crate) const X509_V_ERR_NO_ISSUER_PUBLIC_KEY: i32 = 77;
pub(crate) const X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM: i32 = 78;
/// `X509_V_ERR_OUT_OF_MEM`, which name constraint checking reports for a
/// commonName it cannot convert to UTF-8.
pub(crate) const X509_V_ERR_OUT_OF_MEM: i32 = 17;

/// The verification depth limit (`X509_VERIFY_PARAM` "default" depth 100;
/// chains are built up to one longer).
const DEPTH: usize = 101;

const S_DOUNTRUSTED: u32 = 1;
const S_DOTRUSTED: u32 = 2;
const S_DOALTERNATE: u32 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Trust {
    Trusted,
    Untrusted,
}

/// `X509_verify_cert_error_string`.
pub fn error_string(n: i32) -> &'static str {
    match n {
        0 => "ok",
        1 => "unspecified certificate verification error",
        2 => "unable to get issuer certificate",
        3 => "unable to get certificate CRL",
        4 => "unable to decrypt certificate's signature",
        5 => "unable to decrypt CRL's signature",
        6 => "unable to decode issuer public key",
        7 => "certificate signature failure",
        8 => "CRL signature failure",
        9 => "certificate is not yet valid",
        10 => "certificate has expired",
        11 => "CRL is not yet valid",
        12 => "CRL has expired",
        13 => "format error in certificate's notBefore field",
        14 => "format error in certificate's notAfter field",
        15 => "format error in CRL's lastUpdate field",
        16 => "format error in CRL's nextUpdate field",
        17 => "out of memory",
        18 => "self signed certificate",
        19 => "self signed certificate in certificate chain",
        20 => "unable to get local issuer certificate",
        21 => "unable to verify the first certificate",
        22 => "certificate chain too long",
        23 => "certificate revoked",
        24 => "invalid CA certificate",
        25 => "path length constraint exceeded",
        26 => "unsupported certificate purpose",
        27 => "certificate not trusted",
        28 => "certificate rejected",
        29 => "subject issuer mismatch",
        30 => "authority and subject key identifier mismatch",
        31 => "authority and issuer serial number mismatch",
        32 => "key usage does not include certificate signing",
        33 => "unable to get CRL issuer certificate",
        34 => "unhandled critical extension",
        35 => "key usage does not include CRL signing",
        36 => "unhandled critical CRL extension",
        37 => "invalid non-CA certificate (has CA markings)",
        38 => "proxy path length constraint exceeded",
        39 => "key usage does not include digital signature",
        40 => "proxy certificates not allowed, please set the appropriate flag",
        41 => "invalid or inconsistent certificate extension",
        42 => "invalid or inconsistent certificate policy extension",
        43 => "no explicit policy",
        44 => "Different CRL scope",
        45 => "Unsupported extension feature",
        46 => "RFC 3779 resource not subset of parent's resources",
        47 => "permitted subtree violation",
        48 => "excluded subtree violation",
        49 => "name constraints minimum and maximum not supported",
        50 => "application verification failure",
        51 => "unsupported name constraint type",
        52 => "unsupported or invalid name constraint syntax",
        53 => "unsupported or invalid name syntax",
        54 => "CRL path validation error",
        55 => "Path Loop",
        56 => "Suite B: certificate version invalid",
        57 => "Suite B: invalid public key algorithm",
        58 => "Suite B: invalid ECC curve",
        59 => "Suite B: invalid signature algorithm",
        60 => "Suite B: curve not allowed for this LOS",
        61 => "Suite B: cannot sign P-384 with P-256",
        62 => "Hostname mismatch",
        63 => "Email address mismatch",
        64 => "IP address mismatch",
        65 => "No matching DANE TLSA records",
        66 => "EE certificate key too weak",
        67 => "CA certificate key too weak",
        68 => "CA signature digest algorithm too weak",
        69 => "Invalid certificate verification context",
        70 => "Issuer certificate lookup error",
        71 => "Certificate Transparency required, but no valid SCTs found",
        72 => "proxy subject name violation",
        73 => "OCSP verification needed",
        74 => "OCSP verification failed",
        75 => "OCSP unknown cert",
        79 => "Certificate public key has explicit ECC parameters",
        _ => "unknown certificate verification error",
    }
}

/// `X509_cmp_time(t, now)`: -1 when `t` is at or before `now`, 1 when
/// after, 0 when it is not exactly `YYMMDDHHMMSSZ` (UTCTime) or
/// `YYYYMMDDHHMMSSZ` (GeneralizedTime) with valid field values.
pub(crate) fn cmp_time(t: &asn1::AStr, now: i64) -> i32 {
    match time_to_unix(t) {
        Some(s) if s <= now => -1,
        Some(_) => 1,
        None => 0,
    }
}

/// The time an `ASN1_TIME` that `X509_cmp_time` accepts stands for, in
/// seconds since the epoch (`asn1_time_to_tm`'s checks).
fn time_to_unix(t: &asn1::AStr) -> Option<i64> {
    let len = match t.ty {
        asn1::V_UTCTIME => 13,
        asn1::V_GENERALIZEDTIME => 15,
        _ => return None,
    };
    let d = &t.data;
    if d.len() != len || !d[..len - 1].iter().all(u8::is_ascii_digit) || d[len - 1] != b'Z' {
        return None;
    }
    let two = |i: usize| i64::from(d[i] - b'0') * 10 + i64::from(d[i + 1] - b'0');
    let (year, rest) = if t.ty == asn1::V_UTCTIME {
        let yy = two(0);
        (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
    } else {
        (two(0) * 100 + two(2), 4)
    };
    let (mon, day, hour, min, sec) = (two(rest), two(rest + 2), two(rest + 4), two(rest + 6), two(rest + 8));
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mon) || day < 1 || day > mdays[(mon - 1) as usize] || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    Some(days_from_civil(year, mon, day) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `x509_likely_issued(issuer, x) == X509_V_OK` (the store context's
/// `check_issued`).
pub(crate) fn check_issued(x: &Certificate, issuer: &Certificate) -> bool {
    if !issuer.subject.eq_canon(&x.issuer) || issuer.invalid() || x.invalid() {
        return false;
    }
    if x.ex.akid.is_some()
        && ext::check_akid(x.ex.akid.as_ref(), issuer.ex.skid.as_deref(), &issuer.serial, &issuer.issuer).is_err()
    {
        return false;
    }
    key::check_sig_alg_match(issuer.key.as_ref(), &x.tbs_alg.oid).is_ok()
}

/// `cert_self_signed`.
fn self_signed(x: &Certificate) -> bool {
    !x.invalid() && x.ex.flags & EXFLAG_SS != 0
}

/// `X509_check_ca` (`check_ca`): 0 not a CA, 1 a CA, 3 a self-signed v1
/// certificate without basicConstraints, 4 keyUsage with keyCertSign but
/// no basicConstraints, 5 a Netscape CA type.
pub(crate) fn check_ca(x: &Certificate) -> i32 {
    let f = x.ex.flags;
    if f & EXFLAG_KUSAGE != 0 && x.ex.kusage & KU_KEY_CERT_SIGN == 0 {
        return 0;
    }
    if f & EXFLAG_BCONS != 0 {
        return i32::from(f & EXFLAG_CA != 0);
    }
    if f & (EXFLAG_V1 | EXFLAG_SS) == EXFLAG_V1 | EXFLAG_SS {
        3
    } else if f & EXFLAG_KUSAGE != 0 {
        4
    } else if f & EXFLAG_NSCERT != 0 && x.ex.nscert & NS_ANY_CA != 0 {
        5
    } else {
        0
    }
}

/// `x509_check_cert_time(ctx, x, -1)`: is `x` valid now?
fn time_valid(x: &Certificate, now: i64) -> bool {
    cmp_time(&x.not_before, now) < 0 && cmp_time(&x.not_after, now) > 0
}

/// `X509_verify(x, key)`: the signature check of `internal_verify`.
pub(crate) fn x509_verify(x: &Certificate, key: &PublicKey) -> bool {
    if !x.sig_alg.same(&x.tbs_alg) || x.signature.bits_left & 7 != 0 {
        return false;
    }
    let Some(alg) = key::sig_alg(&x.sig_alg.oid) else { return false };
    if !matches!(alg.md, Md::Md5 | Md::Sha1 | Md::Sha224 | Md::Sha256 | Md::Sha384 | Md::Sha512) {
        // Unavailable in 1.1.1t, or not implemented here.
        return false;
    }
    // EVP_PKEY_type(pknid) must be the key's type: an RSA key, not an
    // RSASSA-PSS one.
    let PublicKey::Rsa(rsa) = key else { return false };
    if alg.pkey != key::NID_RSA {
        return false;
    }
    let Some(di) = key::digest_info(alg.md, x.tbs()) else { return false };
    rsa.verify_pkcs1(&di, &x.signature.data)
}

/// An `X509_STORE_CTX` during `X509_verify_cert`.
struct Ctx<'a> {
    store: &'a [Certificate],
    untrusted: Option<&'a [Certificate]>,
    chain: Vec<&'a Certificate>,
    num_untrusted: usize,
    /// `ctx->error`, which stays set after the callback ignores it.
    error: i32,
    now: i64,
}

impl<'a> Ctx<'a> {
    /// The original's verify callback (FUN_00148210).
    fn verify_cb(&self, ok: bool) -> bool {
        self.error == X509_V_ERR_CERT_NOT_YET_VALID || self.error == X509_V_ERR_CERT_HAS_EXPIRED || ok
    }

    /// `verify_cb_cert`.
    fn cb_cert(&mut self, err: i32) -> bool {
        if err != X509_V_OK {
            self.error = err;
        }
        self.verify_cb(false)
    }

    /// `X509_STORE_CTX_get1_issuer`: the first certificate in the store
    /// with `x`'s issuer as subject that issued `x` and is valid now, else
    /// the last that issued it.
    fn get_issuer(&self, x: &Certificate) -> Option<&'a Certificate> {
        let mut matches = self.store.iter().filter(|c| c.subject.eq_canon(&x.issuer));
        let first = matches.next()?;
        if check_issued(x, first) && time_valid(first, self.now) {
            return Some(first);
        }
        let mut issuer = None;
        for c in std::iter::once(first).chain(matches) {
            if check_issued(x, c) {
                issuer = Some(c);
                if time_valid(c, self.now) {
                    break;
                }
            }
        }
        issuer
    }

    /// `find_issuer` over the untrusted certificates.
    fn find_issuer(&self, sk: &[&'a Certificate], x: &Certificate) -> Option<&'a Certificate> {
        let mut rv = None;
        for &issuer in sk {
            let in_chain = self.chain.iter().any(|c| c.same(issuer));
            if check_issued(x, issuer) && ((x.ex.flags & EXFLAG_SI != 0 && self.chain.len() == 1) || !in_chain) {
                rv = Some(issuer);
                if time_valid(issuer, self.now) {
                    break;
                }
            }
        }
        rv
    }

    /// `check_trust`: a self-signed certificate from the store at or after
    /// `num_untrusted` is a trust anchor (`trust_compat`).
    fn check_trust(&self, num_untrusted: usize) -> Trust {
        if self.chain[num_untrusted.min(self.chain.len())..].iter().any(|c| self_signed(c)) {
            Trust::Trusted
        } else {
            Trust::Untrusted
        }
    }

    /// `build_chain`.
    fn build_chain(&mut self) -> bool {
        let mut ss = self_signed(self.chain[0]);
        let mut search = if self.untrusted.is_some() { S_DOUNTRUSTED } else { 0 };
        // X509_V_FLAG_TRUSTED_FIRST is set, so no alternate chains.
        search |= S_DOTRUSTED;
        let may_alternate = false;
        let mut sktmp: Vec<&'a Certificate> = self.untrusted.unwrap_or_default().iter().collect();
        let mut trust = Trust::Untrusted;
        let mut alt_untrusted = 0;
        while search != 0 {
            if search & S_DOTRUSTED != 0 {
                let mut num = self.chain.len();
                let i = if search & S_DOALTERNATE != 0 { alt_untrusted } else { num };
                let x = self.chain[i - 1];
                let found = if DEPTH < num { None } else { self.get_issuer(x) };
                if let Some(xtmp) = found {
                    if search & S_DOALTERNATE != 0 {
                        search &= !S_DOALTERNATE;
                        self.chain.truncate(i);
                        num = i;
                        self.num_untrusted = num;
                    }
                    let mut ok = true;
                    if !ss {
                        self.chain.push(xtmp);
                        ss = self_signed(xtmp);
                    } else if num == self.num_untrusted {
                        // A self-signed untrusted certificate must be in
                        // the store exactly.
                        if !x.same(xtmp) {
                            ok = false;
                        } else {
                            num -= 1;
                            self.num_untrusted = num;
                            self.chain[num] = xtmp;
                        }
                    }
                    if ok {
                        search &= !S_DOUNTRUSTED;
                        trust = self.check_trust(num);
                        if trust == Trust::Trusted {
                            break;
                        }
                        if !ss {
                            continue;
                        }
                    }
                }
                if search & S_DOUNTRUSTED == 0 {
                    if search & S_DOALTERNATE != 0 {
                        alt_untrusted -= 1;
                        if alt_untrusted > 0 {
                            continue;
                        }
                    }
                    if !may_alternate || search & S_DOALTERNATE != 0 || self.num_untrusted < 2 {
                        break;
                    }
                    search |= S_DOALTERNATE;
                    alt_untrusted = self.num_untrusted - 1;
                    ss = false;
                }
            }
            if search & S_DOUNTRUSTED != 0 {
                let num = self.chain.len();
                let x = self.chain[num - 1];
                let xtmp = if ss || DEPTH < num { None } else { self.find_issuer(&sktmp, x) };
                let Some(xtmp) = xtmp else {
                    search &= !S_DOUNTRUSTED;
                    search |= S_DOTRUSTED;
                    continue;
                };
                if let Some(pos) = sktmp.iter().position(|c| std::ptr::eq(*c, xtmp)) {
                    sktmp.remove(pos);
                }
                self.chain.push(xtmp);
                self.num_untrusted += 1;
                ss = self_signed(xtmp);
            }
        }
        let num = self.chain.len();
        if num <= DEPTH && trust == Trust::Untrusted && num == self.num_untrusted {
            trust = self.check_trust(num);
        }
        if trust == Trust::Trusted {
            return true;
        }
        let err = if num > DEPTH {
            X509_V_ERR_CERT_CHAIN_TOO_LONG
        } else if ss && self.chain.len() == 1 {
            X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        } else if ss {
            X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        } else if self.num_untrusted < num {
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
        } else {
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        };
        self.cb_cert(err)
    }

    /// `check_chain_extensions` (no purpose, proxy certificates not
    /// allowed, not strict).
    fn check_chain_extensions(&mut self) -> bool {
        let num = self.chain.len();
        let mut must_be_ca = -1;
        let mut plen: i64 = 0;
        for i in 0..num {
            let x = self.chain[i];
            if x.ex.flags & EXFLAG_CRITICAL != 0 && !self.cb_cert(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) {
                return false;
            }
            if x.ex.flags & EXFLAG_PROXY != 0 && !self.cb_cert(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED) {
                return false;
            }
            let ret = check_ca(x);
            let ok = match must_be_ca {
                -1 => true,
                0 => {
                    if ret != 0 {
                        self.error = X509_V_ERR_INVALID_NON_CA;
                        false
                    } else {
                        true
                    }
                }
                _ => {
                    // X509_V_FLAG_X509_STRICT is implicit for intermediate
                    // CAs: only the top of the chain may be a CA by a
                    // weaker test (v1 root, keyUsage, Netscape type).
                    if ret == 0 || (i + 1 < num && ret != 1) {
                        self.error = X509_V_ERR_INVALID_CA;
                        false
                    } else {
                        true
                    }
                }
            };
            if !ok && !self.cb_cert(X509_V_OK) {
                return false;
            }
            if i > 1 && x.ex.pathlen != -1 && plen > x.ex.pathlen && !self.cb_cert(X509_V_ERR_PATH_LENGTH_EXCEEDED) {
                return false;
            }
            if i > 0 && x.ex.flags & EXFLAG_SI == 0 {
                plen += 1;
            }
            must_be_ca = if x.ex.flags & EXFLAG_PROXY != 0 { 0 } else { 1 };
        }
        true
    }

    /// `x509_check_cert_time(ctx, x, depth)`.
    fn check_cert_time(&mut self, x: &Certificate) -> bool {
        let i = cmp_time(&x.not_before, self.now);
        if i == 0 && !self.cb_cert(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD) {
            return false;
        }
        if i > 0 && !self.cb_cert(X509_V_ERR_CERT_NOT_YET_VALID) {
            return false;
        }
        let i = cmp_time(&x.not_after, self.now);
        if i == 0 && !self.cb_cert(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD) {
            return false;
        }
        if i < 0 && !self.cb_cert(X509_V_ERR_CERT_HAS_EXPIRED) {
            return false;
        }
        true
    }

    /// `internal_verify`: signatures (not of a self-signed top) and times
    /// (of every certificate, the trust anchor too).
    fn internal_verify(&mut self) -> bool {
        let mut n = self.chain.len() - 1;
        let mut xi = self.chain[n];
        let mut xs;
        let mut same;
        if check_issued(xi, xi) {
            xs = xi;
            same = true;
        } else {
            if n == 0 {
                if !self.cb_cert(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) {
                    return false;
                }
                return self.check_cert_time(xi) && self.verify_cb(true);
            }
            n -= 1;
            xs = self.chain[n];
            same = false;
        }
        loop {
            if !same {
                let ret = signing_allowed(xi, xs);
                if ret != X509_V_OK && !self.cb_cert(ret) {
                    return false;
                }
                match &xi.key {
                    None => {
                        if !self.cb_cert(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY) {
                            return false;
                        }
                    }
                    Some(k) => {
                        if !x509_verify(xs, k) && !self.cb_cert(X509_V_ERR_CERT_SIGNATURE_FAILURE) {
                            return false;
                        }
                    }
                }
            }
            if !self.check_cert_time(xs) {
                return false;
            }
            // "Signal success at this depth" (the callback returns 1).
            if !self.verify_cb(true) {
                return false;
            }
            if n == 0 {
                return true;
            }
            n -= 1;
            xi = xs;
            xs = self.chain[n];
            same = false;
        }
    }

    /// `check_name_constraints` (proxy certificates were rejected before).
    fn check_name_constraints(&mut self) -> bool {
        let num = self.chain.len();
        for i in (0..num).rev() {
            let x = self.chain[i];
            if i > 0 && x.ex.flags & EXFLAG_SI != 0 {
                continue;
            }
            for j in (i + 1..num).rev() {
                let Some(nc) = &self.chain[j].ex.nc else { continue };
                let mut rv = ncons::check(x, nc);
                if rv == X509_V_OK && i == 0 && !ncons::has_dns_san(x) {
                    rv = ncons::check_cn(x, nc);
                }
                match rv {
                    X509_V_OK => {}
                    X509_V_ERR_OUT_OF_MEM => return false,
                    _ => {
                        if !self.cb_cert(rv) {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// `verify_chain`.
    fn verify_chain(&mut self) -> bool {
        if !self.build_chain() || !self.check_chain_extensions() {
            return false;
        }
        if !self.internal_verify() || !self.check_name_constraints() {
            return false;
        }
        // RFC 3779 path validation applies when the phone certificate has
        // an IP address or AS number extension; it is not implemented here
        // (see crate::cert), so such certificates are refused.
        if self.chain[0].ex.rfc3779 && !self.cb_cert(X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE) {
            return false;
        }
        true
    }
}

/// `x509_signing_allowed(issuer, subject)`.
fn signing_allowed(issuer: &Certificate, subject: &Certificate) -> i32 {
    let ku_reject = |usage| issuer.ex.flags & EXFLAG_KUSAGE != 0 && issuer.ex.kusage & usage == 0;
    if subject.ex.flags & EXFLAG_PROXY != 0 {
        if ku_reject(KU_DIGITAL_SIGNATURE) {
            return X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
        }
    } else if ku_reject(KU_KEY_CERT_SIGN) {
        return X509_V_ERR_KEYUSAGE_NO_CERTSIGN;
    }
    X509_V_OK
}

/// `X509_STORE_CTX_init(ctx, store, cert, untrusted)` and
/// `X509_verify_cert(ctx)` with the original's callback: Ok when the
/// certificate verifies, else the `X509_STORE_CTX_get_error` code.
pub(crate) fn verify_cert(
    store: &[Certificate],
    cert: &Certificate,
    untrusted: Option<&[Certificate]>,
    now: i64,
) -> Result<(), i32> {
    let mut ctx = Ctx { store, untrusted, chain: vec![cert], num_untrusted: 1, error: X509_V_OK, now };
    if ctx.verify_chain() {
        Ok(())
    } else if ctx.error == X509_V_OK {
        Err(X509_V_ERR_UNSPECIFIED)
    } else {
        Err(ctx.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ty: i32, s: &str) -> asn1::AStr {
        asn1::AStr { ty, data: s.as_bytes().to_vec(), bits_left: 0 }
    }

    #[test]
    fn times() {
        let utc = asn1::V_UTCTIME;
        let gen = asn1::V_GENERALIZEDTIME;
        assert_eq!(time_to_unix(&t(utc, "700101000000Z")), Some(0));
        assert_eq!(time_to_unix(&t(utc, "491231235959Z")), Some(2524607999));
        assert_eq!(time_to_unix(&t(utc, "500101000000Z")), Some(-631152000));
        assert_eq!(time_to_unix(&t(gen, "19691231235959Z")), Some(-1));
        assert_eq!(time_to_unix(&t(gen, "20000229000000Z")), Some(951782400));
        assert_eq!(time_to_unix(&t(gen, "00010101000000Z")), Some(-62135596800));
        for bad in ["0001010000Z", "700101000000", "7001010000000Z", "701301000000Z", "700132000000Z", "700229000000Z", "700101240000Z", "700101006000Z", "700101000060Z", "70010100000aZ"] {
            assert_eq!(time_to_unix(&t(utc, bad)), None, "{}", bad);
        }
        assert_eq!(time_to_unix(&t(gen, "20000101000000.5Z")), None);
        assert_eq!(time_to_unix(&t(4, "700101000000Z")), None);
        assert_eq!(cmp_time(&t(utc, "700101000000Z"), 0), -1);
        assert_eq!(cmp_time(&t(utc, "700101000001Z"), 0), 1);
    }

    #[test]
    fn strings() {
        assert_eq!(error_string(20), "unable to get local issuer certificate");
        assert_eq!(error_string(18), "self signed certificate");
        assert_eq!(error_string(76), "unknown certificate verification error");
    }
}
