//! Phone certificate verification (`load_castore`, `session_verify_cert`,
//! `session_load_rsa_key`).
//!
//! The CA store is built from the user-supplied `phone_ca_file` PEM bundle
//! (the original embeds three CA certificates; they must never be copied
//! into this project).

use crate::{LogLevel, ProtoError, Result};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::pkey::{PKey, Public};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509StoreContext, X509StoreContextRef, X509};
use openssl_sys as ffi;
use std::os::raw::{c_char, c_int, c_ulong, c_void};

// libcrypto functions that openssl-sys does not declare.
extern "C" {
    fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    fn X509_STORE_CTX_set_verify_cb(
        ctx: *mut ffi::X509_STORE_CTX,
        cb: Option<unsafe extern "C" fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int>,
    );
    fn X509_STORE_CTX_get0_param(ctx: *mut ffi::X509_STORE_CTX) -> *mut ffi::X509_VERIFY_PARAM;
}

/// `X509_V_ERR_CERT_NOT_YET_VALID`.
pub const ERR_CERT_NOT_YET_VALID: i32 = 9;
/// `X509_V_ERR_CERT_HAS_EXPIRED`.
pub const ERR_CERT_HAS_EXPIRED: i32 = 10;

/// The trusted CA certificates phones are verified against.
pub struct CaStore {
    store: X509Store,
    count: usize,
}

impl CaStore {
    /// Build a store from a PEM bundle (every certificate in it).  An empty
    /// or unreadable bundle is an error.
    pub fn from_pem(pem: &[u8]) -> Result<CaStore> {
        let certs = X509::stack_from_pem(pem).map_err(|e| ProtoError::Invalid(format!("Error parsing CA certificates: {}", e)))?;
        if certs.is_empty() {
            return Err(ProtoError::Invalid("No CA certificates found".into()));
        }
        CaStore::from_certs(&certs)
    }

    /// Build a store from certificates (`X509_STORE_add_cert` each).
    pub fn from_certs(certs: &[X509]) -> Result<CaStore> {
        let err = |e: openssl::error::ErrorStack| ProtoError::Crypto(e.to_string());
        let mut b = X509StoreBuilder::new().map_err(err)?;
        for c in certs {
            b.add_cert(c.clone()).map_err(err)?;
        }
        Ok(CaStore { store: b.build(), count: certs.len() })
    }

    /// Number of certificates loaded.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Who presented the certificate; only used in the original's log
/// messages (session contact, MAC, and user agent).  A missing MAC prints
/// as "(null)", as glibc prints the original's NULL pointer.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientInfo<'a> {
    pub contact: &'a str,
    pub mac: Option<&'a str>,
    pub user_agent: &'a str,
}

/// A phone certificate that passed verification.
pub struct VerifiedClient {
    /// The certificate that was verified (the last one in the body); its
    /// key encrypts the common password.
    pub certificate: X509,
    /// Its public key (`X509_get_pubkey`); `None` if OpenSSL cannot decode
    /// it, which the original only notices when it generates the common
    /// password ("failed to get pkey during common password generation").
    pub public_key: Option<PKey<Public>>,
    /// The intermediate certificate's serial number as the original
    /// stores it (session +0xe20): 0 for the legacy form.  It is read from
    /// the second certificate, or, while the value read is 0, from the
    /// ones after it.  A non-zero value makes the server send
    /// `X-Digium-AppServer-Handshake-Version: 1`.
    pub intermediate_serial: i64,
    /// True for the legacy single-certificate form.
    pub legacy: bool,
}

impl VerifiedClient {
    /// Value for `X-Digium-AppServer-Handshake-Version`, if it is sent.
    pub fn handshake_version(&self) -> Option<&'static str> {
        (self.intermediate_serial != 0).then_some("1")
    }
}

/// Why verification failed.  Each variant holds the detail the original
/// puts in its log message (which has already been logged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    /// No certificate could be read (OpenSSL error string).
    Unreadable(String),
    /// More than one certificate, but not three; the count excludes the
    /// first certificate, as in the original's message.
    WrongChainLength(usize),
    /// The intermediate's serial number could not be read or is negative.
    NoSerial(String),
    /// The verification context could not be set up.
    Context(String),
    /// Verification failed (`X509_verify_cert_error_string`).
    Verify(String),
}

impl CertError {
    /// The message the original logs for this error (with its newline,
    /// except for the chain length message, which has none).
    pub fn log_message(&self, contact: &str) -> String {
        match self {
            CertError::Unreadable(e) => format!("<{}>: Unable to read client cert: {}\n", contact, e),
            CertError::WrongChainLength(n) => {
                format!("<{}>: Expected two certificates in the chain, found {}", contact, n)
            }
            CertError::NoSerial(e) => {
                format!("<{}>: Unable to get serial number of intermediate cert: {}\n", contact, e)
            }
            CertError::Context(e) => format!("<{}>: Could not initialize store context: {}\n", contact, e),
            CertError::Verify(e) => format!("<{}>: Client cert failed to verify: {}\n", contact, e),
        }
    }
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.log_message("").trim_start_matches("<>: ").trim_end())
    }
}

fn log(level: LogLevel, line: u32, msg: &str) {
    crate::log(level, "phone_message.c", line, "session_verify_cert", msg);
}

/// `ERR_get_error()` formatted with `ERR_error_string_n` (256 bytes).
fn openssl_error_string() -> String {
    let mut buf = [0 as c_char; 256];
    unsafe {
        let e = ffi::ERR_get_error();
        ERR_error_string_n(e, buf.as_mut_ptr(), buf.len());
        std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

/// `PEM_read_bio_X509` on the body: the first read, then reads until one
/// fails, exactly as the original's loop (a bad first certificate does
/// not stop the later reads).
fn read_certs(pem: &[u8]) -> std::result::Result<(Option<X509>, Vec<X509>), ()> {
    let len = c_int::try_from(pem.len()).map_err(|_| ())?;
    unsafe {
        ffi::init();
        let bio = ffi::BIO_new_mem_buf(pem.as_ptr() as *const c_void, len);
        if bio.is_null() {
            return Err(());
        }
        let read = || {
            let x = ffi::PEM_read_bio_X509(bio, std::ptr::null_mut(), None, std::ptr::null_mut());
            if x.is_null() {
                None
            } else {
                Some(X509::from_ptr(x))
            }
        };
        let first = read();
        let mut rest = Vec::new();
        while let Some(x) = read() {
            rest.push(x);
        }
        ffi::BIO_free_all(bio);
        Ok((first, rest))
    }
}

/// The verify callback (FUN_00148210): ignore validity-period errors.
unsafe extern "C" fn verify_cb(ok: c_int, ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    let err = ffi::X509_STORE_CTX_get_error(ctx);
    if err == ERR_CERT_NOT_YET_VALID || err == ERR_CERT_HAS_EXPIRED {
        1
    } else {
        ok
    }
}

/// `strtoll(BN_bn2dec(serial), NULL, 10)`: saturates at the `i64` range.
fn serial_of(cert: &X509) -> Option<i64> {
    let dec = cert.serial_number().to_bn().ok()?.to_dec_str().ok()?;
    let s: &str = &dec;
    Some(s.parse::<i64>().unwrap_or(if s.starts_with('-') { i64::MIN } else { i64::MAX }))
}

/// Restore the line breaks at PEM boundaries that a Handshake body lost
/// on the way (deviation, port plan section 8, item 12).
///
/// Asterisk 24's res_pjsip_messaging strips trailing CR and LF from every
/// MESSAGE body, so when a phone's chunk ends right after a BEGIN or END
/// line, or right before one, the reassembled body has, e.g.,
/// `-----BEGIN CERTIFICATE-----MIIB...`, `...==-----END CERTIFICATE-----`,
/// or `-----END CERTIFICATE----------BEGIN CERTIFICATE-----`, which
/// OpenSSL's PEM reader does not accept.  This puts a line break before
/// every `-----BEGIN ` and `-----END ` marker line that does not start the
/// text or a line, and after every such line that is not followed by one
/// or by the end of the text.  Well-formed PEM text is returned unchanged.
pub fn restore_pem_newlines(pem: &str) -> String {
    const DASHES: &str = "-----";
    let mut out = String::with_capacity(pem.len() + 8);
    let mut rest = pem;
    loop {
        let start = [rest.find("-----BEGIN "), rest.find("-----END ")].into_iter().flatten().min();
        let Some(start) = start else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        let at = &rest[start..];
        let label_start = if at.starts_with("-----BEGIN ") { 11 } else { 9 };
        let label_len = at[label_start..].find(['-', '\r', '\n']).unwrap_or(at.len() - label_start);
        let end = label_start + label_len + DASHES.len();
        if !at[label_start + label_len..].starts_with(DASHES) {
            // Not a marker line: keep the dashes and look further on.
            out.push_str(DASHES);
            rest = &at[DASHES.len()..];
            continue;
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&at[..end]);
        rest = &at[end..];
        if !rest.is_empty() && !rest.starts_with('\n') && !rest.starts_with("\r\n") {
            out.push('\n');
        }
    }
}

/// Verify the PEM certificate(s) a phone sent in its Handshake body
/// (`session_verify_cert`, FUN_00148230), logging as the original does.
///
/// One certificate: the legacy form, verified directly against `store`.
/// Otherwise exactly three: the first is ignored (it is the legacy
/// certificate for older servers), the second is the intermediate (its
/// serial is reported), and the last is the phone certificate, verified
/// with the second and third as untrusted chain.  Validity-period errors
/// (`X509_V_ERR_CERT_NOT_YET_VALID`, `X509_V_ERR_CERT_HAS_EXPIRED`) are
/// ignored.  The verification security level is 0 so that 512-bit keys
/// and SHA-1 signatures verify as they do under the original's OpenSSL
/// 1.1.
pub fn verify_client_chain(
    store: &CaStore,
    pem: &str,
    client: &ClientInfo,
) -> std::result::Result<VerifiedClient, CertError> {
    let who = || format!("Contact: {} MAC: {} UA: {}", client.contact, client.mac.unwrap_or("(null)"), client.user_agent);
    unsafe { ffi::ERR_clear_error() };
    let result = verify_inner(store, pem, client, &who);
    unsafe { ffi::ERR_clear_error() };
    result
}

fn verify_inner(
    store: &CaStore,
    pem: &str,
    client: &ClientInfo,
    who: &dyn Fn() -> String,
) -> std::result::Result<VerifiedClient, CertError> {
    let fail = |line: u32, e: CertError| {
        log(LogLevel::Dpma, line, &e.log_message(client.contact));
        Err(e)
    };
    let Ok((first, rest)) = read_certs(pem.as_bytes()) else {
        return fail(0x208, CertError::Unreadable(openssl_error_string()));
    };

    // The serial number is read from the second certificate (and the
    // following ones while it reads as 0) as the certificates are read.
    let mut serial: i64 = 0;
    for c in &rest {
        if serial != 0 {
            break;
        }
        match serial_of(c) {
            Some(s) if s >= 0 => {
                serial = s;
                log(
                    LogLevel::Debug(1),
                    0x22f,
                    &format!("{} Intermediate cert serial number: {}\n", who(), s),
                );
            }
            _ => return fail(0x22b, CertError::NoSerial(openssl_error_string())),
        }
    }

    let legacy = rest.is_empty();
    let cert = if legacy {
        log(LogLevel::Debug(1), 0x235, &format!("{} Using legacy certificate\n", who()));
        match first {
            Some(c) => c,
            None => return fail(0x23a, CertError::Unreadable(openssl_error_string())),
        }
    } else if rest.len() != 2 {
        return fail(0x23f, CertError::WrongChainLength(rest.len()));
    } else {
        rest[1].clone()
    };

    let mut chain = Stack::new().map_err(|_| CertError::Context(openssl_error_string()))?;
    for c in &rest {
        let _ = chain.push(c.clone());
    }
    let Ok(mut ctx) = X509StoreContext::new() else {
        let e = openssl_error_string();
        log(LogLevel::Dpma, 0x246, &format!("<{}>: Unable create context: {}\n", client.contact, e));
        return Err(CertError::Context(e));
    };
    let verified = ctx.init(&store.store, &cert, &chain, |ctx: &mut X509StoreContextRef| {
        unsafe {
            X509_STORE_CTX_set_verify_cb(ctx.as_ptr(), Some(verify_cb));
            ffi::X509_VERIFY_PARAM_set_auth_level(X509_STORE_CTX_get0_param(ctx.as_ptr()), 0);
        }
        let ok = ctx.verify_cert().unwrap_or(false);
        Ok((ok, ctx.error().error_string().to_string()))
    });
    match verified {
        Err(_) => {
            let e = ctx.error().error_string().to_string();
            fail(0x24b, CertError::Context(e))
        }
        Ok((false, e)) => fail(0x258, CertError::Verify(e)),
        Ok((true, _)) => Ok(VerifiedClient {
            public_key: cert.public_key().ok(),
            certificate: cert,
            intermediate_serial: serial,
            legacy,
        }),
    }
}

/// Load a phone public key saved in AstDB (`session_load_rsa_key`, in
/// FUN_0014b450): `PEM_read_bio_RSA_PUBKEY`, which reads the first
/// `PUBLIC KEY` block and skips any other PEM blocks.  A key under 512
/// bits is logged and dropped (`Ok(None)`); the original then keeps the
/// session without a key.  Unreadable input is an error (the caller logs
/// "Failed to load rsa key").
pub fn load_public_key(pem: &str) -> Result<Option<PKey<Public>>> {
    let log = |line: u32, msg: &str| {
        crate::log(LogLevel::Dpma, "phone_message.c", line, "session_load_rsa_key", &format!("{}\n", msg));
    };
    if pem.is_empty() {
        let msg = "failed to load client public rsa key - is null";
        log(0x1a8, msg);
        return Err(ProtoError::Invalid(msg.into()));
    }
    let rsa = openssl::rsa::Rsa::public_key_from_pem(pem.as_bytes()).map_err(|e| ProtoError::Crypto(e.to_string()))?;
    if rsa.size() < 0x40 {
        log(0x1bd, "failed to load client public rsa key - less than 512 bits");
        return Ok(None);
    }
    PKey::from_rsa(rsa).map(Some).map_err(|e| ProtoError::Crypto(e.to_string()))
}

/// PEM encoding of a public key (`-----BEGIN PUBLIC KEY-----`), readable
/// by [`load_public_key`].
pub fn public_key_pem(key: &PKey<Public>) -> Result<String> {
    let pem = key.public_key_to_pem().map_err(|e| ProtoError::Crypto(e.to_string()))?;
    String::from_utf8(pem).map_err(|e| ProtoError::Invalid(e.to_string()))
}

#[cfg(test)]
pub(crate) mod testpki {
    //! A throwaway PKI generated inside the tests (nothing from the
    //! original binary).
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509Builder, X509NameBuilder, X509};

    pub struct Issued {
        pub cert: X509,
        pub key: PKey<Private>,
    }

    pub struct Opts {
        pub bits: u32,
        pub serial: i64,
        pub ca: bool,
        pub not_before_days: i64,
        pub not_after_days: i64,
        pub md: MessageDigest,
    }

    impl Default for Opts {
        fn default() -> Opts {
            Opts { bits: 1024, serial: 1, ca: false, not_before_days: -1, not_after_days: 365, md: MessageDigest::sha256() }
        }
    }

    /// Issue a certificate for `cn`; self-signed when `issuer` is `None`.
    pub fn issue(cn: &str, issuer: Option<&Issued>, o: Opts) -> Issued {
        let key = PKey::from_rsa(Rsa::generate(o.bits).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_dec_str(&o.serial.to_string()).unwrap();
        b.set_serial_number(&Asn1Integer::from_bn(&serial).unwrap()).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(issuer.map(|i| i.cert.subject_name()).unwrap_or(&name)).unwrap();
        b.set_pubkey(&key).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        b.set_not_before(&Asn1Time::from_unix(now + o.not_before_days * 86400).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::from_unix(now + o.not_after_days * 86400).unwrap()).unwrap();
        if o.ca {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        }
        b.sign(issuer.map(|i| &i.key).unwrap_or(&key), o.md).unwrap();
        Issued { cert: b.build(), key }
    }

    pub fn pem(certs: &[&X509]) -> String {
        certs.iter().map(|c| String::from_utf8(c.to_pem().unwrap()).unwrap()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testpki::*;
    use super::*;
    use crate::testlog;
    use openssl::hash::MessageDigest;

    const CLIENT: ClientInfo = ClientInfo { contact: "sip:phone@127.0.0.1:5060", mac: Some("000fd3000001"), user_agent: "Digium D65 2_9_17" };

    struct Pki {
        root: Issued,
        inter: Issued,
        phone: Issued,
        legacy: Issued,
    }

    fn pki() -> Pki {
        let root = issue("Test Root", None, Opts { ca: true, serial: 1, ..Default::default() });
        let inter = issue("Test Intermediate", Some(&root), Opts { ca: true, serial: 4660, ..Default::default() });
        let phone = issue("000fd3000001", Some(&inter), Opts { serial: 77, ..Default::default() });
        let legacy = issue("legacy 000fd3000001", Some(&root), Opts { serial: 5, ..Default::default() });
        Pki { root, inter, phone, legacy }
    }

    fn store(p: &Pki) -> CaStore {
        CaStore::from_pem(&p.root.cert.to_pem().unwrap()).unwrap()
    }

    #[test]
    fn shareable_between_threads() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<CaStore>();
        send_sync::<VerifiedClient>();
    }

    #[test]
    fn ca_store_loading() {
        let p = pki();
        let other = issue("Other Root", None, Opts { ca: true, ..Default::default() });
        let s = CaStore::from_pem(pem(&[&p.root.cert, &other.cert]).as_bytes()).unwrap();
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());
        assert!(CaStore::from_pem(b"").is_err());
        assert!(CaStore::from_pem(b"not a certificate").is_err());
    }

    #[test]
    fn legacy_form() {
        let p = pki();
        let (r, logs) = testlog::capture(|| verify_client_chain(&store(&p), &pem(&[&p.legacy.cert]), &CLIENT));
        let v = r.unwrap();
        assert!(v.legacy);
        assert_eq!(v.intermediate_serial, 0);
        assert_eq!(v.handshake_version(), None);
        assert_eq!(v.certificate.to_der().unwrap(), p.legacy.cert.to_der().unwrap());
        assert!(v.public_key.unwrap().public_eq(&p.legacy.key));
        assert_eq!(
            logs,
            vec!["Contact: sip:phone@127.0.0.1:5060 MAC: 000fd3000001 UA: Digium D65 2_9_17 Using legacy certificate\n"]
        );
    }

    #[test]
    fn chain_form() {
        let p = pki();
        let body = pem(&[&p.legacy.cert, &p.inter.cert, &p.phone.cert]);
        let (r, logs) = testlog::capture(|| verify_client_chain(&store(&p), &body, &CLIENT));
        let v = r.unwrap();
        assert!(!v.legacy);
        assert_eq!(v.intermediate_serial, 4660);
        assert_eq!(v.handshake_version(), Some("1"));
        assert_eq!(v.certificate.to_der().unwrap(), p.phone.cert.to_der().unwrap());
        assert_eq!(
            logs,
            vec!["Contact: sip:phone@127.0.0.1:5060 MAC: 000fd3000001 UA: Digium D65 2_9_17 Intermediate cert serial number: 4660\n"]
        );
        // The first certificate is ignored entirely, even if it is junk
        // signed by nobody we trust.
        let junk = issue("junk", None, Opts::default());
        let body = pem(&[&junk.cert, &p.inter.cert, &p.phone.cert]);
        assert!(verify_client_chain(&store(&p), &body, &CLIENT).is_ok());
        // Text around and between the PEM blocks is skipped.
        let body = format!("garbage\n{}\nmore\n{}{}trailer", pem(&[&p.legacy.cert]), pem(&[&p.inter.cert]), pem(&[&p.phone.cert]));
        assert!(verify_client_chain(&store(&p), &body, &CLIENT).is_ok());
    }

    #[test]
    fn pem_newlines_restored() {
        let p = pki();
        // Well-formed text (LF or CRLF) and text without markers are
        // unchanged.
        for body in [pem(&[&p.legacy.cert]), pem(&[&p.legacy.cert, &p.inter.cert, &p.phone.cert])] {
            assert_eq!(restore_pem_newlines(&body), body);
            let crlf = body.replace('\n', "\r\n");
            assert_eq!(restore_pem_newlines(&crlf), crlf);
        }
        for s in ["", "hello", "-----", "a-----b", "-----BEGIN", "-----BEGIN CERT", "x-----BEGIN CERT\n-----", "-----END-----"] {
            assert_eq!(restore_pem_newlines(s), s);
        }
        // Each kind of lost line break: after a BEGIN line, before an END
        // line, and between an END line and the next BEGIN line.
        assert_eq!(
            restore_pem_newlines("-----BEGIN CERTIFICATE-----AAAA\nBBBB-----END CERTIFICATE-----"),
            "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----"
        );
        assert_eq!(
            restore_pem_newlines("-----END A-----\r\n-----BEGIN B----------END B----------BEGIN C-----x"),
            "-----END A-----\r\n-----BEGIN B-----\n-----END B-----\n-----BEGIN C-----\nx"
        );
        assert_eq!(restore_pem_newlines("junk-----BEGIN A-----"), "junk\n-----BEGIN A-----");
        // Every line break at a PEM boundary lost (chunks ending right
        // before and after each BEGIN and END line): both forms verify
        // again.
        for body in [pem(&[&p.legacy.cert]), pem(&[&p.legacy.cert, &p.inter.cert, &p.phone.cert])] {
            let broken = body.replace("-----\n", "-----").replace("\n-----", "-----");
            assert!(verify_client_chain(&store(&p), &broken, &CLIENT).is_err());
            let fixed = restore_pem_newlines(&broken);
            assert_eq!(fixed, body.trim_end_matches('\n'));
            assert!(verify_client_chain(&store(&p), &fixed, &CLIENT).is_ok());
        }
    }

    #[test]
    fn wrong_chain_lengths() {
        let p = pki();
        let s = store(&p);
        let (r, logs) = testlog::capture(|| verify_client_chain(&s, &pem(&[&p.inter.cert, &p.phone.cert]), &CLIENT));
        assert_eq!(r.err(), Some(CertError::WrongChainLength(1)));
        assert_eq!(logs.last().unwrap(), "<sip:phone@127.0.0.1:5060>: Expected two certificates in the chain, found 1");
        let four = pem(&[&p.legacy.cert, &p.inter.cert, &p.phone.cert, &p.phone.cert]);
        assert_eq!(verify_client_chain(&s, &four, &CLIENT).err(), Some(CertError::WrongChainLength(3)));
    }

    #[test]
    fn unreadable() {
        let p = pki();
        let s = store(&p);
        for body in ["", "hello", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"] {
            let (r, logs) = testlog::capture(|| verify_client_chain(&s, body, &ClientInfo { contact: "c", mac: None, user_agent: "ua" }));
            assert!(matches!(r, Err(CertError::Unreadable(_))), "{:?}", body);
            assert_eq!(logs[0], "Contact: c MAC: (null) UA: ua Using legacy certificate\n");
            assert!(logs[1].starts_with("<c>: Unable to read client cert: error:"), "{}", logs[1]);
        }
    }

    #[test]
    fn expired_and_not_yet_valid_accepted() {
        let p = pki();
        let expired = issue("old phone", Some(&p.root), Opts { not_before_days: -400, not_after_days: -30, ..Default::default() });
        assert!(verify_client_chain(&store(&p), &pem(&[&expired.cert]), &CLIENT).is_ok());
        let future = issue("new phone", Some(&p.root), Opts { not_before_days: 30, not_after_days: 400, ..Default::default() });
        assert!(verify_client_chain(&store(&p), &pem(&[&future.cert]), &CLIENT).is_ok());
        // An expired intermediate and root, too.
        let root = issue("Old Root", None, Opts { ca: true, not_before_days: -900, not_after_days: -1, ..Default::default() });
        let inter = issue("Old Inter", Some(&root), Opts { ca: true, serial: 9, not_before_days: -900, not_after_days: -1, ..Default::default() });
        let phone = issue("phone", Some(&inter), Opts { not_before_days: -900, not_after_days: -1, ..Default::default() });
        let s = CaStore::from_certs(std::slice::from_ref(&root.cert)).unwrap();
        let v = verify_client_chain(&s, &pem(&[&phone.cert, &inter.cert, &phone.cert]), &CLIENT).unwrap();
        assert_eq!(v.intermediate_serial, 9);
    }

    #[test]
    fn small_keys_and_sha1_accepted() {
        let root = issue("Weak Root", None, Opts { ca: true, bits: 512, md: MessageDigest::sha1(), ..Default::default() });
        let inter = issue("Weak Inter", Some(&root), Opts { ca: true, bits: 512, serial: 3, md: MessageDigest::sha1(), ..Default::default() });
        let phone = issue("phone", Some(&inter), Opts { bits: 512, md: MessageDigest::sha1(), ..Default::default() });
        let s = CaStore::from_certs(std::slice::from_ref(&root.cert)).unwrap();
        let v = verify_client_chain(&s, &pem(&[&phone.cert, &inter.cert, &phone.cert]), &CLIENT).unwrap();
        // The common password can be encrypted to a 512-bit key.
        let pass = crate::crypto::new_common_password().unwrap();
        let b64 = crate::crypto::encrypt_common_password(v.public_key.as_ref().unwrap(), &pass).unwrap();
        assert_eq!(crate::crypto::decrypt_common_password(&phone.key, &b64).unwrap(), pass);
        let legacy = issue("legacy", Some(&root), Opts { bits: 512, md: MessageDigest::sha1(), ..Default::default() });
        assert!(verify_client_chain(&s, &pem(&[&legacy.cert]), &CLIENT).is_ok());
    }

    #[test]
    fn wrong_ca_rejected() {
        let p = pki();
        let other = issue("Other Root", None, Opts { ca: true, ..Default::default() });
        let s = CaStore::from_certs(std::slice::from_ref(&other.cert)).unwrap();
        let (r, logs) = testlog::capture(|| verify_client_chain(&s, &pem(&[&p.legacy.cert]), &CLIENT));
        assert_eq!(r.err(), Some(CertError::Verify("unable to get local issuer certificate".into())));
        assert_eq!(logs[1], "<sip:phone@127.0.0.1:5060>: Client cert failed to verify: unable to get local issuer certificate\n");
        let body = pem(&[&p.legacy.cert, &p.inter.cert, &p.phone.cert]);
        assert!(matches!(verify_client_chain(&s, &body, &CLIENT), Err(CertError::Verify(_))));
        // A phone certificate signed by a different intermediate.
        let p2 = pki();
        let body = pem(&[&p.legacy.cert, &p.inter.cert, &p2.phone.cert]);
        assert!(matches!(verify_client_chain(&store(&p), &body, &CLIENT), Err(CertError::Verify(_))));
        // The intermediate alone is not trusted as a root.
        let s = CaStore::from_certs(std::slice::from_ref(&p.inter.cert)).unwrap();
        assert!(verify_client_chain(&s, &pem(&[&p.legacy.cert]), &CLIENT).is_err());
    }

    #[test]
    fn serial_quirks() {
        let p = pki();
        // A zero serial on the intermediate makes the original read the
        // next certificate's serial.
        let inter0 = issue("Inter0", Some(&p.root), Opts { ca: true, serial: 0, ..Default::default() });
        let phone = issue("phone", Some(&inter0), Opts { serial: 99, ..Default::default() });
        let (r, logs) = testlog::capture(|| verify_client_chain(&store(&p), &pem(&[&p.legacy.cert, &inter0.cert, &phone.cert]), &CLIENT));
        assert_eq!(r.unwrap().intermediate_serial, 99);
        assert_eq!(logs.len(), 2);
        assert!(logs[0].ends_with("Intermediate cert serial number: 0\n"));
        assert!(logs[1].ends_with("Intermediate cert serial number: 99\n"));
        // A negative serial is an error.
        let neg = issue("InterNeg", Some(&p.root), Opts { ca: true, serial: -5, ..Default::default() });
        let (r, logs) = testlog::capture(|| verify_client_chain(&store(&p), &pem(&[&p.legacy.cert, &neg.cert, &phone.cert]), &CLIENT));
        assert!(matches!(r, Err(CertError::NoSerial(_))));
        assert!(logs[0].starts_with("<sip:phone@127.0.0.1:5060>: Unable to get serial number of intermediate cert: "));
    }

    #[test]
    fn public_keys() {
        let p = pki();
        let public = p.phone.cert.public_key().unwrap();
        let pem_text = public_key_pem(&public).unwrap();
        assert!(pem_text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        let k = load_public_key(&pem_text).unwrap().unwrap();
        assert!(k.public_eq(&public));
        // Other PEM blocks before the key are skipped; a certificate alone
        // is not a public key.
        let mixed = format!("{}{}", pem(&[&p.phone.cert]), pem_text);
        assert!(load_public_key(&mixed).unwrap().unwrap().public_eq(&public));
        assert!(load_public_key(&pem(&[&p.phone.cert])).is_err());
        let (r, logs) = testlog::capture(|| load_public_key(""));
        assert!(r.is_err());
        assert_eq!(logs, vec!["failed to load client public rsa key - is null\n"]);
        // 512 bits is the minimum; smaller keys are dropped.
        let k512 = PKey::from_rsa(openssl::rsa::Rsa::generate(512).unwrap()).unwrap();
        let k512 = PKey::public_key_from_pem(&k512.public_key_to_pem().unwrap()).unwrap();
        assert!(load_public_key(&public_key_pem(&k512).unwrap()).unwrap().is_some());
        // Build a 504-bit public key by hand (OpenSSL will not generate one).
        let n = openssl::bn::BigNum::from_hex_str(&format!("C{}1", "0".repeat(124))).unwrap();
        let e = openssl::bn::BigNum::from_u32(65537).unwrap();
        let small = openssl::rsa::Rsa::from_public_components(n, e).unwrap();
        assert_eq!(small.size(), 63);
        let small_pem = String::from_utf8(small.public_key_to_pem().unwrap()).unwrap();
        let (r, logs) = testlog::capture(|| load_public_key(&small_pem));
        assert!(r.unwrap().is_none());
        assert_eq!(logs, vec!["failed to load client public rsa key - less than 512 bits\n"]);
    }
}
