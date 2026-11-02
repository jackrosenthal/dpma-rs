//! Phone certificate verification (`load_castore`, `session_verify_cert`,
//! `session_load_rsa_key`).
//!
//! The CA store is built from the user-supplied `phone_ca_file` PEM bundle
//! (the original embeds three CA certificates; they must never be copied
//! into this project).
//!
//! # The verifier
//!
//! The original links OpenSSL 1.1.1t statically and verifies with
//! `X509_verify_cert` and a callback that ignores the validity period.
//! This module does what 1.1.1t does, following its source
//! (`crypto/x509/x509_vfy.c`, `crypto/x509v3/v3_purp.c`, `v3_ncons.c`,
//! `crypto/asn1/tasn_dec.c`, `crypto/pem/pem_lib.c`), in
//! [`crate::x509`]:
//!
//! **Reading.**  Certificates are read with 1.1.1t's PEM reader and BER
//! decoder (see [`crate::x509`]'s `pem` and `asn1` modules for exactly
//! what they tolerate).  Names compare by 1.1.1t's canonical form (case
//! and white space folded, string types unified).  The extensions 1.1.1t
//! interprets (basicConstraints, keyUsage, extendedKeyUsage, nsCertType,
//! subject and authority key identifiers, subjectAltName,
//! nameConstraints, CRL distribution points, proxyCertInfo, and the RFC
//! 3779 extensions) are decoded the same way; one that occurs twice or
//! does not decode makes the certificate invalid (`EXFLAG_INVALID`), and an
//! invalid certificate never links into a chain.
//!
//! **Checks made** (in 1.1.1t's order; the first failure is the error
//! logged):
//!
//! 1. Chain building (`build_chain`), trusted store first: an issuer is a
//!    certificate whose subject equals the subject's issuer name, whose
//!    authority key identifier (if the subject has one) matches its key
//!    identifier, serial number, and issuer name, and whose key type
//!    matches the subject's signature algorithm (`x509_likely_issued`);
//!    among several, the first valid now is preferred.  The phone's
//!    certificates are searched after the store, each used once.  The
//!    chain must end at a certificate from the store that is self-signed
//!    (self-issued, with a matching key identifier and key type) and not
//!    invalid: that is the trust anchor.  A self-signed phone certificate
//!    is accepted only if the same certificate is in the store.  Chains
//!    longer than 101 are refused.  Errors: unable to get local issuer
//!    certificate (20), unable to get issuer certificate (2), self signed
//!    certificate (18), self signed certificate in certificate chain (19),
//!    certificate chain too long (22).
//! 2. Extensions (`check_chain_extensions`): no unknown critical extension
//!    (34) and no proxy certificate (40) anywhere; every issuer must be a
//!    CA (24): basicConstraints with CA:TRUE (and keyUsage, if present,
//!    with keyCertSign) for an intermediate; for the top of the chain also
//!    a self-signed v1 certificate without basicConstraints, a
//!    certificate whose keyUsage has keyCertSign, or a Netscape CA type;
//!    path length constraints of the issuers (25).
//! 3. Signatures and times (`internal_verify`): every signature except the
//!    trust anchor's own, with the issuer's key (6, 7), after checking the
//!    issuer's keyUsage allows certificate signing (32; in practice
//!    already refused by step 2); the signature algorithm in the
//!    certificate must equal the one in its signed part.  Every
//!    certificate's notBefore and notAfter must be `YYMMDDHHMMSSZ` or
//!    `YYYYMMDDHHMMSSZ` with valid values (13, 14); not yet valid (9) and
//!    expired (10) are ignored by the original's callback.
//! 4. Name constraints of the issuers on the subject names, email
//!    addresses, subjectAltNames, and (for the phone certificate) host
//!    name-like commonNames (47, 48, 49, 51, 53), as `v3_ncons.c` does.
//!
//! The security level is the default -1, so key sizes and digests are not
//! restricted: 512-bit RSA keys and MD5 and SHA-1 signatures verify.
//!
//! **Left out**, with the reasons:
//!
//! - Signature algorithms other than RSA PKCS#1 v1.5 with MD5, SHA-1,
//!   SHA-224, SHA-256, SHA-384, or SHA-512 (1.1.1t also verifies RSA with
//!   MD4, MDC2, RIPEMD-160, SHA-3, and RSASSA-PSS, and DSA, ECDSA, Ed25519,
//!   and Ed448): they fail as certificate signature failure (7).  A
//!   phone's key must be RSA anyway (the common password is encrypted to
//!   it), and its CAs are expected to sign with RSA PKCS#1 v1.5 too.
//! - Public keys other than RSA are not decoded, only recognized by
//!   algorithm: such a key counts as decodable, as a well-formed one is
//!   for 1.1.1t.  A malformed DSA or EC key would make 1.1.1t refuse the
//!   certificate as an issuer, which here fails at its signature instead.
//! - RFC 3779 path validation: a phone certificate with an IP address or
//!   AS number extension is refused (Unsupported extension feature, 45)
//!   where 1.1.1t checks the resources against the issuers'.
//! - Encrypted PEM blocks: 1.1.1t asks for a pass phrase on the process's
//!   terminal (or reads standard input); here the read fails as it fails
//!   in 1.1.1t when no pass phrase can be read.
//! - The order of same-named certificates in the store: 1.1.1t sorts the
//!   store with the C library's `qsort`; this keeps `phone_ca_file`'s order
//!   (what a stable sort, such as glibc's merge sort, gives).
//! - Not applicable to the original's call, so not implemented: CRLs,
//!   purposes and trust settings (none are set), policies, host, email,
//!   and IP checks, DANE, Suite B, the X509_STRICT checks, partial
//!   chains, and the original's messages for allocation failures ("Unable
//!   create context", "Could not initialize store context").
//!
//! **Error texts.**  The original logs `X509_verify_cert_error_string`
//! texts for verification failures and `ERR_error_string_n` texts for
//! unreadable certificates; both are 1.1.1t's here (see
//! [`crate::errstack`]).
//!
//! **Why not x509-cert's decoder.**  The `x509-cert` crate decodes DER
//! only, so it refuses certificates 1.1.1t reads (BER lengths and strings,
//! booleans other than 0x00 and 0xFF, times before 1970, OIDs over 39
//! octets, version numbers beyond v3), and it does not check what 1.1.1t
//! checks while decoding (the tags and UTF-8 of name values, the lengths
//! of NULL and BOOLEAN parameters), so it would accept some certificates
//! 1.1.1t refuses.  It also re-encodes the signed part instead of keeping
//! it as it came.  So certificates are decoded with a reimplementation of
//! 1.1.1t's decoder; the signatures use the `rsa`, `sha1`, `sha2`, and
//! `md-5` crates, and the tests build their certificates with
//! `x509-cert`'s builder.

use crate::errstack::{self, Errs};
use crate::x509::pem::{self, Bio};
use crate::x509::verify;
use crate::{LogLevel, ProtoError, Result};
use dpma_bytes::{bformat, ByteSlice};

pub use crate::rsakey::RsaKey;
pub use crate::x509::key::PublicKey;
pub use crate::x509::Certificate;

/// `X509_V_ERR_CERT_NOT_YET_VALID`.
pub const ERR_CERT_NOT_YET_VALID: i32 = 9;
/// `X509_V_ERR_CERT_HAS_EXPIRED`.
pub const ERR_CERT_HAS_EXPIRED: i32 = 10;

/// The trusted CA certificates phones are verified against (the original's
/// `X509_STORE`).
pub struct CaStore {
    certs: Vec<Certificate>,
}

impl CaStore {
    /// Build a store from a PEM bundle: every certificate in it, read with
    /// 1.1.1t's PEM reader, which skips text and blocks with other labels
    /// around the certificates.  Reading stops at the end of the text; any
    /// other failure (a malformed block or certificate) is an error, as is
    /// a bundle without certificates.
    pub fn from_pem(pem: &[u8]) -> Result<CaStore> {
        let mut bio = Bio::new(pem);
        let mut certs = Vec::new();
        loop {
            let mut errs = Errs::new();
            match pem::read_bio_x509(&mut bio, &mut errs) {
                Some(c) => certs.push(c),
                None => {
                    let last = errs.last();
                    if errstack::lib(last) == errstack::LIB_PEM && errstack::reason(last) == errstack::pem::R_NO_START_LINE
                    {
                        break;
                    }
                    let text = errs.0.iter().map(|e| errstack::error_string(e.code)).collect::<Vec<_>>().join(", ");
                    return Err(ProtoError::Invalid(format!("Error parsing CA certificates: {}", text)));
                }
            }
        }
        if certs.is_empty() {
            return Err(ProtoError::Invalid("No CA certificates found".into()));
        }
        CaStore::from_certs(&certs)
    }

    /// Build a store from certificates (`X509_STORE_add_cert` each; an
    /// exact duplicate is not added again).
    pub fn from_certs(certs: &[Certificate]) -> Result<CaStore> {
        let mut store: Vec<Certificate> = Vec::new();
        for c in certs {
            if !store.iter().any(|s| s.same(c)) {
                store.push(c.clone());
            }
        }
        Ok(CaStore { certs: store })
    }

    /// Number of certificates loaded.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Read the certificates in a PEM text (as [`CaStore::from_pem`] does).
pub fn certificates_from_pem(pem: &[u8]) -> Result<Vec<Certificate>> {
    Ok(CaStore::from_pem(pem)?.certs)
}

/// Who presented the certificate; only used in the original's log
/// messages (session contact, MAC, and user agent).  A missing MAC prints
/// as "(null)", as glibc prints the original's NULL pointer.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientInfo<'a> {
    pub contact: &'a [u8],
    pub mac: Option<&'a [u8]>,
    pub user_agent: &'a [u8],
}

/// A phone certificate that passed verification.
#[derive(Debug, Clone)]
pub struct VerifiedClient {
    /// The certificate that was verified (the last one in the body); its
    /// key encrypts the common password.
    pub certificate: Certificate,
    /// Its public key (`X509_get_pubkey`); `None` if 1.1.1t cannot decode
    /// it, which the original only notices when it generates the common
    /// password ("failed to get pkey during common password generation").
    pub public_key: Option<PublicKey>,
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
    /// No certificate could be read (`ERR_error_string_n` text).
    Unreadable(String),
    /// More than one certificate, but not three; the count excludes the
    /// first certificate, as in the original's message.
    WrongChainLength(usize),
    /// The intermediate's serial number is negative (`ERR_error_string_n`
    /// text).
    NoSerial(String),
    /// Verification failed (`X509_verify_cert_error_string`).
    Verify(String),
}

impl CertError {
    /// The message the original logs for this error (with its newline,
    /// except for the chain length message, which has none).
    pub fn log_message(&self, contact: &[u8]) -> Vec<u8> {
        match self {
            CertError::Unreadable(e) => bformat!("<{}>: Unable to read client cert: {}\n", contact, e),
            CertError::WrongChainLength(n) => {
                bformat!("<{}>: Expected two certificates in the chain, found {}", contact, n)
            }
            CertError::NoSerial(e) => {
                bformat!("<{}>: Unable to get serial number of intermediate cert: {}\n", contact, e)
            }
            CertError::Verify(e) => bformat!("<{}>: Client cert failed to verify: {}\n", contact, e),
        }
    }
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self.log_message(b"");
        f.write_str(String::from_utf8_lossy(&msg).trim_start_matches("<>: ").trim_end())
    }
}

fn log(level: LogLevel, line: u32, msg: &[u8]) {
    crate::log(level, "phone_message.c", line, "session_verify_cert", msg);
}

/// Restore the line breaks at PEM boundaries that a Handshake body lost
/// on the way (deviation, port plan section 8, item 12).
///
/// Asterisk 24's res_pjsip_messaging strips trailing CR and LF from every
/// MESSAGE body, so when a phone's chunk ends right after a BEGIN or END
/// line, or right before one, the reassembled body has, e.g.,
/// `-----BEGIN CERTIFICATE-----MIIB...`, `...==-----END CERTIFICATE-----`,
/// or `-----END CERTIFICATE----------BEGIN CERTIFICATE-----`, which
/// the PEM reader does not accept.  This puts a line break before every
/// `-----BEGIN ` and `-----END ` marker line that does not start the text
/// or a line, and after every such line that is not followed by one or by
/// the end of the text.  Well-formed PEM text is returned unchanged.
pub fn restore_pem_newlines(pem: impl AsRef<[u8]>) -> Vec<u8> {
    const DASHES: &[u8] = b"-----";
    let pem = pem.as_ref();
    let mut out = Vec::with_capacity(pem.len() + 8);
    let mut rest = pem;
    loop {
        let start = [rest.find("-----BEGIN "), rest.find("-----END ")].into_iter().flatten().min();
        let Some(start) = start else {
            out.extend_from_slice(rest);
            return out;
        };
        out.extend_from_slice(&rest[..start]);
        let at = &rest[start..];
        let label_start = if at.starts_with(b"-----BEGIN ") { 11 } else { 9 };
        let label_len = at[label_start..].find_byteset(b"-\r\n").unwrap_or(at.len() - label_start);
        let end = label_start + label_len + DASHES.len();
        if !at[label_start + label_len..].starts_with(DASHES) {
            // Not a marker line: keep the dashes and look further on.
            out.extend_from_slice(DASHES);
            rest = &at[DASHES.len()..];
            continue;
        }
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(&at[..end]);
        rest = &at[end..];
        if !rest.is_empty() && !rest.starts_with(b"\n") && !rest.starts_with(b"\r\n") {
            out.push(b'\n');
        }
    }
}

/// Seconds since the epoch, as `time(NULL)`.
fn now() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Verify the PEM certificate(s) a phone sent in its Handshake body
/// (`session_verify_cert`, FUN_00148230), logging as the original does.
///
/// One certificate: the legacy form, verified directly against `store`.
/// Otherwise exactly three: the first is ignored (it is the legacy
/// certificate for older servers), the second is the intermediate (its
/// serial is reported), and the last is the phone certificate, verified
/// with the second and third as untrusted chain.  See the module
/// documentation for what verification checks.
pub fn verify_client_chain(
    store: &CaStore,
    pem: impl AsRef<[u8]>,
    client: &ClientInfo,
) -> std::result::Result<VerifiedClient, CertError> {
    verify_client_chain_at(store, pem, client, now())
}

/// [`verify_client_chain`] at the time `now` (seconds since the epoch).
pub fn verify_client_chain_at(
    store: &CaStore,
    pem: impl AsRef<[u8]>,
    client: &ClientInfo,
    now: i64,
) -> std::result::Result<VerifiedClient, CertError> {
    let who = || {
        let mac: &[u8] = client.mac.unwrap_or(b"(null)");
        bformat!("Contact: {} MAC: {} UA: {}", client.contact, mac, client.user_agent)
    };
    let fail = |line: u32, e: CertError| {
        log(LogLevel::Dpma, line, &e.log_message(client.contact));
        Err(e)
    };
    // The original copies the body with strlen and reads it from a memory
    // BIO.  Its error queue is taken to be empty here (see errstack).
    let body = crate::cbuf::c_bytes(pem.as_ref());
    let mut errs = Errs::new();
    let mut bio = Bio::new(body);
    let first = pem::read_bio_x509(&mut bio, &mut errs);
    let mut chain: Option<Vec<Certificate>> = None;
    let mut serial: i64 = 0;
    // The serial number is read from the second certificate (and the
    // following ones while it reads as 0) as the certificates are read.
    while let Some(x) = pem::read_bio_x509(&mut bio, &mut errs) {
        let s = x.serial_i64();
        chain.get_or_insert_with(Vec::new).push(x);
        if serial == 0 {
            if s < 0 {
                return fail(0x22b, CertError::NoSerial(errstack::error_string(errs.get())));
            }
            serial = s;
            log(LogLevel::Debug(1), 0x22f, &bformat!("{} Intermediate cert serial number: {}\n", who(), s));
        }
    }
    let (cert, untrusted, legacy) = match &chain {
        None => {
            log(LogLevel::Debug(1), 0x235, &bformat!("{} Using legacy certificate\n", who()));
            match &first {
                Some(c) => (c, None, true),
                None => return fail(0x23a, CertError::Unreadable(errstack::error_string(errs.get()))),
            }
        }
        Some(c) if c.len() != 2 => return fail(0x23f, CertError::WrongChainLength(c.len())),
        Some(c) => (&c[1], Some(c.as_slice()), false),
    };
    match verify::verify_cert(&store.certs, cert, untrusted, now) {
        Ok(()) => Ok(VerifiedClient {
            public_key: cert.public_key().cloned(),
            certificate: cert.clone(),
            intermediate_serial: serial,
            legacy,
        }),
        Err(code) => fail(0x258, CertError::Verify(verify::error_string(code).to_string())),
    }
}

/// Load a phone public key saved in AstDB (`session_load_rsa_key`, in
/// FUN_0014b450): `PEM_read_bio_RSA_PUBKEY`, which reads the first
/// `PUBLIC KEY` block (an RSA or RSASSA-PSS `SubjectPublicKeyInfo`) and
/// skips any other PEM blocks.  A key under 512 bits is logged and dropped
/// (`Ok(None)`); the original then keeps the session without a key.
/// Unreadable input is an error (the caller logs "Failed to load rsa
/// key").
pub fn load_public_key(pem: impl AsRef<[u8]>) -> Result<Option<PublicKey>> {
    let pem = pem.as_ref();
    let log = |line: u32, msg: &str| {
        crate::log(LogLevel::Dpma, "phone_message.c", line, "session_load_rsa_key", format!("{}\n", msg).as_bytes());
    };
    if pem.is_empty() {
        let msg = "failed to load client public rsa key - is null";
        log(0x1a8, msg);
        return Err(ProtoError::Invalid(msg.into()));
    }
    let mut errs = Errs::new();
    let key = pem::read_bio_pubkey_der(&mut Bio::new(pem), &mut errs)
        .and_then(|der| crate::x509::key::d2i_pubkey(&der, &mut errs));
    let key = match key {
        Some(k) if k.rsa().is_some() => k,
        _ => return Err(ProtoError::Crypto(errstack::error_string(errs.peek()))),
    };
    if key.rsa().is_some_and(|k| k.size() < 0x40) {
        log(0x1bd, "failed to load client public rsa key - less than 512 bits");
        return Ok(None);
    }
    Ok(Some(key))
}

/// PEM encoding of an RSA public key (`-----BEGIN PUBLIC KEY-----`, an
/// rsaEncryption `SubjectPublicKeyInfo`), readable by [`load_public_key`].
pub fn public_key_pem(key: &PublicKey) -> Result<String> {
    let rsa = key.rsa().ok_or_else(|| ProtoError::Invalid("not an RSA key".into()))?;
    Ok(pem::encode("PUBLIC KEY", &rsa.spki_der()))
}

#[cfg(test)]
mod testpki;
#[cfg(test)]
mod tests;
