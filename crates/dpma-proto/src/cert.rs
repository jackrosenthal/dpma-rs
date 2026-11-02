//! Phone certificate verification (`load_castore`, `session_verify_cert`).
//!
//! The CA store is built from a PEM bundle of CA certificates: by default
//! the ones built into the official DPMA, or the `phone_ca_file` when set.
//! A phone sends its certificates in its Handshake body, and they are
//! verified against the store.
//!
//! The official DPMA verifies with OpenSSL 1.1.1t's `X509_verify_cert`.
//! This module does not reproduce OpenSSL: it decodes certificates with the
//! `x509-cert` crate (strict DER) and makes the checks that the
//! certificates the module meets need.  Those are the built-in
//! certificates, the chains genuine phones send, and the test PKI.
//! `phone_ca_file` and `appserver_certificate` are meant for development
//! and testing only.
//!
//! # Reading
//!
//! Certificates are read from the `-----BEGIN CERTIFICATE-----` PEM blocks
//! of a text, in order; text around the blocks and blocks with other
//! labels are skipped.  A block is readable when its base64 text (white
//! space ignored) decodes to one DER certificate that `x509-cert` decodes,
//! with its basicConstraints and keyUsage extensions, if present, decoding
//! and occurring once.  Where the official DPMA logs OpenSSL's error text
//! for a certificate it cannot read, this module logs [`PARSE_ERROR`]
//! instead, whatever the reason.  A Handshake body is read as a C string,
//! up to its first NUL, as the official DPMA reads it.
//!
//! # Verification
//!
//! The certificate verified is the only one of a legacy body, or the last
//! of a three-certificate body, with the second and third as the
//! certificates that may complete its chain (see [`verify_client_chain`]).
//! The checks follow, in order.  The first that fails is logged with the
//! text OpenSSL's `X509_verify_cert_error_string` gives for it, which the
//! official DPMA logs.
//!
//! 1. **The chain.**  From the phone's certificate on, the issuer of a
//!    certificate is the first certificate, not yet in the chain, whose
//!    subject matches the certificate's issuer name.  It is searched for
//!    in the store first, then, as long as no store certificate is in the
//!    chain, among the phone's certificates.  Two names match when they
//!    have the same attributes in the same order, with equal values, where
//!    a PrintableString, UTF8String, or IA5String value equals one of the
//!    others with the same octets.  (Digium's CA writes its name both
//!    ways: the built-in AppServer certificate's issuer name has
//!    PrintableString values where the subject of the valid built-in
//!    "Digium Appserver" certificate has UTF8String ones.)  The chain ends
//!    at a self-issued certificate (its subject matching its issuer),
//!    which must be in the store byte for byte: that is the trust anchor.
//!    A phone's self-issued certificate is therefore trusted only if the
//!    store has the same certificate.  Errors: "unable
//!    to get local issuer certificate" (no issuer, and no store
//!    certificate in the chain), "unable to get issuer certificate" (no
//!    issuer for a store certificate that is not self-issued), "self
//!    signed certificate" (the phone's certificate is self-issued and not
//!    in the store), and "self signed certificate in certificate chain"
//!    (another certificate of the phone's is).
//! 2. **Extensions.**  No certificate in the chain may have a critical
//!    extension other than basicConstraints and keyUsage, which are
//!    checked, and extendedKeyUsage, subjectAltName, certificatePolicies,
//!    policyMappings, policyConstraints, inhibitAnyPolicy, and the Netscape
//!    certificate type, which are accepted unchecked, as OpenSSL 1.1.1t
//!    accepts them without a purpose or a policy check ("unhandled critical
//!    extension").  Every issuer (every certificate after the phone's)
//!    must have basicConstraints with CA:TRUE, except that a v1 trust
//!    anchor needs none ("invalid CA certificate"); if it has keyUsage,
//!    keyCertSign must be set ("key usage does not include certificate
//!    signing"); and its pathLenConstraint, if any, must be at least the
//!    number of intermediate certificates below it ("path length
//!    constraint exceeded").
//! 3. **Signatures.**  Every certificate but the trust anchor must be
//!    signed with the key of the next one in the chain: RSA PKCS#1 v1.5
//!    with SHA-1 or SHA-256 (sha1WithRSAEncryption or
//!    sha256WithRSAEncryption), the same algorithm in the signed part as
//!    outside it, and an RSA key of 512 to 4096 bits (the `rsa` crate's
//!    limit).  Anything else is "certificate signature failure".  The trust
//!    anchor's own signature is not checked.
//!
//! Validity periods are not checked: the official DPMA's verify callback
//! ignores OpenSSL's "certificate is not yet valid" and "certificate has
//! expired".
//!
//! The public key of the verified certificate is returned for the session
//! (the common password is encrypted to it).

mod verify;

use crate::{LogLevel, ProtoError, Result};
use base64::Engine;
use dpma_bytes::{bformat, ByteSlice};
use x509_cert::der::{Decode, Header, Reader, SliceReader, Tag, Tagged};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
use x509_cert::name::Name;

pub use crate::rsakey::RsaKey;

/// What is logged, where the official DPMA logs OpenSSL's error text, for a
/// certificate that cannot be read (see the module documentation).
pub const PARSE_ERROR: &str = "certificate parse error";

/// What is logged for an intermediate certificate with a negative serial
/// number (where the official DPMA logs whatever OpenSSL error is queued).
pub const NEGATIVE_SERIAL: &str = "negative serial number";

/// A certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// An RSA key (rsaEncryption).
    Rsa(RsaKey),
    /// A key of another type, which the common password cannot be
    /// encrypted to.
    Other,
}

impl PublicKey {
    /// The RSA key, if it is one.
    pub fn rsa(&self) -> Option<&RsaKey> {
        match self {
            PublicKey::Rsa(k) => Some(k),
            PublicKey::Other => None,
        }
    }
}

/// A certificate, as `x509-cert` decodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The DER encoding as it came.
    der: Vec<u8>,
    /// The signed part (`TBSCertificate`) as it came.
    tbs: Vec<u8>,
    cert: x509_cert::Certificate,
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    key: Option<PublicKey>,
}

impl Certificate {
    /// Decode a DER certificate: None if `x509-cert` refuses it, or its
    /// basicConstraints or keyUsage extension does not decode or occurs
    /// more than once.
    fn from_der(der: &[u8]) -> Option<Certificate> {
        let cert = x509_cert::Certificate::from_der(der).ok()?;
        // The signature is checked over the signed part as it came, not
        // as x509-cert would encode it again.
        let mut reader = SliceReader::new(der).ok()?;
        Header::decode(&mut reader).ok()?;
        let tbs = reader.tlv_bytes().ok()?.to_vec();
        let t = &cert.tbs_certificate;
        let basic_constraints = t.get::<BasicConstraints>().ok()?.map(|(_, e)| e);
        let key_usage = t.get::<KeyUsage>().ok()?.map(|(_, e)| e);
        let key = decode_key(&t.subject_public_key_info);
        Some(Certificate {
            der: der.to_vec(),
            tbs,
            cert,
            basic_constraints,
            key_usage,
            key,
        })
    }

    /// The certificate's DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Its public key; None for an RSA key that does not decode.
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.key.as_ref()
    }

    /// The serial number as the official DPMA reads it,
    /// `strtoll(BN_bn2dec(serial))` (so a value too large saturates), or
    /// None when it is negative.
    fn serial(&self) -> Option<i64> {
        let b = self.cert.tbs_certificate.serial_number.as_bytes();
        if b.first().is_some_and(|&x| x & 0x80 != 0) {
            return None;
        }
        let digits = &b[b.iter().take_while(|&&x| x == 0).count()..];
        if digits.len() > 8 {
            return Some(i64::MAX);
        }
        let v = digits.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x));
        Some(i64::try_from(v).unwrap_or(i64::MAX))
    }

    /// Does the subject match the issuer name?
    fn self_issued(&self) -> bool {
        names_match(
            &self.cert.tbs_certificate.subject,
            &self.cert.tbs_certificate.issuer,
        )
    }
}

/// Do two names match (see the module documentation)?
fn names_match(a: &Name, b: &Name) -> bool {
    fn text(v: &x509_cert::der::Any) -> Option<&[u8]> {
        matches!(
            v.tag(),
            Tag::PrintableString | Tag::Utf8String | Tag::Ia5String
        )
        .then(|| v.value())
    }
    a.0.len() == b.0.len()
        && a.0.iter().zip(&b.0).all(|(x, y)| {
            x.0.len() == y.0.len()
                && x.0.iter().zip(y.0.iter()).all(|(v, w)| {
                    v.oid == w.oid
                        && match (text(&v.value), text(&w.value)) {
                            (Some(s), Some(t)) => s == t,
                            _ => v.value == w.value,
                        }
                })
        })
}

/// The public key of a `SubjectPublicKeyInfo`.
fn decode_key(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Option<PublicKey> {
    if spki.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
        return Some(PublicKey::Other);
    }
    let k = rsa::pkcs1::RsaPublicKey::from_der(spki.subject_public_key.as_bytes()?).ok()?;
    Some(PublicKey::Rsa(RsaKey::from_be_bytes(
        k.modulus.as_bytes(),
        k.public_exponent.as_bytes(),
    )))
}

/// The certificates in the `CERTIFICATE` PEM blocks of `text`, in order;
/// None for a block that cannot be read (a BEGIN line without an END line
/// takes the rest of the text).
fn pem_certificates(text: &[u8]) -> impl Iterator<Item = Option<Certificate>> + '_ {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut rest = text;
    std::iter::from_fn(move || {
        let body = &rest[rest.find(BEGIN)? + BEGIN.len()..];
        let Some(len) = body.find(END) else {
            rest = b"";
            return Some(None);
        };
        rest = &body[len + END.len()..];
        let b64: Vec<u8> = body[..len]
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD.decode(b64).ok();
        Some(der.and_then(|d| Certificate::from_der(&d)))
    })
}

/// The trusted CA certificates phones are verified against (the official
/// DPMA's `X509_STORE`).
pub struct CaStore {
    certs: Vec<Certificate>,
}

impl CaStore {
    /// Build a store from a PEM bundle: every certificate in it.  A block
    /// that cannot be read is an error, as is a bundle without
    /// certificates.
    pub fn from_pem(pem: &[u8]) -> Result<CaStore> {
        let certs = pem_certificates(pem)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                ProtoError::Invalid(format!("Error parsing CA certificates: {}", PARSE_ERROR))
            })?;
        if certs.is_empty() {
            return Err(ProtoError::Invalid("No CA certificates found".into()));
        }
        Ok(CaStore { certs })
    }
}

/// Who presented the certificate; only used in the official DPMA's log
/// messages.  A missing MAC prints as "(null)", as glibc prints the
/// official DPMA's NULL pointer.
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
    /// Its public key (`X509_get_pubkey`); `None` for an RSA key that does
    /// not decode, which the official DPMA only notices when it generates
    /// the common password ("failed to get pkey during common password
    /// generation").
    pub public_key: Option<PublicKey>,
    /// The intermediate certificate's serial number as the official DPMA
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

/// Why verification failed (already logged as the official DPMA logs it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    /// No certificate could be read.
    Unreadable,
    /// More than one certificate, but not three; the count excludes the
    /// first certificate, as in the official DPMA's message.
    WrongChainLength(usize),
    /// The intermediate's serial number is negative.
    NoSerial,
    /// Verification failed, with the error text.
    Verify(&'static str),
}

impl CertError {
    /// The message the official DPMA logs for this error (with its newline,
    /// except for the chain length message, which has none).
    pub fn log_message(&self, contact: &[u8]) -> Vec<u8> {
        match self {
            CertError::Unreadable => bformat!(
                "<{}>: Unable to read client cert: {}\n",
                contact,
                PARSE_ERROR
            ),
            CertError::WrongChainLength(n) => {
                bformat!(
                    "<{}>: Expected two certificates in the chain, found {}",
                    contact,
                    n
                )
            }
            CertError::NoSerial => {
                bformat!(
                    "<{}>: Unable to get serial number of intermediate cert: {}\n",
                    contact,
                    NEGATIVE_SERIAL
                )
            }
            CertError::Verify(e) => {
                bformat!("<{}>: Client cert failed to verify: {}\n", contact, e)
            }
        }
    }
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self.log_message(b"");
        f.write_str(
            String::from_utf8_lossy(&msg)
                .trim_start_matches("<>: ")
                .trim_end(),
        )
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
/// OpenSSL's PEM reader does not accept.  (This module's reader does, but
/// the body is also saved in AstDB, where the official DPMA may read it.)
/// This puts a line break before every `-----BEGIN ` and `-----END `
/// marker line that does not start the text or a line, and after every
/// such line that is not followed by one or by the end of the text.
/// Well-formed PEM text is returned unchanged.
pub fn restore_pem_newlines(pem: impl AsRef<[u8]>) -> Vec<u8> {
    const DASHES: &[u8] = b"-----";
    let pem = pem.as_ref();
    let mut out = Vec::with_capacity(pem.len() + 8);
    let mut rest = pem;
    loop {
        let start = [rest.find("-----BEGIN "), rest.find("-----END ")]
            .into_iter()
            .flatten()
            .min();
        let Some(start) = start else {
            out.extend_from_slice(rest);
            return out;
        };
        out.extend_from_slice(&rest[..start]);
        let at = &rest[start..];
        let label_start = if at.starts_with(b"-----BEGIN ") {
            11
        } else {
            9
        };
        let label_len = at[label_start..]
            .find_byteset(b"-\r\n")
            .unwrap_or(at.len() - label_start);
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

/// Verify the PEM certificate(s) a phone sent in its Handshake body
/// (`session_verify_cert`, FUN_00148230), logging as the official DPMA
/// does.
///
/// The certificates are read in order; reading stops at the first block
/// after the first that cannot be read.  One certificate is the legacy
/// form, verified directly against `store`.  Otherwise there must be
/// exactly three: the first is ignored (it is the legacy certificate for
/// older servers), the second is the intermediate (its serial is
/// reported), and the last is the phone certificate, verified with the
/// second and third as the certificates that may complete its chain.  See
/// the module documentation for what verification checks.
pub fn verify_client_chain(
    store: &CaStore,
    pem: impl AsRef<[u8]>,
    client: &ClientInfo,
) -> std::result::Result<VerifiedClient, CertError> {
    let who = || {
        let mac: &[u8] = client.mac.unwrap_or(b"(null)");
        bformat!(
            "Contact: {} MAC: {} UA: {}",
            client.contact,
            mac,
            client.user_agent
        )
    };
    let fail = |line: u32, e: CertError| {
        log(LogLevel::Dpma, line, &e.log_message(client.contact));
        Err(e)
    };
    // The official DPMA copies the body with strlen.
    let mut certs = pem_certificates(crate::cbuf::c_bytes(pem.as_ref()));
    let first = certs.next().flatten();
    let mut chain: Option<Vec<Certificate>> = None;
    let mut serial: i64 = 0;
    // The serial number is read from the second certificate (and the
    // following ones while it reads as 0) as the certificates are read.
    while let Some(Some(x)) = certs.next() {
        let s = x.serial();
        chain.get_or_insert_with(Vec::new).push(x);
        if serial == 0 {
            let Some(s) = s else {
                return fail(0x22b, CertError::NoSerial);
            };
            serial = s;
            log(
                LogLevel::Debug(1),
                0x22f,
                &bformat!("{} Intermediate cert serial number: {}\n", who(), s),
            );
        }
    }
    let (cert, untrusted, legacy) = match &chain {
        None => {
            log(
                LogLevel::Debug(1),
                0x235,
                &bformat!("{} Using legacy certificate\n", who()),
            );
            match &first {
                Some(c) => (c, &[][..], true),
                None => return fail(0x23a, CertError::Unreadable),
            }
        }
        Some(c) if c.len() != 2 => return fail(0x23f, CertError::WrongChainLength(c.len())),
        Some(c) => (&c[1], c.as_slice(), false),
    };
    match verify::verify(&store.certs, cert, untrusted) {
        Ok(()) => Ok(VerifiedClient {
            public_key: cert.public_key().cloned(),
            certificate: cert.clone(),
            intermediate_serial: serial,
            legacy,
        }),
        Err(e) => fail(0x258, CertError::Verify(e)),
    }
}

#[cfg(test)]
mod testpki;
#[cfg(test)]
mod tests;
