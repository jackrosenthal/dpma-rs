//! The phone's side of certificate-based communication: the provisioning
//! CA private key, and phone identities minted the way the phones mint
//! theirs.
//!
//! Every phone ships the provisioning CA's private key (`/etc/cakey.pem`),
//! so it is effectively public and embedded here.  Each phone mints its
//! identity at first boot: a fresh 512-bit RSA key, and a certificate
//! with the subject `C=US, ST=CA, O=Digium, Inc, CN=Digium Appserver`,
//! serial `0x55`, 30-year validity, and a SHA-1 signature, issued by that
//! CA.  Minted identities verify against [`super::DEFAULT_PHONE_CA`]
//! exactly as genuine phones' do.

use std::sync::OnceLock;

use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Any, PrintableStringRef, SetOfVec, Utf8StringRef};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::EncodePem;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

use crate::{ProtoError, Result};

use super::{base64_text, pem_certificate_blocks, Certificate, DEFAULT_PHONE_CA};

/// The provisioning CA's private key (PKCS#8 PEM).  Its certificate is in
/// [`super::DEFAULT_PHONE_CA`].
pub const DEFAULT_PHONE_CA_KEY: &[u8] = include_bytes!("../trust/cakey.pem");

/// The provisioning CA private key of [`DEFAULT_PHONE_CA_KEY`].
pub fn phone_ca_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::from_pkcs8_pem(
            std::str::from_utf8(DEFAULT_PHONE_CA_KEY).expect("the embedded phone CA key is UTF-8"),
        )
        .expect("the embedded phone CA key parses")
    })
}

/// The certificate of [`phone_ca_key`] that the phones present as the
/// middle certificate of the chain form: the self-signed certificate of
/// that key in [`super::DEFAULT_PHONE_CA`] with the latest `notBefore`.
/// A `CERTIFICATE` PEM block.
pub fn phone_ca_certificate_pem() -> &'static [u8] {
    static PEM: OnceLock<&'static [u8]> = OnceLock::new();
    PEM.get_or_init(|| {
        let ca_key = phone_ca_key();
        let mut best: Option<(std::time::Duration, &'static [u8])> = None;
        for block in pem_certificate_blocks(DEFAULT_PHONE_CA) {
            let Some(cert) = block_certificate(block) else {
                continue;
            };
            if !cert.self_issued() || !has_ca_public_key(&cert, ca_key) {
                continue;
            }
            let not_before = cert
                .cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration();
            if best.as_ref().is_none_or(|(t, _)| not_before > *t) {
                best = Some((not_before, block));
            }
        }
        best.map(|(_, b)| b)
            .expect("the phone CA certificate is in the built-in store")
    })
}

/// The subject name of [`phone_ca_certificate_pem`], as the minted
/// certificates name their issuer.
pub fn phone_ca_subject() -> &'static Name {
    static NAME: OnceLock<Name> = OnceLock::new();
    NAME.get_or_init(|| {
        block_certificate(phone_ca_certificate_pem())
            .expect("the phone CA certificate parses")
            .cert
            .tbs_certificate
            .subject
            .clone()
    })
}

/// A phone identity: the certificate the Handshake presents and the
/// private key that decrypts the common password encrypted to it.
#[derive(Clone)]
pub struct PhoneIdentity {
    /// The certificate, PEM (the Handshake body of the legacy form).
    pub certificate_pem: Vec<u8>,
    /// The private key of the certificate.
    pub private_key: RsaPrivateKey,
}

impl PhoneIdentity {
    /// Mints a fresh identity; see the module documentation for what the
    /// certificate contains.
    pub fn generate() -> Result<PhoneIdentity> {
        Self::generate_with(
            std::time::SystemTime::now(),
            std::time::SystemTime::now() + std::time::Duration::from_secs(946_080_000),
            Some((phone_ca_key(), phone_ca_subject())),
        )
    }

    /// Like [`generate`], but valid from `not_before` to `not_after`, and
    /// issued by `issuer`'s key with its name as the issuer name (or
    /// self-signed, with the phones' subject as the issuer name, when
    /// `issuer` is `None`).
    pub fn generate_with(
        not_before: std::time::SystemTime,
        not_after: std::time::SystemTime,
        issuer: Option<(&RsaPrivateKey, &Name)>,
    ) -> Result<PhoneIdentity> {
        let key = RsaPrivateKey::new(&mut OsRng, 512)
            .map_err(|e| ProtoError::Invalid(format!("RSA key generation failed: {}", e)))?;
        let validity = Validity {
            not_before: Time::try_from(not_before).map_err(|e| invalid("notBefore", e))?,
            not_after: Time::try_from(not_after).map_err(|e| invalid("notAfter", e))?,
        };
        Ok(PhoneIdentity {
            certificate_pem: mint_certificate(&key, SerialNumber::from(0x55u64), validity, issuer)?,
            private_key: key,
        })
    }

    /// The certificate's DER encoding.
    pub fn certificate_der(&self) -> Result<Vec<u8>> {
        pem_certificate_der(&self.certificate_pem)
    }

    /// The body of a Handshake in the legacy form: this certificate alone.
    pub fn legacy_body(&self) -> Vec<u8> {
        self.certificate_pem.clone()
    }

    /// The body of a Handshake in the chain form: the `legacy` certificate
    /// (which servers ignore), the CA's certificate, and this one.
    pub fn chain_body(&self, legacy: &PhoneIdentity) -> Vec<u8> {
        let mut ca = phone_ca_certificate_pem().to_vec();
        if !ca.ends_with(b"\n") {
            ca.push(b'\n');
        }
        [
            legacy.certificate_pem.as_slice(),
            &ca,
            &self.certificate_pem,
        ]
        .concat()
    }
}

/// The static subject of the phones' certificates.
pub(crate) fn phone_subject() -> Result<Name> {
    let atv = |oid: &str, value: Any| -> Result<RelativeDistinguishedName> {
        let set = SetOfVec::try_from(vec![AttributeTypeAndValue {
            oid: ObjectIdentifier::new_unwrap(oid),
            value,
        }])
        .map_err(|e| invalid(oid, e))?;
        Ok(RelativeDistinguishedName::from(set))
    };
    let printable = |oid: &str, value: &str| -> Result<RelativeDistinguishedName> {
        atv(
            oid,
            Any::encode_from(&PrintableStringRef::new(value).map_err(|e| invalid(oid, e))?)
                .map_err(|e| invalid(oid, e))?,
        )
    };
    let utf8 = |oid: &str, value: &str| -> Result<RelativeDistinguishedName> {
        atv(
            oid,
            Any::encode_from(&Utf8StringRef::new(value).map_err(|e| invalid(oid, e))?)
                .map_err(|e| invalid(oid, e))?,
        )
    };
    Ok(RdnSequence(vec![
        printable("2.5.4.6", "US")?,
        utf8("2.5.4.8", "CA")?,
        utf8("2.5.4.10", "Digium, Inc")?,
        utf8("2.5.4.3", "Digium Appserver")?,
    ]))
}

/// Mints a `CERTIFICATE` PEM for `key`'s public key, signed with SHA-1 by
/// `issuer`'s key (or by `key` itself, with its subject as the issuer,
/// when `issuer` is `None`), with `serial` and `validity`, and the leaf
/// profile's extensions.
pub(crate) fn mint_certificate(
    key: &RsaPrivateKey,
    serial: SerialNumber,
    validity: Validity,
    issuer: Option<(&RsaPrivateKey, &Name)>,
) -> Result<Vec<u8>> {
    let subject = phone_subject()?;
    let (signer_key, issuer_name) = match issuer {
        None => (key, subject.clone()),
        Some((k, n)) => (k, n.clone()),
    };
    let signer = SigningKey::<sha1::Sha1>::new(signer_key.clone());
    let spki = SubjectPublicKeyInfoOwned::from_key(key.to_public_key())
        .map_err(|e| invalid("subject public key info", e))?;
    let b = CertificateBuilder::new(
        Profile::Leaf {
            issuer: issuer_name,
            enable_key_agreement: false,
            enable_key_encipherment: true,
            include_subject_key_identifier: true,
        },
        serial,
        validity,
        subject,
        spki,
        &signer,
    )
    .map_err(|e| invalid("certificate builder", e))?;
    let cert = b
        .build::<rsa::pkcs1v15::Signature>()
        .map_err(|e| invalid("certificate", e))?;
    cert.to_pem(LineEnding::LF)
        .map(String::into_bytes)
        .map_err(|e| invalid("PEM", e))
}

/// Whether `cert` carries the public key of `ca_key`.
fn has_ca_public_key(cert: &Certificate, ca_key: &RsaPrivateKey) -> bool {
    let k = super::RsaKey::from_be_bytes(&ca_key.n().to_bytes_be(), &ca_key.e().to_bytes_be());
    cert.public_key() == Some(&super::PublicKey::Rsa(k))
}

/// The DER certificate of a `CERTIFICATE` PEM block; None when the block
/// does not decode.
fn block_certificate(block: &[u8]) -> Option<Certificate> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(base64_text(block))
        .ok()?;
    Certificate::from_der(&der)
}

fn pem_certificate_der(pem: &[u8]) -> Result<Vec<u8>> {
    let blocks = pem_certificate_blocks(pem);
    let Some(block) = blocks.first() else {
        return Err(ProtoError::Invalid("no PEM certificate".into()));
    };
    base64::engine::general_purpose::STANDARD
        .decode(base64_text(block))
        .map_err(|e| ProtoError::Invalid(format!("unreadable PEM certificate: {}", e)))
}

fn invalid(what: &str, e: impl std::fmt::Display) -> ProtoError {
    ProtoError::Invalid(format!("certificate {what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{verify_client_chain, CaStore, ClientInfo};

    #[test]
    fn ca_key_matches_its_certificate() {
        let cert =
            block_certificate(phone_ca_certificate_pem()).expect("the phone CA certificate parses");
        assert!(cert.self_issued());
        assert!(has_ca_public_key(&cert, phone_ca_key()));
    }

    #[test]
    fn minted_identity_verifies_as_legacy() {
        let id = PhoneIdentity::generate().unwrap();
        let client = verify_client_chain(
            &CaStore::builtin(),
            &id.certificate_pem,
            &ClientInfo::default(),
        )
        .expect("a minted phone identity verifies");
        assert!(client.legacy);
        assert_eq!(client.intermediate_serial, 0);
        assert!(client.handshake_version().is_none());
    }

    #[test]
    fn chain_form_verifies_with_a_version() {
        let a = PhoneIdentity::generate().unwrap();
        let b = PhoneIdentity::generate().unwrap();
        let mut body = a.certificate_pem.clone();
        body.extend_from_slice(phone_ca_certificate_pem());
        body.extend_from_slice(&b.certificate_pem);
        let client = verify_client_chain(&CaStore::builtin(), &body, &ClientInfo::default())
            .expect("the chain form of a minted identity verifies");
        assert!(!client.legacy);
        // The middle certificate's serial (0xc59a7e173d539fb5) saturates,
        // as the official DPMA's strtoll of it does.
        assert_eq!(client.intermediate_serial, i64::MAX);
        assert_eq!(client.handshake_version(), Some("1"));
    }

    #[test]
    fn common_password_round_trips() {
        use crate::crypto::{decrypt_common_password, encrypt_common_password};
        let id = PhoneIdentity::generate().unwrap();
        let client = verify_client_chain(
            &CaStore::builtin(),
            &id.certificate_pem,
            &ClientInfo::default(),
        )
        .unwrap();
        let password = crate::crypto::new_common_password().unwrap();
        let b64 = encrypt_common_password(client.public_key.as_ref().unwrap(), &password).unwrap();
        assert_eq!(
            decrypt_common_password(&id.private_key, &b64).unwrap(),
            password
        );
    }
}
