//! The simulator's view of the test PKI (made by [`crate::mkpki`]).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use regex::bytes::Regex;
use rsa::pkcs8::DecodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::Value;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

use super::crypto::load_private_key;

/// The test PKI directory with its `bundles.json`.
pub struct Pki {
    /// The directory.
    pub dir: PathBuf,
    /// The parsed `bundles.json`.
    pub manifest: Value,
}

/// A handshake bundle: the request body and the key that decrypts the
/// common password.
pub struct Bundle {
    /// The certificates in body order, concatenated (PEM).
    pub body: Vec<u8>,
    /// The private key of the last certificate.
    pub key: RsaPrivateKey,
}

impl Pki {
    /// Opens the PKI in `dir` (fails when there is no `bundles.json`).
    pub fn open(dir: &Path) -> Result<Pki> {
        let path = dir.join("bundles.json");
        if !path.exists() {
            bail!("no test PKI in {}; run dpma-mkpki first", dir.display());
        }
        let text = std::fs::read_to_string(&path)?;
        let manifest = serde_json::from_str(&text).with_context(|| path.display().to_string())?;
        Ok(Pki {
            dir: dir.to_path_buf(),
            manifest,
        })
    }

    /// The names of the bundles.
    pub fn bundle_names(&self) -> Vec<String> {
        self.manifest["bundles"]
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Loads the bundle `name`.
    pub fn bundle(&self, name: &str) -> Result<Bundle> {
        let Some(b) = self.manifest["bundles"].get(name) else {
            bail!(
                "unknown bundle {name:?} (have: {})",
                self.bundle_names().join(", ")
            );
        };
        let mut body = Vec::new();
        for c in b["certs"].as_array().into_iter().flatten() {
            let f = self.dir.join(c.as_str().unwrap_or_default());
            body.extend(std::fs::read(&f).with_context(|| f.display().to_string())?);
        }
        let key = load_private_key(&self.dir.join(b["key"].as_str().unwrap_or_default()))?;
        Ok(Bundle { body, key })
    }

    /// Verifies the certificate in a HandshakeResponse body against the
    /// test AppServer CA: `(true, subject)` or `(false, why)`.
    pub fn check_appserver(&self, body: &[u8]) -> (bool, String) {
        let Some(der) = pem_certificates(body).into_iter().next() else {
            return (false, "no certificate in the HandshakeResponse body".into());
        };
        let cert = match Certificate::from_der(&der) {
            Ok(c) => c,
            Err(e) => return (false, format!("unparsable AppServer certificate: {e}")),
        };
        let ca_file = self.dir.join(
            self.manifest["appserver_ca"]
                .as_str()
                .unwrap_or("appserver-ca.pem"),
        );
        let ca = match std::fs::read(&ca_file)
            .map_err(anyhow::Error::from)
            .and_then(|d| parse_certificate(&d))
        {
            Ok(c) => c,
            Err(e) => return (false, format!("cannot read {}: {e}", ca_file.display())),
        };
        let subject = cert.tbs_certificate.subject.to_string();
        if let Err(e) = verify_directly_issued_by(&cert, &ca) {
            return (
                false,
                format!("{subject} is not signed by the test AppServer CA ({e})"),
            );
        }
        if !within_validity(&cert) {
            return (false, format!("{subject} is outside its validity period"));
        }
        (true, subject)
    }
}

fn pem_block() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----").unwrap()
    })
}

/// The PEM certificate blocks in `data`, in order (each as it appears,
/// markers included).
pub fn pem_blocks(data: &[u8]) -> Vec<&[u8]> {
    pem_block().find_iter(data).map(|m| m.as_bytes()).collect()
}

/// The DER of every PEM certificate in `data` (blocks whose base64 does
/// not decode are skipped).  Line breaks inside a block do not matter.
pub fn pem_certificates(data: &[u8]) -> Vec<Vec<u8>> {
    pem_block()
        .captures_iter(data)
        .filter_map(|c| {
            let b64: Vec<u8> = c[1]
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            base64::engine::general_purpose::STANDARD.decode(b64).ok()
        })
        .collect()
}

/// The first certificate of a PEM text.
pub fn parse_certificate(pem: &[u8]) -> Result<Certificate> {
    let der = pem_certificates(pem)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no PEM certificate"))?;
    Certificate::from_der(&der).map_err(|e| anyhow!("unparsable certificate: {e}"))
}

/// The RSA public key of a certificate.
pub fn public_key(cert: &Certificate) -> Result<RsaPublicKey> {
    let der = cert.tbs_certificate.subject_public_key_info.to_der()?;
    RsaPublicKey::from_public_key_der(&der).map_err(|e| anyhow!("not an RSA key: {e}"))
}

/// Whether `cert` names `issuer` as its issuer and carries a valid
/// signature by its key.  No validity period, extension, or policy
/// checks.
pub fn verify_directly_issued_by(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    if cert.tbs_certificate.issuer.to_der()? != issuer.tbs_certificate.subject.to_der()? {
        bail!("Issuer certificate subject does not match certificate issuer");
    }
    let key = public_key(issuer)?;
    let tbs = cert.tbs_certificate.to_der()?;
    let sig = Signature::try_from(cert.signature.raw_bytes())
        .map_err(|e| anyhow!("bad signature: {e}"))?;
    let oid = cert.signature_algorithm.oid.to_string();
    let res = match oid.as_str() {
        "1.2.840.113549.1.1.5" => VerifyingKey::<sha1::Sha1>::new(key).verify(&tbs, &sig),
        "1.2.840.113549.1.1.11" => VerifyingKey::<sha2::Sha256>::new(key).verify(&tbs, &sig),
        "1.2.840.113549.1.1.12" => VerifyingKey::<sha2::Sha384>::new(key).verify(&tbs, &sig),
        "1.2.840.113549.1.1.13" => VerifyingKey::<sha2::Sha512>::new(key).verify(&tbs, &sig),
        other => bail!("unsupported signature algorithm {other}"),
    };
    res.map_err(|_| anyhow!("InvalidSignature"))
}

/// Whether now is within the certificate's validity period.
pub fn within_validity(cert: &Certificate) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let v = &cert.tbs_certificate.validity;
    v.not_before.to_unix_duration() <= now && now <= v.not_after.to_unix_duration()
}

/// The modulus size of an RSA private key, in bits.
pub fn key_bits(key: &RsaPrivateKey) -> usize {
    use rsa::traits::PublicKeyParts;
    key.n().bits()
}
