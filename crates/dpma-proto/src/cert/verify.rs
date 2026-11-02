//! Chain building and the checks of [`super`] (see its documentation),
//! with OpenSSL's error texts (`X509_verify_cert_error_string`).

use super::{names_match, Certificate, PublicKey};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha2::Digest;
use x509_cert::certificate::Version;
use x509_cert::der::oid::ObjectIdentifier;

pub(crate) const UNABLE_TO_GET_ISSUER_CERT: &str = "unable to get issuer certificate";
pub(crate) const CERT_SIGNATURE_FAILURE: &str = "certificate signature failure";
pub(crate) const DEPTH_ZERO_SELF_SIGNED_CERT: &str = "self signed certificate";
pub(crate) const SELF_SIGNED_CERT_IN_CHAIN: &str = "self signed certificate in certificate chain";
pub(crate) const UNABLE_TO_GET_ISSUER_CERT_LOCALLY: &str = "unable to get local issuer certificate";
pub(crate) const INVALID_CA: &str = "invalid CA certificate";
pub(crate) const PATH_LENGTH_EXCEEDED: &str = "path length constraint exceeded";
pub(crate) const KEYUSAGE_NO_CERTSIGN: &str = "key usage does not include certificate signing";
pub(crate) const UNHANDLED_CRITICAL_EXTENSION: &str = "unhandled critical extension";

const fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}

/// The extensions a certificate may mark critical.
const HANDLED: [ObjectIdentifier; 9] = [
    oid("2.5.29.19"), // basicConstraints
    oid("2.5.29.15"), // keyUsage
    oid("2.5.29.37"), // extendedKeyUsage
    oid("2.5.29.17"), // subjectAltName
    oid("2.5.29.32"), // certificatePolicies
    oid("2.5.29.33"), // policyMappings
    oid("2.5.29.36"), // policyConstraints
    oid("2.5.29.54"), // inhibitAnyPolicy
    oid("2.16.840.1.113730.1.1"), // Netscape certificate type
];

const SHA1_WITH_RSA: ObjectIdentifier = oid("1.2.840.113549.1.1.5");
const SHA256_WITH_RSA: ObjectIdentifier = oid("1.2.840.113549.1.1.11");

/// The smallest RSA key that verifies signatures, in bits.
const MIN_RSA_BITS: usize = 512;

/// Verify `leaf` against the store, with `untrusted` the certificates the
/// phone sent (which may include `leaf`).  Err holds the error text.
pub(crate) fn verify(store: &[Certificate], leaf: &Certificate, untrusted: &[Certificate]) -> Result<(), &'static str> {
    let chain = build_chain(store, leaf, untrusted)?;
    check_extensions(&chain)?;
    for pair in chain.windows(2) {
        if !signed_by(pair[0], pair[1]) {
            return Err(CERT_SIGNATURE_FAILURE);
        }
    }
    Ok(())
}

/// The chain from `leaf` to its trust anchor.
fn build_chain<'a>(
    store: &'a [Certificate],
    leaf: &'a Certificate,
    untrusted: &'a [Certificate],
) -> Result<Vec<&'a Certificate>, &'static str> {
    let in_store = |c: &Certificate| store.iter().any(|s| s.der == c.der);
    let mut chain = vec![leaf];
    let mut trusted = false;
    loop {
        let x = chain[chain.len() - 1];
        if x.self_issued() {
            if in_store(x) {
                return Ok(chain);
            }
            return Err(if chain.len() == 1 { DEPTH_ZERO_SELF_SIGNED_CERT } else { SELF_SIGNED_CERT_IN_CHAIN });
        }
        let issues_x = |c: &&Certificate| {
            names_match(&c.cert.tbs_certificate.subject, &x.cert.tbs_certificate.issuer)
                && !chain.iter().any(|d| d.der == c.der)
        };
        let issuer = match store.iter().find(issues_x) {
            Some(i) => {
                trusted = true;
                Some(i)
            }
            None if !trusted => untrusted.iter().find(issues_x),
            None => None,
        };
        match issuer {
            Some(i) => chain.push(i),
            None if trusted => return Err(UNABLE_TO_GET_ISSUER_CERT),
            None => return Err(UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
        }
    }
}

/// The critical extensions, and the issuers' basicConstraints and
/// keyUsage.
fn check_extensions(chain: &[&Certificate]) -> Result<(), &'static str> {
    for (i, c) in chain.iter().enumerate() {
        let t = &c.cert.tbs_certificate;
        if t.extensions.iter().flatten().any(|e| e.critical && !HANDLED.contains(&e.extn_id)) {
            return Err(UNHANDLED_CRITICAL_EXTENSION);
        }
        if i == 0 {
            continue;
        }
        let v1_anchor = i == chain.len() - 1 && t.version == Version::V1;
        match &c.basic_constraints {
            Some(bc) if bc.ca => {}
            None if v1_anchor => {}
            _ => return Err(INVALID_CA),
        }
        if c.key_usage.is_some_and(|ku| !ku.key_cert_sign()) {
            return Err(KEYUSAGE_NO_CERTSIGN);
        }
        // The intermediates below chain[i] are chain[1..i].
        if let Some(max) = c.basic_constraints.as_ref().and_then(|bc| bc.path_len_constraint) {
            if i - 1 > usize::from(max) {
                return Err(PATH_LENGTH_EXCEEDED);
            }
        }
    }
    Ok(())
}

/// Is `c` signed with `issuer`'s key?
fn signed_by(c: &Certificate, issuer: &Certificate) -> bool {
    let Some(PublicKey::Rsa(k)) = &issuer.key else { return false };
    let Ok(key) = RsaPublicKey::new(BigUint::from_bytes_be(&k.n()), BigUint::from_bytes_be(&k.e())) else {
        return false;
    };
    let alg = &c.cert.signature_algorithm;
    let Some(sig) = c.cert.signature.as_bytes() else { return false };
    if k.bits() < MIN_RSA_BITS || *alg != c.cert.tbs_certificate.signature {
        return false;
    }
    let verified = if alg.oid == SHA1_WITH_RSA {
        key.verify(Pkcs1v15Sign::new::<sha1::Sha1>(), &sha1::Sha1::digest(&c.tbs), sig)
    } else if alg.oid == SHA256_WITH_RSA {
        key.verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &sha2::Sha256::digest(&c.tbs), sig)
    } else {
        return false;
    };
    verified.is_ok()
}
