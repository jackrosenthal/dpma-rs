//! The verifier's tests, with the official trust material and identities
//! minted the way the phones mint theirs.

use super::verify::*;
use super::*;
use base64::Engine;
use x509_cert::certificate::Version;

const CLIENT: ClientInfo = ClientInfo {
    contact: b"sip:phone@127.0.0.1:5060",
    mac: Some(b"000fd3000001"),
    user_agent: b"Digium D65 2_9_17",
};

fn verify(
    store: &CaStore,
    body: impl AsRef<[u8]>,
) -> std::result::Result<VerifiedClient, CertError> {
    verify_client_chain(store, body, &CLIENT)
}

/// A `CERTIFICATE` PEM block for `der`.
fn pem_of(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// The phone CA's certificate, ending in a line break.
fn ca_pem() -> String {
    let mut ca = String::from_utf8(phone_ca_certificate_pem().to_vec()).unwrap();
    if !ca.ends_with('\n') {
        ca.push('\n');
    }
    ca
}

/// A minted identity's certificate, the CA's, and the chain form (the
/// legacy certificate, the CA's, and the identity's).
struct Minted {
    der: Vec<u8>,
    legacy: String,
    chain: String,
}

fn minted() -> Minted {
    let ca = ca_pem();
    let legacy = PhoneIdentity::generate().unwrap();
    let phone = PhoneIdentity::generate().unwrap();
    let phone_pem = String::from_utf8(phone.certificate_pem.clone()).unwrap();
    let legacy_pem = String::from_utf8(legacy.certificate_pem).unwrap();
    Minted {
        der: phone.certificate_der().unwrap(),
        chain: format!("{legacy_pem}{ca}{phone_pem}"),
        legacy: phone_pem,
    }
}

#[test]
fn shareable_between_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<CaStore>();
    send_sync::<VerifiedClient>();
}

#[test]
fn pem_newlines_restored() {
    let m = minted();
    let store = CaStore::builtin();
    // Well-formed text (LF or CRLF) and text without markers are
    // unchanged.
    for body in [&m.legacy, &m.chain] {
        assert_eq!(restore_pem_newlines(body), body.as_bytes());
        let crlf = body.replace('\n', "\r\n");
        assert_eq!(restore_pem_newlines(&crlf), crlf.as_bytes());
    }
    for t in [
        "",
        "hello",
        "-----",
        "a-----b",
        "-----BEGIN",
        "-----BEGIN CERT",
        "x-----BEGIN CERT\n-----",
        "-----END-----",
    ] {
        assert_eq!(restore_pem_newlines(t), t.as_bytes());
    }
    // Each kind of lost line break: after a BEGIN line, before an END
    // line, and between an END line and the next BEGIN line.
    assert_eq!(
        restore_pem_newlines("-----BEGIN CERTIFICATE-----AAAA\nBBBB-----END CERTIFICATE-----"),
        "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----".as_bytes()
    );
    assert_eq!(
        restore_pem_newlines(
            "-----END A-----\r\n-----BEGIN B----------END B----------BEGIN C-----x"
        ),
        "-----END A-----\r\n-----BEGIN B-----\n-----END B-----\n-----BEGIN C-----\nx".as_bytes()
    );
    assert_eq!(
        restore_pem_newlines("junk-----BEGIN A-----"),
        b"junk\n-----BEGIN A-----"
    );
    // Every line break at a PEM boundary lost (chunks ending right before
    // and after each BEGIN and END line): both forms are restored, and
    // verify.
    for body in [&m.legacy, &m.chain] {
        let broken = body.replace("-----\n", "-----").replace("\n-----", "-----");
        let fixed = restore_pem_newlines(&broken);
        assert_eq!(fixed, body.trim_end_matches('\n').as_bytes());
        assert!(verify(&store, &fixed).is_ok());
    }
}

#[test]
fn no_panics_on_damaged_input() {
    // The verifier sees what any device sends: damaged certificates must
    // be refused, never crash the module.  Every octet of the phone's
    // certificate changed several ways, and every truncation, as a legacy
    // certificate and as the last of a chain.
    let m = minted();
    let store = CaStore::builtin();
    let der = &m.der;
    let mut bodies: Vec<Vec<u8>> = (0..der.len()).map(|n| der[..n].to_vec()).collect();
    for i in 0..der.len() {
        for v in [
            0x00,
            0x01,
            0x1f,
            0x30,
            0x7f,
            0x80,
            0x81,
            0x84,
            0xff,
            der[i] ^ 0x80,
        ] {
            let mut d = der.clone();
            d[i] = v;
            bodies.push(d);
        }
    }
    let ca = ca_pem();
    let first = m
        .chain
        .split_inclusive("-----END CERTIFICATE-----\n")
        .next();
    for d in bodies {
        let one = pem_of(&d);
        let _ = verify(&store, &one);
        let _ = verify(&store, format!("{}{ca}{one}", first.unwrap()));
    }
}

#[test]
fn embedded_trust_material() {
    // The bundle reads as three self-issued certificates: the Sangoma
    // root (v3, CA:TRUE, 4096 bits), the Digium AppServer CA as a v1
    // certificate, and the same CA (same key) as an expired v3
    // certificate with CA:TRUE.
    let certs: Vec<Certificate> = pem_certificates(DEFAULT_PHONE_CA)
        .map(Option::unwrap)
        .collect();
    assert_eq!(certs.len(), 3);
    for c in &certs {
        assert!(c.self_issued());
    }
    let versions: Vec<_> = certs
        .iter()
        .map(|c| c.cert.tbs_certificate.version)
        .collect();
    assert_eq!(versions, [Version::V3, Version::V1, Version::V3]);
    let ca: Vec<_> = certs
        .iter()
        .map(|c| c.basic_constraints.as_ref().map(|bc| bc.ca))
        .collect();
    assert_eq!(ca, [Some(true), None, Some(true)]);
    let bits: Vec<usize> = certs
        .iter()
        .map(|c| c.public_key().unwrap().rsa().unwrap().bits())
        .collect();
    assert_eq!(bits, [4096, 1024, 1024]);
    assert_eq!(certs[1].public_key(), certs[2].public_key());
    let store = CaStore::builtin();
    // Each verifies as a phone's legacy certificate (it is in the store).
    for c in &certs {
        assert!(verify(&store, pem_of(c.der())).is_ok());
    }
    // The AppServer certificate (v1, a 512-bit key, SHA-256) is issued by
    // "Digium Appserver": it verifies against the bundle, against either
    // Digium Appserver certificate alone, and not against the Sangoma
    // root.
    let app: Vec<Certificate> = pem_certificates(DEFAULT_APPSERVER_CERTIFICATE)
        .map(Option::unwrap)
        .collect();
    assert_eq!(app.len(), 1);
    assert_eq!(app[0].cert.tbs_certificate.version, Version::V1);
    assert_eq!(app[0].public_key().unwrap().rsa().unwrap().bits(), 512);
    let v = verify(&store, DEFAULT_APPSERVER_CERTIFICATE).unwrap();
    assert!(v.legacy);
    assert_eq!(v.certificate, app[0]);
    let only = |i: usize| CaStore::from_pem(pem_of(certs[i].der()).as_bytes()).unwrap();
    assert!(verify(&only(1), DEFAULT_APPSERVER_CERTIFICATE).is_ok());
    assert!(verify(&only(2), DEFAULT_APPSERVER_CERTIFICATE).is_ok());
    assert_eq!(
        verify(&only(0), DEFAULT_APPSERVER_CERTIFICATE).err(),
        Some(CertError::Verify(UNABLE_TO_GET_ISSUER_CERT_LOCALLY))
    );
}
