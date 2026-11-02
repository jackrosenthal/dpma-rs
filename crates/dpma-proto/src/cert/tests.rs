//! The verifier's cases.  Each expected outcome is what OpenSSL 1.1.1t's
//! `X509_verify_cert` (with the original's callback) gives, and the
//! comment says why, by the 1.1.1t function that decides it.

use super::testpki::*;
use super::*;
use crate::testlog;
use rsa::traits::PublicKeyParts;
use x509_cert::ext::pkix::KeyUsages;

const CLIENT: ClientInfo =
    ClientInfo { contact: b"sip:phone@127.0.0.1:5060", mac: Some(b"000fd3000001"), user_agent: b"Digium D65 2_9_17" };

struct Pki {
    root: Issued,
    inter: Issued,
    phone: Issued,
    legacy: Issued,
}

fn pki() -> Pki {
    let root = Spec::new("CN=Test Root,O=DPMA Test", 1).ca().ext(subject_key_id(b"root")).issue(None);
    let inter = Spec::new("CN=Test Intermediate,O=DPMA Test", 2)
        .serial(4660)
        .ca()
        .ext(subject_key_id(b"inter"))
        .ext(authority_key_id(b"root"))
        .issue(Some(&root));
    let phone = Spec::new("CN=000fd3000001,O=DPMA Test", 3)
        .serial(77)
        .ext(key_usage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment))
        .ext(authority_key_id(b"inter"))
        .issue(Some(&inter));
    let legacy =
        Spec::new("CN=legacy 000fd3000001,O=DPMA Test", 4).serial(5).ext(authority_key_id(b"root")).issue(Some(&root));
    Pki { root, inter, phone, legacy }
}

fn store_of(certs: &[&Issued]) -> CaStore {
    CaStore::from_pem(pem(certs).as_bytes()).unwrap()
}

fn verify(store: &CaStore, body: impl AsRef<[u8]>) -> std::result::Result<VerifiedClient, CertError> {
    verify_client_chain_at(store, body, &CLIENT, NOW)
}

/// The chain form: the legacy certificate, `inter`, and `phone`.
fn chain(p: &Pki, inter: &Issued, phone: &Issued) -> String {
    pem(&[&p.legacy, inter, phone])
}

/// The `X509_verify_cert_error_string` failure for error `code`.
fn failed(code: i32) -> std::result::Result<(), CertError> {
    Err(CertError::Verify(crate::x509::verify::error_string(code).to_string()))
}

fn outcome(r: std::result::Result<VerifiedClient, CertError>) -> std::result::Result<(), CertError> {
    r.map(|_| ())
}

/// The first error of an unreadable body.
fn unreadable(text: &str) -> std::result::Result<(), CertError> {
    Err(CertError::Unreadable(text.to_string()))
}

const NO_START_LINE: &str = "error:0909006C:PEM routines:get_name:no start line";

#[test]
fn shareable_between_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<CaStore>();
    send_sync::<VerifiedClient>();
}

#[test]
fn ca_store_loading() {
    let p = pki();
    let other = Spec::new("CN=Other Root", 5).ca().issue(None);
    // Text around the blocks and blocks with other labels are skipped;
    // "X509 CERTIFICATE" is read as a certificate; duplicates are kept
    // once (X509_STORE_add_cert).
    let bundle = format!(
        "# CA bundle\n{}junk\n-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n{}{}",
        p.root.pem(),
        other.pem().replace("CERTIFICATE", "X509 CERTIFICATE"),
        p.root.pem()
    );
    let s = CaStore::from_pem(bundle.as_bytes()).unwrap();
    assert_eq!(s.len(), 2);
    assert!(!s.is_empty());
    assert_eq!(CaStore::from_pem(b"").err().unwrap().message(), "No CA certificates found");
    assert_eq!(CaStore::from_pem(b"not a certificate").err().unwrap().message(), "No CA certificates found");
    // A malformed block is an error.
    let bad = format!("{}-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", p.root.pem());
    let e = CaStore::from_pem(bad.as_bytes()).err().unwrap();
    assert!(
        e.message().starts_with("Error parsing CA certificates: error:0D0680A8:asn1 encoding routines:asn1_check_tlen:wrong tag"),
        "{}",
        e.message()
    );
}

#[test]
fn legacy_form() {
    // A certificate issued by the store's self-signed root.
    let p = pki();
    let (r, logs) = testlog::capture(|| verify(&store_of(&[&p.root]), pem(&[&p.legacy])));
    let v = r.unwrap();
    assert!(v.legacy);
    assert_eq!(v.intermediate_serial, 0);
    assert_eq!(v.handshake_version(), None);
    assert_eq!(v.certificate.der(), p.legacy.der.as_slice());
    let k = v.public_key.unwrap();
    assert_eq!(k.rsa().unwrap().spki_der(), rsa::pkcs8::EncodePublicKey::to_public_key_der(&p.legacy.key.to_public_key()).unwrap().as_bytes());
    assert_eq!(logs, vec!["Contact: sip:phone@127.0.0.1:5060 MAC: 000fd3000001 UA: Digium D65 2_9_17 Using legacy certificate\n"]);
}

#[test]
fn chain_form() {
    let p = pki();
    let s = store_of(&[&p.root]);
    let (r, logs) = testlog::capture(|| verify(&s, chain(&p, &p.inter, &p.phone)));
    let v = r.unwrap();
    assert!(!v.legacy);
    assert_eq!(v.intermediate_serial, 4660);
    assert_eq!(v.handshake_version(), Some("1"));
    assert_eq!(v.certificate.der(), p.phone.der.as_slice());
    assert_eq!(
        logs,
        vec!["Contact: sip:phone@127.0.0.1:5060 MAC: 000fd3000001 UA: Digium D65 2_9_17 Intermediate cert serial number: 4660\n"]
    );
    // The first certificate is ignored entirely, even if it is signed by
    // nobody we trust.
    let junk = Spec::new("CN=junk", 6).issue(None);
    assert!(verify(&s, pem(&[&junk, &p.inter, &p.phone])).is_ok());
    // Text around and between the PEM blocks is skipped, CRLF works.
    let body = format!("garbage\n{}\nmore\n{}{}trailer", p.legacy.pem(), p.inter.pem(), p.phone.pem());
    assert!(verify(&s, &body).is_ok());
    assert!(verify(&s, body.replace('\n', "\r\n")).is_ok());
    // A body is a C string: nothing after a NUL is read.
    let cut = format!("{}\0{}{}", p.legacy.pem(), p.inter.pem(), p.phone.pem());
    assert!(verify(&s, &cut).unwrap().legacy);
}

#[test]
fn validity_period_ignored() {
    // Errors 9 and 10 are ignored by the original's callback
    // (FUN_00148210), for every certificate, the trust anchor too.
    let p = pki();
    let s = store_of(&[&p.root]);
    let expired = Spec::new("CN=old phone", 7).validity(time(2001, 1, 1), time(2002, 1, 1)).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&expired])).is_ok());
    let future = Spec::new("CN=new phone", 7).validity(time(2030, 1, 1), time(2060, 1, 1)).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&future])).is_ok());
    let root = Spec::new("CN=Old Root", 8).ca().validity(time(2001, 1, 1), time(2002, 1, 1)).issue(None);
    let inter = Spec::new("CN=Old Inter", 9).serial(9).ca().validity(time(2001, 1, 1), time(2002, 1, 1)).issue(Some(&root));
    let phone = Spec::new("CN=phone", 10).validity(time(2040, 1, 1), time(2041, 1, 1)).issue(Some(&inter));
    let v = verify(&store_of(&[&root]), pem(&[&phone, &inter, &phone])).unwrap();
    assert_eq!(v.intermediate_serial, 9);
    // A time before 1970 is fine (UTCTime 1965).
    let old = Spec::new("CN=old", 7).validity(time(1970, 1, 1), time(2035, 1, 1)).issue(Some(&p.root));
    let old = resign(&patch(&old.der, b"700101000000Z", b"650101000000Z"), &p.root.key, Hash::Sha256);
    let old_pem = crate::x509::pem::encode("CERTIFICATE", &old);
    assert!(verify(&s, &old_pem).is_ok());
}

#[test]
fn time_format_errors() {
    // X509_cmp_time returns 0 for a time that is not YYMMDDHHMMSSZ with
    // valid values; x509_check_cert_time reports 13 or 14, which the
    // callback does not ignore.
    let p = pki();
    let s = store_of(&[&p.root]);
    let base = Spec::new("CN=phone", 11).issue(Some(&p.root));
    for (from, to, code) in [
        (&b"250101000000Z"[..], &b"251301000000Z"[..], verify::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD),
        (b"250101000000Z", b"250230000000Z", verify::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD),
        (b"250101000000Z", b"250101000060Z", verify::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD),
        (b"350101000000Z", b"350101000000+", verify::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD),
    ] {
        let der = resign(&patch(&base.der, from, to), &p.root.key, Hash::Sha256);
        let r = verify(&s, crate::x509::pem::encode("CERTIFICATE", &der));
        assert_eq!(outcome(r), failed(code), "{:?}", std::str::from_utf8(to));
    }
}

#[test]
fn wrong_issuer() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // Signed by a root that is not in the store: build_chain finds no
    // issuer for it in the store (X509_STORE_CTX_get1_issuer), so error 20.
    let other = Spec::new("CN=Other Root", 12).ca().issue(None);
    let (r, logs) = testlog::capture(|| verify(&s, pem(&[&Spec::new("CN=x", 13).issue(Some(&other))])));
    assert_eq!(outcome(r), failed(verify::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    assert_eq!(logs[1], "<sip:phone@127.0.0.1:5060>: Client cert failed to verify: unable to get local issuer certificate\n");
    // The phone certificate is issued by another intermediate: the one
    // sent is not its issuer (names differ), so 20 again.
    let inter2 = Spec::new("CN=Other Intermediate", 14).ca().issue(Some(&p.root));
    let phone2 = Spec::new("CN=000fd3000002", 15).issue(Some(&inter2));
    assert_eq!(outcome(verify(&s, chain(&p, &p.inter, &phone2))), failed(20));
    // Same issuer name, another key, no key identifiers: the chain links
    // by name (x509_likely_issued), and internal_verify's X509_verify
    // fails, so 7.
    let impostor = Spec::new("CN=Test Intermediate,O=DPMA Test", 16).ca().issue(Some(&p.root));
    let phone3 = Spec::new("CN=000fd3000003", 17).issue(Some(&impostor));
    assert_eq!(outcome(verify(&s, chain(&p, &p.inter, &phone3))), failed(verify::X509_V_ERR_CERT_SIGNATURE_FAILURE));
    // An authorityKeyIdentifier that does not match the intermediate's
    // subjectKeyIdentifier: X509_check_akid refuses the link, so 20.
    let phone4 = Spec::new("CN=000fd3000004", 18).ext(authority_key_id(b"other")).issue(Some(&p.inter));
    assert_eq!(outcome(verify(&s, chain(&p, &p.inter, &phone4))), failed(20));
}

#[test]
fn bad_signature_and_tampering() {
    let p = pki();
    let s = store_of(&[&p.root]);
    let body = |der: &[u8]| crate::x509::pem::encode("CERTIFICATE", der);
    // A changed signature octet: RSA_verify fails, so 7.
    let mut bad = p.legacy.der.clone();
    let (_, _, sig) = parts(&bad);
    bad[sig.start + 10] ^= 1;
    assert_eq!(outcome(verify(&s, body(&bad))), failed(7));
    // A changed signed part (the subject): the signature no longer
    // matches, so 7.
    let tampered = patch(&p.legacy.der, b"legacy 000fd3000001", b"legacy 000fd3000009");
    assert_eq!(outcome(verify(&s, body(&tampered))), failed(7));
    // The outer signature algorithm differs from the signed one
    // (X509_ALGOR_cmp in X509_verify), so 7.
    let (_, alg, _) = parts(&p.legacy.der);
    let mut swapped = p.legacy.der.clone();
    let oid_end = alg.start + 2 + 2 + 9;
    assert_eq!(swapped[oid_end - 1], 0x0b);
    swapped[oid_end - 1] = 0x0c;
    assert_eq!(outcome(verify(&s, body(&swapped))), failed(7));
    // Unused bits in the signature BIT STRING (ASN1_item_verify), so 7.
    let mut bits = p.legacy.der.clone();
    let (_, _, sig) = parts(&bits);
    bits[sig.start - 1] = 1;
    assert_eq!(outcome(verify(&s, body(&bits))), failed(7));
    // A tampered intermediate in the chain form, so 7.
    let inter = Issued {
        der: patch(&p.inter.der, b"Test Intermediate", b"Test Intermediatf"),
        name: std::str::FromStr::from_str("CN=Test Intermediatf,O=DPMA Test").unwrap(),
        ..p.inter.clone()
    };
    let phone = Spec::new("CN=000fd3000005", 19).issue(Some(&inter));
    assert_eq!(outcome(verify(&s, chain(&p, &inter, &phone))), failed(7));
}

#[test]
fn intermediate_must_be_a_ca() {
    // check_chain_extensions: an intermediate must have basicConstraints
    // with CA:TRUE (X509_check_ca == 1; X509_V_FLAG_X509_STRICT is
    // implicit for intermediates), else 24.
    let p = pki();
    let s = store_of(&[&p.root]);
    let cases = [
        ("no basicConstraints", Spec::new("CN=I1", 20).ext(subject_key_id(b"i1"))),
        ("CA:FALSE", Spec::new("CN=I2", 21).ext(basic_constraints(false, None))),
        ("keyCertSign only", Spec::new("CN=I3", 22).ext(key_usage(KeyUsages::KeyCertSign))),
        // A v1 intermediate (no extensions at all) is not self-signed, so
        // not a v1 root either.
        ("v1", Spec::new("CN=I4", 23)),
    ];
    for (what, spec) in cases {
        let inter = spec.serial(100).issue(Some(&p.root));
        let phone = Spec::new("CN=phone", 24).issue(Some(&inter));
        assert_eq!(outcome(verify(&s, chain(&p, &inter, &phone))), failed(verify::X509_V_ERR_INVALID_CA), "{}", what);
    }
}

#[test]
fn trust_anchor_ca_rules() {
    // For the top of the chain any X509_check_ca result but 0 will do: a
    // self-signed v1 root (3) and a root with keyCertSign but no
    // basicConstraints (4) are accepted; a v3 root with neither, or with
    // CA:FALSE, is not (24).
    let p = pki();
    for (what, spec, ok) in [
        ("v1 root", Spec::new("CN=V1 Root", 30), true),
        ("keyUsage root", Spec::new("CN=KU Root", 31).ext(key_usage(KeyUsages::KeyCertSign)), true),
        ("bare v3 root", Spec::new("CN=Bare Root", 32).ext(subject_key_id(b"bare")), false),
        ("CA:FALSE root", Spec::new("CN=False Root", 33).ext(basic_constraints(false, None)), false),
    ] {
        let root = spec.issue(None);
        let leaf = Spec::new("CN=leaf", 34).issue(Some(&root));
        let r = outcome(verify(&store_of(&[&root]), pem(&[&leaf])));
        if ok {
            assert_eq!(r, Ok(()), "{}", what);
        } else {
            assert_eq!(r, failed(verify::X509_V_ERR_INVALID_CA), "{}", what);
        }
        // The same root with a v1 intermediate below it: the
        // intermediate is never a CA.
        let inter = Spec::new("CN=v1 inter", 35).serial(3).issue(Some(&root));
        let phone = Spec::new("CN=phone", 36).issue(Some(&inter));
        assert_eq!(outcome(verify(&store_of(&[&root]), chain(&p, &inter, &phone))), failed(24), "{}", what);
    }
}

#[test]
fn key_usage_without_cert_sign() {
    // check_ca refuses an issuer whose keyUsage lacks keyCertSign before
    // basicConstraints count (ku_reject), so 24 for an intermediate and
    // for the root.  (x509_signing_allowed's 32 is not reached.)
    let p = pki();
    let s = store_of(&[&p.root]);
    let inter = Spec::new("CN=KU Inter", 40)
        .serial(41)
        .ext(basic_constraints(true, None))
        .ext(key_usage(KeyUsages::DigitalSignature))
        .issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 42).issue(Some(&inter));
    assert_eq!(outcome(verify(&s, chain(&p, &inter, &phone))), failed(24));
    let root = Spec::new("CN=KU Root", 43)
        .ext(basic_constraints(true, None))
        .ext(key_usage(KeyUsages::DigitalSignature))
        .issue(None);
    let leaf = Spec::new("CN=leaf", 44).issue(Some(&root));
    assert_eq!(outcome(verify(&store_of(&[&root]), pem(&[&leaf]))), failed(24));
}

#[test]
fn path_length() {
    // check_chain_extensions checks pathLenConstraint from depth 2: the
    // root's 0 is exceeded by one intermediate (25); 1 is enough; an
    // intermediate's 0 allows the phone below it.
    let p = pki();
    for (root_len, inter_len, ok) in [(Some(0), None, false), (Some(1), None, true), (None, Some(0), true)] {
        let root = Spec::new("CN=PL Root", 50)
            .ext(basic_constraints(true, root_len))
            .ext(key_usage(KeyUsages::KeyCertSign))
            .issue(None);
        let inter = Spec::new("CN=PL Inter", 51)
            .serial(52)
            .ext(basic_constraints(true, inter_len))
            .ext(key_usage(KeyUsages::KeyCertSign))
            .issue(Some(&root));
        let phone = Spec::new("CN=phone", 53).issue(Some(&inter));
        let r = outcome(verify(&store_of(&[&root]), chain(&p, &inter, &phone)));
        assert_eq!(r, if ok { Ok(()) } else { failed(verify::X509_V_ERR_PATH_LENGTH_EXCEEDED) }, "{:?}", (root_len, inter_len));
    }
}

#[test]
fn unknown_critical_extension() {
    // x509v3_cache_extensions sets EXFLAG_CRITICAL for a critical
    // extension X509_supported_extension does not know;
    // check_chain_extensions reports 34 for any certificate in the chain.
    let p = pki();
    let s = store_of(&[&p.root]);
    let unknown = |critical| ext("1.3.6.1.4.1.99999.1", critical, &x509_cert::der::asn1::Null);
    let leaf = Spec::new("CN=leaf", 60).ext(unknown(true)).issue(Some(&p.root));
    assert_eq!(outcome(verify(&s, pem(&[&leaf]))), failed(verify::X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION));
    let leaf = Spec::new("CN=leaf", 60).ext(unknown(false)).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&leaf])).is_ok());
    // On the root too.
    let root = Spec::new("CN=Crit Root", 61).ca().ext(unknown(true)).issue(None);
    let leaf = Spec::new("CN=leaf", 62).issue(Some(&root));
    assert_eq!(outcome(verify(&store_of(&[&root]), pem(&[&leaf]))), failed(34));
    // Critical certificatePolicies is known to 1.1.1t (not checked
    // without X509_V_FLAG_POLICY_CHECK): accepted.
    let policies = ext("2.5.29.32", true, &vec![x509_cert::ext::pkix::certpolicy::PolicyInformation {
        policy_identifier: x509_cert::der::oid::ObjectIdentifier::new_unwrap("2.5.29.32.0"),
        policy_qualifiers: None,
    }]);
    let leaf = Spec::new("CN=leaf", 63).ext(policies).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&leaf])).is_ok());
    // A critical BOOLEAN of 0x01 (not DER) is TRUE for 1.1.1t.
    let leaf = Spec::new("CN=leaf", 64).ext(unknown(true)).issue(Some(&p.root));
    let der = resign(&patch(&leaf.der, &[0x01, 0x01, 0xff, 0x04], &[0x01, 0x01, 0x01, 0x04]), &p.root.key, Hash::Sha256);
    assert_eq!(outcome(verify(&s, crate::x509::pem::encode("CERTIFICATE", &der))), failed(34));
}

#[test]
fn self_signed_certificates() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // A self-signed phone certificate that is not in the store: build_chain
    // finds nothing for it, so 18.
    let selfie = Spec::new("CN=selfie", 70).issue(None);
    assert_eq!(outcome(verify(&s, pem(&[&selfie]))), failed(verify::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
    // The same certificate in the store is its own trust anchor.
    assert!(verify(&store_of(&[&p.root, &selfie]), pem(&[&selfie])).is_ok());
    // A different certificate with the same name and key identifier in the
    // store is not: build_chain wants an exact match (X509_cmp), so 18.
    let twin = Spec::new("CN=selfie", 71).issue(None);
    assert_eq!(outcome(verify(&store_of(&[&twin]), pem(&[&selfie]))), failed(18));
    // A self-signed CA sent by the phone as its intermediate: 19.
    let rogue = Spec::new("CN=Rogue Root", 72).ca().serial(73).issue(None);
    let phone = Spec::new("CN=phone", 74).issue(Some(&rogue));
    assert_eq!(outcome(verify(&s, chain(&p, &rogue, &phone))), failed(verify::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN));
}

#[test]
fn chain_must_reach_the_store() {
    let p = pki();
    // Only the intermediate in the store: it is not self-signed, so not
    // a trust anchor (trust_compat), and its issuer is not there: 2.
    let s = store_of(&[&p.inter]);
    assert_eq!(outcome(verify(&s, chain(&p, &p.inter, &p.phone))), failed(verify::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT));
    let leaf = Spec::new("CN=leaf", 80).issue(Some(&p.inter));
    assert_eq!(outcome(verify(&s, pem(&[&leaf]))), failed(2));
    // The intermediate and the root in the store: the phone's chain
    // completes from the store (trusted first).
    assert!(verify(&store_of(&[&p.inter, &p.root]), pem(&[&leaf])).is_ok());
    // A rogue PKI: 20.
    let rogue_root = Spec::new("CN=Test Root,O=Rogue", 81).ca().issue(None);
    let rogue_inter = Spec::new("CN=Rogue Inter", 82).serial(83).ca().issue(Some(&rogue_root));
    let rogue_phone = Spec::new("CN=phone", 84).issue(Some(&rogue_inter));
    assert_eq!(outcome(verify(&store_of(&[&p.root]), chain(&p, &rogue_inter, &rogue_phone))), failed(20));
}

#[test]
fn signature_algorithms_and_key_sizes() {
    // The security level is -1 (no SSL context, no auth level): any key
    // size and digest 1.1.1t has verifies (check_key_level and
    // check_sig_level return 1).
    for (hash, bits) in [
        (Hash::Md5, 1024),
        (Hash::Sha1, 512),
        (Hash::Sha224, 1024),
        (Hash::Sha256, 2048),
        (Hash::Sha384, 1024),
        (Hash::Sha512, 1024),
    ] {
        let root = Spec::new("CN=Alg Root", 90).bits(bits, 90).hash(hash).ca().issue(None);
        let inter = Spec::new("CN=Alg Inter", 91).bits(bits, 91).hash(hash).serial(92).ca().issue(Some(&root));
        let phone = Spec::new("CN=phone", 93).bits(bits, 93).hash(hash).issue(Some(&inter));
        let r = verify(&store_of(&[&root]), pem(&[&phone, &inter, &phone]));
        assert!(r.is_ok(), "{:?} {}: {:?}", hash, bits, r.err());
    }
    let p = pki();
    let s = store_of(&[&p.root]);
    // sha1WithRSA under its OIW OID (1.3.14.3.2.29) is in 1.1.1t's table.
    let mut spec = Spec::new("CN=oiw", 94).hash(Hash::Sha1);
    spec.sig_oid = Some("1.3.14.3.2.29");
    assert!(verify(&s, pem(&[&spec.issue(Some(&p.root))])).is_ok());
    // sha512-224WithRSA is not in 1.1.1t's signature table: the root
    // cannot be its issuer (check_sig_alg_match), so 20.
    let mut spec = Spec::new("CN=unknown alg", 95);
    spec.sig_oid = Some("1.2.840.113549.1.1.15");
    assert_eq!(outcome(verify(&s, pem(&[&spec.issue(Some(&p.root))]))), failed(20));
    // md2WithRSAEncryption links (the table has it) but 1.1.1t has no MD2
    // (disabled in its default build), so 7.
    let mut spec = Spec::new("CN=md2", 96);
    spec.sig_oid = Some("1.2.840.113549.1.1.2");
    assert_eq!(outcome(verify(&s, pem(&[&spec.issue(Some(&p.root))]))), failed(7));
    // RSASSA-PSS is not implemented here (see the module documentation);
    // with these NULL parameters 1.1.1t's rsa_item_verify refuses it too
    // (rsa_pss_decode wants a SEQUENCE), so 7 either way.
    let mut spec = Spec::new("CN=pss", 97);
    spec.sig_oid = Some("1.2.840.113549.1.1.10");
    assert_eq!(outcome(verify(&s, pem(&[&spec.issue(Some(&p.root))]))), failed(7));
}

#[test]
fn name_comparison_is_canonical() {
    // X509_NAME_cmp compares canonical encodings: case, white space, and
    // string types do not matter; the attributes do.
    let root = Spec::new("CN=Test  Root,O=DPMA Test", 100).ca().issue(None);
    // The same name, spelled differently, as the issuer of the leaf.
    let leaf = Spec::new("CN=leaf", 101).issue(Some(&Issued {
        name: std::str::FromStr::from_str("CN=test root,O=dpma   TEST").unwrap(),
        ..root.clone()
    }));
    assert!(verify(&store_of(&[&root]), pem(&[&leaf])).is_ok());
    let other = Spec::new("CN=leaf", 102).issue(Some(&Issued {
        name: std::str::FromStr::from_str("CN=Test Root2,O=DPMA Test").unwrap(),
        ..root.clone()
    }));
    assert_eq!(outcome(verify(&store_of(&[&root]), pem(&[&other]))), failed(20));
}

#[test]
fn name_constraints() {
    // check_name_constraints applies the root's nameConstraints to the
    // phone's subject alternative names, and to a host name-like common
    // name when there is no dNSName (NAME_CONSTRAINTS_check_CN).
    use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
    use x509_cert::ext::pkix::name::GeneralName;
    let subtree = |d: &str| GeneralSubtree {
        base: GeneralName::DnsName(x509_cert::der::asn1::Ia5String::new(d).unwrap()),
        minimum: 0,
        maximum: None,
    };
    let nc = NameConstraints { permitted_subtrees: Some(vec![subtree(".example.com")]), excluded_subtrees: None };
    let root = Spec::new("CN=NC Root", 110).ca().ext(ext("2.5.29.30", true, &nc)).issue(None);
    let s = store_of(&[&root]);
    let leaf = |cn: &str, san: Option<&str>| {
        let mut spec = Spec::new(&format!("CN={}", cn), 111);
        if let Some(san) = san {
            spec = spec.ext(dns_san(&[san]));
        }
        pem(&[&spec.issue(Some(&root))])
    };
    assert!(verify(&s, leaf("000fd3000001", Some("phone.example.com"))).is_ok());
    assert_eq!(outcome(verify(&s, leaf("000fd3000001", Some("phone.other.com")))), failed(verify::X509_V_ERR_PERMITTED_VIOLATION));
    assert_eq!(outcome(verify(&s, leaf("phone.other.com", None))), failed(47));
    assert!(verify(&s, leaf("phone.example.com", None)).is_ok());
    // A common name that is not a host name is not checked.
    assert!(verify(&s, leaf("000fd3000001", None)).is_ok());
    // Minimum or maximum in a subtree of the name's type: 49.
    let nc = NameConstraints {
        permitted_subtrees: Some(vec![GeneralSubtree { maximum: Some(3), ..subtree("example.com") }]),
        excluded_subtrees: None,
    };
    let root = Spec::new("CN=NC Root", 112).ca().ext(ext("2.5.29.30", true, &nc)).issue(None);
    let leaf = Spec::new("CN=leaf", 113).ext(dns_san(&["a.example.com"])).issue(Some(&root));
    assert_eq!(outcome(verify(&store_of(&[&root]), pem(&[&leaf]))), failed(verify::X509_V_ERR_SUBTREE_MINMAX));
}

#[test]
fn invalid_extensions_break_the_chain() {
    // A certificate whose interpreted extensions occur twice or do not
    // decode is EXFLAG_INVALID; x509_likely_issued refuses it as subject
    // and as issuer, so no chain forms: 20.
    let p = pki();
    let s = store_of(&[&p.root]);
    let dup = Spec::new("CN=dup", 120).ext(basic_constraints(false, None)).ext(basic_constraints(false, None));
    assert_eq!(outcome(verify(&s, pem(&[&dup.issue(Some(&p.root))]))), failed(20));
    let bad_san = Spec::new("CN=bad san", 121).ext(ext("2.5.29.17", false, &x509_cert::der::asn1::Null));
    assert_eq!(outcome(verify(&s, pem(&[&bad_san.issue(Some(&p.root))]))), failed(20));
    // CA:FALSE with a path length is invalid too.
    let inter = Spec::new("CN=bad inter", 122).serial(123).ext(basic_constraints(false, Some(1))).issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 124).issue(Some(&inter));
    assert_eq!(outcome(verify(&s, chain(&p, &inter, &phone))), failed(20));
    // An RFC 3779 extension on the phone certificate: not implemented
    // here, refused with 45 (1.1.1t would check it against the issuers).
    let blocks = x509_cert::der::asn1::Null;
    let mut addr = Spec::new("CN=addr", 125).ext(ext("1.3.6.1.5.5.7.1.7", true, &blocks)).issue(Some(&p.root));
    // An empty IPAddrBlocks (SEQUENCE {}) decodes.
    addr.der = resign(&patch(&addr.der, &[0x04, 0x02, 0x05, 0x00], &[0x04, 0x02, 0x30, 0x00]), &p.root.key, Hash::Sha256);
    assert_eq!(outcome(verify(&s, pem(&[&addr]))), failed(verify::X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE));
}

#[test]
fn malformed_input() {
    let p = pki();
    let s = store_of(&[&p.root]);
    let client = ClientInfo { contact: b"c", mac: None, user_agent: b"ua" };
    let read = |body: &[u8]| testlog::capture(|| verify_client_chain_at(&s, body, &client, NOW));
    let block = |b64: &str| format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64);
    let der_pem = |der: &[u8]| crate::x509::pem::encode("CERTIFICATE", der);
    let truncated = der_pem(&p.legacy.der[..100]);
    // The subject's O value as a UTF8String that is not UTF-8.
    let mut bad_utf8 = p.legacy.der.clone();
    let i = bad_utf8.windows(9).rposition(|w| w == b"DPMA Test").unwrap();
    bad_utf8[i - 2] = 0x0c;
    bad_utf8[i] = 0xc0;
    for (body, first_error) in [
        // No PEM block at all (get_name).
        (String::new(), NO_START_LINE),
        ("hello".to_string(), NO_START_LINE),
        // Three zero octets: not a SEQUENCE (asn1_check_tlen).
        (block("AAAA"), "error:0D0680A8:asn1 encoding routines:asn1_check_tlen:wrong tag"),
        // Cut short: the outer length is longer than the data.
        (truncated, "error:0D07209B:asn1 encoding routines:ASN1_get_object:too long"),
        // Base64 errors (EVP_DecodeUpdate) and END lines that do not match.
        (block("MII!"), "error:09091064:PEM routines:PEM_read_bio_ex:bad base64 decode"),
        (block("MIIB=A"), "error:09091064:PEM routines:PEM_read_bio_ex:bad base64 decode"),
        (
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERT-----\n".to_string(),
            "error:0908F066:PEM routines:get_header_and_data:bad end line",
        ),
        (
            "-----BEGIN CERTIFICATE-----\nAAAA\n".to_string(),
            "error:0908F066:PEM routines:get_header_and_data:bad end line",
        ),
        // An empty block fails without an error; the next read's "no
        // start line" is the first on the queue.
        ("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n".to_string(), NO_START_LINE),
        // A blank line inside the base64 text: the part before it is taken
        // for a header (PEM_get_EVP_CIPHER_INFO).
        (block("QUJD\n\nQUJD"), "error:0906B06B:PEM routines:PEM_get_EVP_CIPHER_INFO:not proc type"),
        // An encrypted block: 1.1.1t's pass phrase prompt fails.
        (
            "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nQUJD\n-----END CERTIFICATE-----\n".to_string(),
            "error:2807106B:UI routines:UI_process:processing error",
        ),
        // A "TRUSTED CERTIFICATE" block is not read as a certificate.
        (p.legacy.pem().replace("CERTIFICATE", "TRUSTED CERTIFICATE"), NO_START_LINE),
        // A name value that is not valid UTF-8 (x509_name_canon).
        (der_pem(&bad_utf8), "error:0D07A086:asn1 encoding routines:ASN1_mbstring_ncopy:invalid utf8string"),
    ] {
        let (r, logs) = read(body.as_bytes());
        assert_eq!(outcome(r), unreadable(first_error), "{:?}", body);
        assert_eq!(logs[0], "Contact: c MAC: (null) UA: ua Using legacy certificate\n");
        assert_eq!(logs[1], format!("<c>: Unable to read client cert: {}\n", first_error));
    }
    // What 1.1.1t tolerates: BER (an indefinite-length outer SEQUENCE),
    // data after the certificate, "X509 CERTIFICATE", headers, junk lines.
    let der = &p.legacy.der;
    let (tbs, _, _) = parts(der);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[tbs.start..]);
    ber.extend([0, 0]);
    let mut trailing = der.clone();
    trailing.extend(b"trailing data");
    let blank_header = p.legacy.pem().replacen("-----\n", "-----\n\n", 1);
    for body in [
        der_pem(&ber),
        der_pem(&trailing),
        p.legacy.pem().replace("CERTIFICATE", "X509 CERTIFICATE"),
        blank_header,
        format!("junk -----BEGIN x\n{}\n\n-----END junk\n", p.legacy.pem()),
    ] {
        assert!(verify(&s, &body).is_ok(), "{}", body);
    }
}

#[test]
fn pem_newlines_restored() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // Well-formed text (LF or CRLF) and text without markers are
    // unchanged.
    for body in [pem(&[&p.legacy]), chain(&p, &p.inter, &p.phone)] {
        assert_eq!(restore_pem_newlines(&body), body.as_bytes());
        let crlf = body.replace('\n', "\r\n");
        assert_eq!(restore_pem_newlines(&crlf), crlf.as_bytes());
    }
    for t in ["", "hello", "-----", "a-----b", "-----BEGIN", "-----BEGIN CERT", "x-----BEGIN CERT\n-----", "-----END-----"] {
        assert_eq!(restore_pem_newlines(t), t.as_bytes());
    }
    // Each kind of lost line break: after a BEGIN line, before an END
    // line, and between an END line and the next BEGIN line.
    assert_eq!(
        restore_pem_newlines("-----BEGIN CERTIFICATE-----AAAA\nBBBB-----END CERTIFICATE-----"),
        "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----".as_bytes()
    );
    assert_eq!(
        restore_pem_newlines("-----END A-----\r\n-----BEGIN B----------END B----------BEGIN C-----x"),
        "-----END A-----\r\n-----BEGIN B-----\n-----END B-----\n-----BEGIN C-----\nx".as_bytes()
    );
    assert_eq!(restore_pem_newlines("junk-----BEGIN A-----"), b"junk\n-----BEGIN A-----");
    // Every line break at a PEM boundary lost (chunks ending right before
    // and after each BEGIN and END line): both forms verify again.
    for body in [pem(&[&p.legacy]), chain(&p, &p.inter, &p.phone)] {
        let broken = body.replace("-----\n", "-----").replace("\n-----", "-----");
        assert!(verify(&s, &broken).is_err());
        let fixed = restore_pem_newlines(&broken);
        assert_eq!(fixed, body.trim_end_matches('\n').as_bytes());
        assert!(verify(&s, &fixed).is_ok());
    }
}

#[test]
fn wrong_chain_lengths() {
    let p = pki();
    let s = store_of(&[&p.root]);
    let (r, logs) = testlog::capture(|| verify(&s, pem(&[&p.inter, &p.phone])));
    assert_eq!(r.err(), Some(CertError::WrongChainLength(1)));
    assert_eq!(logs.last().unwrap(), "<sip:phone@127.0.0.1:5060>: Expected two certificates in the chain, found 1");
    let four = pem(&[&p.legacy, &p.inter, &p.phone, &p.phone]);
    assert_eq!(verify(&s, &four).err(), Some(CertError::WrongChainLength(3)));
    // Reading stops at the first block that fails, so a chain whose
    // second block is unreadable is verified as the legacy form.
    let body = format!("{}-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n{}", p.legacy.pem(), p.phone.pem());
    assert!(verify(&s, &body).unwrap().legacy);
    // A first block that does not read, then one certificate: the chain
    // form with one certificate after the first.
    let body = format!("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n{}", p.legacy.pem());
    assert_eq!(verify(&s, &body).err(), Some(CertError::WrongChainLength(1)));
}

#[test]
fn serial_quirks() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // A zero serial on the intermediate makes the original read the next
    // certificate's serial.
    let inter0 = Spec::new("CN=Inter0", 130).serial(0).ca().issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 99).issue(Some(&inter0));
    let (r, logs) = testlog::capture(|| verify(&s, pem(&[&p.legacy, &inter0, &phone])));
    assert_eq!(r.unwrap().intermediate_serial, 99);
    assert_eq!(logs.len(), 2);
    assert!(logs[0].ends_with("Intermediate cert serial number: 0\n"));
    assert!(logs[1].ends_with("Intermediate cert serial number: 99\n"));
    // A negative serial is an error, logged with whatever is first on the
    // error queue: nothing...
    let neg = Spec::new("CN=InterNeg", 131).serial_der(&[0xfb]).ca().issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 132).issue(Some(&neg));
    let (r, logs) = testlog::capture(|| verify(&s, pem(&[&p.legacy, &neg, &phone])));
    assert_eq!(r.err(), Some(CertError::NoSerial("error:00000000:lib(0):func(0):reason(0)".into())));
    assert_eq!(
        logs,
        vec!["<sip:phone@127.0.0.1:5060>: Unable to get serial number of intermediate cert: error:00000000:lib(0):func(0):reason(0)\n"]
    );
    // ...or the error of a first block that did not read.
    let body = format!("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n{}{}", neg.pem(), phone.pem());
    assert_eq!(
        verify(&s, &body).err(),
        Some(CertError::NoSerial("error:0D0680A8:asn1 encoding routines:asn1_check_tlen:wrong tag".into()))
    );
    // Serials too large for a long long saturate (strtoll).
    let big = Spec::new("CN=InterBig", 133).serial_der(&[0x7f; 12]).ca().issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 134).issue(Some(&big));
    assert_eq!(verify(&s, pem(&[&p.legacy, &big, &phone])).unwrap().intermediate_serial, i64::MAX);
}

#[test]
fn public_keys() {
    let p = pki();
    let cert = certificates_from_pem(p.phone.pem().as_bytes()).unwrap().remove(0);
    let public = cert.public_key().unwrap().clone();
    let pem_text = public_key_pem(&public).unwrap();
    assert!(pem_text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert_eq!(load_public_key(&pem_text).unwrap().unwrap(), public);
    // Other PEM blocks before the key are skipped; a certificate alone
    // is not a public key, nor is a PKCS#1 "RSA PUBLIC KEY" block.
    let mixed = format!("{}{}", p.phone.pem(), pem_text);
    assert_eq!(load_public_key(&mixed).unwrap().unwrap(), public);
    assert!(load_public_key(p.phone.pem()).is_err());
    assert!(load_public_key(pem_text.replace("PUBLIC KEY", "RSA PUBLIC KEY")).is_err());
    let (r, logs) = testlog::capture(|| load_public_key(""));
    assert!(r.is_err());
    assert_eq!(logs, vec!["failed to load client public rsa key - is null\n"]);
    // 512 bits is the minimum; smaller keys are dropped.
    let k512 = PublicKey::Rsa(RsaKey::from_be_bytes(&key(512, 1).n().to_bytes_be(), &[1, 0, 1]));
    assert!(load_public_key(public_key_pem(&k512).unwrap()).unwrap().is_some());
    let mut n = vec![0xc0];
    n.extend([0u8; 61]);
    n.push(1);
    let small = PublicKey::Rsa(RsaKey::from_be_bytes(&n, &[1, 0, 1]));
    assert_eq!(small.rsa().unwrap().size(), 63);
    let (r, logs) = testlog::capture(|| load_public_key(public_key_pem(&small).unwrap()));
    assert!(r.unwrap().is_none());
    assert_eq!(logs, vec!["failed to load client public rsa key - less than 512 bits\n"]);
}

#[test]
fn no_panics_on_damaged_input() {
    // The decoder and verifier see what any device sends: damaged
    // certificates must be refused, never crash the module.  Every octet
    // of a chain's certificates changed several ways, and every
    // truncation.
    let p = pki();
    let s = store_of(&[&p.root]);
    for (k, target) in [&p.legacy, &p.inter, &p.phone].into_iter().enumerate() {
        let der = &target.der;
        let mut bodies: Vec<Vec<u8>> = (0..der.len()).map(|n| der[..n].to_vec()).collect();
        for i in 0..der.len() {
            for v in [0x00, 0x01, 0x1f, 0x30, 0x7f, 0x80, 0x81, 0x84, 0xff, der[i] ^ 0x80] {
                let mut d = der.clone();
                d[i] = v;
                bodies.push(d);
            }
        }
        for d in bodies {
            let mut errs = Errs::new();
            let _ = Certificate::d2i(&d, &mut errs);
            let one = crate::x509::pem::encode("CERTIFICATE", &d);
            let body = match k {
                0 => one,
                1 => format!("{}{}{}", p.legacy.pem(), one, p.phone.pem()),
                _ => format!("{}{}{}", p.legacy.pem(), p.inter.pem(), one),
            };
            let _ = verify(&s, &body);
        }
    }
}

/// The original's CA certificates and AppServer certificate, which the
/// module embeds (crates/res_dpma_rs/src/trust).
const EMBEDDED_CA: &[u8] = include_bytes!("../../../res_dpma_rs/src/trust/phone_ca.pem");
const EMBEDDED_APPSERVER: &[u8] = include_bytes!("../../../res_dpma_rs/src/trust/appserver.pem");

#[test]
fn embedded_trust_material() {
    // The bundle reads as three certificates: the Sangoma root (v3,
    // CA:TRUE, 4096 bits), the Digium AppServer CA as a v1 certificate,
    // and the same CA (same key) as an expired v3 certificate whose
    // authorityKeyIdentifier names its own key, issuer, and serial.  All
    // are self-signed (x509v3_cache_extensions) and valid trust anchors;
    // X509_check_ca gives 1, 3 (a self-signed v1 root), and 1.
    let certs = certificates_from_pem(EMBEDDED_CA).unwrap();
    assert_eq!(certs.len(), 3);
    for c in &certs {
        assert!(!c.invalid());
        assert_ne!(c.ex.flags & crate::x509::ext::EXFLAG_SS, 0);
    }
    assert_eq!(certs.iter().map(crate::x509::verify::check_ca).collect::<Vec<_>>(), [1, 3, 1]);
    let bits: Vec<usize> = certs.iter().map(|c| c.public_key().unwrap().rsa().unwrap().bits()).collect();
    assert_eq!(bits, [4096, 1024, 1024]);
    assert_eq!(certs[1].public_key(), certs[2].public_key());
    let store = CaStore::from_pem(EMBEDDED_CA).unwrap();
    assert_eq!(store.len(), 3);
    // Each verifies as a phone's legacy certificate (it is in the store;
    // the expired one too, error 10 being ignored).
    for c in &certs {
        let body = crate::x509::pem::encode("CERTIFICATE", c.der());
        assert!(verify(&store, &body).is_ok());
    }
    // The AppServer certificate (v1, a 512-bit key, SHA-256) is issued by
    // "Digium Appserver": it verifies against the bundle (the valid v1 CA
    // is preferred, X509_STORE_CTX_get1_issuer), against the expired v3 CA
    // alone, and not against the Sangoma root.
    let app = certificates_from_pem(EMBEDDED_APPSERVER).unwrap();
    assert_eq!(app.len(), 1);
    assert_eq!(app[0].public_key().unwrap().rsa().unwrap().bits(), 512);
    let v = verify(&store, EMBEDDED_APPSERVER).unwrap();
    assert!(v.legacy);
    assert_eq!(v.certificate, app[0]);
    let only = |i: usize| CaStore::from_certs(std::slice::from_ref(&certs[i])).unwrap();
    assert!(verify(&only(2), EMBEDDED_APPSERVER).is_ok());
    assert!(verify(&only(1), EMBEDDED_APPSERVER).is_ok());
    assert_eq!(outcome(verify(&only(0), EMBEDDED_APPSERVER)), failed(20));
}
