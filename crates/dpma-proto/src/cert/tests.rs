//! The verifier's cases, by the checks of the module documentation.

use super::testpki::*;
use super::verify::*;
use super::*;
use crate::testlog;
use rsa::traits::PublicKeyParts;
use x509_cert::certificate::Version;
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
    verify_client_chain(store, body, &CLIENT)
}

/// The chain form: the legacy certificate, `inter`, and `phone`.
fn chain(p: &Pki, inter: &Issued, phone: &Issued) -> String {
    pem(&[&p.legacy, inter, phone])
}

fn failed(text: &'static str) -> std::result::Result<(), CertError> {
    Err(CertError::Verify(text))
}

fn outcome(r: std::result::Result<VerifiedClient, CertError>) -> std::result::Result<(), CertError> {
    r.map(|_| ())
}

fn rsa_key(k: &rsa::RsaPrivateKey) -> PublicKey {
    PublicKey::Rsa(RsaKey::from_be_bytes(&k.n().to_bytes_be(), &k.e().to_bytes_be()))
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
    let other = Spec::new("CN=Other Root", 5).ca().issue(None);
    // Text around the blocks and blocks with other labels are skipped.
    let bundle = format!(
        "# CA bundle\n{}junk\n-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n{}",
        p.root.pem(),
        other.pem(),
    );
    let s = CaStore::from_pem(bundle.as_bytes()).unwrap();
    assert!(verify(&s, pem(&[&p.legacy])).is_ok());
    assert!(verify(&s, pem(&[&Spec::new("CN=x", 6).issue(Some(&other))])).is_ok());
    for empty in ["", "not a certificate", "-----BEGIN X509 CERTIFICATE-----\nQUJD\n-----END X509 CERTIFICATE-----\n"] {
        assert_eq!(CaStore::from_pem(empty.as_bytes()).err().unwrap().message(), "No CA certificates found");
    }
    // A block that cannot be read is an error.
    let bad = format!("{}-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", p.root.pem());
    let e = CaStore::from_pem(bad.as_bytes()).err().unwrap();
    assert_eq!(e.message(), "Error parsing CA certificates: certificate parse error");
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
    assert_eq!(v.public_key, Some(rsa_key(&p.legacy.key)));
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
    assert_eq!(v.public_key, Some(rsa_key(&p.phone.key)));
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
    // The official DPMA's callback ignores "not yet valid" and "expired",
    // for every certificate, the trust anchor too.
    let p = pki();
    let s = store_of(&[&p.root]);
    let expired = Spec::new("CN=old phone", 7).validity(time(2001, 1, 1), time(2002, 1, 1)).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&expired])).is_ok());
    let future = Spec::new("CN=new phone", 7).validity(time(2090, 1, 1), time(2091, 1, 1)).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&future])).is_ok());
    let root = Spec::new("CN=Old Root", 8).ca().validity(time(2001, 1, 1), time(2002, 1, 1)).issue(None);
    let inter = Spec::new("CN=Old Inter", 9).serial(9).ca().validity(time(2001, 1, 1), time(2002, 1, 1)).issue(Some(&root));
    let phone = Spec::new("CN=phone", 10).validity(time(2090, 1, 1), time(2091, 1, 1)).issue(Some(&inter));
    let v = verify(&store_of(&[&root]), pem(&[&phone, &inter, &phone])).unwrap();
    assert_eq!(v.intermediate_serial, 9);
}

#[test]
fn issuer_names() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // Signed by a root that is not in the store.
    let other = Spec::new("CN=Other Root", 12).ca().issue(None);
    let (r, logs) = testlog::capture(|| verify(&s, pem(&[&Spec::new("CN=x", 13).issue(Some(&other))])));
    assert_eq!(outcome(r), failed(UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    assert_eq!(logs[1], "<sip:phone@127.0.0.1:5060>: Client cert failed to verify: unable to get local issuer certificate\n");
    // The phone certificate is issued by another intermediate: the one
    // sent is not its issuer (the names differ).
    let inter2 = Spec::new("CN=Other Intermediate", 14).ca().issue(Some(&p.root));
    let phone2 = Spec::new("CN=000fd3000002", 15).issue(Some(&inter2));
    assert_eq!(outcome(verify(&s, chain(&p, &p.inter, &phone2))), failed(UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    // The same name spelled with other case or spacing is another name.
    for spelling in ["CN=test root,O=DPMA Test", "CN=Test  Root,O=DPMA Test"] {
        let issuer = Issued { name: std::str::FromStr::from_str(spelling).unwrap(), ..p.root.clone() };
        let leaf = Spec::new("CN=leaf", 16).issue(Some(&issuer));
        assert_eq!(outcome(verify(&s, pem(&[&leaf]))), failed(UNABLE_TO_GET_ISSUER_CERT_LOCALLY), "{}", spelling);
    }
    // But the root's name with PrintableString values for its UTF8String
    // ones is the same name.
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::der::{asn1::SetOfVec, Any, Tag};
    use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
    let printable = RdnSequence(
        p.root
            .name
            .0
            .iter()
            .map(|rdn| {
                let atvs = rdn.0.iter().map(|a| AttributeTypeAndValue {
                    oid: a.oid,
                    value: Any::new(Tag::PrintableString, a.value.value()).unwrap(),
                });
                RelativeDistinguishedName::from(SetOfVec::try_from(atvs.collect::<Vec<_>>()).unwrap())
            })
            .collect(),
    );
    assert_ne!(printable, p.root.name);
    let leaf = Spec::new("CN=leaf", 16).issue(Some(&Issued { name: printable, ..p.root.clone() }));
    assert!(verify(&s, pem(&[&leaf])).is_ok());
    // Same issuer name, another key: the chain links by name, and the
    // signature does not verify.
    let impostor = Spec::new("CN=Test Intermediate,O=DPMA Test", 17).ca().issue(Some(&p.root));
    let phone3 = Spec::new("CN=000fd3000003", 18).issue(Some(&impostor));
    assert_eq!(outcome(verify(&s, chain(&p, &p.inter, &phone3))), failed(CERT_SIGNATURE_FAILURE));
    // Authority key identifiers are not used.
    let phone4 = Spec::new("CN=000fd3000004", 19).ext(authority_key_id(b"other")).issue(Some(&p.inter));
    assert!(verify(&s, chain(&p, &p.inter, &phone4)).is_ok());
}

#[test]
fn bad_signature_and_tampering() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // A changed signature octet.
    let mut bad = p.legacy.der.clone();
    let (_, _, sig) = parts(&bad);
    bad[sig.start + 10] ^= 1;
    assert_eq!(outcome(verify(&s, pem_of(&bad))), failed(CERT_SIGNATURE_FAILURE));
    // A changed signed part (the subject): the signature no longer
    // matches.
    let tampered = patch(&p.legacy.der, b"legacy 000fd3000001", b"legacy 000fd3000009");
    assert_eq!(outcome(verify(&s, pem_of(&tampered))), failed(CERT_SIGNATURE_FAILURE));
    // The outer signature algorithm differs from the signed one.
    let (_, alg, _) = parts(&p.legacy.der);
    let mut swapped = p.legacy.der.clone();
    let oid_end = alg.start + 2 + 2 + 9;
    assert_eq!(swapped[oid_end - 1], 0x0b);
    swapped[oid_end - 1] = 0x0c;
    assert_eq!(outcome(verify(&s, pem_of(&swapped))), failed(CERT_SIGNATURE_FAILURE));
    // Unused bits in the signature BIT STRING.
    let mut bits = p.legacy.der.clone();
    let (_, _, sig) = parts(&bits);
    bits[sig.start - 1] = 1;
    assert_eq!(outcome(verify(&s, pem_of(&bits))), failed(CERT_SIGNATURE_FAILURE));
    // A tampered intermediate in the chain form.
    let inter = Issued {
        der: patch(&p.inter.der, b"Test Intermediate", b"Test Intermediatf"),
        name: std::str::FromStr::from_str("CN=Test Intermediatf,O=DPMA Test").unwrap(),
        ..p.inter.clone()
    };
    let phone = Spec::new("CN=000fd3000005", 19).issue(Some(&inter));
    assert_eq!(outcome(verify(&s, chain(&p, &inter, &phone))), failed(CERT_SIGNATURE_FAILURE));
}

#[test]
fn intermediate_must_be_a_ca() {
    let p = pki();
    let s = store_of(&[&p.root]);
    let cases = [
        ("no basicConstraints", Spec::new("CN=I1", 20).ext(subject_key_id(b"i1"))),
        ("CA:FALSE", Spec::new("CN=I2", 21).ext(basic_constraints(false, None))),
        ("keyCertSign only", Spec::new("CN=I3", 22).ext(key_usage(KeyUsages::KeyCertSign))),
        // Only a trust anchor may be a v1 CA.
        ("v1", Spec::new("CN=I4", 23)),
    ];
    for (what, spec) in cases {
        let inter = spec.serial(100).issue(Some(&p.root));
        let phone = Spec::new("CN=phone", 24).issue(Some(&inter));
        assert_eq!(outcome(verify(&s, chain(&p, &inter, &phone))), failed(INVALID_CA), "{}", what);
    }
}

#[test]
fn trust_anchor_ca_rules() {
    // A trust anchor needs basicConstraints with CA:TRUE, unless it is a
    // v1 certificate.
    let p = pki();
    for (what, spec, ok) in [
        ("v1 root", Spec::new("CN=V1 Root", 30), true),
        ("CA root", Spec::new("CN=CA Root", 31).ext(basic_constraints(true, None)), true),
        ("keyUsage root", Spec::new("CN=KU Root", 32).ext(key_usage(KeyUsages::KeyCertSign)), false),
        ("bare v3 root", Spec::new("CN=Bare Root", 33).ext(subject_key_id(b"bare")), false),
        ("CA:FALSE root", Spec::new("CN=False Root", 34).ext(basic_constraints(false, None)), false),
    ] {
        let root = spec.issue(None);
        let leaf = Spec::new("CN=leaf", 35).issue(Some(&root));
        let r = outcome(verify(&store_of(&[&root]), pem(&[&leaf])));
        assert_eq!(r, if ok { Ok(()) } else { failed(INVALID_CA) }, "{}", what);
        // The same root with a v1 intermediate below it: the
        // intermediate is never a CA.
        let inter = Spec::new("CN=v1 inter", 36).serial(3).issue(Some(&root));
        let phone = Spec::new("CN=phone", 37).issue(Some(&inter));
        assert_eq!(outcome(verify(&store_of(&[&root]), chain(&p, &inter, &phone))), failed(INVALID_CA), "{}", what);
    }
}

#[test]
fn key_usage_without_cert_sign() {
    // An issuer whose keyUsage lacks keyCertSign, an intermediate or the
    // root.
    let p = pki();
    let s = store_of(&[&p.root]);
    let inter = Spec::new("CN=KU Inter", 40)
        .serial(41)
        .ext(basic_constraints(true, None))
        .ext(key_usage(KeyUsages::DigitalSignature))
        .issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 42).issue(Some(&inter));
    assert_eq!(outcome(verify(&s, chain(&p, &inter, &phone))), failed(KEYUSAGE_NO_CERTSIGN));
    let root = Spec::new("CN=KU Root", 43)
        .ext(basic_constraints(true, None))
        .ext(key_usage(KeyUsages::DigitalSignature))
        .issue(None);
    let leaf = Spec::new("CN=leaf", 44).issue(Some(&root));
    assert_eq!(outcome(verify(&store_of(&[&root]), pem(&[&leaf]))), failed(KEYUSAGE_NO_CERTSIGN));
    // The phone's own keyUsage is not checked (pki()'s phone has no
    // keyCertSign).
    assert!(verify(&s, chain(&p, &p.inter, &p.phone)).is_ok());
}

#[test]
fn path_length() {
    // The root's 0 is exceeded by one intermediate; 1 is enough; an
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
        assert_eq!(r, if ok { Ok(()) } else { failed(PATH_LENGTH_EXCEEDED) }, "{:?}", (root_len, inter_len));
    }
}

#[test]
fn critical_extensions() {
    let p = pki();
    let s = store_of(&[&p.root]);
    let unknown = |critical| ext("1.3.6.1.4.1.99999.1", critical, &x509_cert::der::asn1::Null);
    let leaf = Spec::new("CN=leaf", 60).ext(unknown(true)).issue(Some(&p.root));
    assert_eq!(outcome(verify(&s, pem(&[&leaf]))), failed(UNHANDLED_CRITICAL_EXTENSION));
    let leaf = Spec::new("CN=leaf", 60).ext(unknown(false)).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&leaf])).is_ok());
    // On the root too.
    let root = Spec::new("CN=Crit Root", 61).ca().ext(unknown(true)).issue(None);
    let leaf = Spec::new("CN=leaf", 62).issue(Some(&root));
    assert_eq!(outcome(verify(&store_of(&[&root]), pem(&[&leaf]))), failed(UNHANDLED_CRITICAL_EXTENSION));
    // Critical certificatePolicies and extendedKeyUsage are accepted.
    let policies = ext("2.5.29.32", true, &vec![x509_cert::ext::pkix::certpolicy::PolicyInformation {
        policy_identifier: x509_cert::der::oid::ObjectIdentifier::new_unwrap("2.5.29.32.0"),
        policy_qualifiers: None,
    }]);
    let eku = ext("2.5.29.37", true, &vec![x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2")]);
    let leaf = Spec::new("CN=leaf", 63).ext(policies).ext(eku).issue(Some(&p.root));
    assert!(verify(&s, pem(&[&leaf])).is_ok());
    // Name constraints are not supported: refused as unhandled.
    use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
    use x509_cert::ext::pkix::name::GeneralName;
    let subtree = GeneralSubtree {
        base: GeneralName::DnsName(x509_cert::der::asn1::Ia5String::new(".example.com").unwrap()),
        minimum: 0,
        maximum: None,
    };
    let nc = NameConstraints { permitted_subtrees: Some(vec![subtree]), excluded_subtrees: None };
    let root = Spec::new("CN=NC Root", 64).ca().ext(ext("2.5.29.30", true, &nc)).issue(None);
    let leaf = Spec::new("CN=leaf", 65).issue(Some(&root));
    assert_eq!(outcome(verify(&store_of(&[&root]), pem(&[&leaf]))), failed(UNHANDLED_CRITICAL_EXTENSION));
}

#[test]
fn self_signed_certificates() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // A self-signed phone certificate that is not in the store.
    let selfie = Spec::new("CN=selfie", 70).issue(None);
    assert_eq!(outcome(verify(&s, pem(&[&selfie]))), failed(DEPTH_ZERO_SELF_SIGNED_CERT));
    // The same certificate in the store is its own trust anchor.
    assert!(verify(&store_of(&[&p.root, &selfie]), pem(&[&selfie])).is_ok());
    // A different certificate with the same name in the store is not.
    let twin = Spec::new("CN=selfie", 71).issue(None);
    assert_eq!(outcome(verify(&store_of(&[&twin]), pem(&[&selfie]))), failed(DEPTH_ZERO_SELF_SIGNED_CERT));
    // A self-signed CA sent by the phone as its intermediate.
    let rogue = Spec::new("CN=Rogue Root", 72).ca().serial(73).issue(None);
    let phone = Spec::new("CN=phone", 74).issue(Some(&rogue));
    assert_eq!(outcome(verify(&s, chain(&p, &rogue, &phone))), failed(SELF_SIGNED_CERT_IN_CHAIN));
}

#[test]
fn chain_must_reach_the_store() {
    let p = pki();
    // Only the intermediate in the store: it is not self-issued, so not
    // a trust anchor, and its issuer is not there.
    let s = store_of(&[&p.inter]);
    assert_eq!(outcome(verify(&s, chain(&p, &p.inter, &p.phone))), failed(UNABLE_TO_GET_ISSUER_CERT));
    let leaf = Spec::new("CN=leaf", 80).issue(Some(&p.inter));
    assert_eq!(outcome(verify(&s, pem(&[&leaf]))), failed(UNABLE_TO_GET_ISSUER_CERT));
    // The intermediate and the root in the store: the chain completes
    // from the store.
    assert!(verify(&store_of(&[&p.inter, &p.root]), pem(&[&leaf])).is_ok());
    // A rogue PKI.
    let rogue_root = Spec::new("CN=Test Root,O=Rogue", 81).ca().issue(None);
    let rogue_inter = Spec::new("CN=Rogue Inter", 82).serial(83).ca().issue(Some(&rogue_root));
    let rogue_phone = Spec::new("CN=phone", 84).issue(Some(&rogue_inter));
    assert_eq!(
        outcome(verify(&store_of(&[&p.root]), chain(&p, &rogue_inter, &rogue_phone))),
        failed(UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    );
}

#[test]
fn signature_algorithms_and_key_sizes() {
    // SHA-1 and SHA-256 with RSA keys from 512 bits.
    for (hash, bits) in [(Hash::Sha1, 512), (Hash::Sha256, 512), (Hash::Sha1, 1024), (Hash::Sha256, 2048)] {
        let root = Spec::new("CN=Alg Root", 90).bits(bits, 90).hash(hash).ca().issue(None);
        let inter = Spec::new("CN=Alg Inter", 91).bits(bits, 91).hash(hash).serial(92).ca().issue(Some(&root));
        let phone = Spec::new("CN=phone", 93).bits(bits, 93).hash(hash).issue(Some(&inter));
        let r = verify(&store_of(&[&root]), pem(&[&phone, &inter, &phone]));
        assert!(r.is_ok(), "{:?} {}: {:?}", hash, bits, r.err());
    }
    let p = pki();
    let s = store_of(&[&p.root]);
    // Other hashes, correctly signed.
    for hash in [Hash::Sha224, Hash::Sha384, Hash::Sha512] {
        let leaf = Spec::new("CN=leaf", 94).hash(hash).issue(Some(&p.root));
        assert_eq!(outcome(verify(&s, pem(&[&leaf]))), failed(CERT_SIGNATURE_FAILURE), "{:?}", hash);
    }
    // Other algorithms: md5WithRSAEncryption, RSASSA-PSS, and
    // sha1WithRSA under its OIW OID.
    for oid in ["1.2.840.113549.1.1.4", "1.2.840.113549.1.1.10", "1.3.14.3.2.29"] {
        let mut spec = Spec::new("CN=leaf", 95).hash(Hash::Sha1);
        spec.sig_oid = Some(oid);
        assert_eq!(outcome(verify(&s, pem(&[&spec.issue(Some(&p.root))]))), failed(CERT_SIGNATURE_FAILURE), "{}", oid);
    }
    // An issuer key under 512 bits.
    let small = Spec::new("CN=Small Root", 96).bits(384, 96).hash(Hash::Sha1).ca().issue(None);
    let leaf = Spec::new("CN=leaf", 97).hash(Hash::Sha1).issue(Some(&small));
    assert_eq!(outcome(verify(&store_of(&[&small]), pem(&[&leaf]))), failed(CERT_SIGNATURE_FAILURE));
}

#[test]
fn unreadable_input() {
    let p = pki();
    let s = store_of(&[&p.root]);
    let client = ClientInfo { contact: b"c", mac: None, user_agent: b"ua" };
    let read = |body: &[u8]| testlog::capture(|| verify_client_chain(&s, body, &client));
    let block = |b64: &str| format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64);
    // BER: an indefinite-length outer SEQUENCE.
    let der = &p.legacy.der;
    let (tbs, _, _) = parts(der);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[tbs.start..]);
    ber.extend([0, 0]);
    let mut trailing = der.clone();
    trailing.extend(b"trailing data");
    // A basicConstraints extension that does not decode, and one that
    // occurs twice.
    let bad_bc = Spec::new("CN=bad", 98).ext(ext("2.5.29.19", false, &x509_cert::der::asn1::Null)).issue(Some(&p.root));
    let two_bc =
        Spec::new("CN=two", 99).ext(basic_constraints(false, None)).ext(basic_constraints(false, None)).issue(Some(&p.root));
    for body in [
        String::new(),
        "hello".to_string(),
        block("AAAA"),
        pem_of(&der[..100]),
        block("MII!"),
        block("MIIB=A"),
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERT-----\n".to_string(),
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n".to_string(),
        "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nQUJD\n-----END CERTIFICATE-----\n".to_string(),
        p.legacy.pem().replace("CERTIFICATE", "TRUSTED CERTIFICATE"),
        p.legacy.pem().replace("CERTIFICATE", "X509 CERTIFICATE"),
        pem_of(&ber),
        pem_of(&trailing),
        bad_bc.pem(),
        two_bc.pem(),
    ] {
        let (r, logs) = read(body.as_bytes());
        assert_eq!(r.err(), Some(CertError::Unreadable), "{:?}", body);
        assert_eq!(logs[0], "Contact: c MAC: (null) UA: ua Using legacy certificate\n");
        assert_eq!(logs[1], "<c>: Unable to read client cert: certificate parse error\n");
    }
    // Text around the block and line breaks anywhere in the base64 text
    // are fine.
    let one_line = p.legacy.pem().replace('\n', "");
    assert!(verify(&s, format!("junk -----BEGIN x\n{}\n\n-----END junk\n", p.legacy.pem())).is_ok());
    assert!(verify(&s, &one_line).is_ok());
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
    // and after each BEGIN and END line): both forms are restored, and
    // verify.
    for body in [pem(&[&p.legacy]), chain(&p, &p.inter, &p.phone)] {
        let broken = body.replace("-----\n", "-----").replace("\n-----", "-----");
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
fn intermediate_serials() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // A zero serial on the intermediate makes the official DPMA read the
    // next certificate's serial.
    let inter0 = Spec::new("CN=Inter0", 130).serial(0).ca().issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 99).issue(Some(&inter0));
    let (r, logs) = testlog::capture(|| verify(&s, pem(&[&p.legacy, &inter0, &phone])));
    assert_eq!(r.unwrap().intermediate_serial, 99);
    assert_eq!(logs.len(), 2);
    assert!(logs[0].ends_with("Intermediate cert serial number: 0\n"));
    assert!(logs[1].ends_with("Intermediate cert serial number: 99\n"));
    // A negative serial is an error.
    let neg = Spec::new("CN=InterNeg", 131).serial_der(&[0xfb]).ca().issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 132).issue(Some(&neg));
    let (r, logs) = testlog::capture(|| verify(&s, pem(&[&p.legacy, &neg, &phone])));
    assert_eq!(r.err(), Some(CertError::NoSerial));
    assert_eq!(
        logs,
        vec!["<sip:phone@127.0.0.1:5060>: Unable to get serial number of intermediate cert: negative serial number\n"]
    );
    // Serials too large for a long long saturate (strtoll).
    let big = Spec::new("CN=InterBig", 133).serial_der(&[0x7f; 12]).ca().issue(Some(&p.root));
    let phone = Spec::new("CN=phone", 134).issue(Some(&big));
    assert_eq!(verify(&s, pem(&[&p.legacy, &big, &phone])).unwrap().intermediate_serial, i64::MAX);
}

#[test]
fn public_keys() {
    let p = pki();
    let s = store_of(&[&p.root]);
    // A phone key that is not RSA (here, the rsaEncryption OID changed to
    // RSAES-OAEP's) still verifies: only the issuers' keys are used.
    let rsa_oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let mut oaep_oid = rsa_oid;
    oaep_oid[10] = 0x07;
    let (tbs, _, _) = parts(&p.legacy.der);
    let spki = tbs.start + p.legacy.der[tbs.clone()].windows(11).rposition(|w| w == rsa_oid).unwrap();
    let mut other = p.legacy.der.clone();
    other[spki..spki + 11].copy_from_slice(&oaep_oid);
    let other = resign(&other, &p.root.key, Hash::Sha256);
    assert_eq!(verify(&s, pem_of(&other)).unwrap().public_key, Some(PublicKey::Other));
    // An RSA key that does not decode (its SEQUENCE tag changed).
    let mut broken = p.legacy.der.clone();
    let seq = spki + 11 + 2 + 3 + 1;
    assert_eq!(broken[seq - 1..seq + 1], [0x00, 0x30]);
    broken[seq] = 0x31;
    let broken = resign(&broken, &p.root.key, Hash::Sha256);
    assert_eq!(verify(&s, pem_of(&broken)).unwrap().public_key, None);
}

#[test]
fn no_panics_on_damaged_input() {
    // The verifier sees what any device sends: damaged certificates must
    // be refused, never crash the module.  Every octet of a chain's
    // certificates changed several ways, and every truncation.
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
            let one = pem_of(&d);
            let body = match k {
                0 => one,
                1 => format!("{}{}{}", p.legacy.pem(), one, p.phone.pem()),
                _ => format!("{}{}{}", p.legacy.pem(), p.inter.pem(), one),
            };
            let _ = verify(&s, &body);
        }
    }
}

/// The official DPMA's CA certificates and AppServer certificate, which the
/// module embeds (crates/res_dpma_rs/src/trust).
const EMBEDDED_CA: &[u8] = include_bytes!("../../../res_dpma_rs/src/trust/phone_ca.pem");
const EMBEDDED_APPSERVER: &[u8] = include_bytes!("../../../res_dpma_rs/src/trust/appserver.pem");

#[test]
fn embedded_trust_material() {
    // The bundle reads as three self-issued certificates: the Sangoma
    // root (v3, CA:TRUE, 4096 bits), the Digium AppServer CA as a v1
    // certificate, and the same CA (same key) as an expired v3
    // certificate with CA:TRUE.
    let certs: Vec<Certificate> = pem_certificates(EMBEDDED_CA).map(Option::unwrap).collect();
    assert_eq!(certs.len(), 3);
    for c in &certs {
        assert!(c.self_issued());
    }
    let versions: Vec<_> = certs.iter().map(|c| c.cert.tbs_certificate.version).collect();
    assert_eq!(versions, [Version::V3, Version::V1, Version::V3]);
    let ca: Vec<_> = certs.iter().map(|c| c.basic_constraints.as_ref().map(|bc| bc.ca)).collect();
    assert_eq!(ca, [Some(true), None, Some(true)]);
    let bits: Vec<usize> = certs.iter().map(|c| c.public_key().unwrap().rsa().unwrap().bits()).collect();
    assert_eq!(bits, [4096, 1024, 1024]);
    assert_eq!(certs[1].public_key(), certs[2].public_key());
    let store = CaStore::from_pem(EMBEDDED_CA).unwrap();
    // Each verifies as a phone's legacy certificate (it is in the store).
    for c in &certs {
        assert!(verify(&store, pem_of(c.der())).is_ok());
    }
    // The AppServer certificate (v1, a 512-bit key, SHA-256) is issued by
    // "Digium Appserver": it verifies against the bundle, against either
    // Digium Appserver certificate alone, and not against the Sangoma
    // root.
    let app: Vec<Certificate> = pem_certificates(EMBEDDED_APPSERVER).map(Option::unwrap).collect();
    assert_eq!(app.len(), 1);
    assert_eq!(app[0].cert.tbs_certificate.version, Version::V1);
    assert_eq!(app[0].public_key().unwrap().rsa().unwrap().bits(), 512);
    let v = verify(&store, EMBEDDED_APPSERVER).unwrap();
    assert!(v.legacy);
    assert_eq!(v.certificate, app[0]);
    let only = |i: usize| CaStore::from_pem(pem_of(certs[i].der()).as_bytes()).unwrap();
    assert!(verify(&only(1), EMBEDDED_APPSERVER).is_ok());
    assert!(verify(&only(2), EMBEDDED_APPSERVER).is_ok());
    assert_eq!(outcome(verify(&only(0), EMBEDDED_APPSERVER)), failed(UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
}
