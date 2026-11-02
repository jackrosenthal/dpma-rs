//! The test PKI for the phone simulator (the Rust form of the former
//! `tests/sim/mkpki.py`).
//!
//! Everything is generated locally; nothing comes from the original
//! binary.  The PKI has two independent halves, the phone side (the CAs
//! and phone certificates) and the AppServer side:
//!
//! | Entity | Issuer | Notes |
//! |---|---|---|
//! | `root-ca` | itself | The module's `phone_ca_file`. |
//! | `intermediate-ca` | root-ca | Serial number 4097 (logged by the module as "Intermediate cert serial number"). |
//! | `phone` | intermediate-ca | Chain form phone certificate. |
//! | `legacy` | root-ca | Legacy form phone certificate. |
//! | `phone-expired`, `legacy-expired` | intermediate-ca, root-ca | Valid 2001 to 2002. |
//! | `rogue-ca`, `rogue` | itself, rogue-ca | Not trusted by the module. |
//! | `weak` | root-ca | 512-bit RSA key, SHA-1 signature. |
//! | `appserver-ca`, `appserver` | itself, appserver-ca | The module's `appserver_certificate`; the simulator checks the HandshakeResponse body against `appserver-ca`. |
//!
//! Files (in the PKI directory, by default `dev/sim/pki`, not committed):
//! `<name>.key` (PKCS#1 PEM, mode 0600) and `<name>.pem` for every
//! entity, and `bundles.json`, which lists the handshake bodies the
//! simulator can send ([`BUNDLES`]): the certificates in body order and
//! the key that decrypts the common password.  The server encrypts the
//! common password to the key of the last certificate of the body.
//! Existing files are kept unless [`Generator::force`] is set.
//!
//! | Bundle | Body | The module's answer |
//! |---|---|---|
//! | `legacy` | legacy | HandshakeResponse |
//! | `chain` | legacy, intermediate-ca, phone | HandshakeResponse with `Handshake-Version: 1` |
//! | `chain-expired`, `legacy-expired` | as above, expired | Accepted (OpenSSL errors 9 and 10 are ignored) |
//! | `weak` | weak | Accepted (512-bit keys and SHA-1 must work) |
//! | `rogue` | rogue | No reply; an auth incident |
//! | `two`, `four` | 2 or 4 certificates | No reply ("Expected two certificates in the chain, found 1" or "3") |
//!
//! [`install`] copies `root-ca.pem` to
//! `<etc>/dpma/phone_ca.pem` and `appserver.pem` to
//! `<etc>/dpma/appserver.pem` (the defaults of `phone_ca_file` and
//! `appserver_certificate`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use serde_json::json;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Any, PrintableStringRef, SetOfVec, Utf8StringRef};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{DateTime, Decode, EncodePem};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

use crate::sim::crypto::load_private_key;
use crate::sim::pki::parse_certificate;

/// The fixed serial number of the intermediate CA.
pub const INTERMEDIATE_SERIAL: u32 = 4097;

/// The organization of the test PKI's names.
pub const ORG: &str = "DPMA Simulator Test PKI";

/// The handshake bundles: name, certificates in body order, key entity,
/// and description.
pub const BUNDLES: [(&str, &[&str], &str, &str); 8] = [
    (
        "legacy",
        &["legacy"],
        "legacy",
        "legacy form: one certificate signed by the root CA",
    ),
    (
        "chain",
        &["legacy", "intermediate-ca", "phone"],
        "phone",
        "chain form: legacy, intermediate, and phone certificates",
    ),
    (
        "chain-expired",
        &["legacy", "intermediate-ca", "phone-expired"],
        "phone-expired",
        "chain form with an expired phone certificate (accepted)",
    ),
    (
        "legacy-expired",
        &["legacy-expired"],
        "legacy-expired",
        "legacy form with an expired certificate (accepted)",
    ),
    (
        "rogue",
        &["rogue"],
        "rogue",
        "legacy form signed by an untrusted CA (rejected)",
    ),
    (
        "two",
        &["intermediate-ca", "phone"],
        "phone",
        "two certificates (rejected: 'Expected two certificates in the chain, found 1')",
    ),
    (
        "four",
        &["legacy", "intermediate-ca", "phone", "phone"],
        "phone",
        "four certificates (rejected: '... found 3')",
    ),
    (
        "weak",
        &["weak"],
        "weak",
        "legacy form, 512-bit RSA key with a SHA-1 signature (accepted)",
    ),
];

/// A subject name: `C=US, O=<org>, CN=<cn>` (country as a
/// PrintableString, the others as UTF8Strings).
pub fn name(cn: &str, org: &str) -> Result<Name> {
    let atv = |oid: &str, value: Any| -> Result<RelativeDistinguishedName> {
        let atv = x509_cert::attr::AttributeTypeAndValue {
            oid: ObjectIdentifier::new_unwrap(oid),
            value,
        };
        Ok(RelativeDistinguishedName::from(SetOfVec::try_from(vec![
            atv,
        ])?))
    };
    Ok(RdnSequence(vec![
        atv(
            "2.5.4.6",
            Any::encode_from(&PrintableStringRef::new("US")?)?,
        )?,
        atv("2.5.4.10", Any::encode_from(&Utf8StringRef::new(org)?)?)?,
        atv("2.5.4.3", Any::encode_from(&Utf8StringRef::new(cn)?)?)?,
    ]))
}

/// Makes the test PKI (see the module documentation).
pub struct Generator {
    dir: PathBuf,
    force: bool,
    mac: String,
    bits: usize,
    quiet: bool,
    now: SystemTime,
}

/// How an entity is signed.
#[derive(Clone, Copy)]
enum Digest {
    Sha256,
    Sha1,
}

struct Spec<'a> {
    entity: &'a str,
    cn: String,
    org: &'a str,
    issuer: Option<&'a str>,
    ca: bool,
    pathlen: Option<u8>,
    serial: Option<u32>,
    validity: Option<(SystemTime, SystemTime)>,
    bits: usize,
    digest: Digest,
}

impl Generator {
    /// A generator for the PKI directory `dir` (created when missing).
    pub fn new(dir: &Path) -> Generator {
        Generator {
            dir: dir.to_path_buf(),
            force: false,
            mac: crate::sim::DEFAULT_MAC.into(),
            bits: 2048,
            quiet: false,
            now: SystemTime::now(),
        }
    }

    /// Regenerate existing files (default: keep them).
    pub fn force(mut self, yes: bool) -> Self {
        self.force = yes;
        self
    }

    /// The MAC used in the subject names (colons removed, lowercase).
    pub fn mac(mut self, mac: &str) -> Self {
        self.mac = mac.replace(':', "").to_lowercase();
        self
    }

    /// The RSA key size of every entity but `weak` (default 2048; smaller
    /// keys make quick throwaway PKIs for unit tests).
    pub fn bits(mut self, bits: usize) -> Self {
        self.bits = bits;
        self
    }

    /// Print nothing.
    pub fn quiet(mut self) -> Self {
        self.quiet = true;
        self
    }

    fn say(&self, text: &str) {
        if !self.quiet {
            println!("{text}");
        }
    }

    fn path(&self, entity: &str, ext: &str) -> PathBuf {
        self.dir.join(format!("{entity}.{ext}"))
    }

    fn exists(&self, entity: &str) -> bool {
        !self.force && self.path(entity, "key").exists() && self.path(entity, "pem").exists()
    }

    fn load(&self, entity: &str) -> Result<(RsaPrivateKey, Certificate)> {
        let key = load_private_key(&self.path(entity, "key"))?;
        let cert = parse_certificate(&std::fs::read(self.path(entity, "pem"))?)
            .with_context(|| self.path(entity, "pem").display().to_string())?;
        Ok((key, cert))
    }

    fn save(
        &self,
        entity: &str,
        key: &RsaPrivateKey,
        cert: &Certificate,
        what: &str,
    ) -> Result<()> {
        let key_path = self.path(entity, "key");
        let pem = key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| anyhow!("{e}"))?;
        std::fs::write(&key_path, pem.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        let cert_pem = cert.to_pem(LineEnding::LF).map_err(|e| anyhow!("{e}"))?;
        std::fs::write(self.path(entity, "pem"), cert_pem)?;
        self.say(&format!("  wrote {entity}.{{key,pem}}: {what}"));
        Ok(())
    }

    fn random_serial() -> Result<SerialNumber> {
        let mut b = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut b);
        b[0] &= 0x7f;
        if b[0] == 0 {
            b[0] = 1;
        }
        Ok(SerialNumber::new(&b)?)
    }

    fn make(&self, s: Spec<'_>) -> Result<()> {
        if self.exists(s.entity) {
            return Ok(());
        }
        let key =
            RsaPrivateKey::new(&mut rand::thread_rng(), s.bits).map_err(|e| anyhow!("{e}"))?;
        let subject = name(&s.cn, s.org)?;
        let (issuer_key, issuer_name) = match s.issuer {
            None => (key.clone(), None),
            Some(i) => {
                let (k, c) = self.load(i)?;
                (k, Some(c.tbs_certificate.subject))
            }
        };
        let day = Duration::from_secs(86400);
        let (not_before, not_after) = s.validity.unwrap_or((
            self.now - day,
            self.now + day * 365 * if s.ca { 20 } else { 10 },
        ));
        let validity = Validity {
            not_before: Time::try_from(not_before)?,
            not_after: Time::try_from(not_after)?,
        };
        let serial = match s.serial {
            Some(n) => SerialNumber::from(n),
            None => Self::random_serial()?,
        };
        let spki_der = key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| anyhow!("{e}"))?;
        let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?;
        let issuer_spki_der = issuer_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| anyhow!("{e}"))?;
        let issuer_spki = SubjectPublicKeyInfoOwned::from_der(issuer_spki_der.as_bytes())?;
        let profile = Profile::Manual {
            issuer: issuer_name,
        };
        let usage = if s.ca {
            KeyUsages::KeyCertSign | KeyUsages::CRLSign
        } else {
            KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment
        };
        let ski = SubjectKeyIdentifier::try_from(spki.owned_to_ref())?;
        let aki = AuthorityKeyIdentifier::try_from(issuer_spki.owned_to_ref())?;
        let bc = BasicConstraints {
            ca: s.ca,
            path_len_constraint: s.pathlen,
        };
        macro_rules! build {
            ($d:ty) => {{
                let signer = SigningKey::<$d>::new(issuer_key.clone());
                let mut b =
                    CertificateBuilder::new(profile, serial, validity, subject, spki, &signer)?;
                b.add_extension(&bc)?;
                b.add_extension(&ski)?;
                b.add_extension(&aki)?;
                b.add_extension(&KeyUsage(usage))?;
                b.build::<rsa::pkcs1v15::Signature>()?
            }};
        }
        use x509_cert::spki::der::referenced::OwnedToRef;
        let cert = match s.digest {
            Digest::Sha256 => build!(sha2::Sha256),
            Digest::Sha1 => build!(sha1::Sha1),
        };
        let what = if s.bits < 1024 {
            format!(
                "{}-bit RSA, SHA-1, issued by {}",
                s.bits,
                s.issuer.unwrap_or("itself")
            )
        } else {
            cert.tbs_certificate.subject.to_string()
        };
        self.save(s.entity, &key, &cert, &what)
    }

    /// Creates the missing files (all of them with [`Generator::force`])
    /// and writes `bundles.json`.
    pub fn generate(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir).with_context(|| self.dir.display().to_string())?;
        self.say(&format!("generating test PKI in {}", self.dir.display()));
        let mac = &self.mac;
        let spec = |entity, cn: String, issuer, ca| Spec {
            entity,
            cn,
            org: ORG,
            issuer,
            ca,
            pathlen: None,
            serial: None,
            validity: None,
            bits: self.bits,
            digest: Digest::Sha256,
        };
        let old = (
            SystemTime::from(DateTime::new(2001, 1, 1, 0, 0, 0)?),
            SystemTime::from(DateTime::new(2002, 1, 1, 0, 0, 0)?),
        );
        self.make(spec(
            "root-ca",
            "DPMA Test Phone Root CA".into(),
            None,
            true,
        ))?;
        self.make(Spec {
            pathlen: Some(0),
            serial: Some(INTERMEDIATE_SERIAL),
            ..spec(
                "intermediate-ca",
                "DPMA Test Phone Intermediate CA".into(),
                Some("root-ca"),
                true,
            )
        })?;
        self.make(spec(
            "phone",
            format!("DPMA Sim Phone {mac}"),
            Some("intermediate-ca"),
            false,
        ))?;
        self.make(spec(
            "legacy",
            format!("DPMA Sim Legacy Phone {mac}"),
            Some("root-ca"),
            false,
        ))?;
        self.make(Spec {
            validity: Some(old),
            ..spec(
                "phone-expired",
                format!("DPMA Sim Expired Phone {mac}"),
                Some("intermediate-ca"),
                false,
            )
        })?;
        self.make(Spec {
            validity: Some(old),
            ..spec(
                "legacy-expired",
                format!("DPMA Sim Expired Legacy Phone {mac}"),
                Some("root-ca"),
                false,
            )
        })?;
        self.make(Spec {
            org: "Rogue",
            ..spec("rogue-ca", "DPMA Untrusted Rogue CA".into(), None, true)
        })?;
        self.make(Spec {
            org: "Rogue",
            ..spec(
                "rogue",
                format!("DPMA Sim Rogue Phone {mac}"),
                Some("rogue-ca"),
                false,
            )
        })?;
        let weak_kept = !self.force && self.path("weak", "pem").exists();
        if !weak_kept {
            let day = Duration::from_secs(86400);
            self.make(Spec {
                bits: 512,
                digest: Digest::Sha1,
                serial: Some(513),
                validity: Some((self.now, self.now + day * 3650)),
                ..spec(
                    "weak",
                    format!("DPMA Sim Weak Legacy Phone {mac}"),
                    Some("root-ca"),
                    false,
                )
            })?;
        }
        self.make(spec(
            "appserver-ca",
            "DPMA Test AppServer CA".into(),
            None,
            true,
        ))?;
        self.make(spec(
            "appserver",
            "DPMA Test AppServer".into(),
            Some("appserver-ca"),
            false,
        ))?;

        let mut bundles = serde_json::Map::new();
        for (n, certs, key, desc) in BUNDLES {
            let certs: Vec<String> = certs.iter().map(|c| format!("{c}.pem")).collect();
            bundles.insert(
                n.into(),
                json!({"certs": certs, "key": format!("{key}.key"), "description": desc}),
            );
        }
        let manifest = json!({
            "appserver_ca": "appserver-ca.pem",
            "phone_ca": "root-ca.pem",
            "intermediate_serial": INTERMEDIATE_SERIAL,
            "bundles": bundles,
        });
        std::fs::write(
            self.dir.join("bundles.json"),
            serde_json::to_string_pretty(&manifest)? + "\n",
        )?;
        let names: Vec<&str> = BUNDLES.iter().map(|b| b.0).collect();
        self.say(&format!("  wrote bundles.json: {}", names.join(", ")));
        Ok(())
    }
}

/// Installs the trust material of the PKI in `pki_dir` into an instance's
/// configuration directory `etc` (`.../etc/asterisk`): `root-ca.pem` as
/// `dpma/phone_ca.pem` and `appserver.pem` as `dpma/appserver.pem`,
/// each written to a temporary file and renamed into place.
pub fn install(pki_dir: &Path, etc: &Path, quiet: bool) -> Result<()> {
    if !etc.is_dir() {
        anyhow::bail!(
            "{} is not an Asterisk configuration directory",
            etc.display()
        );
    }
    let dest = etc.join("dpma");
    std::fs::create_dir_all(&dest)?;
    for (src, dst) in [
        ("root-ca.pem", "phone_ca.pem"),
        ("appserver.pem", "appserver.pem"),
    ] {
        let tmp = dest.join(format!(".{dst}.new"));
        std::fs::copy(pki_dir.join(src), &tmp)
            .with_context(|| pki_dir.join(src).display().to_string())?;
        std::fs::rename(&tmp, dest.join(dst))?;
        if !quiet {
            println!("installed {src} as {}", dest.join(dst).display());
        }
    }
    Ok(())
}

/// Verifies every certificate with the `openssl verify` command; the
/// expected outcome follows the module's rules (expiry ignored, 512-bit
/// keys accepted).  Prints one line per case and returns the number of
/// unexpected outcomes.
pub fn check(dir: &Path) -> Result<usize> {
    let d = |f: &str| dir.join(f).display().to_string();
    let mut cases: Vec<(&str, Vec<String>, bool)> = vec![
        (
            "legacy",
            vec!["-CAfile".into(), d("root-ca.pem"), d("legacy.pem")],
            true,
        ),
        (
            "chain",
            vec![
                "-CAfile".into(),
                d("root-ca.pem"),
                "-untrusted".into(),
                d("intermediate-ca.pem"),
                d("phone.pem"),
            ],
            true,
        ),
        (
            "intermediate",
            vec!["-CAfile".into(), d("root-ca.pem"), d("intermediate-ca.pem")],
            true,
        ),
        (
            "chain-expired",
            vec![
                "-no_check_time".into(),
                "-CAfile".into(),
                d("root-ca.pem"),
                "-untrusted".into(),
                d("intermediate-ca.pem"),
                d("phone-expired.pem"),
            ],
            true,
        ),
        (
            "chain-expired (time checked)",
            vec![
                "-CAfile".into(),
                d("root-ca.pem"),
                "-untrusted".into(),
                d("intermediate-ca.pem"),
                d("phone-expired.pem"),
            ],
            false,
        ),
        (
            "legacy-expired",
            vec![
                "-no_check_time".into(),
                "-CAfile".into(),
                d("root-ca.pem"),
                d("legacy-expired.pem"),
            ],
            true,
        ),
        (
            "rogue",
            vec!["-CAfile".into(), d("root-ca.pem"), d("rogue.pem")],
            false,
        ),
        (
            "phone without intermediate",
            vec!["-CAfile".into(), d("root-ca.pem"), d("phone.pem")],
            false,
        ),
        (
            "appserver",
            vec!["-CAfile".into(), d("appserver-ca.pem"), d("appserver.pem")],
            true,
        ),
        (
            "appserver against phone CA",
            vec!["-CAfile".into(), d("root-ca.pem"), d("appserver.pem")],
            false,
        ),
    ];
    if dir.join("weak.pem").exists() {
        cases.push((
            "weak (auth level 0)",
            vec![
                "-auth_level".into(),
                "0".into(),
                "-CAfile".into(),
                d("root-ca.pem"),
                d("weak.pem"),
            ],
            true,
        ));
    }
    let mut failures = 0;
    let error_line = regex::Regex::new(r"error \d+ at \d+ depth")?;
    for (label, args, want) in cases {
        let out = Command::new("openssl")
            .arg("verify")
            .args(&args)
            .output()
            .context("running openssl")?;
        let ok = out.status.success();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        let reason = text
            .lines()
            .find(|l| error_line.is_match(l))
            .map(|l| l.rsplit(':').next().unwrap_or("").trim().to_string());
        let detail = reason.unwrap_or_else(|| if ok { "OK".into() } else { "failed".into() });
        let good = ok == want;
        if !good {
            failures += 1;
        }
        println!(
            "{:<4} {:<30} {} ({detail})",
            if good { "ok" } else { "FAIL" },
            label,
            if ok { "verifies" } else { "rejected" }
        );
    }
    Ok(failures)
}
