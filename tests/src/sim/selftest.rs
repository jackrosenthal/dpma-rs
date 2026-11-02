//! The simulator's self-test (no server needed) and the cross-check
//! vectors.
//!
//! [`run`] checks: known-answer key, IV, and ciphertext (and
//! `EVP_BytesToKey` against fixed known answers, [`BYTES_TO_KEY_KATS`]),
//! stream encryption, header fields, `set_hex` and `ast_base64decode`
//! quirks, both directions of framing (the server side emulated from
//! `phone_msg_outgoing_send` and `incoming_check_finalize`), the CR/LF
//! rule, RSA common passwords with every bundle key, the AppServer check,
//! an in-process protocol round trip over UDP sockets against
//! [`FakeServer`] (both handshake forms, encrypted requests and replies in
//! many chunks, tokens, events, unknown session, rejected certificate),
//! `tests/data/vectors.json`, and dpma-proto's
//! `crates/dpma-proto/tests/fixtures/proto_vectors.json`.
//!
//! [`make_vectors`] writes the vectors that dpma-proto's
//! `tests/sim_vectors.rs` checks the module's crypto against.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bstr::{BString, ByteSlice};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use rsa::Pkcs1v15Encrypt;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use x509_cert::der::Decode;
use x509_cert::Certificate;

use super::crypto::*;
use super::framing::*;
use super::pki::{
    key_bits, parse_certificate, pem_certificates, public_key, verify_directly_issued_by, Pki,
};
use super::proto::*;
use super::{repo_root, Form, Options, Phone};
use crate::harness::Checker;
use crate::sip::{self, Message};

/// The known-answer password: bytes 0 to 39.
pub const KAT_PASSWORD: [u8; 40] = {
    let mut a = [0u8; 40];
    let mut i = 0;
    while i < 40 {
        a[i] = i as u8;
        i += 1;
    }
    a
};
/// The known-answer salt: bytes 1 to 8.
pub const KAT_SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
/// Key for [`KAT_PASSWORD`] and [`KAT_SALT`] (`EVP_BytesToKey`, computed
/// independently with Python's hashlib).
pub const KAT_KEY: &str = "600d4ffb274b57fc61281e5709e7f660";
/// IV for [`KAT_PASSWORD`] and [`KAT_SALT`].
pub const KAT_IV: &str = "1886e7fef5d8004f796243b3de6a68aa";
/// The known-answer plaintext.
pub const KAT_PLAIN: &[u8] = b"<config></config>";
/// [`KAT_PLAIN`] encrypted with AES-128-CBC under [`KAT_KEY`] and
/// [`KAT_IV`] (computed independently of this code), base64.
pub const KAT_CIPHER_B64: &str = "AUjOV390vW2DtV+JXPqenXE+oRcQpCc41+4TU6Vr6MA=";

/// `tests/data/vectors.json`, the vectors dpma-proto checks.
pub fn vectors_path() -> PathBuf {
    repo_root().join("tests").join("data").join("vectors.json")
}

/// dpma-proto's vectors, checked by [`run`].
pub fn proto_vectors_path() -> PathBuf {
    repo_root()
        .join("crates")
        .join("dpma-proto")
        .join("tests")
        .join("fixtures")
        .join("proto_vectors.json")
}

/// Deterministic vectors for cross-checking other implementations
/// (dpma-proto): key and IV derivation, a body, a header field, and the
/// server's framing of an encrypted event over UDP (prefix in every
/// chunk, one CBC stream, each chunk's ciphertext base64 encoded on its
/// own), all with a fixed password and salt.
pub fn make_vectors() -> Value {
    let (pw, salt) = (&KAT_PASSWORD[..], &KAT_SALT[..]);
    let mut body = b"<config>".to_vec();
    for _ in 0..100 {
        body.extend_from_slice(b"0123456789");
    }
    body.extend_from_slice(b"</config>");
    let frames = server_frame(
        &body,
        SERVER_UDP_ENCRYPTED_LIMIT,
        Some((pw, salt)),
        COMMAND_PREFIX,
        false,
    );
    let frames: Vec<Value> = frames
        .iter()
        .map(|f| {
            let mut h = serde_json::Map::new();
            for (k, v) in &f.headers {
                h.insert(k.to_string(), Value::String(v.clone()));
            }
            json!({"headers": h, "body": f.body.to_str_lossy()})
        })
        .collect();
    json!({
        "password_hex": hex::encode(pw),
        "salt_hex": salt_hex(salt),
        "key_hex": KAT_KEY,
        "iv_hex": KAT_IV,
        "plain": KAT_PLAIN.to_str_lossy(),
        "cipher_b64": b64encode(&encrypt(pw, salt, KAT_PLAIN)),
        "field_1234_b64": encrypt_field(pw, salt, b"1234"),
        "event_body": body.to_str_lossy(),
        "event_frames_udp": frames,
    })
}

/// [`make_vectors`] as the text of `tests/data/vectors.json`.
pub fn vectors_text() -> String {
    serde_json::to_string_pretty(&make_vectors()).unwrap_or_default() + "\n"
}

/// Known answers for `EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt,
/// password, 1)`: password and salt (hex), key and IV.  Computed
/// independently with Python's hashlib from the definition in the
/// official DPMA's OpenSSL 1.1.1t (`crypto/evp/evp_key.c`: D1 =
/// SHA1(password || salt), D2 = SHA1(D1 || password || salt), key =
/// D1[0..16], IV = D1[16..20] || D2[0..12]).
pub const BYTES_TO_KEY_KATS: [(&str, &str, &str, &str); 6] = [
    ("", "3132333435363738", "7c222fb2927d828af22f592134e89324", "80637c0d7a6e3c10173302c9578ee71c"),
    ("78", "3132333435363738", "947788df997e7a3a3a974204486b5233", "9abdf89b8358e0c4a989f89694f12309"),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
        "0102030405060708",
        "600d4ffb274b57fc61281e5709e7f660",
        "1886e7fef5d8004f796243b3de6a68aa",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffff",
        "989fbd16297ef75e5a9d5c63f7096c99",
        "b455563de0606deaeaa55baeb093dafe",
    ),
    (
        "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
        "0000000000000000",
        "e6014ae359ac8fcd57c02182e8d51e5e",
        "5f2651aa7220d151f186f26f39aab36b",
    ),
    ("64706d612d7273", "0011223344556677", "d2b10809b051799e8eab22c1eb1504fd", "21a3a94d58740b75adbc09594e6ff47c"),
];

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

/// Runs the self-test, reporting into `c`.  `pki_dir` is the test PKI
/// (its checks and the protocol round trip are skipped when it is
/// missing).
pub fn run(c: &mut Checker, pki_dir: &Path) {
    crypto_checks(c);
    framing_checks(c);
    match Pki::open(pki_dir) {
        Ok(pki) => {
            if let Err(e) = pki_checks(c, &pki) {
                c.fail("PKI checks", e);
            }
            if let Err(e) = loopback_test(c, pki_dir) {
                c.fail("loopback test", e);
            }
        }
        Err(e) => c.skip("PKI checks", e),
    }
    let path = vectors_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            c.check(
                "vectors.json matches this implementation",
                v == make_vectors(),
                path.display(),
            );
        }
        Err(_) => c.skip("vectors.json", format!("not found: {}", path.display())),
    }
    let path = proto_vectors_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => check_proto_vectors(c, &v),
            Err(e) => c.fail("proto_vectors.json", e),
        },
        Err(_) => c.skip(
            "proto_vectors.json",
            format!("not found: {}", path.display()),
        ),
    }
}

fn crypto_checks(c: &mut Checker) {
    let (key, iv) = evp_bytes_to_key(&KAT_PASSWORD, &KAT_SALT);
    c.check(
        "EVP_BytesToKey known answer",
        hex::encode(key) == KAT_KEY && hex::encode(iv) == KAT_IV,
        format!("{} {}", hex::encode(key), hex::encode(iv)),
    );
    let mut d1 = Sha1::new();
    d1.update(KAT_PASSWORD);
    d1.update(KAT_SALT);
    let d1 = d1.finalize();
    let mut d2 = Sha1::new();
    d2.update(d1);
    d2.update(KAT_PASSWORD);
    d2.update(KAT_SALT);
    let d2 = d2.finalize();
    let mut want_iv = d1[16..20].to_vec();
    want_iv.extend_from_slice(&d2[..12]);
    c.check(
        "key/IV equal the plan's D1/D2 formula",
        key[..] == d1[..16] && iv[..] == want_iv[..],
        "",
    );
    let kats_ok = BYTES_TO_KEY_KATS.iter().all(|(pw, salt, key, iv)| {
        let (pw, salt) = (hex::decode(pw).unwrap_or_default(), hex::decode(salt).unwrap_or_default());
        let (k, i) = evp_bytes_to_key(&pw, &salt);
        hex::encode(k) == *key && hex::encode(i) == *iv
    });
    c.check(
        "EVP_BytesToKey known answers (6 vectors)",
        kats_ok,
        "",
    );

    let ct = encrypt(&KAT_PASSWORD, &KAT_SALT, KAT_PLAIN);
    c.check(
        "AES-128-CBC known answer",
        b64encode(&ct) == KAT_CIPHER_B64,
        b64encode(&ct),
    );
    c.check(
        "decrypt known answer",
        decrypt(&KAT_PASSWORD, &KAT_SALT, &ct).ok().as_deref() == Some(KAT_PLAIN),
        "",
    );
    c.check(
        "empty plaintext encrypts to one padding block",
        encrypt(&KAT_PASSWORD, &KAT_SALT, b"").len() == 16,
        "",
    );

    let data = random_bytes(2000);
    let whole = encrypt(&KAT_PASSWORD, &KAT_SALT, &data);
    let mut ok = true;
    let cut_lists: [Vec<usize>; 5] = [
        vec![420],
        vec![1, 15, 16, 17],
        vec![0x1a4; 4],
        vec![900, 900],
        vec![7; 100],
    ];
    for cuts in cut_lists {
        let mut e = StreamEncryptor::new(&KAT_PASSWORD, &KAT_SALT);
        let mut pieces = Vec::new();
        let mut pos = 0;
        for n in cuts {
            pieces.push(e.update(&data[pos..pos + n]));
            pos += n;
        }
        let mut last = e.update(&data[pos..]);
        last.extend(e.finish());
        pieces.push(last);
        ok &= pieces.iter().all(|p| p.len() % 16 == 0) && pieces.concat() == whole;
    }
    c.check(
        "stream updates give whole blocks and equal one-shot encryption",
        ok,
        "",
    );

    let salt = random_bytes(8);
    let pw = random_bytes(40);
    let long = "x".repeat(100);
    let ok = ["1234", "", long.as_str(), "päss"].iter().all(|v| {
        decrypt_field(
            &pw,
            &salt,
            encrypt_field(&pw, &salt, v.as_bytes()).as_bytes(),
        )
        .ok()
        .as_deref()
            == Some(v.as_bytes())
    });
    c.check("encrypted header fields round trip", ok, "");
    let hx = salt_hex(&salt);
    c.check(
        "salt hex is 16 uppercase digits",
        hx.len() == 16
            && hx
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
        &hx,
    );
    c.check(
        "set_hex parses both cases",
        set_hex(hx.as_bytes()).ok().map(|s| s.to_vec()) == Some(salt.clone())
            && set_hex(hx.to_lowercase().as_bytes())
                .ok()
                .map(|s| s.to_vec())
                == Some(salt.clone()),
        "",
    );
    c.check(
        "set_hex zero fills short strings",
        set_hex(b"ABC").ok() == Some([0xab, 0xc0, 0, 0, 0, 0, 0, 0]),
        "",
    );
    c.check(
        "set_hex rejects more than 16 digits",
        set_hex(&[b'0'; 17]).is_err(),
        "",
    );

    c.check(
        "ast_base64decode stops at '='",
        ast_base64decode(b"QUJD=QUJD", usize::MAX) == b"ABC",
        "",
    );
    c.check(
        "ast_base64decode maps non-alphabet characters to 63",
        Some(ast_base64decode(b"QU*D", usize::MAX)) == b64decode_strict(b"QU/D").ok(),
        "",
    );
}

fn framing_checks(c: &mut Checker) {
    let body = random_bytes(1500);
    let salt = random_bytes(8);
    let pw = random_bytes(40);
    let mut ok = true;
    for size in [600, 100, 4] {
        let wire = frame_request_body(&body, size, Some((&pw, &salt)), ChunkStyle::Split, false)
            .unwrap_or_default();
        let joined = wire.concat();
        ok &= wire.iter().all(|w| w.len() <= size)
            && decrypt(&pw, &salt, &ast_base64decode(&joined, usize::MAX))
                .ok()
                .as_ref()
                == Some(&body);
    }
    c.check(
        "split framing reassembles as the server does (concatenate, decode once)",
        ok,
        "",
    );
    let wire = frame_request_body(&body, 420, Some((&pw, &salt)), ChunkStyle::Stream, false)
        .unwrap_or_default();
    let joined = wire.concat();
    c.check(
        "stream framing: a single server-side decode stops at mid-stream '=' padding",
        joined[..joined.len().saturating_sub(4)].contains(&b'=')
            && ast_base64decode(&joined, usize::MAX).len() < body.len(),
        "",
    );
    let decoded: Option<Vec<u8>> = wire
        .iter()
        .map(|w| b64decode_strict(w).ok())
        .collect::<Option<Vec<_>>>()
        .map(|v| v.concat());
    c.check(
        "stream framing decodes chunk by chunk",
        decoded.and_then(|d| decrypt(&pw, &salt, &d).ok()).as_ref() == Some(&body),
        "",
    );
    let lens: Vec<usize> = frame_request_body(&[b'a'; 1300], 600, None, ChunkStyle::Split, false)
        .unwrap_or_default()
        .iter()
        .map(Vec::len)
        .collect();
    c.same(
        "plaintext framing splits at the size",
        lens,
        vec![600, 600, 100],
    );
    let text = b"line one\r\nline two\nline three\n".repeat(30);
    let mut bad = None;
    for size in [9, 10, 11, 50, 600] {
        let pieces =
            frame_request_body(&text, size, None, ChunkStyle::Split, false).unwrap_or_default();
        let joined: Vec<u8> = pieces.iter().flat_map(|p| asterisk_print_body(p)).collect();
        let mut want: &[u8] = &text;
        while let [rest @ .., b'\r' | b'\n'] = want {
            want = rest;
        }
        if joined != want {
            bad = Some(size);
            break;
        }
    }
    match bad {
        None => c.check(
            "plaintext chunks survive print_body's CR/LF stripping",
            true,
            "",
        ),
        Some(size) => c.check(
            format!("plaintext chunks survive print_body's CR/LF stripping (size {size})"),
            false,
            "",
        ),
    };
    let mut pem = Vec::new();
    for _ in 0..2 {
        pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        pem.extend_from_slice(&b"QUJD".repeat(16));
        pem.push(b'\n');
        pem.extend_from_slice(&b"REVG".repeat(5));
        pem.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
    }
    let pieces = frame_request_body(&pem, 50, None, ChunkStyle::Split, true).unwrap_or_default();
    let stripped: Vec<u8> = pieces.iter().flat_map(|p| asterisk_print_body(p)).collect();
    let want = pem
        .replace(b"-----\n", b"-----")
        .replace(b"\n-----", b"-----");
    c.check(
        "PEM cuts: chunks end at BEGIN and END lines, at most the size",
        pieces.concat() == pem && pieces.iter().all(|p| p.len() <= 50) && stripped == want,
        "",
    );

    // Server-to-phone framing, emulating phone_msg_outgoing_send, against
    // this simulator's reassembly (chunks delivered in random order).
    let via_reassembly = |frames: &[ServerFrame], extra: &[(&str, &str)]| -> Option<super::Reply> {
        let phone = Phone::offline(Options::default().quiet());
        phone.set_common_password(Some(pw.clone()));
        let mut order: Vec<&ServerFrame> = frames.iter().collect();
        order.shuffle(&mut rand::thread_rng());
        for f in order {
            let mut h: Vec<(String, BString)> = vec![(H_ID.into(), "77".into())];
            h.extend(
                extra
                    .iter()
                    .map(|(k, v)| (k.to_string(), BString::from(*v))),
            );
            h.extend(
                f.headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), BString::from(v.as_str()))),
            );
            phone.deliver(Message::new("MESSAGE sip:x@y SIP/2.0", h, f.body.clone()));
        }
        phone.next_event(Duration::ZERO, None)
    };
    let mut ev_body = b"<config>".to_vec();
    ev_body.extend_from_slice(&[b'y'; 900]);
    ev_body.extend_from_slice(b"</config>");
    type Case<'a> = (
        &'a str,
        Vec<u8>,
        usize,
        bool,
        &'a [u8],
        Vec<(&'a str, &'a str)>,
    );
    let cases: Vec<Case> = vec![
        (
            "encrypted UDP reply",
            random_bytes(1000),
            SERVER_UDP_ENCRYPTED_LIMIT,
            true,
            b"",
            vec![(H_RESPONSE_TYPE, "ConfigResponse")],
        ),
        (
            "encrypted TCP reply",
            random_bytes(1000),
            SERVER_TCP_LIMIT,
            true,
            b"",
            vec![(H_RESPONSE_TYPE, "ConfigResponse")],
        ),
        (
            "encrypted event, prefix in every chunk",
            ev_body,
            SERVER_UDP_ENCRYPTED_LIMIT,
            true,
            COMMAND_PREFIX,
            vec![(H_EVENT, "digium.config.update")],
        ),
        (
            "encrypted error reply",
            b"<error msg=\"Session Timeout\" />".to_vec(),
            SERVER_UDP_ENCRYPTED_LIMIT,
            true,
            COMMAND_PREFIX,
            vec![(H_RESPONSE_TYPE, "ConfigResponse"), (H_ERROR, "-398")],
        ),
        (
            "plaintext event over UDP",
            vec![b'e'; 1000],
            SERVER_UDP_PLAIN_LIMIT,
            false,
            COMMAND_PREFIX,
            vec![(H_EVENT, "x")],
        ),
        (
            "plaintext HandshakeResponse, UDP",
            vec![b'z'; 700],
            SERVER_UDP_PLAIN_LIMIT,
            false,
            b"",
            vec![(H_RESPONSE_TYPE, "HandshakeResponse")],
        ),
        (
            "plaintext HandshakeResponse, TCP",
            vec![b'z'; 700],
            SERVER_TCP_LIMIT,
            false,
            b"",
            vec![(H_RESPONSE_TYPE, "HandshakeResponse")],
        ),
        (
            "empty body is sent as 'empty body'",
            Vec::new(),
            SERVER_UDP_ENCRYPTED_LIMIT,
            true,
            b"",
            vec![(H_RESPONSE_TYPE, "PingResponse")],
        ),
    ];
    for (label, payload, limit, enc, prefix, extra) in cases {
        let s = random_bytes(8);
        let hs = extra
            .iter()
            .any(|(k, v)| *k == H_RESPONSE_TYPE && *v == "HandshakeResponse");
        let frames = server_frame(
            &payload,
            limit,
            enc.then_some((&pw[..], &s[..])),
            prefix,
            hs,
        );
        let mut ok = if hs && frames.len() == 1 {
            frames[0].header(H_SEQUENCE).is_none()
        } else {
            frames
                .iter()
                .enumerate()
                .all(|(i, f)| f.header(H_SEQUENCE) == Some(i.to_string().as_str()))
                && frames
                    .iter()
                    .enumerate()
                    .all(|(i, f)| f.header(H_FINISHED).is_some() == (i == frames.len() - 1))
        };
        if !enc {
            ok &= frames.iter().all(|f| f.body.len() <= limit);
        }
        let r = via_reassembly(&frames, &extra);
        let want: &[u8] = if payload.is_empty() {
            b"empty body"
        } else {
            &payload
        };
        let good = ok
            && r.as_ref()
                .is_some_and(|r| r.payload == want && r.problems.is_empty());
        let detail = r
            .map(|r| format!("{:?}", r.problems))
            .unwrap_or_else(|| "no message".into());
        c.check(
            format!("server framing: {label} ({} chunks)", frames.len()),
            good,
            detail,
        );
    }
}

fn pki_checks(c: &mut Checker, pki: &Pki) -> Result<()> {
    for name in ["legacy", "chain", "weak"] {
        if !pki.bundle_names().iter().any(|n| n == name) {
            continue;
        }
        let b = pki.bundle(name)?;
        let ders = pem_certificates(&b.body);
        let cert =
            Certificate::from_der(ders.last().ok_or_else(|| anyhow!("empty bundle {name}"))?)?;
        let common = random_bytes(40);
        let enc = public_key(&cert)?.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &common)?;
        let got = rsa_decrypt_common_password(&b.key, b64encode(&enc).as_bytes()).ok();
        c.check(
            format!(
                "common password round trip with the {name} key ({} bits)",
                key_bits(&b.key)
            ),
            got.as_ref() == Some(&common),
            "",
        );
    }
    let (ok, info) = pki.check_appserver(&std::fs::read(pki.dir.join("appserver.pem"))?);
    c.check(
        "the test AppServer certificate verifies against the test AppServer CA",
        ok,
        info,
    );
    let (ok, info) = pki.check_appserver(&std::fs::read(pki.dir.join("phone.pem"))?);
    c.check(
        "a phone certificate is not accepted as the AppServer",
        !ok,
        info,
    );
    Ok(())
}

fn check_proto_vectors(c: &mut Checker, v: &Value) {
    let s = |x: &Value| x.as_str().unwrap_or_default().to_string();
    let hexb = |x: &Value| hex::decode(x.as_str().unwrap_or_default()).unwrap_or_default();
    let arr = |k: &str| v[k].as_array().cloned().unwrap_or_default();

    let kdf = arr("kdf");
    let ok = kdf.iter().all(|e| {
        let Ok(salt) = set_hex(s(&e["salt_hex"]).as_bytes()) else {
            return false;
        };
        let (k, i) = evp_bytes_to_key(&hexb(&e["password_hex"]), &salt);
        hex::encode(k) == s(&e["key_hex"]) && hex::encode(i) == s(&e["iv_hex"])
    });
    c.check(format!("proto_vectors: key and IV ({})", kdf.len()), ok, "");

    let ef = arr("encrypt_field");
    let ok = ef.iter().all(|e| {
        let pw = hexb(&e["password_hex"]);
        let Ok(salt) = set_hex(s(&e["salt_hex"]).as_bytes()) else {
            return false;
        };
        encrypt_field(&pw, &salt, s(&e["plain"]).as_bytes()) == s(&e["b64"])
            && decrypt_field(&pw, &salt, s(&e["b64"]).as_bytes()).ok()
                == Some(s(&e["plain"]).into_bytes())
    });
    c.check(
        format!("proto_vectors: header fields ({})", ef.len()),
        ok,
        "",
    );

    let sh = arr("salt_from_hex");
    let ok = sh.iter().all(|e| match set_hex(s(&e["hex"]).as_bytes()) {
        Ok(got) => !e["error"].as_bool().unwrap_or(false) && hex::encode(got) == s(&e["bytes_hex"]),
        Err(_) => e["error"].as_bool().unwrap_or(false),
    });
    c.check(format!("proto_vectors: set_hex ({})", sh.len()), ok, "");

    let bd = arr("base64_decode");
    let ok = bd.iter().all(|e| {
        let max = e["max"].as_u64().map_or(usize::MAX, |m| m as usize);
        hex::encode(ast_base64decode(s(&e["text"]).as_bytes(), max)) == s(&e["bytes_hex"])
    });
    c.check(
        format!("proto_vectors: ast_base64decode ({})", bd.len()),
        ok,
        "",
    );

    let sp = arr("split");
    let ok = sp.iter().all(|e| {
        let frames = server_frame(
            s(&e["body"]).as_bytes(),
            e["limit"].as_u64().unwrap_or(0) as usize,
            None,
            s(&e["prefix"]).as_bytes(),
            e["handshake_response"].as_bool().unwrap_or(false),
        );
        let got: Vec<Value> = frames
            .iter()
            .map(|f| {
                json!({
                    "sequence": f.header(H_SEQUENCE).and_then(|x| x.parse::<i64>().ok()),
                    "finished": f.header(H_FINISHED).is_some(),
                    "plain": f.body.to_str_lossy(),
                })
            })
            .collect();
        Value::Array(got) == e["chunks"]
    });
    c.check(format!("proto_vectors: chunking ({})", sp.len()), ok, "");

    let oe = arr("outgoing_encrypted");
    let ok = oe.iter().all(|e| {
        let pw = hexb(&e["password_hex"]);
        let Ok(salt) = set_hex(s(&e["salt_hex"]).as_bytes()) else {
            return false;
        };
        let body = s(&e["body"]).into_bytes();
        let prefix = s(&e["prefix"]).into_bytes();
        let limit = e["limit"].as_u64().unwrap_or(0) as usize;
        let frames = server_frame(&body, limit, Some((&pw, &salt)), &prefix, false);
        let got: Vec<Value> = frames
            .iter()
            .map(|f| {
                json!({
                    "sequence": f.header(H_SEQUENCE).and_then(|x| x.parse::<i64>().ok()),
                    "finished": f.header(H_FINISHED).is_some(),
                    "b64": f.body.to_str_lossy(),
                })
            })
            .collect();
        let chunks = e["chunks"].as_array().cloned().unwrap_or_default();
        let wire: Option<Vec<u8>> = chunks
            .iter()
            .map(|w| b64decode_strict(s(&w["b64"]).as_bytes()).ok())
            .collect::<Option<Vec<_>>>()
            .map(|v| v.concat());
        let plain = wire.and_then(|w| decrypt(&pw, &salt, &w).ok());
        let want: Vec<u8> = split_bytes(&body, limit - prefix.len())
            .unwrap_or_default()
            .iter()
            .flat_map(|p| prefix.iter().chain(p.iter()).copied())
            .collect();
        Value::Array(got) == e["chunks"] && plain == Some(want)
    });
    c.check(
        format!(
            "proto_vectors: server-to-phone encrypted chunks ({})",
            oe.len()
        ),
        ok,
        "",
    );

    let inc = arr("incoming_from_phone");
    let ok = inc.iter().all(|e| {
        let pw = hexb(&e["password_hex"]);
        let Ok(salt) = set_hex(s(&e["salt_hex"]).as_bytes()) else {
            return false;
        };
        let body = s(&e["body"]).into_bytes();
        let parts = frame_request_body(
            &body,
            e["chunk_len"].as_u64().unwrap_or(1) as usize,
            Some((&pw, &salt)),
            ChunkStyle::Split,
            false,
        )
        .unwrap_or_default();
        let want: Vec<String> = e["parts"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| p.as_str().unwrap_or_default().to_string())
            .collect();
        let got: Vec<String> = parts
            .iter()
            .map(|p| p.to_str_lossy().into_owned())
            .collect();
        got == want
            && decrypt(
                &pw,
                &salt,
                &ast_base64decode(want.concat().as_bytes(), usize::MAX),
            )
            .ok()
                == Some(body)
    });
    c.check(
        format!(
            "proto_vectors: phone-to-server encrypted chunks ({})",
            inc.len()
        ),
        ok,
        "",
    );

    let r = &v["rsa_common_password"];
    let ok = parse_private_key_pem(&s(&r["private_key_pem"]))
        .and_then(|k| rsa_decrypt_common_password(&k, s(&r["password_b64"]).as_bytes()))
        .map(|p| hex::encode(p) == s(&r["common_password_hex"]))
        .unwrap_or(false);
    c.check("proto_vectors: RSA common password", ok, "");

    let eb = arr("error_bodies");
    let ok = eb.iter().all(|e| {
        let code = e["code"].as_i64().unwrap_or(0) as i32;
        error_body(code) == s(&e["body"]) && msg_error_text(code) == s(&e["text"])
    });
    c.check(
        format!("proto_vectors: error bodies ({})", eb.len()),
        ok,
        "",
    );
}

// ---------------------------------------------------------------------
// The fake server

struct FakeTx {
    parts: Vec<(i64, Message)>,
    fin: Option<i64>,
}

/// One completed transaction the fake server received: its first chunk,
/// the reassembled (decrypted) body, and the decrypted header fields.
pub struct Seen {
    /// The first chunk.
    pub first: Message,
    /// The body.
    pub body: Vec<u8>,
    /// Decrypted `Password`, `ConfigPassword`, and `Config-Token`.
    pub fields: HashMap<&'static str, Vec<u8>>,
}

#[derive(Default)]
struct FakeState {
    sessions: HashMap<String, (Vec<u8>, BString, BString)>,
    partial: HashMap<String, FakeTx>,
    seen: Vec<Seen>,
    phone_addr: Option<SocketAddr>,
}

/// A minimal in-process stand-in for the module, for the self-test only:
/// it receives MESSAGEs on a UDP socket and processes them the way the
/// decompile does (transactions keyed `"<ID>-<MAC>"`, completion when the
/// finishing chunk's sequence equals the chunk count minus one, bodies
/// concatenated and decoded once with `ast_base64decode`, header fields
/// decrypted with the same salt), then answers with [`server_frame`]
/// framing.  It verifies chains with signatures only (none of the
/// official DPMA's chain rules) and knows Handshake, PingRequest,
/// TokenRequest, ConfigRequest, and events.
pub struct FakeServer {
    sock: Arc<UdpSocket>,
    /// The server's UDP port.
    pub port: u16,
    state: Arc<Mutex<FakeState>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

struct FakeCtx {
    sock: Arc<UdpSocket>,
    port: u16,
    state: Arc<Mutex<FakeState>>,
    root: Certificate,
    appserver_pem: Vec<u8>,
}

impl FakeServer {
    /// Starts the server with the root CA and AppServer certificate of the
    /// PKI in `pki_dir`.
    pub fn start(pki_dir: &Path) -> Result<FakeServer> {
        let root = parse_certificate(&std::fs::read(pki_dir.join("root-ca.pem"))?)?;
        let appserver_pem = std::fs::read(pki_dir.join("appserver.pem"))?;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0")?);
        sock.set_read_timeout(Some(Duration::from_millis(100)))?;
        let port = sock.local_addr()?.port();
        let state = Arc::new(Mutex::new(FakeState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = FakeCtx {
            sock: sock.clone(),
            port,
            state: state.clone(),
            root,
            appserver_pem,
        };
        let st = stop.clone();
        let thread = std::thread::spawn(move || ctx.run(&st));
        Ok(FakeServer {
            sock,
            port,
            state,
            stop,
            thread: Some(thread),
        })
    }

    /// The transactions received so far (calls `f` with them).
    pub fn with_seen<T>(&self, f: impl FnOnce(&[Seen]) -> T) -> T {
        f(&self.state.lock().unwrap().seen)
    }

    /// Sends an encrypted event to the phone of session `sid`.
    pub fn event(&self, sid: &str, name: &str, body: &[u8]) -> Result<()> {
        let pw = self
            .state
            .lock()
            .unwrap()
            .sessions
            .get(sid)
            .map(|s| s.0.clone())
            .ok_or_else(|| anyhow!("no session"))?;
        let salt = random_bytes(8);
        let frames = server_frame(
            body,
            SERVER_UDP_ENCRYPTED_LIMIT,
            Some((&pw, &salt)),
            COMMAND_PREFIX,
            false,
        );
        let base: Vec<(String, BString)> = vec![
            (H_EVENT.into(), name.into()),
            (H_SESSION.into(), sid.into()),
        ];
        send_frames(&self.sock, self.port, &self.state, &base, &frames);
        Ok(())
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn send_frames(
    sock: &UdpSocket,
    port: u16,
    state: &Mutex<FakeState>,
    base: &[(String, BString)],
    frames: &[ServerFrame],
) {
    let Some(addr) = state.lock().unwrap().phone_addr else {
        return;
    };
    for f in frames {
        let mut h: Vec<(String, BString)> = vec![
            (
                "Via".into(),
                format!(
                    "SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bK{}",
                    crate::util::token_hex(6)
                )
                .into(),
            ),
            ("From".into(), "<sip:server@127.0.0.1>;tag=s".into()),
            ("To".into(), "<sip:phone@127.0.0.1>".into()),
            ("Call-ID".into(), crate::util::token_hex(8).into()),
            ("CSeq".into(), "1 MESSAGE".into()),
        ];
        h.extend(base.iter().cloned());
        h.extend(
            f.headers
                .iter()
                .map(|(k, v)| (k.to_string(), BString::from(v.as_str()))),
        );
        h.push(("Content-Length".into(), f.body.len().to_string().into()));
        let _ = sock.send_to(
            &Message::new("MESSAGE sip:phone@127.0.0.1 SIP/2.0", h, f.body.clone()).encode(),
            addr,
        );
    }
}

impl FakeCtx {
    fn run(&self, stop: &AtomicBool) {
        let mut buf = vec![0u8; 65535];
        while !stop.load(Ordering::SeqCst) {
            let Ok((n, addr)) = self.sock.recv_from(&mut buf) else {
                continue;
            };
            let data = &buf[..n];
            if data.trim_ascii().is_empty() {
                continue;
            }
            let Ok(msg) = sip::parse(data, Some(addr)) else {
                continue;
            };
            if !msg.is_request() {
                continue;
            }
            let g = |n: &str| msg.get(n).cloned().unwrap_or_default();
            let mut to = g("To");
            to.extend_from_slice(b";tag=x");
            let resp = Message::new(
                "SIP/2.0 202 Accepted",
                vec![
                    ("Via".into(), g("Via")),
                    ("From".into(), g("From")),
                    ("To".into(), to),
                    ("Call-ID".into(), g("Call-ID")),
                    ("CSeq".into(), g("CSeq")),
                    ("Content-Length".into(), "0".into()),
                ],
                Vec::new(),
            );
            let _ = self.sock.send_to(&resp.encode(), addr);
            self.state.lock().unwrap().phone_addr = Some(addr);
            self.add(msg);
        }
    }

    fn add(&self, mut msg: Message) {
        let g = |m: &Message, n: &str| m.get(n).cloned().unwrap_or_default();
        let txid = g(&msg, H_ID);
        let key = if txid.is_empty() {
            crate::util::token_hex(4)
        } else {
            let mac = g(&msg, H_MAC);
            format!(
                "{}-{}",
                txid,
                if mac.is_empty() {
                    "unknown".into()
                } else {
                    mac.to_string()
                }
            )
        };
        let seq_text = g(&msg, H_SEQUENCE);
        let seq: i64 = seq_text
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        msg.body = asterisk_print_body(&msg.body).into();
        let finished = seq_text.is_empty() || !g(&msg, H_FINISHED).is_empty();
        let complete = {
            let mut st = self.state.lock().unwrap();
            let t = st.partial.entry(key.clone()).or_insert(FakeTx {
                parts: Vec::new(),
                fin: None,
            });
            t.parts.push((seq, msg));
            t.parts.sort_by_key(|p| p.0);
            if finished {
                t.fin = Some(seq);
            }
            if t.fin != Some(t.parts.len() as i64 - 1) {
                return;
            }
            st.partial.remove(&key)
        };
        let Some(t) = complete else { return };
        let first = t.parts[0].1.clone();
        let mut body: Vec<u8> = t
            .parts
            .iter()
            .flat_map(|p| p.1.body.iter().copied())
            .collect();
        let salt_text = g(&first, H_SALT);
        let mut fields = HashMap::new();
        let session = self
            .state
            .lock()
            .unwrap()
            .sessions
            .get(&g(&first, H_SESSION).to_string())
            .cloned();
        if let (false, Some(session)) = (salt_text.is_empty(), session) {
            if let Ok(salt) = set_hex(&salt_text) {
                if !body.is_empty() {
                    body = decrypt(&session.0, &salt, &ast_base64decode(&body, usize::MAX))
                        .unwrap_or_default();
                }
                for name in [H_PASSWORD, H_CONFIG_PASSWORD, H_CONFIG_TOKEN] {
                    let v = g(&first, name);
                    if !v.is_empty() {
                        fields.insert(
                            name,
                            decrypt(&session.0, &salt, &ast_base64decode(&v, usize::MAX))
                                .unwrap_or_default(),
                        );
                    }
                }
            }
        }
        self.state.lock().unwrap().seen.push(Seen {
            first: first.clone(),
            body: body.clone(),
            fields: fields.clone(),
        });
        self.handle(&first, &body, &fields);
    }

    fn send(&self, base: &[(String, BString)], frames: &[ServerFrame]) {
        send_frames(&self.sock, self.port, &self.state, base, frames);
    }

    fn handle(&self, first: &Message, body: &[u8], fields: &HashMap<&'static str, Vec<u8>>) {
        let g = |n: &str| first.get(n).cloned().unwrap_or_default();
        let rtype = g(H_REQUEST_TYPE);
        let mut base: Vec<(String, BString)> = vec![(H_ID.into(), g(H_ID))];
        if rtype == "Handshake" {
            let certs: Vec<Certificate> = pem_certificates(body)
                .iter()
                .filter_map(|d| Certificate::from_der(d).ok())
                .collect();
            let verified = match certs.len() {
                1 => verify_directly_issued_by(&certs[0], &self.root).is_ok(),
                3 => {
                    verify_directly_issued_by(&certs[2], &certs[1]).is_ok()
                        && verify_directly_issued_by(&certs[1], &self.root).is_ok()
                }
                _ => false,
            };
            if !verified {
                return; // no reply, as the module
            }
            let pw = random_bytes(40);
            let sid = rand::thread_rng().gen_range(1..=(1u64 << 31)).to_string();
            let Ok(enc) = public_key(&certs[certs.len() - 1])
                .and_then(|k| Ok(k.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &pw)?))
            else {
                return;
            };
            self.state
                .lock()
                .unwrap()
                .sessions
                .insert(sid.clone(), (pw, g(H_MAC), g("Contact")));
            base.push((H_RESPONSE_TYPE.into(), "HandshakeResponse".into()));
            base.push((H_SESSION.into(), sid.into()));
            base.push((H_PASSWORD.into(), b64encode(&enc).into()));
            base.push((
                format!("{P}Token-Auth-Requirements"),
                "mac,configpass".into(),
            ));
            base.push((format!("{P}Userlist-Auth-Requirements"), "disabled".into()));
            if certs.len() == 3 {
                base.push((H_HANDSHAKE_VERSION.into(), "1".into()));
            }
            self.send(
                &base,
                &server_frame(&self.appserver_pem, SERVER_UDP_PLAIN_LIMIT, None, b"", true),
            );
            return;
        }
        let sid = g(H_SESSION).to_string();
        let pw = self
            .state
            .lock()
            .unwrap()
            .sessions
            .get(&sid)
            .map(|s| s.0.clone());
        let Some(pw) = pw else {
            base.push((H_RESPONSE_TYPE.into(), "HandshakeResponse".into()));
            base.push((H_ERROR.into(), "-398".into()));
            self.send(
                &base,
                &[ServerFrame {
                    headers: Vec::new(),
                    body: Vec::new(),
                }],
            );
            return;
        };
        let salt = random_bytes(8);
        base.push((H_SESSION.into(), sid.into()));
        let enc = Some((&pw[..], &salt[..]));
        if rtype == "PingRequest" {
            base.push((H_RESPONSE_TYPE.into(), "PingResponse".into()));
            self.send(
                &base,
                &server_frame(b"", SERVER_UDP_ENCRYPTED_LIMIT, enc, b"", false),
            );
        } else if rtype == "TokenRequest" {
            base.push((H_RESPONSE_TYPE.into(), "TokenResponse".into()));
            let token = format!(
                "token-for-{}-{}",
                fields
                    .get(H_CONFIG_PASSWORD)
                    .map(|v| v.to_str_lossy().into_owned())
                    .unwrap_or_else(|| "None".into()),
                g(H_MAC)
            );
            base.push((
                H_CONFIG_TOKEN.into(),
                encrypt_field(&pw, &salt, token.as_bytes()).into(),
            ));
            self.send(
                &base,
                &server_frame(body, SERVER_UDP_ENCRYPTED_LIMIT, enc, b"", false),
            );
        } else if rtype == "ConfigRequest" {
            base.push((H_RESPONSE_TYPE.into(), "ConfigResponse".into()));
            let mut doc = format!(
                "<config token='{}'>",
                fields
                    .get(H_CONFIG_TOKEN)
                    .map(|v| v.to_str_lossy().into_owned())
                    .unwrap_or_default()
            )
            .into_bytes();
            doc.extend_from_slice(body);
            doc.extend_from_slice(&[b'x'; 1500]);
            doc.extend_from_slice(b"</config>");
            self.send(
                &base,
                &server_frame(&doc, SERVER_UDP_ENCRYPTED_LIMIT, enc, b"", false),
            );
        }
    }
}

/// Runs the simulator against [`FakeServer`] over real UDP sockets.
pub fn loopback_test(c: &mut Checker, pki_dir: &Path) -> Result<()> {
    let server = FakeServer::start(pki_dir)?;
    for form in [Form::Legacy, Form::Chain] {
        let mut opts = Options::default().quiet();
        opts.sip_port = server.port;
        opts.pki = pki_dir.to_path_buf();
        opts.form = form;
        opts.timeout = Duration::from_secs(3);
        opts.chunk_delay = Duration::ZERO;
        let fname = form.bundle();
        let phone = Phone::start(opts)?;
        let ex = phone.handshake().send()?;
        let r = ex.reply.as_ref();
        c.check(
            format!(
                "loopback {fname} handshake ({} request chunks, {} reply chunks)",
                ex.chunks,
                r.map_or(0, |r| r.parts.len())
            ),
            ex.ok()
                && phone.common_password().is_some()
                && r.is_some_and(|r| r.appserver_ok == Some(true))
                && (phone.handshake_version().is_some_and(|v| v == "1")) == (form == Form::Chain),
            ex.describe(0),
        );
        let sid = phone.session().unwrap_or_default();
        let ex = phone.ping().send()?;
        c.check(
            format!("loopback {fname} encrypted ping"),
            ex.ok()
                && ex.encrypted
                && ex
                    .reply
                    .as_ref()
                    .is_some_and(|r| r.encrypted && r.body == "empty body"),
            ex.describe(0),
        );
        let ex = phone
            .get_token()
            .user("simphone")
            .pin("1234")
            .config_password("344486")
            .chunk_size(40)
            .send()?;
        let fields_ok = server.with_seen(|s| {
            s.last().is_some_and(|l| {
                l.fields.get(H_PASSWORD).is_some_and(|v| v == b"1234")
                    && l.fields
                        .get(H_CONFIG_PASSWORD)
                        .is_some_and(|v| v == b"344486")
            })
        });
        c.check(
            format!("loopback {fname} TokenRequest fields and token"),
            ex.ok()
                && fields_ok
                && phone
                    .token()
                    .is_some_and(|t| t == format!("token-for-344486-{}", phone.mac())),
            ex.describe(0),
        );
        let mut big = b"<request>".to_vec();
        big.extend_from_slice(&[b'q'; 2000]);
        big.extend_from_slice(b"</request>");
        let ex = phone.config().body(&big).send()?;
        let seen_big = server.with_seen(|s| s.last().is_some_and(|l| l.body == big));
        c.check(
            format!(
                "loopback {fname} multi-chunk request and reply ({} up, {} down)",
                ex.chunks,
                ex.reply.as_ref().map_or(0, |r| r.parts.len())
            ),
            ex.ok()
                && ex.chunks > 1
                && ex
                    .reply
                    .as_ref()
                    .is_some_and(|r| r.parts.len() > 1 && r.body.find(&big).is_some())
                && seen_big,
            ex.describe(0),
        );
        let mut ev = b"<config>".to_vec();
        ev.extend_from_slice(&[b'e'; 900]);
        ev.extend_from_slice(b"</config>");
        server.event(&sid, "digium.config.update", &ev)?;
        let got = phone.next_event(Duration::from_secs(3), None);
        c.check(
            format!("loopback {fname} multi-chunk encrypted event"),
            got.as_ref().is_some_and(|r| {
                r.event
                    .as_ref()
                    .is_some_and(|e| e == "digium.config.update")
                    && r.payload == ev
                    && r.problems.is_empty()
            }),
            got.as_ref()
                .map(|r| r.describe(0).to_string())
                .unwrap_or_else(|| "no event".into()),
        );
        phone.set_session(Some("12345".into()));
        let ex = phone.ping().send()?;
        c.check(
            format!("loopback {fname} unknown session gets HandshakeResponse -398"),
            ex.reply.as_ref().is_some_and(|r| {
                r.is_response("HandshakeResponse") && r.error.as_ref().is_some_and(|e| e == "-398")
            }) && !ex.ok(),
            ex.describe(0),
        );
    }
    let mut opts = Options::default().quiet();
    opts.sip_port = server.port;
    opts.pki = pki_dir.to_path_buf();
    opts.bundle = Some("rogue".into());
    opts.timeout = Duration::from_secs(1);
    let phone = Phone::start(opts)?;
    let ex = phone.handshake().send()?;
    c.check(
        "loopback rogue certificate gets no reply",
        ex.reply.is_none() && !ex.ok(),
        ex.describe(0),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole self-test, with a freshly made PKI (small keys, so it is
    /// quick).
    #[test]
    fn selftest_with_fresh_pki() {
        let dir = std::env::temp_dir().join(format!("dpma-tests-pki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::mkpki::Generator::new(&dir)
            .bits(1024)
            .quiet()
            .generate()
            .unwrap();
        let mut c = Checker::new();
        run(&mut c, &dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(c.passed(), "{}", c.summary());
    }

    #[test]
    fn vectors_file_is_current() {
        let text = std::fs::read_to_string(vectors_path()).unwrap();
        assert_eq!(text, vectors_text());
    }
}
