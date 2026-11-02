//! Cross-check vectors for other implementations of the protocol (the
//! phone simulator of dpma-tests, `tests/src/sim`, checks its crypto and
//! framing against `tests/fixtures/proto_vectors.json`).
//!
//! `verify_fixture` recomputes every deterministic value from the inputs in
//! the file.  To rebuild the file (a new RSA test key is generated), run
//! `cargo test -p dpma-proto --test vectors -- --ignored regenerate`.

use dpma_proto::{crypto, errors, framing};
use serde_json::{json, Value};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/proto_vectors.json");

/// A 40-byte printable password (the KDF vector was also computed with
/// Python's hashlib and checked with `openssl enc -P`).
const PASS_TEXT: &[u8] = b"test-common-password-0123456789abcdefghi";

fn pass_binary() -> Vec<u8> {
    (0..40u32).map(|i| (i * 37 + 11) as u8).collect()
}

fn text(n: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ<>&\"' ";
    (0..n).map(|i| ALPHABET[i % ALPHABET.len()] as char).collect()
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn unh(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn chunks_json(chunks: &[framing::Chunk]) -> Value {
    Value::Array(
        chunks
            .iter()
            .map(|c| json!({"sequence": c.sequence, "finished": c.finished, "plain": String::from_utf8(c.plain.clone()).unwrap()}))
            .collect(),
    )
}

/// Inputs of the split cases: (body length, prefix, limit, handshake).
fn split_inputs() -> Vec<(usize, &'static str, usize, bool)> {
    let p = framing::COMMAND_PREFIX;
    vec![
        (0, "", framing::UDP_ENCRYPTED_LIMIT, false),
        (0, p, framing::UDP_ENCRYPTED_LIMIT, false),
        (10, "", framing::UDP_PLAIN_LIMIT, true),
        (framing::UDP_PLAIN_LIMIT, "", framing::UDP_PLAIN_LIMIT, true),
        (framing::UDP_PLAIN_LIMIT + 1, "", framing::UDP_PLAIN_LIMIT, true),
        (framing::UDP_ENCRYPTED_LIMIT - p.len(), p, framing::UDP_ENCRYPTED_LIMIT, false),
        (framing::UDP_ENCRYPTED_LIMIT - p.len() + 1, p, framing::UDP_ENCRYPTED_LIMIT, false),
        (framing::UDP_ENCRYPTED_LIMIT, "", framing::UDP_ENCRYPTED_LIMIT, false),
        (2 * framing::UDP_ENCRYPTED_LIMIT + 1, "", framing::UDP_ENCRYPTED_LIMIT, false),
        (2 * framing::TCP_LIMIT + 1, "", framing::TCP_LIMIT, false),
        (framing::TCP_LIMIT, p, framing::TCP_LIMIT, false),
    ]
}

fn build() -> Value {
    let salts: [[u8; 8]; 3] = [[1, 2, 3, 4, 5, 6, 7, 8], [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33], [0xff; 8]];
    let passwords = [PASS_TEXT.to_vec(), pass_binary()];

    let mut kdf = Vec::new();
    for p in &passwords {
        for sl in &salts {
            let (k, iv) = crypto::derive_key_iv(p, sl);
            kdf.push(json!({"password_hex": h(p), "salt_hex": crypto::salt_to_hex(sl), "key_hex": h(&k), "iv_hex": h(&iv)}));
        }
    }

    let mut fields = Vec::new();
    let long = text(100);
    for (plain, pi, si) in [("", 0, 1), ("1234", 1, 1), ("Hello, phone!", 0, 0), ("exactly 16 bytes", 1, 0), (long.as_str(), 0, 2)] {
        let p = &passwords[pi];
        let sl = &salts[si];
        fields.push(json!({
            "password_hex": h(p), "salt_hex": crypto::salt_to_hex(sl), "plain": plain,
            "b64": crypto::encrypt_field(p, sl, plain.as_bytes()).unwrap(),
        }));
    }

    let salt_hex: Vec<Value> = ["0123456789ABCDEF", "0123456789abcdef", "aBcD", "A", "123", "", "0123456789ABCDEF0", "12G4"]
        .iter()
        .map(|x| match crypto::salt_from_hex(x) {
            Ok(b) => json!({"hex": x, "bytes_hex": h(&b)}),
            Err(_) => json!({"hex": x, "error": true}),
        })
        .collect();

    let b64: Vec<Value> = [("Zm9vYmFy", None), ("Zg==Zm9v", None), ("Zm9v\nYmFy", None), ("Zm9v YmFy", None), ("Zm9", None), ("Zm9vYmFy", Some(4usize))]
        .iter()
        .map(|(t, max)| {
            let out = crypto::base64_decode_max(t, max.unwrap_or(usize::MAX));
            json!({"text": t, "max": max, "bytes_hex": h(&out)})
        })
        .collect();

    let split: Vec<Value> = split_inputs()
        .into_iter()
        .map(|(n, prefix, limit, hs)| {
            let body = text(n);
            json!({"body": body, "prefix": prefix, "limit": limit, "handshake_response": hs,
                   "chunks": chunks_json(&framing::split(body.as_bytes(), prefix, limit, hs))})
        })
        .collect();

    let mut outgoing = Vec::new();
    for (i, (n, prefix, limit)) in [(30, framing::COMMAND_PREFIX, framing::UDP_ENCRYPTED_LIMIT), (1000, "", framing::UDP_ENCRYPTED_LIMIT), (2000, "", framing::TCP_LIMIT)]
        .into_iter()
        .enumerate()
    {
        let body = text(n);
        let p = &passwords[i % 2];
        let sl = &salts[i % 3];
        let chunks = framing::split(body.as_bytes(), prefix, limit, false);
        let b64 = framing::encrypt_chunks(&chunks, p, sl).unwrap();
        let wire: Vec<Value> = chunks
            .iter()
            .zip(&b64)
            .map(|(c, b)| json!({"sequence": c.sequence, "finished": c.finished, "b64": b}))
            .collect();
        outgoing.push(json!({"password_hex": h(p), "salt_hex": crypto::salt_to_hex(sl), "body": body,
                             "prefix": prefix, "limit": limit, "chunks": wire}));
    }

    let body = text(700);
    let parts = framing::encrypt_for_server(body.as_bytes(), PASS_TEXT, &salts[1], 400).unwrap();
    let incoming = json!([{"password_hex": h(PASS_TEXT), "salt_hex": crypto::salt_to_hex(&salts[1]),
                           "body": body, "chunk_len": 400, "parts": parts}]);

    let key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(1024).unwrap()).unwrap();
    let public = openssl::pkey::PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();
    let common = pass_binary();
    let rsa = json!({
        "private_key_pem": String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
        "common_password_hex": h(&common),
        "password_b64": crypto::encrypt_common_password(&public, &common).unwrap(),
    });

    let error_bodies: Vec<Value> = [-1, -98, -192, -195, -198, -199, -200, -398, -400, -7]
        .iter()
        .map(|&c| json!({"code": c, "body": framing::error_body(c), "text": errors::msg_error_text(c)}))
        .collect();

    json!({
        "description": "dpma-proto cross-check vectors: AES-128-CBC, key and IV = EVP_BytesToKey(SHA-1, salt, password, 1), base64 as Asterisk does it, chunking, and RSA common password. Generated by crates/dpma-proto/tests/vectors.rs; the RSA key is a throwaway test key.",
        "kdf": kdf,
        "encrypt_field": fields,
        "salt_from_hex": salt_hex,
        "base64_decode": b64,
        "split": split,
        "outgoing_encrypted": outgoing,
        "incoming_from_phone": incoming,
        "rsa_common_password": rsa,
        "error_bodies": error_bodies,
    })
}

#[test]
#[ignore]
fn regenerate() {
    let v = build();
    std::fs::create_dir_all(std::path::Path::new(FIXTURE).parent().unwrap()).unwrap();
    std::fs::write(FIXTURE, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
}

#[test]
fn verify_fixture() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();

    for c in v["kdf"].as_array().unwrap() {
        let (k, iv) = crypto::derive_key_iv(&unh(&c["password_hex"]), &crypto::salt_from_hex(s(&c["salt_hex"])).unwrap());
        assert_eq!(h(&k), s(&c["key_hex"]));
        assert_eq!(h(&iv), s(&c["iv_hex"]));
    }
    // The independently computed vector.
    let first = &v["kdf"][0];
    assert_eq!(unh(&first["password_hex"]), PASS_TEXT);
    assert_eq!(s(&first["salt_hex"]), "0102030405060708");
    assert_eq!(s(&first["key_hex"]), "9322be0248c5e61def028c2cb3de0a5c");
    assert_eq!(s(&first["iv_hex"]), "4d1e73291b82fe60abf2f19dfc4237f4");

    for c in v["encrypt_field"].as_array().unwrap() {
        let p = unh(&c["password_hex"]);
        let sl = crypto::salt_from_hex(s(&c["salt_hex"])).unwrap();
        assert_eq!(crypto::encrypt_field(&p, &sl, s(&c["plain"]).as_bytes()).unwrap(), s(&c["b64"]));
        assert_eq!(crypto::decrypt_field(&p, s(&c["salt_hex"]), s(&c["b64"])).unwrap(), s(&c["plain"]).as_bytes());
    }
    assert!(v["encrypt_field"].as_array().unwrap().iter().any(|c| c["b64"] == "GS9WsQejwMVM/QGEVE8Ijw=="));

    for c in v["salt_from_hex"].as_array().unwrap() {
        match crypto::salt_from_hex(s(&c["hex"])) {
            Ok(b) => assert_eq!(h(&b), s(&c["bytes_hex"])),
            Err(_) => assert_eq!(c["error"], true),
        }
    }

    for c in v["base64_decode"].as_array().unwrap() {
        let max = c["max"].as_u64().map(|m| m as usize).unwrap_or(usize::MAX);
        assert_eq!(h(&crypto::base64_decode_max(s(&c["text"]), max)), s(&c["bytes_hex"]));
    }

    for c in v["split"].as_array().unwrap() {
        let chunks = framing::split(
            s(&c["body"]).as_bytes(),
            s(&c["prefix"]),
            c["limit"].as_u64().unwrap() as usize,
            c["handshake_response"].as_bool().unwrap(),
        );
        assert_eq!(chunks_json(&chunks), c["chunks"]);
    }

    for c in v["outgoing_encrypted"].as_array().unwrap() {
        let p = unh(&c["password_hex"]);
        let sl = crypto::salt_from_hex(s(&c["salt_hex"])).unwrap();
        let chunks = framing::split(s(&c["body"]).as_bytes(), s(&c["prefix"]), c["limit"].as_u64().unwrap() as usize, false);
        let b64 = framing::encrypt_chunks(&chunks, &p, &sl).unwrap();
        let wire = c["chunks"].as_array().unwrap();
        assert_eq!(wire.len(), chunks.len());
        for ((w, ch), b) in wire.iter().zip(&chunks).zip(&b64) {
            assert_eq!(w["b64"], json!(b));
            assert_eq!(w["sequence"], json!(ch.sequence));
            assert_eq!(w["finished"], json!(ch.finished));
        }
        let refs: Vec<&[u8]> = wire.iter().map(|w| s(&w["b64"]).as_bytes()).collect();
        let plain = framing::decrypt_chunks(&refs, &p, s(&c["salt_hex"])).unwrap();
        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.plain.clone()).collect();
        assert_eq!(plain, expected);
    }

    for c in v["incoming_from_phone"].as_array().unwrap() {
        let p = unh(&c["password_hex"]);
        let mut r = framing::Reassembly::new();
        let parts = c["parts"].as_array().unwrap();
        for (i, part) in parts.iter().enumerate() {
            r.add(Some(i.to_string().as_bytes()), i + 1 == parts.len(), s(part).into());
        }
        assert!(r.is_complete());
        assert_eq!(crypto::decrypt_body(&p, s(&c["salt_hex"]), r.body()).unwrap(), s(&c["body"]).as_bytes());
    }

    let rsa = &v["rsa_common_password"];
    let key = openssl::pkey::PKey::private_key_from_pem(s(&rsa["private_key_pem"]).as_bytes()).unwrap();
    assert_eq!(h(&crypto::decrypt_common_password(&key, s(&rsa["password_b64"])).unwrap()), s(&rsa["common_password_hex"]));

    for c in v["error_bodies"].as_array().unwrap() {
        let code = c["code"].as_i64().unwrap() as i32;
        assert_eq!(framing::error_body(code), s(&c["body"]));
        assert_eq!(errors::msg_error_text(code), s(&c["text"]));
    }
}
