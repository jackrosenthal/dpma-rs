//! Cross-check against the phone simulator's vectors (`tests/data/vectors.json`,
//! written by `dpma-sim vectors` from the `dpma-tests` crate, an independent
//! implementation from the decompile that uses RustCrypto instead of
//! OpenSSL): key and IV derivation, a body, a header field, and the
//! server's framing of an encrypted event over UDP.  The simulator checks
//! the other direction against `tests/fixtures/proto_vectors.json` in its
//! self-test.

use dpma_proto::{crypto, framing};
use serde_json::Value;

const SIM_VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/data/vectors.json");

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn simulator_vectors() {
    let text = std::fs::read_to_string(SIM_VECTORS).unwrap_or_else(|e| panic!("{SIM_VECTORS}: {e}"));
    let v: Value = serde_json::from_str(&text).unwrap();
    let password = hex::decode(s(&v["password_hex"])).unwrap();
    let salt = crypto::salt_from_hex(s(&v["salt_hex"])).unwrap();
    assert_eq!(crypto::salt_to_hex(&salt), s(&v["salt_hex"]));

    let (key, iv) = crypto::derive_key_iv(&password, &salt);
    assert_eq!(hex::encode(key), s(&v["key_hex"]));
    assert_eq!(hex::encode(iv), s(&v["iv_hex"]));

    let cipher = crypto::encrypt(&password, &salt, s(&v["plain"]).as_bytes()).unwrap();
    assert_eq!(crypto::base64_encode(&cipher), s(&v["cipher_b64"]));
    assert_eq!(
        crypto::decrypt_body(&password, s(&v["salt_hex"]), s(&v["cipher_b64"])).unwrap(),
        s(&v["plain"]).as_bytes()
    );
    assert_eq!(crypto::encrypt_field(&password, &salt, b"1234").unwrap(), s(&v["field_1234_b64"]));
    assert_eq!(
        crypto::decrypt_header_field(&password, s(&v["salt_hex"]), s(&v["field_1234_b64"])).unwrap(),
        b"1234"
    );

    // The server's framing of an encrypted event over UDP, as
    // session::outgoing::send builds it.
    let chunks = framing::split(
        s(&v["event_body"]).as_bytes(),
        framing::COMMAND_PREFIX,
        framing::chunk_limit(true, false),
        false,
    );
    let wire = framing::encrypt_chunks(&chunks, &password, &salt).unwrap();
    let frames = v["event_frames_udp"].as_array().unwrap();
    assert_eq!(frames.len(), chunks.len());
    for ((f, c), w) in frames.iter().zip(&chunks).zip(&wire) {
        assert_eq!(s(&f["body"]), w);
        let h = &f["headers"];
        assert_eq!(s(&h["X-Digium-AppServer-Message-Salt"]), crypto::salt_to_hex(&salt));
        assert_eq!(h["X-Digium-AppServer-Message-Sequence"].as_str().map(str::to_string), c.sequence.map(|n| n.to_string()));
        assert_eq!(h.get("X-Digium-AppServer-Message-Finished").and_then(Value::as_str) == Some("1"), c.finished);
    }
    let bodies: Vec<&[u8]> = frames.iter().map(|f| s(&f["body"]).as_bytes()).collect();
    let plain = framing::decrypt_chunks(&bodies, &password, s(&v["salt_hex"])).unwrap();
    let expected: Vec<u8> = chunks.iter().flat_map(|c| c.plain.clone()).collect();
    assert_eq!(plain, expected);
}
