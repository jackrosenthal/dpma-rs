//! Splitting outgoing bodies into SIP MESSAGEs and reassembling incoming
//! ones (`phone_msg_outgoing_send` FUN_0014c6b0, `incoming_add_msg` and
//! `incoming_build_transaction` in FUN_0014f280, `incoming_check_finalize`
//! FUN_0014a000).
//!
//! # Outgoing
//!
//! Each MESSAGE carries at most `limit` bytes of plaintext: an optional
//! prefix (`"Command: "` for events and error responses, repeated in every
//! chunk) followed by the next part of the body.  The limit is 0x267 for
//! unencrypted messages (only HandshakeResponse), 0x1a4 for encrypted
//! ones, and 0x384 for either when the response URI contains
//! `transport=tcp`.  For encrypted messages the chunk plaintext is fed to
//! one continuous CBC stream (no padding until the last chunk) and each
//! chunk's ciphertext is base64 encoded on its own, so every chunk but the
//! last carries whole blocks only and the phone must decode each chunk's
//! base64 separately before decrypting the concatenation.  All chunks
//! except a single-chunk HandshakeResponse carry
//! `X-Digium-AppServer-Message-Sequence: N` (N from 0); the last also
//! carries `X-Digium-AppServer-Message-Finished: 1`.  The sender pauses
//! `message_delay` milliseconds between chunks.  An empty body is sent as
//! the literal text "empty body".  A non-zero error code appends
//! `<error msg="..." />` to whatever body was already there.
//!
//! The original sets the message variables of every chunk in this order
//! (each only when non-empty): RequestType (or ResponseType, which wins),
//! Handshake-Version, Username, Response-URI, Response-FullContact,
//! Token-Auth-Requirements, Userlist-Auth-Requirements, Password
//! (verbatim), X-Event-Name, Session, X-Origination-Network (from the
//! session), HTTP-Status, MD5, Error-ID, Password (encrypted),
//! Config-Token (encrypted), then the body, Message-Salt,
//! Message-Sequence, Message-Finished, and ID (the outgoing id, or for
//! requests a counter 1..100000 incremented once per message).
//!
//! # Incoming
//!
//! Messages are grouped by `"<X-Digium-AppServer-ID>-<MAC or unknown>"`
//! (messages without an ID each start a new group).  Parts are kept in
//! sequence order; a part without a sequence (or with an empty one) or
//! with a non-empty `Message-Finished` value marks the group finished and
//! records its sequence as the last one.  The group is complete when it is
//! finished and holds (last sequence + 1) parts.  The bodies are then
//! concatenated in order and, when the first part has a salt, base64
//! decoded as one string and decrypted (`crypto::decrypt_body`).  Because
//! `ast_base64decode` stops at the first `=`, a phone must split one
//! base64 string across its chunks rather than encode each chunk
//! separately.  The first part (lowest sequence) supplies all the message
//! variables.

use crate::crypto::{self, Encryptor, SALT_LEN};
use crate::Result;

/// Prefix of every chunk of an event or error response.
pub const COMMAND_PREFIX: &str = "Command: ";
/// Body sent when there is nothing to send.
pub const EMPTY_BODY: &str = "empty body";

/// Per-chunk plaintext limits (prefix included), from the original's
/// buffer sizes (allocation minus the terminating NUL).
pub const UDP_PLAIN_LIMIT: usize = 0x267;
pub const UDP_ENCRYPTED_LIMIT: usize = 0x1a4;
pub const TCP_LIMIT: usize = 0x384;

/// Size of the buffer for the transaction key (`snprintf(.., 0x80, ..)`).
pub const TRANSACTION_KEY_BUF: usize = 0x80;
/// Size of the buffer `incoming_check_finalize` builds the response URI
/// in.
pub const RESPONSE_URI_BUF: usize = 0x4f;
/// Size of the buffer `incoming_build_transaction` builds the response URI
/// in for its "handshake required" reply.
pub const HANDSHAKE_REQUIRED_URI_BUF: usize = 0x50;

/// Whether replies to `response_uri` use the TCP chunk limit
/// (`strstr(uri, "transport=tcp")`, case sensitive).
pub fn is_tcp(response_uri: &str) -> bool {
    response_uri.contains("transport=tcp")
}

/// The chunk limit for a destination.  `tcp` is true when the response
/// URI contains "transport=tcp" (TCP overrides the encrypted limit too).
pub fn chunk_limit(encrypted: bool, tcp: bool) -> usize {
    if tcp {
        TCP_LIMIT
    } else if encrypted {
        UDP_ENCRYPTED_LIMIT
    } else {
        UDP_PLAIN_LIMIT
    }
}

/// The body of an error reply (appended to the outgoing body):
/// `<error msg="TEXT" />`.
pub fn error_body(code: i32) -> String {
    format!("<error msg=\"{}\" />", crate::errors::msg_error_text(code))
}

/// One outgoing chunk's plaintext and sequence headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Value for `X-Digium-AppServer-Message-Sequence`, if sent.
    pub sequence: Option<u32>,
    /// Whether `X-Digium-AppServer-Message-Finished: 1` is sent.
    pub finished: bool,
    /// Plaintext of this chunk (prefix included).
    pub plain: Vec<u8>,
}

/// Split `body` into chunks of at most `limit` bytes, each starting with
/// `prefix`.  An empty body becomes "empty body".  `handshake_response`
/// (the response type is "HandshakeResponse", case insensitive)
/// suppresses the sequence headers when the whole body fits in one chunk.
/// A `limit` that leaves no room after the prefix is raised to fit one
/// byte (the original would loop forever; its limits never do).
pub fn split(body: &[u8], prefix: &str, limit: usize, handshake_response: bool) -> Vec<Chunk> {
    let body = if body.is_empty() { EMPTY_BODY.as_bytes() } else { body };
    let prefix = prefix.as_bytes();
    let limit = limit.max(prefix.len() + 1);
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let take = (body.len() - offset).min(limit - prefix.len());
        let mut plain = Vec::with_capacity(prefix.len() + take);
        plain.extend_from_slice(prefix);
        plain.extend_from_slice(&body[offset..offset + take]);
        offset += take;
        chunks.push(Chunk { sequence: Some(chunks.len() as u32), finished: offset == body.len(), plain });
    }
    if handshake_response && chunks.len() == 1 {
        chunks[0].sequence = None;
        chunks[0].finished = false;
    }
    chunks
}

/// Encrypt chunks as the original sends them: one CBC stream over all of
/// them (fresh from `password`/`salt`), each chunk's ciphertext base64
/// encoded separately (0x515-byte buffer).  The last chunk includes the
/// padding.
pub fn encrypt_chunks(chunks: &[Chunk], password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Vec<String>> {
    let mut enc = Some(Encryptor::new(password, salt)?);
    let mut out = Vec::with_capacity(chunks.len());
    for (i, c) in chunks.iter().enumerate() {
        let Some(e) = enc.as_mut() else { break };
        let mut cipher = e.update(&c.plain)?;
        if i + 1 == chunks.len() {
            if let Some(e) = enc.take() {
                cipher.extend(e.finish()?);
            }
        }
        out.push(crypto::base64_encode_max(&cipher, crypto::CIPHERTEXT_B64_BUF));
    }
    Ok(out)
}

/// The phone's side of [`encrypt_chunks`]: base64 decode each chunk body,
/// concatenate, and decrypt with the hex salt.
pub fn decrypt_chunks(bodies: &[&str], password: &[u8], salt_hex: &str) -> Result<Vec<u8>> {
    let salt = crypto::salt_from_hex(salt_hex)?;
    let cipher: Vec<u8> = bodies.iter().flat_map(|b| crypto::base64_decode(b)).collect();
    crypto::decrypt(password, &salt, &cipher)
}

/// The phone's way of sending an encrypted body that the server's
/// reassembly accepts: encrypt it whole, base64 encode the ciphertext, and
/// split the text into `chunk_len`-character pieces.
pub fn encrypt_for_server(body: &[u8], password: &[u8], salt: &[u8; SALT_LEN], chunk_len: usize) -> Result<Vec<String>> {
    let b64 = crypto::base64_encode(&crypto::encrypt(password, salt, body)?);
    Ok(b64.as_bytes().chunks(chunk_len.max(1)).map(|c| String::from_utf8_lossy(c).into_owned()).collect())
}

/// `snprintf(buf, size, ...)`: `s` cut to `size - 1` bytes (at a byte
/// boundary; invalid UTF-8 at the cut is replaced).
fn snprintf(s: &str, size: usize) -> String {
    let b = s.as_bytes();
    let n = b.len().min(size.saturating_sub(1));
    String::from_utf8_lossy(&b[..n]).into_owned()
}

/// The transaction key, `"%s-%s"` of `X-Digium-AppServer-ID` and the MAC
/// (`"unknown"` when absent or empty), in a 0x80-byte buffer.
pub fn transaction_key(id: &str, mac: Option<&str>) -> String {
    let mac = match mac {
        Some(m) if !m.is_empty() => m,
        _ => "unknown",
    };
    snprintf(&format!("{}-{}", id, mac), TRANSACTION_KEY_BUF)
}

/// Where replies go: `"%s%s%s"` of `X-Digium-AppServer-Response-URI`,
/// `";transport="` when `PJSIP_TRANSPORT` is present (even if empty), and
/// its value, in a buffer of `size` bytes ([`RESPONSE_URI_BUF`] or
/// [`HANDSHAKE_REQUIRED_URI_BUF`]; `usize::MAX` for no limit).
pub fn response_uri(uri: &str, transport: Option<&str>, size: usize) -> String {
    let s = match transport {
        Some(t) => format!("{};transport={}", uri, t),
        None => uri.to_string(),
    };
    snprintf(&s, size)
}

/// `strtol(s, NULL, 10)` truncated to `int`, as used for the sequence
/// header: leading whitespace, an optional sign, then decimal digits;
/// anything else ends the number (0 if there is none).
pub fn parse_sequence(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || (b'\t'..=b'\r').contains(&b[i])) {
        i += 1;
    }
    let neg = match b.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let mut v: i64 = 0;
    let mut overflow = false;
    while let Some(&c) = b.get(i) {
        if !c.is_ascii_digit() {
            break;
        }
        match v.checked_mul(10).and_then(|x| x.checked_add(i64::from(c - b'0'))) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    // strtol saturates at LONG_MIN/LONG_MAX; the int conversion keeps the
    // low 32 bits.
    let v = if overflow {
        if neg {
            i64::MIN
        } else {
            i64::MAX
        }
    } else if neg {
        -v
    } else {
        v
    };
    v as i32
}

/// One received part of a transaction.
#[derive(Debug, Clone)]
pub struct Part<M> {
    pub sequence: i32,
    pub body: String,
    /// Caller data, e.g., the message itself.
    pub meta: M,
}

/// Incoming parts of one transaction, ordered by sequence number
/// (`incoming_add_msg`).
#[derive(Debug)]
pub struct Reassembly<M = ()> {
    parts: Vec<Part<M>>,
    /// Set once a finishing part has arrived.
    pub finished: bool,
    /// Number of parts received (duplicates included).
    pub count: usize,
    /// Sequence number of the (latest) finishing part.
    pub last_sequence: i32,
}

impl<M> Default for Reassembly<M> {
    fn default() -> Self {
        Reassembly { parts: Vec::new(), finished: false, count: 0, last_sequence: 0 }
    }
}

impl Reassembly<()> {
    pub fn new() -> Reassembly<()> {
        Reassembly::default()
    }

    /// Add a part.  `sequence` is the header value (None when absent);
    /// `finished` is whether `Message-Finished` was present and non-empty.
    /// A part without a sequence, or with an empty one, finishes the
    /// transaction.
    pub fn add(&mut self, sequence: Option<&str>, finished: bool, body: String) {
        self.add_part(sequence, finished, body, ());
    }
}

impl<M> Reassembly<M> {
    /// Add a part with caller data (see [`Reassembly::add`]).
    pub fn add_part(&mut self, sequence: Option<&str>, finished: bool, body: String, meta: M) {
        let seq = match sequence {
            None => 0,
            Some("") => 0,
            Some(s) => parse_sequence(s),
        };
        let finishes = match sequence {
            None => true,
            Some(s) => finished || s.is_empty(),
        };
        if finishes {
            self.last_sequence = seq;
            self.finished = true;
        }
        // Before the first part with a greater sequence (after equal ones).
        let pos = if self.parts.first().is_some_and(|p| seq < p.sequence) {
            0
        } else {
            self.parts.iter().skip(1).position(|p| p.sequence > seq).map(|i| i + 1).unwrap_or(self.parts.len())
        };
        self.parts.insert(pos, Part { sequence: seq, body, meta });
        self.count += 1;
    }

    /// `incoming_check_finalize`'s test: finished, and as many parts as
    /// the last sequence number plus one.
    pub fn is_complete(&self) -> bool {
        self.count != 0 && self.finished && i64::from(self.last_sequence) == self.count as i64 - 1
    }

    /// The bodies concatenated in sequence order.
    pub fn body(&self) -> String {
        self.parts.iter().map(|p| p.body.as_str()).collect()
    }

    /// The parts in sequence order.
    pub fn parts(&self) -> &[Part<M>] {
        &self.parts
    }

    /// The first part's data; its message supplies the variables.
    pub fn first(&self) -> Option<&M> {
        self.parts.first().map(|p| &p.meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"0123456789012345678901234567890123456789";

    fn joined(chunks: &[Chunk], prefix: &str) -> Vec<u8> {
        chunks.iter().flat_map(|c| c.plain[prefix.len()..].to_vec()).collect()
    }

    #[test]
    fn limits() {
        assert_eq!(chunk_limit(false, false), 615);
        assert_eq!(chunk_limit(true, false), 420);
        assert_eq!(chunk_limit(true, true), 900);
        assert_eq!(chunk_limit(false, true), 900);
        assert!(is_tcp("sip:1.2.3.4:5060;transport=tcp"));
        assert!(!is_tcp("sip:1.2.3.4:5060;transport=TCP"));
        assert!(!is_tcp("sip:1.2.3.4:5060;transport=udp"));
    }

    #[test]
    fn split_all_limits() {
        for (encrypted, tcp) in [(false, false), (true, false), (true, true), (false, true)] {
            let limit = chunk_limit(encrypted, tcp);
            for prefix in ["", COMMAND_PREFIX] {
                let room = limit - prefix.len();
                for n in [1, room - 1, room, room + 1, 2 * room, 2 * room + 1, 5 * room + 7] {
                    let body: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
                    let chunks = split(&body, prefix, limit, false);
                    assert_eq!(chunks.len(), n.div_ceil(room), "limit {} prefix {:?} n {}", limit, prefix, n);
                    for (i, c) in chunks.iter().enumerate() {
                        assert!(c.plain.len() <= limit);
                        assert!(c.plain.starts_with(prefix.as_bytes()));
                        assert_eq!(c.sequence, Some(i as u32));
                        assert_eq!(c.finished, i + 1 == chunks.len());
                        if i + 1 < chunks.len() {
                            assert_eq!(c.plain.len(), limit);
                        }
                    }
                    assert_eq!(joined(&chunks, prefix), body);
                }
            }
        }
    }

    #[test]
    fn split_handshake_and_empty() {
        let one = split(b"cert", "", UDP_PLAIN_LIMIT, true);
        assert_eq!(one, vec![Chunk { sequence: None, finished: false, plain: b"cert".to_vec() }]);
        let two = split(&[b'x'; 700], "", UDP_PLAIN_LIMIT, true);
        assert_eq!(two.len(), 2);
        assert_eq!((two[0].sequence, two[0].finished), (Some(0), false));
        assert_eq!((two[1].sequence, two[1].finished), (Some(1), true));
        assert_eq!(two[1].plain.len(), 700 - 615);
        let empty = split(b"", "", UDP_ENCRYPTED_LIMIT, false);
        assert_eq!(empty, vec![Chunk { sequence: Some(0), finished: true, plain: b"empty body".to_vec() }]);
        let empty = split(b"", COMMAND_PREFIX, UDP_ENCRYPTED_LIMIT, false);
        assert_eq!(empty[0].plain, b"Command: empty body");
    }

    #[test]
    fn error_bodies() {
        assert_eq!(error_body(-398), "<error msg=\"Session Timeout\" />");
        assert_eq!(error_body(-195), "<error msg=\"Specfied user not found\" />");
        assert_eq!(error_body(-5), "<error msg=\"Unknown error\" />");
    }

    #[test]
    fn encrypted_chunks_round_trip() {
        let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let body: Vec<u8> = (0..3000).map(|i| b' ' + (i % 90) as u8).collect();
        for limit in [UDP_ENCRYPTED_LIMIT, TCP_LIMIT] {
            let chunks = split(&body, COMMAND_PREFIX, limit, false);
            let b64 = encrypt_chunks(&chunks, PASS, &salt).unwrap();
            assert_eq!(b64.len(), chunks.len());
            // Every chunk but the last is whole blocks without padding;
            // the whole is one stream.
            let all_plain: Vec<u8> = chunks.iter().flat_map(|c| c.plain.clone()).collect();
            let one_shot = crypto::encrypt(PASS, &salt, &all_plain).unwrap();
            let cat: Vec<u8> = b64.iter().flat_map(|b| crypto::base64_decode(b)).collect();
            assert_eq!(cat, one_shot);
            let refs: Vec<&str> = b64.iter().map(|s| s.as_str()).collect();
            assert_eq!(decrypt_chunks(&refs, PASS, &crypto::salt_to_hex(&salt)).unwrap(), all_plain);
            // Concatenating the chunk texts (what the server does with
            // incoming parts) only works when no chunk is padded.
            let concat: String = b64.concat();
            let padded = b64[..b64.len() - 1].iter().any(|s| s.ends_with('='));
            let r = crypto::decrypt_body(PASS, &crypto::salt_to_hex(&salt), &concat);
            assert_eq!(padded, r.ok() != Some(all_plain.clone()));
        }
    }

    #[test]
    fn phone_to_server_encryption() {
        let salt = [1; 8];
        let body = "<request method=\"x\">".repeat(80);
        let parts = encrypt_for_server(body.as_bytes(), PASS, &salt, 300).unwrap();
        assert!(parts.len() > 1);
        let mut r = Reassembly::new();
        let n = parts.len();
        for (i, p) in parts.iter().enumerate().rev() {
            r.add(Some(&i.to_string()), i + 1 == n, p.clone());
        }
        assert!(r.is_complete());
        assert_eq!(crypto::decrypt_body(PASS, "0101010101010101", &r.body()).unwrap(), body.as_bytes());
    }

    #[test]
    fn reassembly_ordering() {
        let mut r = Reassembly::new();
        r.add(Some("2"), true, "c".into());
        assert!(!r.is_complete());
        r.add(Some("0"), false, "a".into());
        assert!(!r.is_complete());
        r.add(Some("1"), false, "b".into());
        assert!(r.is_complete());
        assert_eq!(r.body(), "abc");
        assert_eq!(r.count, 3);
        assert_eq!(r.last_sequence, 2);

        // No sequence: a single, finished part.
        let mut r = Reassembly::new();
        r.add(None, false, "only".into());
        assert!(r.is_complete());
        // Empty sequence: finished at 0.
        let mut r = Reassembly::new();
        r.add(Some(""), false, "x".into());
        assert!(r.is_complete());
        // Not finished without the flag.
        let mut r = Reassembly::new();
        r.add(Some("0"), false, "x".into());
        assert!(!r.is_complete());
        // A duplicate counts, so a missing part can be papered over, as in
        // the original.
        let mut r = Reassembly::new();
        r.add(Some("0"), false, "a".into());
        r.add(Some("0"), false, "a2".into());
        r.add(Some("2"), true, "c".into());
        assert!(r.is_complete());
        assert_eq!(r.body(), "aa2c");
        // Equal sequences keep arrival order; lower ones go in front.
        let mut r: Reassembly<u32> = Reassembly::default();
        r.add_part(Some("5"), false, "e".into(), 1);
        r.add_part(Some("3"), false, "c".into(), 2);
        r.add_part(Some("5"), false, "e2".into(), 3);
        r.add_part(Some("4"), false, "d".into(), 4);
        r.add_part(Some("1"), false, "a".into(), 5);
        r.add_part(Some("9"), false, "z".into(), 6);
        assert_eq!(r.body(), "acdee2z");
        assert_eq!(r.first(), Some(&5));
        let seqs: Vec<i32> = r.parts().iter().map(|p| p.sequence).collect();
        assert_eq!(seqs, vec![1, 3, 4, 5, 5, 9]);
    }

    #[test]
    fn sequence_parsing() {
        assert_eq!(parse_sequence("0"), 0);
        assert_eq!(parse_sequence("17"), 17);
        assert_eq!(parse_sequence(" 3x"), 3);
        assert_eq!(parse_sequence("+4"), 4);
        assert_eq!(parse_sequence("-1"), -1);
        assert_eq!(parse_sequence("abc"), 0);
        assert_eq!(parse_sequence("4294967297"), 1);
        assert_eq!(parse_sequence("99999999999999999999"), -1);
    }

    #[test]
    fn keys_and_uris() {
        assert_eq!(transaction_key("12", Some("000fd3000001")), "12-000fd3000001");
        assert_eq!(transaction_key("12", Some("")), "12-unknown");
        assert_eq!(transaction_key("12", None), "12-unknown");
        assert_eq!(transaction_key(&"9".repeat(200), None).len(), 127);
        assert_eq!(response_uri("pjsip:1.2.3.4:5060", Some("transport-udp"), RESPONSE_URI_BUF), "pjsip:1.2.3.4:5060;transport=transport-udp");
        assert_eq!(response_uri("pjsip:1.2.3.4:5060", Some(""), RESPONSE_URI_BUF), "pjsip:1.2.3.4:5060;transport=");
        assert_eq!(response_uri("pjsip:1.2.3.4:5060", None, RESPONSE_URI_BUF), "pjsip:1.2.3.4:5060");
        let long = format!("pjsip:{}", "a".repeat(100));
        assert_eq!(response_uri(&long, None, RESPONSE_URI_BUF).len(), 78);
        assert_eq!(response_uri(&long, None, HANDSHAKE_REQUIRED_URI_BUF).len(), 79);
        assert_eq!(response_uri(&long, Some("tcp"), usize::MAX), format!("{};transport=tcp", long));
    }
}
