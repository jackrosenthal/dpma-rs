//! Splitting outgoing bodies into SIP MESSAGEs and reassembling incoming
//! ones (`phone_msg_outgoing_send`, `incoming_add_msg`,
//! `incoming_check_finalize`).
//!
//! Outgoing: each MESSAGE carries at most `limit` bytes of plaintext:
//! an optional prefix (`"Command: "` for events and error responses,
//! repeated in every chunk) followed by the next part of the body.  For
//! encrypted messages the chunk plaintext is fed to one continuous CBC
//! stream and each chunk's ciphertext is base64 encoded on its own.  All
//! chunks except a single-chunk HandshakeResponse carry
//! `X-Digium-AppServer-Message-Sequence: N` (N from 0); the last also
//! carries `X-Digium-AppServer-Message-Finished: 1`.  The sender pauses
//! `message_delay` milliseconds between chunks.  An empty body is sent as
//! the literal text "empty body".
//!
//! Incoming: messages with the same `X-Digium-AppServer-ID` and MAC are
//! collected in sequence order until one has `Message-Finished` set (or
//! has no sequence), then the bodies are concatenated (and decrypted).
//!
//! Owner: P1 "proto" (wave 1).

/// Prefix of every chunk of an event or error response.
pub const COMMAND_PREFIX: &str = "Command: ";
/// Body sent when there is nothing to send.
pub const EMPTY_BODY: &str = "empty body";

/// Per-chunk plaintext limits (prefix included), from the original's
/// buffer sizes (allocation minus the terminating NUL).
pub const UDP_PLAIN_LIMIT: usize = 0x267;
pub const UDP_ENCRYPTED_LIMIT: usize = 0x1a4;
pub const TCP_LIMIT: usize = 0x384;

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
/// `prefix`.  `handshake_response` suppresses the sequence headers when
/// the whole body fits in one chunk.
pub fn split(_body: &[u8], _prefix: &str, _limit: usize, _handshake_response: bool) -> Vec<Chunk> {
    Vec::new()
}

/// Incoming parts of one transaction, ordered by sequence number.
#[derive(Debug, Default)]
pub struct Reassembly {
    parts: Vec<(i64, String)>,
    /// Set once the finishing part has arrived.
    pub finished: bool,
    /// Number of parts received.
    pub count: usize,
}

impl Reassembly {
    pub fn new() -> Reassembly {
        Reassembly::default()
    }

    /// Add a part.  `sequence` is the header value (None when absent);
    /// `finished` is whether `Message-Finished` was present and non-empty.
    /// A part without a sequence, or with an empty one, finishes the
    /// transaction (as in `incoming_add_msg`).
    pub fn add(&mut self, _sequence: Option<&str>, _finished: bool, body: String) {
        self.parts.push((0, body));
        self.count += 1;
    }

    /// The bodies concatenated in sequence order.
    pub fn body(&self) -> String {
        self.parts.iter().map(|(_, b)| b.as_str()).collect()
    }
}
