//! Protocol messages as data, and the encoding and decoding of whole
//! exchanges, for a server and for a phone.
//!
//! A [`Message`] is one SIP MESSAGE: header names and values, and a body.
//! Nothing here reads or writes SIP; the caller turns a `Message` into
//! whatever its SIP stack sends, and back.
//!
//! * [`Outgoing::encode`] is what a server sends: a reply, an event, or a
//!   request, split into MESSAGEs, encrypted with the session's common
//!   password, with every header the phone expects.
//! * [`Request::encode`] is the phone's request to a server.
//! * [`Transactions`] groups the MESSAGEs that arrive by transaction, and
//!   [`Collector::decode`] turns a finished transaction into an
//!   [`Incoming`]: the reassembled and decrypted body and the decrypted
//!   header fields.  It decodes what a server receives from a phone, or what
//!   a phone receives from a server; the two differ in how the body is
//!   cut into base64 chunks.

use crate::framing::{self, Reassembly};
use crate::{crypto, headers as h, ProtoError, Result};
use std::sync::atomic::{AtomicI32, Ordering};

/// One SIP MESSAGE of the protocol: the headers that carry it, and its body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// Header names and values, in the order they are set.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Message {
    /// The value of the first header called `name` (ASCII case is ignored).
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// Set a header, replacing one of the same name.
    pub fn set(&mut self, name: &str, value: impl AsRef<[u8]>) {
        let value = value.as_ref().to_vec();
        match self
            .headers
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            Some((_, v)) => *v = value,
            None => self.headers.push((name.to_string(), value)),
        }
    }

    /// A message with the headers of `names` that `get` finds, for a caller
    /// that reads incoming messages through its SIP stack.  [`INCOMING`]
    /// lists the headers that decoding reads.
    pub fn collect(
        names: &[&str],
        get: impl Fn(&str) -> Option<Vec<u8>>,
        body: Vec<u8>,
    ) -> Message {
        Message {
            headers: names
                .iter()
                .filter_map(|n| get(n).map(|v| (n.to_string(), v)))
                .collect(),
            body,
        }
    }
}

/// The headers that [`Collector::decode`] and [`Transactions::add`] read.
pub const INCOMING: &[&str] = &[
    h::APPSERVER_ID,
    h::MAC_ADDRESS,
    h::REQUEST_TYPE,
    h::RESPONSE_TYPE,
    h::SESSION,
    h::USERNAME,
    h::RESPONSE_URI,
    h::RESPONSE_FULLCONTACT,
    h::ORIGINATION_NETWORK,
    h::ERROR_ID,
    h::HANDSHAKE_VERSION,
    h::MESSAGE_SALT,
    h::MESSAGE_SEQUENCE,
    h::MESSAGE_FINISHED,
    h::PASSWORD,
    h::CONFIG_PASSWORD,
    h::CONFIG_TOKEN,
];

/// The request id counter: 1 to 100000, advanced once per message that
/// needs an id.
static COUNTER: AtomicI32 = AtomicI32::new(0);

fn next_id() -> i32 {
    let mut cur = COUNTER.load(Ordering::Relaxed);
    loop {
        let next = if cur + 1 > 100000 { 1 } else { cur + 1 };
        match COUNTER.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(c) => cur = c,
        }
    }
}

fn non_empty(v: &[u8]) -> Option<&[u8]> {
    (!v.is_empty()).then_some(v)
}

// ---------------------------------------------------------------------------
// Server to phone
// ---------------------------------------------------------------------------

/// A message a server sends to a phone.  One of `request_type`,
/// `response_type`, or `event_name` (or a non-zero `error`) must be set.
#[derive(Debug, Default, Clone)]
pub struct Outgoing {
    pub body: Vec<u8>,
    /// Message error code (`errors::msg_error_text`); non-zero appends
    /// `<error msg="..." />` to the body, sets Error-ID, and prefixes every
    /// chunk with "Command: ".
    pub error: i32,
    pub request_type: Vec<u8>,
    pub response_type: Vec<u8>,
    pub response_uri: Vec<u8>,
    pub full_contact: Vec<u8>,
    pub userlist_auth_requirements: Vec<u8>,
    pub token_auth_requirements: Vec<u8>,
    /// Sent encrypted in `X-Digium-AppServer-Config-Token`.
    pub config_token: Vec<u8>,
    pub username: Vec<u8>,
    /// Sent verbatim in `X-Digium-AppServer-Password` (the RSA-encrypted
    /// common password in a HandshakeResponse).
    pub password: Vec<u8>,
    /// Sent encrypted in `X-Digium-AppServer-Password`.
    pub encrypted_password: Vec<u8>,
    /// Overrides `X-Digium-AppServer-ID` (requests get a counter).
    pub id: Vec<u8>,
    /// `X-Event-Name`; also selects the "Command: " body prefix.
    pub event_name: Vec<u8>,
    pub http_status: Vec<u8>,
    /// `X-Digium-AppServer-MD5`: the digest of a configuration document
    /// ([`md5_hex`] of the body of the ConfigResponse that carries it).
    /// A phone keeps the value it got with the document and skips the
    /// download when a VerifyResponse states the same value.
    pub md5: Vec<u8>,
}

/// The MD5 of `data` as 32 lowercase hexadecimal digits: the form of
/// `X-Digium-AppServer-MD5`, and of the digest a phone computes over a
/// downloaded document whose response states none.
pub fn md5_hex(data: &[u8]) -> Vec<u8> {
    use md5::{Digest, Md5};
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    Md5::digest(data)
        .iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 15)]])
        .collect()
}

/// The session a server sends in.
#[derive(Debug, Clone, Copy)]
pub struct SendContext<'a> {
    /// The session's common password.
    pub password: &'a [u8],
    pub session_id: &'a [u8],
    pub origination_network: &'a [u8],
    /// The phone sent the certificate-chain form of its Handshake; a
    /// HandshakeResponse says so.
    pub chain_certificate: bool,
}

impl Outgoing {
    pub fn new() -> Outgoing {
        Outgoing::default()
    }

    pub fn append(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    pub fn append_str(&mut self, s: &str) {
        self.body.extend_from_slice(s.as_bytes());
    }

    /// What kind of message this is: the response type, else the request
    /// type, else the event name, else "Error" for an error reply.
    pub fn message_type(&self) -> Option<&[u8]> {
        [&self.response_type, &self.request_type, &self.event_name]
            .into_iter()
            .find(|t| !t.is_empty())
            .map(|t| t.as_slice())
            .or((self.error != 0).then_some(b"Error"))
    }

    /// The MESSAGEs to send, in order.  Every message but a
    /// HandshakeResponse is encrypted with the session's common password and
    /// a fresh salt, and the body is split into chunks of the size the phone
    /// takes.
    pub fn encode(&self, ctx: &SendContext<'_>) -> Result<Vec<Message>> {
        if self.message_type().is_none() {
            return Err(ProtoError::Invalid(
                "the message is not a request, response, event, or error".into(),
            ));
        }
        let handshake = self
            .response_type
            .eq_ignore_ascii_case(b"HandshakeResponse");
        let salt = if handshake {
            None
        } else {
            Some(crypto::new_salt()?)
        };
        let handshake_version = (handshake && ctx.chain_certificate).then_some("1");

        let mut body = self.body.clone();
        let error_id = if self.error != 0 {
            body.extend_from_slice(framing::error_body(self.error).as_bytes());
            self.error.to_string().into_bytes()
        } else {
            Vec::new()
        };
        let limit = framing::chunk_limit(salt.is_some(), framing::is_tcp(&self.response_uri));
        let prefix = if !self.event_name.is_empty() || !error_id.is_empty() {
            framing::COMMAND_PREFIX
        } else {
            ""
        };
        let chunks = framing::split(&body, prefix, limit, handshake);
        let bodies: Vec<Vec<u8>> = match &salt {
            Some(salt) => framing::encrypt_chunks(&chunks, ctx.password, salt)?
                .into_iter()
                .map(String::into_bytes)
                .collect(),
            None => chunks.iter().map(|c| c.plain.clone()).collect(),
        };
        // Header fields encrypted with this message's salt.
        let encrypt_field = |plain: &[u8]| -> Result<Option<String>> {
            match (&salt, non_empty(plain)) {
                (Some(salt), Some(plain)) => {
                    crypto::encrypt_field(ctx.password, salt, plain).map(Some)
                }
                _ => Ok(None),
            }
        };
        let enc_password = encrypt_field(&self.encrypted_password)?;
        let enc_token = encrypt_field(&self.config_token)?;

        let mut out = Vec::with_capacity(chunks.len());
        for (chunk, body) in chunks.into_iter().zip(bodies) {
            let mut m = Message::default();
            if !self.response_type.is_empty() {
                m.set(h::RESPONSE_TYPE, &self.response_type);
            } else if !self.request_type.is_empty() {
                m.set(h::REQUEST_TYPE, &self.request_type);
            }
            if let Some(v) = handshake_version {
                m.set(h::HANDSHAKE_VERSION, v);
            }
            for (name, value) in [
                (h::USERNAME, &self.username[..]),
                (h::RESPONSE_URI, &self.response_uri),
                (h::RESPONSE_FULLCONTACT, &self.full_contact),
                (h::TOKEN_AUTH_REQUIREMENTS, &self.token_auth_requirements),
                (
                    h::USERLIST_AUTH_REQUIREMENTS,
                    &self.userlist_auth_requirements,
                ),
                (h::PASSWORD, &self.password),
                (h::EVENT_NAME, &self.event_name),
                (h::SESSION, ctx.session_id),
                (h::ORIGINATION_NETWORK, ctx.origination_network),
                (h::HTTP_STATUS, &self.http_status),
                (h::MD5, &self.md5),
                (h::ERROR_ID, &error_id),
            ] {
                if let Some(value) = non_empty(value) {
                    m.set(name, value);
                }
            }
            if let Some(v) = &enc_password {
                m.set(h::PASSWORD, v);
            }
            if let Some(v) = &enc_token {
                m.set(h::CONFIG_TOKEN, v);
            }
            m.body = body;
            if let Some(salt) = &salt {
                m.set(h::MESSAGE_SALT, crypto::salt_to_hex(salt));
            }
            if let Some(seq) = chunk.sequence {
                m.set(h::MESSAGE_SEQUENCE, seq.to_string());
            }
            if chunk.finished {
                m.set(h::MESSAGE_FINISHED, "1");
            }
            if !self.id.is_empty() {
                m.set(h::APPSERVER_ID, &self.id);
            } else if !self.request_type.is_empty() {
                m.set(h::APPSERVER_ID, next_id().to_string());
            }
            out.push(m);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Phone to server
// ---------------------------------------------------------------------------

/// The most bytes of body that one MESSAGE to Asterisk can carry:
/// res_pjsip_messaging keeps at most 1023 bytes of a body.
pub const MAX_CHUNK_LEN: usize = 1022;

/// A request that a phone sends to a server.
#[derive(Debug, Default, Clone)]
pub struct Request {
    /// One of the request types in [`crate::types`].
    pub request_type: String,
    /// The transaction id the reply echoes; a counter value when empty.
    pub id: Vec<u8>,
    pub mac: Vec<u8>,
    /// The session id from the HandshakeResponse (requests other than
    /// Handshake and Echo need one).
    pub session_id: Vec<u8>,
    pub origination_network: Vec<u8>,
    /// The phone's user agent, in `X-Digium-User-Agent`; servers learn the
    /// phone's model from it.
    pub user_agent: Vec<u8>,
    pub username: Vec<u8>,
    /// Sent encrypted when the request is.
    pub password: Vec<u8>,
    pub config_password: Vec<u8>,
    pub config_token: Vec<u8>,
    /// Any other headers, set after the ones above.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body.  Without encryption its trailing line breaks are not sent,
    /// as Asterisk would remove them.
    pub body: Vec<u8>,
}

impl Request {
    /// The MESSAGEs to send, in order.  With the session's common password
    /// the body and the secret header fields are encrypted under a fresh
    /// salt; without it they are sent as they are.  `chunk_len` is the most
    /// bytes of body in one MESSAGE, at most [`MAX_CHUNK_LEN`].
    pub fn encode(&self, common_password: Option<&[u8]>, chunk_len: usize) -> Result<Vec<Message>> {
        let chunk_len = chunk_len.clamp(1, MAX_CHUNK_LEN);
        let salt = common_password.map(|_| crypto::new_salt()).transpose()?;
        let secrets = common_password.zip(salt.as_ref());
        let mut base = Message::default();
        base.set(h::REQUEST_TYPE, &self.request_type);
        if self.id.is_empty() {
            base.set(h::APPSERVER_ID, next_id().to_string());
        } else {
            base.set(h::APPSERVER_ID, &self.id);
        }
        base.set(h::MAC_ADDRESS, &self.mac);
        for (name, value) in [
            (h::SESSION, &self.session_id),
            (h::ORIGINATION_NETWORK, &self.origination_network),
            (h::DIGIUM_USER_AGENT, &self.user_agent),
            (h::USERNAME, &self.username),
        ] {
            if let Some(value) = non_empty(value) {
                base.set(name, value);
            }
        }
        for (name, value) in [
            (h::PASSWORD, &self.password),
            (h::CONFIG_PASSWORD, &self.config_password),
            (h::CONFIG_TOKEN, &self.config_token),
        ] {
            let Some(value) = non_empty(value) else {
                continue;
            };
            match secrets {
                Some((password, salt)) => {
                    base.set(name, crypto::encrypt_field(password, salt, value)?)
                }
                None => base.set(name, value),
            }
        }
        if let Some(salt) = &salt {
            base.set(h::MESSAGE_SALT, crypto::salt_to_hex(salt));
        }
        for (name, value) in &self.headers {
            base.set(name, value);
        }

        let bodies = match secrets {
            Some(_) if self.body.is_empty() => vec![Vec::new()],
            Some((password, salt)) => {
                framing::encrypt_for_server(&self.body, password, salt, chunk_len)?
                    .into_iter()
                    .map(String::into_bytes)
                    .collect()
            }
            None => split_plain(&self.body, chunk_len),
        };
        let n = bodies.len();
        Ok(bodies
            .into_iter()
            .enumerate()
            .map(|(i, body)| {
                let mut m = base.clone();
                m.set(h::MESSAGE_SEQUENCE, i.to_string());
                if i + 1 == n {
                    m.set(h::MESSAGE_FINISHED, "1");
                }
                m.body = body;
                m
            })
            .collect())
    }
}

/// `data` in pieces of at most `size` bytes such that no piece ends in CR or
/// LF: Asterisk removes trailing line breaks from the body of every MESSAGE,
/// so one at the end of a chunk would be lost.  The line breaks that end
/// `data` are dropped for the same reason.
fn split_plain(data: &[u8], size: usize) -> Vec<Vec<u8>> {
    let size = size.max(1);
    let data = match data.iter().rposition(|b| !matches!(b, b'\r' | b'\n')) {
        Some(last) => &data[..=last],
        None => &[],
    };
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let mut end = (pos + size).min(data.len());
        if end < data.len() {
            let mut cut = end;
            while cut > pos && matches!(data[cut - 1], b'\r' | b'\n') {
                cut -= 1;
            }
            if cut > pos {
                end = cut;
            }
        }
        out.push(data[pos..end].to_vec());
        pos = end;
    }
    if out.is_empty() {
        out.push(Vec::new());
    }
    out
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// Who sent a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    /// A server: each chunk's ciphertext is base64 encoded on its own.
    Server,
    /// A phone: the whole ciphertext is base64 encoded and the text split
    /// into chunks.
    Phone,
}

/// The MESSAGEs of one transaction, as they arrive.  `M` is the caller's
/// data for each MESSAGE (for example, the SIP message it came from).
pub struct Collector<M = ()> {
    parts: Reassembly<(Message, M)>,
}

impl<M> Default for Collector<M> {
    fn default() -> Self {
        Collector {
            parts: Reassembly::default(),
        }
    }
}

impl<M> Collector<M> {
    pub fn new() -> Collector<M> {
        Collector::default()
    }

    /// Add a MESSAGE.  `Message-Sequence` orders it, and a MESSAGE without
    /// one, or with `Message-Finished`, is the last.
    pub fn add(&mut self, mut m: Message, meta: M) {
        let sequence = m.header(h::MESSAGE_SEQUENCE).map(<[u8]>::to_vec);
        let finished = m.header(h::MESSAGE_FINISHED).is_some_and(|f| !f.is_empty());
        let body = std::mem::take(&mut m.body);
        self.parts
            .add_part(sequence.as_deref(), finished, body, (m, meta));
    }

    /// Whether the last MESSAGE and all those before it have arrived.
    pub fn is_complete(&self) -> bool {
        self.parts.is_complete()
    }

    /// The caller's data for each MESSAGE, in sequence order.
    pub fn into_metas(self) -> Vec<M> {
        self.parts
            .into_parts()
            .into_iter()
            .map(|p| p.meta.1)
            .collect()
    }

    /// Reassemble and decrypt the transaction.  `password` is the session's
    /// common password, needed when the MESSAGEs are encrypted (they carry
    /// a `Message-Salt`).
    ///
    /// A phone that may hold no password, or a different one from the
    /// sender's, should call [`Collector::decode_reply`] so that it still
    /// sees an error reply.
    pub fn decode(&self, from: Sender, password: Option<&[u8]>) -> Result<Incoming> {
        let bodies: Vec<&[u8]> = self
            .parts
            .parts()
            .iter()
            .map(|p| p.body.as_slice())
            .collect();
        let mut incoming = self.envelope()?;
        let mut body: Vec<u8> = bodies.concat();
        if let Some(salt) = incoming.first.header(h::MESSAGE_SALT).and_then(non_empty) {
            let key = password.ok_or_else(|| {
                ProtoError::Invalid("the message is encrypted but there is no password".into())
            })?;
            if !body.is_empty() {
                body = match from {
                    Sender::Phone => crypto::decrypt_body(key, salt, &body)?,
                    Sender::Server => framing::decrypt_chunks(&bodies, key, salt)?,
                };
            }
            for (name, field) in [
                (h::PASSWORD, &mut incoming.password),
                (h::CONFIG_PASSWORD, &mut incoming.config_password),
                (h::CONFIG_TOKEN, &mut incoming.config_token),
            ] {
                if let Some(value) = incoming.first.header(name).and_then(non_empty) {
                    *field = crypto::decrypt_header_field(key, salt, value)?;
                }
            }
        }
        incoming.payload = body.clone();
        incoming.body = body;
        if from == Sender::Server
            && (incoming.error != 0 || incoming.first.header(h::EVENT_NAME).is_some())
        {
            incoming.payload = strip_command_prefixes(&incoming.body, &bodies, incoming.encrypted)?;
        }
        Ok(incoming)
    }

    /// What the transaction's headers say, without decrypting anything:
    /// the ids, the types, and the error are never encrypted.  The body and
    /// the payload are empty; so are the password, the configuration
    /// password, and the configuration token when the MESSAGEs are
    /// encrypted (without a `Message-Salt` they are as they came).
    ///
    /// This is all a receiver can read of a transaction encrypted under a
    /// session it does not share.
    pub fn envelope(&self) -> Result<Incoming> {
        let Some(first) = self.parts.parts().first() else {
            return Err(ProtoError::Invalid("no messages".into()));
        };
        let (first_msg, _) = &first.meta;
        let get = |name: &str| {
            first_msg
                .header(name)
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        };
        let encrypted = first_msg
            .header(h::MESSAGE_SALT)
            .is_some_and(|s| !s.is_empty());
        let secret = |name: &str| if encrypted { Vec::new() } else { get(name) };
        Ok(Incoming {
            id: get(h::APPSERVER_ID),
            request_type: get(h::REQUEST_TYPE),
            response_type: get(h::RESPONSE_TYPE),
            session_id: get(h::SESSION),
            mac: get(h::MAC_ADDRESS),
            username: get(h::USERNAME),
            response_uri: get(h::RESPONSE_URI),
            full_contact: get(h::RESPONSE_FULLCONTACT),
            origination_network: get(h::ORIGINATION_NETWORK),
            handshake_version: get(h::HANDSHAKE_VERSION),
            error: first_msg
                .header(h::ERROR_ID)
                .map_or(0, framing::parse_sequence),
            password: secret(h::PASSWORD),
            config_password: secret(h::CONFIG_PASSWORD),
            config_token: secret(h::CONFIG_TOKEN),
            encrypted,
            body: Vec::new(),
            payload: Vec::new(),
            first: first_msg.clone(),
        })
    }

    /// [`Collector::decode`] for a phone, which must not lose an error
    /// reply that it cannot decrypt.
    ///
    /// A server encrypts "Session Timeout" (-398) under the session it has
    /// for the id the phone sent, when the request fails that session's
    /// checks (another MAC address or contact), and it encrypts the
    /// reassignment push (`bootcReset`, -398) likewise.  A phone that has
    /// handshaken again since, or that never held that session's common
    /// password, cannot decrypt either, yet both tell it to handshake
    /// again, and `X-Digium-AppServer-Error-ID` is not encrypted.
    ///
    /// So when the transaction carries an error and cannot be decrypted
    /// with `password`, the result is its [`Collector::envelope`]: the
    /// error and the ids, with an empty body.  A transaction without an
    /// error that cannot be decrypted is still an `Err`.
    pub fn decode_reply(&self, password: Option<&[u8]>) -> Result<Incoming> {
        match self.decode(Sender::Server, password) {
            Ok(incoming) => Ok(incoming),
            Err(e) => match self.envelope() {
                Ok(envelope) if envelope.error != 0 => Ok(envelope),
                _ => Err(e),
            },
        }
    }
}

/// `body` without the `Command: ` that starts the plaintext of every chunk
/// of an event or an error reply.  `bodies` are the chunks as they arrived.
fn strip_command_prefixes(body: &[u8], bodies: &[&[u8]], encrypted: bool) -> Result<Vec<u8>> {
    let prefix = framing::COMMAND_PREFIX.as_bytes();
    if !body.starts_with(prefix) {
        return Ok(body.to_vec());
    }
    if bodies.len() == 1 {
        return Ok(body[prefix.len()..].to_vec());
    }
    if !encrypted {
        return Ok(bodies
            .iter()
            .flat_map(|b| b.strip_prefix(prefix).unwrap_or(b).iter().copied())
            .collect());
    }
    // The chunk boundaries do not show in the decrypted text, but the server
    // cuts the plaintext at a fixed limit, so find which.
    for limit in [
        framing::UDP_ENCRYPTED_LIMIT,
        framing::TCP_LIMIT,
        framing::UDP_PLAIN_LIMIT,
    ] {
        let starts: Vec<usize> = (0..body.len()).step_by(limit).collect();
        if starts.len() == bodies.len() && starts.iter().all(|&s| body[s..].starts_with(prefix)) {
            return Ok(starts
                .iter()
                .flat_map(|&s| {
                    body[s + prefix.len()..(s + limit).min(body.len())]
                        .iter()
                        .copied()
                })
                .collect());
        }
    }
    Err(ProtoError::Invalid(
        "could not locate the chunk prefixes".into(),
    ))
}

/// A transaction that has arrived whole.
#[derive(Debug, Clone)]
pub struct Incoming {
    /// `X-Digium-AppServer-ID`.
    pub id: Vec<u8>,
    pub request_type: Vec<u8>,
    pub response_type: Vec<u8>,
    pub session_id: Vec<u8>,
    pub mac: Vec<u8>,
    pub username: Vec<u8>,
    /// The `Response-URI` header as it came.
    pub response_uri: Vec<u8>,
    pub full_contact: Vec<u8>,
    pub origination_network: Vec<u8>,
    pub handshake_version: Vec<u8>,
    /// `X-Digium-AppServer-Error-ID`: 0 when there is none, -398 when the
    /// session is unknown and the phone must handshake again.
    pub error: i32,
    /// `X-Digium-AppServer-Password`, decrypted when the message is
    /// encrypted.  In a HandshakeResponse (which is not) it is the common
    /// password encrypted to the phone's key, as base64 text; see
    /// [`crypto::decrypt_common_password`].
    pub password: Vec<u8>,
    pub config_password: Vec<u8>,
    pub config_token: Vec<u8>,
    /// The message carries a `Message-Salt`, so it was encrypted.
    pub encrypted: bool,
    /// The reassembled, decrypted body.  A server sends the text `empty
    /// body` ([`framing::EMPTY_BODY`]) when it has nothing to send.
    pub body: Vec<u8>,
    /// The body of an event or an error reply from a server without the
    /// `Command: ` that starts each of its chunks; otherwise the body.
    pub payload: Vec<u8>,
    /// The first MESSAGE, for any other header.
    pub first: Message,
}

/// Incoming MESSAGEs grouped into transactions.  `D` is the caller's data
/// for a transaction, set when its first MESSAGE arrives.
///
/// A server groups what phones send by `ID` and MAC address (a MESSAGE
/// without an ID is a transaction of its own).  A phone groups what a
/// server sends by `ID`, salt, and type, since events have no ID.
pub struct Transactions<D, M = ()> {
    sender: Sender,
    entries: Vec<Entry<D, M>>,
}

struct Entry<D, M> {
    /// `"<ID>-<MAC or unknown>"`; empty when the MESSAGE had no ID, which
    /// makes it a transaction of its own.
    key: Vec<u8>,
    data: D,
    updated: i64,
    collector: Collector<M>,
}

impl<D, M> Transactions<D, M> {
    /// An empty set for MESSAGEs from `sender`.
    pub const fn new(sender: Sender) -> Self {
        Transactions {
            sender,
            entries: Vec::new(),
        }
    }

    /// Add a MESSAGE to its transaction, starting one with `data` when
    /// there is none.  `now` is the caller's clock, used by
    /// [`Transactions::prune`].  When the MESSAGE completes its
    /// transaction, that is removed and returned.
    pub fn add(&mut self, m: Message, meta: M, now: i64, data: D) -> Option<(D, Collector<M>)> {
        let id = m.header(h::APPSERVER_ID);
        // The key, and whether a MESSAGE can join a transaction of that key.
        let (key, groups) = match self.sender {
            Sender::Phone => (
                framing::transaction_key(id.unwrap_or(b""), m.header(h::MAC_ADDRESS)),
                id.is_some_and(|i| !i.is_empty()),
            ),
            Sender::Server => {
                let kind = [
                    h::RESPONSE_TYPE,
                    h::REQUEST_TYPE,
                    h::EVENT_NAME,
                    h::ERROR_ID,
                ]
                .iter()
                .filter_map(|n| m.header(n))
                .find(|v| !v.is_empty())
                .unwrap_or_default();
                let key = [
                    id.unwrap_or_default(),
                    m.header(h::MESSAGE_SALT).unwrap_or_default(),
                    kind,
                ]
                .join(&0);
                (key, true)
            }
        };
        let found = groups
            .then(|| {
                self.entries
                    .iter()
                    .position(|e| !e.key.is_empty() && e.key.eq_ignore_ascii_case(&key))
            })
            .flatten();
        let idx = match found {
            Some(i) => i,
            None => {
                self.entries.push(Entry {
                    key: if groups || id.is_some() {
                        key
                    } else {
                        Vec::new()
                    },
                    data,
                    updated: now,
                    collector: Collector::new(),
                });
                self.entries.len() - 1
            }
        };
        let e = &mut self.entries[idx];
        e.updated = now;
        e.collector.add(m, meta);
        if !e.collector.is_complete() {
            return None;
        }
        let e = self.entries.remove(idx);
        Some((e.data, e.collector))
    }

    /// Drop the transactions that were last added to more than `max_age`
    /// before `now`; their data.
    pub fn prune(&mut self, now: i64, max_age: i64) -> Vec<D> {
        let (old, keep) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|e| now - e.updated > max_age);
        self.entries = keep;
        old.into_iter().map(|e| e.data).collect()
    }

    /// Make every transaction `secs` older (for tests of pruning).
    pub fn age(&mut self, secs: i64) {
        for e in &mut self.entries {
            e.updated -= secs;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every transaction.
    pub fn clear(&mut self) -> Vec<D> {
        std::mem::take(&mut self.entries)
            .into_iter()
            .map(|e| e.data)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::msg::SESSION_TIMEOUT;

    fn collect(messages: Vec<Message>) -> Collector {
        let mut c = Collector::new();
        for m in messages {
            c.add(m, ());
        }
        assert!(c.is_complete());
        c
    }

    fn ctx<'a>(password: &'a [u8], session_id: &'a [u8]) -> SendContext<'a> {
        SendContext {
            password,
            session_id,
            origination_network: b"",
            chain_certificate: false,
        }
    }

    /// A reply that states a digest carries it in the clear, in the form
    /// a phone compares: 32 lowercase hexadecimal digits.
    #[test]
    fn md5_header() {
        assert_eq!(md5_hex(b""), b"d41d8cd98f00b204e9800998ecf8427e");
        let doc = b"<config>\n</config>\n";
        let out = Outgoing {
            id: b"3".to_vec(),
            response_type: b"VerifyResponse".to_vec(),
            md5: md5_hex(doc),
            ..Default::default()
        };
        let messages = out.encode(&ctx(b"0123456789abcdef", b"9999")).unwrap();
        assert_eq!(
            messages[0].header(crate::headers::MD5),
            Some(&md5_hex(doc)[..])
        );
        // Without a digest there is no header.
        let out = Outgoing {
            id: b"4".to_vec(),
            response_type: b"VerifyResponse".to_vec(),
            ..Default::default()
        };
        let messages = out.encode(&ctx(b"0123456789abcdef", b"9999")).unwrap();
        assert_eq!(messages[0].header(crate::headers::MD5), None);
    }

    /// "Session Timeout" as a server sends it for a request that failed
    /// its session's checks: encrypted under that session's password.
    fn timeout(password: &[u8]) -> Collector {
        let out = Outgoing {
            error: SESSION_TIMEOUT,
            id: b"17".to_vec(),
            response_type: b"FileResponse".to_vec(),
            ..Default::default()
        };
        collect(out.encode(&ctx(password, b"9999")).unwrap())
    }

    #[test]
    fn session_timeout_under_another_password() {
        let theirs = crypto::new_common_password().unwrap();
        let ours = crypto::new_common_password().unwrap();
        let c = timeout(&theirs);

        // Without the password there is nothing to decrypt it with.
        assert!(c.decode(Sender::Server, None).is_err());
        let m = c.decode_reply(None).unwrap();
        assert!(m.body.is_empty() && m.payload.is_empty());

        // With another password the padding check nearly always fails;
        // either way the error and the ids come through.
        for password in [Some(&ours[..]), None] {
            let m = c.decode_reply(password).unwrap();
            assert_eq!(m.error, SESSION_TIMEOUT);
            assert_eq!(m.id, b"17");
            assert_eq!(m.response_type, b"FileResponse");
            assert_eq!(m.session_id, b"9999");
            assert!(m.encrypted);
        }
    }

    #[test]
    fn decode_reply_decrypts_when_it_can() {
        let password = crypto::new_common_password().unwrap();
        let c = timeout(&password);
        let m = c.decode_reply(Some(&password)).unwrap();
        let plain = c.decode(Sender::Server, Some(&password)).unwrap();
        assert_eq!(m.error, SESSION_TIMEOUT);
        assert_eq!(m.payload, plain.payload);
        assert_eq!(m.payload, framing::error_body(SESSION_TIMEOUT).as_bytes());
    }

    #[test]
    fn decode_reply_keeps_the_error_for_other_messages() {
        // An undecryptable reply without an error is not passed off as
        // an empty one.
        let theirs = crypto::new_common_password().unwrap();
        let out = Outgoing {
            id: b"18".to_vec(),
            response_type: b"FileResponse".to_vec(),
            body: b"RIFFdata".to_vec(),
            ..Default::default()
        };
        let c = collect(out.encode(&ctx(&theirs, b"9999")).unwrap());
        assert!(c.decode_reply(None).is_err());
        assert!(Collector::<()>::new().decode_reply(None).is_err());
    }

    #[test]
    fn envelope_of_a_plain_message_keeps_its_fields() {
        // The handshake-required reply for an unknown session: not
        // encrypted, no body.
        let mut m = Message::default();
        m.set(h::RESPONSE_TYPE, "HandshakeResponse");
        m.set(h::ERROR_ID, "-398");
        m.set(h::APPSERVER_ID, "5");
        m.set(h::PASSWORD, "abc");
        let c = collect(vec![m]);
        let e = c.envelope().unwrap();
        assert_eq!((e.error, e.encrypted), (SESSION_TIMEOUT, false));
        assert_eq!(e.password, b"abc");
        let d = c.decode_reply(None).unwrap();
        assert_eq!((d.error, &d.id[..]), (SESSION_TIMEOUT, &b"5"[..]));
        assert_eq!(d.password, b"abc");
    }
}
