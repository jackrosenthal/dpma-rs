//! The phone side of incoming AppServer messages.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use bstr::{BStr, BString, ByteSlice};

use super::crypto::{b64decode_strict, decrypt, decrypt_field, set_hex};
use super::framing::{SERVER_TCP_LIMIT, SERVER_UDP_ENCRYPTED_LIMIT, SERVER_UDP_PLAIN_LIMIT};
use super::proto::*;
use crate::sip::Message;

/// One complete incoming AppServer message: all of its chunks, decrypted
/// (when salted) and with the `Command: ` prefixes of events and error
/// replies removed.
#[derive(Clone, Debug)]
pub struct Reply {
    /// The chunks in sequence order.
    pub parts: Vec<Message>,
    /// `X-Digium-AppServer-ID` (absent on events).
    pub id: Option<BString>,
    /// `X-Digium-AppServer-ResponseType`.
    pub response_type: Option<BString>,
    /// `X-Digium-AppServer-RequestType`.
    pub request_type: Option<BString>,
    /// `X-Event-Name`.
    pub event: Option<BString>,
    /// `X-Digium-AppServer-Session`.
    pub session: Option<BString>,
    /// `X-Digium-AppServer-Error-ID`.
    pub error: Option<BString>,
    /// `X-Digium-AppServer-Message-Salt`.
    pub salt: Option<BString>,
    /// Whether the message carries a salt (is encrypted).
    pub encrypted: bool,
    /// The chunk bodies as received, concatenated.
    pub raw_body: BString,
    /// The decrypted body.
    pub body: BString,
    /// The body without the `Command: ` prefixes (events and error
    /// replies); otherwise the body.
    pub payload: BString,
    /// Decrypted header fields (`Password`, `Config-Token`; for a
    /// handshake, a description of the common password).
    pub fields: Vec<(String, BString)>,
    /// Decoding problems.
    pub problems: Vec<String>,
    /// For a HandshakeResponse: whether the AppServer certificate
    /// verified against the test AppServer CA.
    pub appserver_ok: Option<bool>,
    /// For a HandshakeResponse: the certificate's subject, or why it did
    /// not verify.
    pub appserver_info: Option<String>,
}

fn nonempty_error(e: &Option<BString>) -> bool {
    e.as_ref().is_some_and(|v| !v.is_empty() && v != "0")
}

impl Reply {
    /// A reply from its chunks (in sequence order); call [`Reply::decode`]
    /// to decrypt it.
    pub fn new(parts: Vec<Message>) -> Reply {
        let first = &parts[0];
        let h = |n: &str| first.get(n).cloned();
        let salt = h(H_SALT);
        let raw_body: BString = parts
            .iter()
            .flat_map(|p| p.body.iter().copied())
            .collect::<Vec<u8>>()
            .into();
        Reply {
            id: h(H_ID),
            response_type: h(H_RESPONSE_TYPE),
            request_type: h(H_REQUEST_TYPE),
            event: h(H_EVENT),
            session: h(H_SESSION),
            error: h(H_ERROR),
            encrypted: salt.as_ref().is_some_and(|s| !s.is_empty()),
            salt,
            body: raw_body.clone(),
            payload: raw_body.clone(),
            raw_body,
            fields: Vec::new(),
            problems: Vec::new(),
            appserver_ok: None,
            appserver_info: None,
            parts,
        }
    }

    /// The first chunk.
    pub fn first(&self) -> &Message {
        &self.parts[0]
    }

    /// The transports the chunks arrived on, sorted and joined with
    /// commas: `"udp"`, `"tcp"`, or `"tcp,udp"`.
    pub fn transports(&self) -> Option<String> {
        let mut t: Vec<&str> = self
            .parts
            .iter()
            .filter_map(|p| p.transport.map(|t| t.as_str()))
            .collect();
        t.sort_unstable();
        t.dedup();
        (!t.is_empty()).then(|| t.join(","))
    }

    /// The response type, else the request type, else the event name, else
    /// `Error` for an error without a type.
    pub fn type_name(&self) -> Option<BString> {
        self.response_type
            .clone()
            .or_else(|| self.request_type.clone())
            .or_else(|| self.event.clone())
            .or_else(|| nonempty_error(&self.error).then(|| BString::from("Error")))
    }

    /// No problems and no error (`Error-ID` absent, empty, or 0).
    pub fn ok(&self) -> bool {
        self.problems.is_empty() && !nonempty_error(&self.error)
    }

    /// A header of the first chunk; `X-Digium-AppServer-` may be omitted
    /// from `name`.
    pub fn header(&self, name: &str) -> Option<&BString> {
        let first = self.first();
        first.get(name).or_else(|| {
            if name.len() >= 2 && name[..2].eq_ignore_ascii_case("x-") {
                None
            } else {
                first.get(&format!("{P}{name}"))
            }
        })
    }

    /// A decrypted header field; `X-Digium-AppServer-` may be omitted.
    pub fn field(&self, name: &str) -> Option<&BString> {
        let long = format!("{P}{name}");
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name) || k.eq_ignore_ascii_case(&long))
            .map(|(_, v)| v)
    }

    /// Whether the response type is `t`.
    pub fn is_response(&self, t: &str) -> bool {
        self.response_type.as_ref().is_some_and(|v| v == t)
    }

    /// Decrypts (when salted) with the common password and strips the
    /// `Command: ` prefixes.  Problems are recorded in
    /// [`Reply::problems`].
    pub fn decode(&mut self, password: Option<&[u8]>) {
        if self.encrypted {
            let Some(password) = password else {
                self.problems
                    .push("encrypted message but no common password".into());
                return;
            };
            let res = (|| -> anyhow::Result<()> {
                let salt = set_hex(self.salt.as_ref().map(|s| s.as_slice()).unwrap_or(&[]))?;
                let mut data = Vec::new();
                for p in &self.parts {
                    data.extend(b64decode_strict(&p.body)?);
                }
                self.body = decrypt(password, &salt, &data)?.into();
                for name in [H_PASSWORD, H_CONFIG_TOKEN] {
                    if let Some(v) = self.first().get(name).filter(|v| !v.is_empty()).cloned() {
                        let plain = decrypt_field(password, &salt, &v)?;
                        self.fields.push((name.to_string(), plain.into()));
                    }
                }
                Ok(())
            })();
            if let Err(e) = res {
                self.problems.push(e.to_string());
                return;
            }
        }
        let prefixed = self.event.is_some() || nonempty_error(&self.error);
        self.payload = if prefixed {
            self.strip_prefix()
        } else {
            self.body.clone()
        };
    }

    fn strip_prefix(&mut self) -> BString {
        let body = &self.body;
        let p = COMMAND_PREFIX;
        if !body.starts_with(p) {
            return body.clone();
        }
        if self.parts.len() == 1 {
            return body[p.len()..].into();
        }
        if !self.encrypted {
            let mut out = Vec::new();
            for part in &self.parts {
                out.extend_from_slice(part.body.strip_prefix(p).unwrap_or(&part.body));
            }
            return out.into();
        }
        // Encrypted chunk boundaries are not visible after decryption; the
        // server cut the plaintext at a fixed limit, so find it.
        for limit in [
            SERVER_UDP_ENCRYPTED_LIMIT,
            SERVER_TCP_LIMIT,
            SERVER_UDP_PLAIN_LIMIT,
        ] {
            let starts: Vec<usize> = (0..body.len()).step_by(limit).collect();
            if starts.len() == self.parts.len() && starts.iter().all(|&s| body[s..].starts_with(p))
            {
                let mut out = Vec::new();
                for &s in &starts {
                    out.extend_from_slice(&body[s + p.len()..(s + limit).min(body.len())]);
                }
                return out.into();
            }
        }
        let rest = body[p.len()..].into();
        self.problems
            .push("could not locate the chunk prefixes".into());
        rest
    }

    /// A human-readable description (header values are written as
    /// received).  `verbose` 1 adds every header, 2 the SIP ones too.
    pub fn describe(&self, verbose: i32) -> BString {
        let mut out: Vec<u8> = Vec::new();
        let opt = |v: &Option<BString>| {
            v.as_ref()
                .map(|b| b.to_string())
                .unwrap_or_else(|| "None".into())
        };
        let _ = write!(
            Wr(&mut out),
            "<< {} id={} error={} chunks={} {}",
            self.type_name()
                .map(|b| b.to_string())
                .unwrap_or_else(|| "None".into()),
            opt(&self.id),
            self.error
                .as_ref()
                .map(|b| b.to_string())
                .unwrap_or_else(|| "-".into()),
            self.parts.len(),
            if self.encrypted {
                "encrypted"
            } else {
                "plaintext"
            }
        );
        if let Some(s) = self.session.as_ref().filter(|s| !s.is_empty()) {
            out.extend_from_slice(b" session=");
            out.extend_from_slice(s);
        }
        const SKIP: [&str; 8] = [
            "via",
            "from",
            "to",
            "call-id",
            "cseq",
            "content-length",
            "max-forwards",
            "content-type",
        ];
        for (k, v) in &self.first().headers {
            let lk = k.to_ascii_lowercase();
            let shown = verbose > 0 || (lk.starts_with("x-") && k != H_SEQUENCE && k != H_FINISHED);
            if shown && (verbose > 1 || !SKIP.contains(&lk.as_str())) {
                out.extend_from_slice(format!("\n   {k}: ").as_bytes());
                out.extend_from_slice(v);
            }
        }
        for (k, v) in &self.fields {
            out.extend_from_slice(format!("\n   {k} (decrypted): ").as_bytes());
            out.extend_from_slice(v);
        }
        if let Some(info) = &self.appserver_info {
            let state = if self.appserver_ok == Some(true) {
                "verified, "
            } else {
                "NOT VERIFIED: "
            };
            out.extend_from_slice(format!("\n   AppServer certificate: {state}{info}").as_bytes());
        }
        for p in &self.problems {
            out.extend_from_slice(format!("\n   PROBLEM: {p}").as_bytes());
        }
        let text = self.payload.to_str_lossy();
        out.extend_from_slice(
            format!(
                "\n   body ({} bytes){}",
                self.payload.len(),
                if text.is_empty() { "" } else { ":" }
            )
            .as_bytes(),
        );
        for line in text.lines() {
            out.extend_from_slice(format!("\n   | {line}").as_bytes());
        }
        out.into()
    }
}

struct Wr<'a>(&'a mut Vec<u8>);
impl std::fmt::Write for Wr<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Where a waiting exchange's reply is delivered.
#[derive(Default)]
pub(crate) struct ReplySlot {
    pub(crate) reply: Mutex<Option<Reply>>,
    pub(crate) cv: Condvar,
}

impl ReplySlot {
    pub(crate) fn deliver(&self, reply: Reply) {
        *self.reply.lock().unwrap() = Some(reply);
        self.cv.notify_all();
    }

    pub(crate) fn wait(&self, timeout: Duration) -> Option<Reply> {
        let deadline = Instant::now() + timeout;
        let mut g = self.reply.lock().unwrap();
        loop {
            if let Some(r) = g.take() {
                return Some(r);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            g = self.cv.wait_timeout(g, deadline - now).unwrap().0;
        }
    }
}

/// A request sent by the phone and the reply it got.
pub struct Exchange {
    /// The request type.
    pub request_type: String,
    /// The transaction id.
    pub id: String,
    /// The SIP status of every chunk sent (`None`: no response).
    pub sip_statuses: Vec<Option<u16>>,
    /// The number of chunks of the request.
    pub chunks: usize,
    /// Whether the request was encrypted.
    pub encrypted: bool,
    /// The reply, once it arrived.
    pub reply: Option<Reply>,
    /// When the exchange started.
    pub sent_at: Instant,
    /// Problems sending the request.
    pub problems: Vec<String>,
    /// The response type expected for the request type.
    pub expected: Option<&'static str>,
    /// Whether the reply was waited for.
    pub waited: bool,
    pub(crate) slot: Option<Arc<ReplySlot>>,
}

impl Exchange {
    pub(crate) fn new(request_type: &str, id: &str) -> Exchange {
        Exchange {
            request_type: request_type.to_string(),
            id: id.to_string(),
            sip_statuses: Vec::new(),
            chunks: 0,
            encrypted: false,
            reply: None,
            sent_at: Instant::now(),
            problems: Vec::new(),
            expected: response_for(request_type),
            waited: false,
            slot: None,
        }
    }

    /// Every chunk got a 2xx response.
    pub fn sip_ok(&self) -> bool {
        !self.sip_statuses.is_empty()
            && self
                .sip_statuses
                .iter()
                .all(|s| s.is_some_and(|s| (200..300).contains(&s)))
    }

    /// The request went through, the reply has no problems and no error,
    /// and it has the expected response type.
    pub fn ok(&self) -> bool {
        self.sip_ok()
            && self.problems.is_empty()
            && self.reply.as_ref().is_some_and(|r| {
                r.ok()
                    && self
                        .expected
                        .is_none_or(|e| r.response_type.as_ref().is_some_and(|t| t == e))
            })
    }

    /// Success of a `raw` request: the request went through and any reply
    /// without decoding problems arrived.
    pub fn raw_ok(&self) -> bool {
        self.sip_ok()
            && self.problems.is_empty()
            && self.reply.as_ref().is_some_and(|r| r.problems.is_empty())
    }

    /// The reply, if any.
    pub fn reply(&self) -> Option<&Reply> {
        self.reply.as_ref()
    }

    /// A human-readable description of the request and its reply.
    pub fn describe(&self, verbose: i32) -> BString {
        let st: Vec<String> = self
            .sip_statuses
            .iter()
            .map(|s| s.map(|s| s.to_string()).unwrap_or_else(|| "timeout".into()))
            .collect();
        let st = if st.is_empty() {
            "-".to_string()
        } else {
            st.join(",")
        };
        let mut out: Vec<u8> = format!(
            ">> {} id={} chunks={} {} sip={}",
            self.request_type,
            self.id,
            self.chunks,
            if self.encrypted {
                "encrypted"
            } else {
                "plaintext"
            },
            st
        )
        .into_bytes();
        for p in &self.problems {
            out.extend_from_slice(format!("\n   PROBLEM: {p}").as_bytes());
        }
        out.push(b'\n');
        match &self.reply {
            Some(r) => out.extend_from_slice(&r.describe(verbose)),
            None if self.waited || !self.problems.is_empty() => {
                out.extend_from_slice(b"<< (no reply)")
            }
            None => out.extend_from_slice(b"<< (not waited for)"),
        }
        out.into()
    }
}

impl std::fmt::Debug for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe(0).to_str_lossy())
    }
}

/// Key of an incomplete incoming message: transaction id, salt, and type.
type PartialKey = (BString, BString, BString);

/// The phone side of `incoming_add_msg`: chunks grouped by transaction
/// id, salt, and type (events carry no id); a chunk without a sequence,
/// or the chunk with `Message-Finished` once all chunks before it are in,
/// completes the group.  Incomplete groups are dropped after 40 s.
#[derive(Default)]
pub struct Reassembler {
    partial: HashMap<PartialKey, Vec<(i64, bool, Message)>>,
}

/// What [`Reassembler::add`] did with a chunk.
pub enum Added {
    /// The message is complete: its chunks in sequence order.
    Complete(Vec<Message>),
    /// More chunks are needed.
    Pending,
    /// A chunk with this sequence number was already there.
    Duplicate(i64),
}

impl Reassembler {
    /// Adds one chunk.
    pub fn add(&mut self, msg: Message) -> Added {
        let g = |n: &str| msg.get(n).cloned().unwrap_or_default();
        let seq_text = g(H_SEQUENCE);
        let finished = !g(H_FINISHED).is_empty();
        let kind = [H_RESPONSE_TYPE, H_REQUEST_TYPE, H_EVENT, H_ERROR]
            .iter()
            .map(|n| g(n))
            .find(|v| !v.is_empty())
            .unwrap_or_default();
        let key = (g(H_ID), g(H_SALT), kind);
        let seq: Option<i64> = if seq_text.is_empty() {
            None
        } else {
            seq_text.to_str().ok().and_then(|s| s.trim().parse().ok())
        };
        let parts = self.partial.entry(key.clone()).or_default();
        if let Some(s) = seq {
            if parts.iter().any(|p| p.0 == s) {
                return Added::Duplicate(s);
            }
        }
        parts.push((seq.unwrap_or(0), finished || seq.is_none(), msg));
        parts.sort_by_key(|p| p.0);
        let Some(done) = parts.iter().find(|p| p.1) else {
            return Added::Pending;
        };
        if seq.is_some() && done.0 != parts.len() as i64 - 1 {
            return Added::Pending;
        }
        let parts = self.partial.remove(&key).unwrap_or_default();
        Added::Complete(parts.into_iter().map(|p| p.2).collect())
    }

    /// Drops groups whose last chunk (in sequence order) arrived more than
    /// `max_age` ago; returns how many chunks each dropped group had, with
    /// its key described.
    pub fn expire(&mut self, max_age: Duration) -> Vec<(String, usize)> {
        let now = Instant::now();
        let old: Vec<PartialKey> = self
            .partial
            .iter()
            .filter(|(_, parts)| {
                parts
                    .last()
                    .is_some_and(|p| now.duration_since(p.2.received) > max_age)
            })
            .map(|(k, _)| k.clone())
            .collect();
        old.into_iter()
            .map(|k| {
                let n = self.partial.remove(&k).map(|p| p.len()).unwrap_or(0);
                (
                    format!(
                        "({:?}, {:?}, {:?})",
                        BStr::new(&k.0),
                        BStr::new(&k.1),
                        BStr::new(&k.2)
                    ),
                    n,
                )
            })
            .collect()
    }
}
