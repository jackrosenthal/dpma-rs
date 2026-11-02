//! Checks on simulator exchanges, replies, and AMI messages, one check
//! per condition (the conditions of the old `.sim` scripts' `expect` and
//! `expect-ami`).
//!
//! ```no_run
//! # use dpma_tests::harness::Checker;
//! # use dpma_tests::sim::{Options, Phone};
//! # fn main() -> anyhow::Result<()> {
//! # let phone = Phone::start(Options::default())?;
//! # let mut c = Checker::new();
//! let ex = phone.ping().send()?;
//! c.exchange("encrypted ping", &ex).ty("PingResponse").no_error().encrypted(true).body("empty body");
//! # Ok(()) }
//! ```

use std::fmt::Display;

use bstr::{BStr, BString, ByteSlice};

use super::check::{regex_search, Checker};
use crate::ami::AmiMessage;
use crate::sim::{Exchange, Reply};

/// Checks on one exchange (or one reply received with
/// [`crate::sim::Phone::next_event`]).  Each method records one check
/// named `"<label>: <condition>"` and returns `self` for chaining.
pub struct ExchangeCheck<'a> {
    c: &'a mut Checker,
    label: String,
    ex: Option<&'a Exchange>,
    reply: Option<&'a Reply>,
}

fn show(v: Option<&[u8]>) -> String {
    match v {
        Some(v) if v.len() > 300 => format!("is {:?}...", BStr::new(&v[..300])),
        Some(v) => format!("is {:?}", BStr::new(v)),
        None => "absent".into(),
    }
}

impl Checker {
    /// Checks on an exchange.
    pub fn exchange<'a>(&'a mut self, label: impl Display, ex: &'a Exchange) -> ExchangeCheck<'a> {
        let reply = ex.reply.as_ref();
        ExchangeCheck {
            c: self,
            label: label.to_string(),
            ex: Some(ex),
            reply,
        }
    }

    /// Checks on a reply that is not part of an exchange (an event).
    pub fn reply<'a>(
        &'a mut self,
        label: impl Display,
        reply: Option<&'a Reply>,
    ) -> ExchangeCheck<'a> {
        ExchangeCheck {
            c: self,
            label: label.to_string(),
            ex: None,
            reply,
        }
    }

    /// Checks on an AMI message (for a list action, use
    /// [`crate::ami::AmiResult::merged`]: repeated keys are joined with
    /// line breaks).
    pub fn ami<'a>(&'a mut self, label: impl Display, msg: Option<&'a AmiMessage>) -> AmiCheck<'a> {
        AmiCheck {
            c: self,
            label: label.to_string(),
            msg,
        }
    }
}

impl<'a> ExchangeCheck<'a> {
    fn record(self, cond: &str, ok: bool, detail: impl FnOnce() -> String) -> Self {
        let name = format!("{}: {}", self.label, cond);
        let detail = if ok { String::new() } else { detail() };
        let full = match (ok, self.ex) {
            (false, Some(ex)) => format!("{detail}\n{}", ex.describe(0)),
            (false, None) => match self.reply {
                Some(r) => format!("{detail}\n{}", r.describe(0)),
                None => detail,
            },
            _ => detail,
        };
        self.c.check(name, ok, full);
        self
    }

    fn eq(self, cond: &str, have: Option<BString>, want: &[u8]) -> Self {
        let ok = have.as_ref().is_some_and(|h| h.as_slice() == want);
        self.record(cond, ok, || show(have.as_deref().map(|v| v.as_slice())))
    }

    fn re(self, cond: &str, have: Option<BString>, pattern: &str) -> Self {
        let ok = have.as_ref().is_some_and(|h| regex_search(pattern, h));
        self.record(cond, ok, || show(have.as_deref().map(|v| v.as_slice())))
    }

    /// The command succeeded: the expected response type without an error
    /// ([`Exchange::ok`]).
    pub fn ok(self) -> Self {
        let ok = self.ex.is_some_and(Exchange::ok);
        self.record("ok", ok, String::new)
    }

    /// A `raw` request succeeded: any reply without decoding problems
    /// ([`Exchange::raw_ok`]).
    pub fn raw_ok(self) -> Self {
        let ok = self.ex.is_some_and(Exchange::raw_ok);
        self.record("reply", ok, String::new)
    }

    /// Every chunk of the request got a 2xx SIP response.
    pub fn sip_ok(self) -> Self {
        let ok = self.ex.is_some_and(Exchange::sip_ok);
        self.record("sip ok", ok, String::new)
    }

    /// Every chunk of the request got SIP status `code`.
    pub fn status(self, code: u16) -> Self {
        let st: Vec<Option<u16>> = self.ex.map(|e| e.sip_statuses.clone()).unwrap_or_default();
        let ok = !st.is_empty() && st.iter().all(|s| *s == Some(code));
        self.record(&format!("status={code}"), ok, || format!("SIP {st:?}"))
    }

    /// A reply arrived.
    pub fn has_reply(self) -> Self {
        let ok = self.reply.is_some();
        self.record("reply=yes", ok, || "no reply".into())
    }

    /// No reply arrived.
    pub fn no_reply(self) -> Self {
        let ok = self.reply.is_none();
        self.record("reply=none", ok, || "a reply arrived".into())
    }

    /// The type (response type, else request type, event, or `Error`).
    pub fn ty(self, t: &str) -> Self {
        let have = self.reply.and_then(Reply::type_name);
        self.eq(&format!("type={t}"), have, t.as_bytes())
    }

    /// `X-Event-Name` is `name`.
    pub fn event(self, name: impl AsRef<[u8]>) -> Self {
        let have = self.reply.and_then(|r| r.event.clone());
        let n = name.as_ref();
        self.eq(&format!("event={}", n.as_bstr()), have, n)
    }

    /// No `X-Event-Name`.
    pub fn no_event(self) -> Self {
        let have = self.reply.and_then(|r| r.event.clone());
        let got_reply = self.reply.is_some();
        let ok = got_reply && have.is_none();
        self.record("event!", ok, || {
            if got_reply {
                show(have.as_deref().map(|v| v.as_slice()))
            } else {
                "no reply".into()
            }
        })
    }

    /// `X-Digium-AppServer-Error-ID` is `code`.
    pub fn error(self, code: &str) -> Self {
        let have = self.reply.and_then(|r| r.error.clone());
        self.eq(&format!("error={code}"), have, code.as_bytes())
    }

    /// No `X-Digium-AppServer-Error-ID`.
    pub fn no_error(self) -> Self {
        let have = self
            .reply
            .map(|r| r.error.clone().unwrap_or_else(|| "none".into()));
        self.eq("error=none", have, b"none")
    }

    /// The decrypted body is `body`.
    pub fn body(self, body: impl AsRef<[u8]>) -> Self {
        let have = self.reply.map(|r| r.body.clone());
        let b = body.as_ref();
        self.eq(&format!("body={:?}", short(b)), have, b)
    }

    /// The decrypted body matches `pattern`.
    pub fn body_matches(self, pattern: &str) -> Self {
        let have = self.reply.map(|r| r.body.clone());
        self.re(&format!("body~{pattern}"), have, pattern)
    }

    /// The payload (body without the `Command: ` prefixes) is `payload`.
    pub fn payload(self, payload: impl AsRef<[u8]>) -> Self {
        let have = self.reply.map(|r| r.payload.clone());
        let p = payload.as_ref();
        self.eq(&format!("payload={:?}", short(p)), have, p)
    }

    /// The payload matches `pattern`.
    pub fn payload_matches(self, pattern: &str) -> Self {
        let have = self.reply.map(|r| r.payload.clone());
        self.re(&format!("payload~{pattern}"), have, pattern)
    }

    /// A header of the first chunk is `value` (`X-Digium-AppServer-` may
    /// be omitted from `name`).
    pub fn header(self, name: &str, value: impl AsRef<[u8]>) -> Self {
        let have = self.reply.and_then(|r| r.header(name).cloned());
        let v = value.as_ref();
        self.eq(&format!("header:{name}={}", v.as_bstr()), have, v)
    }

    /// A header of the first chunk matches `pattern`.
    pub fn header_matches(self, name: &str, pattern: &str) -> Self {
        let have = self.reply.and_then(|r| r.header(name).cloned());
        self.re(&format!("header:{name}~{pattern}"), have, pattern)
    }

    /// A header of the first chunk is present.
    pub fn header_present(self, name: &str) -> Self {
        let ok = self.reply.is_some_and(|r| r.header(name).is_some());
        self.record(&format!("header:{name}?"), ok, || "absent".into())
    }

    /// A header of the first chunk is absent.
    pub fn header_absent(self, name: &str) -> Self {
        let have = self.reply.and_then(|r| r.header(name).cloned());
        let ok = self.reply.is_some() && have.is_none();
        self.record(&format!("header:{name}!"), ok, || {
            show(have.as_deref().map(|v| v.as_slice()))
        })
    }

    /// A decrypted header field is `value`.
    pub fn field(self, name: &str, value: impl AsRef<[u8]>) -> Self {
        let have = self.reply.and_then(|r| r.field(name).cloned());
        let v = value.as_ref();
        self.eq(&format!("field:{name}={}", v.as_bstr()), have, v)
    }

    /// The reply has `n` chunks.
    pub fn chunks(self, n: usize) -> Self {
        let have = self.reply.map(|r| BString::from(r.parts.len().to_string()));
        self.eq(&format!("chunks={n}"), have, n.to_string().as_bytes())
    }

    /// The number of chunks of the reply matches `pattern`.
    pub fn chunks_matches(self, pattern: &str) -> Self {
        let have = self.reply.map(|r| BString::from(r.parts.len().to_string()));
        self.re(&format!("chunks~{pattern}"), have, pattern)
    }

    /// The reply's chunks arrived over these transports (`udp`, `tcp`, or
    /// `tcp,udp`).
    pub fn transport(self, t: impl Display) -> Self {
        let t = t.to_string();
        let have = self.reply.and_then(Reply::transports).map(BString::from);
        self.eq(&format!("transport={t}"), have, t.as_bytes())
    }

    /// The reply is (or is not) encrypted.
    pub fn encrypted(self, yes: bool) -> Self {
        let have = self
            .reply
            .map(|r| BString::from(if r.encrypted { "yes" } else { "no" }));
        let want = if yes { "yes" } else { "no" };
        self.eq(&format!("encrypted={want}"), have, want.as_bytes())
    }

    /// The AppServer certificate of a HandshakeResponse verified.
    pub fn appserver_ok(self) -> Self {
        let have = self.reply.map(|r| {
            BString::from(match r.appserver_ok {
                Some(true) => "ok",
                Some(false) => "fail",
                None => "none",
            })
        });
        self.eq("appserver=ok", have, b"ok")
    }

    /// The reply decoded without problems.
    pub fn no_problems(self) -> Self {
        let have = self.reply.map(|r| {
            BString::from(if r.problems.is_empty() {
                "none".into()
            } else {
                r.problems.join("; ")
            })
        });
        self.eq("problems=none", have, b"none")
    }
}

fn short(b: &[u8]) -> BString {
    if b.len() > 40 {
        let mut s = BString::from(&b[..40]);
        s.extend_from_slice(b"...");
        s
    } else {
        b.into()
    }
}

/// Checks on an AMI message.  Repeated keys are seen joined with line
/// breaks.
pub struct AmiCheck<'a> {
    c: &'a mut Checker,
    label: String,
    msg: Option<&'a AmiMessage>,
}

impl AmiCheck<'_> {
    fn record(self, cond: String, ok: bool, have: Option<BString>) -> Self {
        let detail = if ok {
            String::new()
        } else if self.msg.is_none() {
            "no AMI message".into()
        } else {
            show(have.as_deref().map(|v| v.as_slice()))
        };
        self.c
            .check(format!("{}: {}", self.label, cond), ok, detail);
        self
    }

    fn have(&self, key: &str) -> Option<BString> {
        self.msg.and_then(|m| m.joined(key))
    }

    /// `key` is `value`.
    pub fn eq(self, key: &str, value: impl AsRef<[u8]>) -> Self {
        let have = self.have(key);
        let v = value.as_ref();
        let ok = have.as_ref().is_some_and(|h| h.as_slice() == v);
        self.record(format!("{key}={}", v.as_bstr()), ok, have)
    }

    /// `key` is present and not `value`.
    pub fn ne(self, key: &str, value: impl AsRef<[u8]>) -> Self {
        let have = self.have(key);
        let v = value.as_ref();
        let ok = have.as_ref().is_some_and(|h| h.as_slice() != v);
        self.record(format!("{key}!={}", v.as_bstr()), ok, have)
    }

    /// `key` matches `pattern` (`.` matches line breaks).
    pub fn matches(self, key: &str, pattern: &str) -> Self {
        let have = self.have(key);
        let ok = have.as_ref().is_some_and(|h| regex_search(pattern, h));
        self.record(format!("{key}~{pattern}"), ok, have)
    }

    /// `key` is present.
    pub fn present(self, key: &str) -> Self {
        let have = self.have(key);
        let ok = have.is_some();
        self.record(format!("{key}?"), ok, have)
    }

    /// `key` is absent.
    pub fn absent(self, key: &str) -> Self {
        let have = self.have(key);
        let ok = self.msg.is_some() && have.is_none();
        self.record(format!("{key}!"), ok, have)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::Message;

    fn reply(headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let h = headers
            .iter()
            .map(|(k, v)| (k.to_string(), BString::from(*v)))
            .collect();
        let mut r = Reply::new(vec![Message::new("MESSAGE sip:x SIP/2.0", h, body)]);
        r.decode(None);
        r
    }

    #[test]
    fn conditions_pass_and_fail() {
        let r = reply(
            &[
                ("X-Digium-AppServer-ResponseType", "PingResponse"),
                ("X-Digium-AppServer-Session", "42"),
            ],
            b"empty body",
        );
        let mut c = Checker::quiet();
        c.reply("r", Some(&r))
            .ty("PingResponse")
            .no_error()
            .encrypted(false)
            .body("empty body")
            .body_matches("^empty")
            .header("Session", "42")
            .header_absent("ID")
            .no_event()
            .chunks(1)
            .no_problems();
        assert!(c.passed(), "{}", c.summary());
        c.reply("r", Some(&r))
            .ty("EchoResponse")
            .error("0")
            .header_present("ID")
            .transport("udp")
            .chunks(2);
        assert_eq!(c.failures().len(), 5, "{}", c.summary());
        let mut c = Checker::quiet();
        c.reply("none", None).no_reply().ty("PingResponse");
        assert_eq!(c.failures(), ["none: type=PingResponse"]);
    }

    #[test]
    fn ami_conditions() {
        let m = AmiMessage::from_fields(vec![
            ("Response".into(), "Success".into()),
            ("Output".into(), "a".into()),
            ("Output".into(), "SessionID:1 x".into()),
        ]);
        let mut c = Checker::quiet();
        c.ami("m", Some(&m))
            .eq("Response", "Success")
            .matches("Output", "(?m)^SessionID:1 ")
            .absent("Event")
            .present("Output");
        assert!(c.passed(), "{}", c.summary());
        c.ami("m", Some(&m))
            .eq("Output", "a")
            .ne("Response", "Success")
            .present("Event");
        assert_eq!(c.failures().len(), 3);
    }
}
