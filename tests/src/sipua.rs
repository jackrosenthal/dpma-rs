//! A minimal SIP user agent over UDP for test phones.
//!
//! The `*_line` functions write transcript lines that are stable across
//! runs (no ports, tags, or branches), which the pjsip-helpers suite
//! compares with its expected transcript.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bstr::{BString, ByteSlice};
use md5::{Digest, Md5};
use rand::Rng;
use regex::Regex;

use crate::sip::{self, Message};

/// The SDP of an answered call.
pub const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

fn hex32() -> String {
    format!("{:x}", rand::thread_rng().gen::<u32>())
}

fn md5_hex(s: &str) -> String {
    hex::encode(Md5::digest(s.as_bytes()))
}

/// The `Authorization` (or `Proxy-Authorization`) header line answering
/// the digest challenge in `challenge` (a 401 or 407), with qop `auth`.
pub fn digest_authorization(
    challenge: &Message,
    user: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> Option<String> {
    let (hdr, value) = match challenge.get("WWW-Authenticate") {
        Some(v) => ("Authorization", v),
        None => ("Proxy-Authorization", challenge.get("Proxy-Authenticate")?),
    };
    let value = value.to_str_lossy();
    let rest = value.trim_start().strip_prefix("Digest")?.trim_start();
    let re = Regex::new(r#"(\w+)="?([^",]*)"?"#).ok()?;
    let params: Vec<(String, String)> = re
        .captures_iter(rest)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect();
    let p = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let realm = p("realm")?;
    let nonce = p("nonce")?;
    let ha1 = md5_hex(&format!("{user}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let (nc, cnonce) = ("00000001", hex32());
    let resp = md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"));
    let mut v = format!(
        "{hdr}: Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{resp}\", algorithm=MD5, qop=auth, nc={nc}, cnonce=\"{cnonce}\""
    );
    if let Some(o) = p("opaque") {
        v.push_str(&format!(", opaque=\"{o}\""));
    }
    Some(v)
}

/// The status line of a response, or `"no response"`.
pub fn status_line(resp: Option<&Message>) -> String {
    resp.map(|r| r.first_line.to_str_lossy().into_owned())
        .unwrap_or_else(|| "no response".into())
}

/// A status line without the `SIP/2.0 ` prefix.
pub fn status_text(line: &str) -> &str {
    line.strip_prefix("SIP/2.0 ").unwrap_or(line)
}

/// A SIP user agent on a UDP socket bound to 127.0.0.1.
pub struct SipUa {
    sock: UdpSocket,
    server: SocketAddr,
    lport: u16,
    /// The From tag of this agent's requests.
    pub tag: String,
    cseq: u32,
}

impl SipUa {
    /// A user agent talking to `host:port`.
    pub fn new(host: &str, port: u16) -> Result<SipUa> {
        let server = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {host}"))?;
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.set_read_timeout(Some(Duration::from_millis(300)))?;
        let lport = sock.local_addr()?.port();
        Ok(SipUa {
            sock,
            server,
            lport,
            tag: hex32(),
            cseq: 0,
        })
    }

    /// The local port.
    pub fn local_port(&self) -> u16 {
        self.lport
    }

    /// The server address.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Sends bytes to the server.
    pub fn send(&self, data: &[u8]) {
        let _ = self.sock.send_to(data, self.server);
    }

    /// The next message received within `timeout` (unparsable data is
    /// skipped).
    pub fn recv(&self, timeout: Duration) -> Option<Message> {
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 65535];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let _ = self
                .sock
                .set_read_timeout(Some(left.min(Duration::from_millis(300))));
            if let Ok((n, addr)) = self.sock.recv_from(&mut buf) {
                if let Ok(m) = sip::parse(&buf[..n], Some(addr)) {
                    return Some(m);
                }
            }
        }
    }

    /// Sends a request from `from_user` at the server's host.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        method: &str,
        ruri: &str,
        to: &str,
        callid: &str,
        extra: &[String],
        body: &[u8],
        ctype: Option<&str>,
        from_user: &str,
    ) {
        self.cseq += 1;
        let host = self.server.ip();
        let mut lines = vec![
            format!("{method} {ruri} SIP/2.0"),
            format!(
                "Via: SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK{:x};rport",
                self.lport,
                rand::thread_rng().gen::<u64>() >> 16
            ),
            "Max-Forwards: 70".into(),
            format!("From: <sip:{from_user}@{host}>;tag={}", self.tag),
            format!("To: {to}"),
            format!("Call-ID: {callid}"),
            format!("CSeq: {} {method}", self.cseq),
            format!(
                "Contact: <sip:{from_user}@127.0.0.1:{};transport=udp>",
                self.lport
            ),
        ];
        lines.extend(extra.iter().cloned());
        if let Some(c) = ctype {
            lines.push(format!("Content-Type: {c}"));
        }
        lines.push(format!("Content-Length: {}", body.len()));
        let mut data = (lines.join("\r\n") + "\r\n\r\n").into_bytes();
        data.extend_from_slice(body);
        self.send(&data);
    }

    /// Answers `req`.
    pub fn reply(
        &self,
        req: &Message,
        code: u16,
        reason: &str,
        body: &[u8],
        extra: &[String],
        contact_user: &str,
    ) {
        let mut out: Vec<u8> = format!("SIP/2.0 {code} {reason}").into_bytes();
        let mut line = |k: &str, v: &[u8]| {
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v);
        };
        for (k, v) in &req.headers {
            if ["Via", "From", "Call-ID", "CSeq"]
                .iter()
                .any(|h| k.eq_ignore_ascii_case(h))
            {
                line(k, v);
            } else if k.eq_ignore_ascii_case("To") {
                let mut to = v.clone();
                if !to.contains_str(";tag=") {
                    to.extend_from_slice(format!(";tag=uas{}", self.tag).as_bytes());
                }
                line(k, &to);
            }
        }
        line(
            "Contact",
            format!("<sip:{contact_user}@127.0.0.1:{}>", self.lport).as_bytes(),
        );
        for e in extra {
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(e.as_bytes());
        }
        out.extend_from_slice(format!("\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        let _ = self.sock.send_to(&out, req.source.unwrap_or(self.server));
    }

    /// The next final response to a `method` request (provisional ones and
    /// other messages are skipped); `None` on timeout.
    pub fn final_response(&self, method: &str, timeout: Duration) -> Option<Message> {
        let deadline = Instant::now() + timeout;
        while let Some(m) = self.recv(deadline.saturating_duration_since(Instant::now())) {
            let Some(status) = m.status() else { continue };
            let cseq = m.get_str("CSeq").unwrap_or_default();
            if !cseq
                .split_whitespace()
                .nth(1)
                .is_some_and(|x| x.eq_ignore_ascii_case(method))
            {
                continue;
            }
            if status < 200 {
                continue;
            }
            return Some(m);
        }
        None
    }

    /// A REGISTER of `user` (digest authenticated when challenged) with
    /// `User-Agent: <agent>` and `Expires: <expires>`; returns the final
    /// status line.
    pub fn register(&mut self, user: &str, password: &str, agent: &str, expires: u32) -> String {
        let uri = format!("sip:{}:{}", self.server.ip(), self.server.port());
        let callid = format!("{:x}@127.0.0.1", rand::thread_rng().gen::<u64>());
        let to = format!("<sip:{user}@{}>", self.server.ip());
        let extra = vec![
            format!("User-Agent: {agent}"),
            format!("Expires: {expires}"),
        ];
        self.request("REGISTER", &uri, &to, &callid, &extra, b"", None, user);
        let mut resp = self.final_response("REGISTER", Duration::from_secs(5));
        if resp
            .as_ref()
            .is_some_and(|r| r.status() == Some(401) || r.status() == Some(407))
        {
            if let Some(auth) =
                digest_authorization(resp.as_ref().unwrap(), user, password, "REGISTER", &uri)
            {
                let mut e = extra.clone();
                e.push(auth);
                self.request("REGISTER", &uri, &to, &callid, &e, b"", None, user);
                resp = self.final_response("REGISTER", Duration::from_secs(5));
            }
        }
        status_line(resp.as_ref())
    }

    /// An out-of-dialog MESSAGE to `sip:<exten>@<server>` with
    /// `User-Agent: <agent>` and, when given, `X-Digium-User-Agent`;
    /// returns the final status line.
    pub fn message(
        &mut self,
        exten: &str,
        digium_ua: Option<&str>,
        agent: &str,
        body: &str,
    ) -> String {
        let ruri = format!("sip:{exten}@{}:{}", self.server.ip(), self.server.port());
        let mut extra = vec![format!("User-Agent: {agent}")];
        if let Some(d) = digium_ua {
            extra.push(format!("X-Digium-User-Agent: {d}"));
        }
        let callid = format!("{:x}@127.0.0.1", rand::thread_rng().gen::<u64>());
        self.request(
            "MESSAGE",
            &ruri,
            &format!("<{ruri}>"),
            &callid,
            &extra,
            body.as_bytes(),
            Some("text/plain"),
            "dpma-test",
        );
        status_line(
            self.final_response("MESSAGE", Duration::from_secs(5))
                .as_ref(),
        )
    }

    /// Subscribes to `dialog` events of `exten` as `user` (digest
    /// authenticated when challenged) for `duration`, answering every
    /// NOTIFY; returns the transcript lines `SUBSCRIBE <status>` and
    /// `NOTIFY <body on one line>`.
    pub fn subscribe(
        &mut self,
        user: &str,
        password: &str,
        agent: &str,
        exten: &str,
        to: Option<&str>,
        duration: Duration,
    ) -> Vec<String> {
        let ruri = format!("sip:{exten}@{}:{}", self.server.ip(), self.server.port());
        let to = format!("<{}>", to.unwrap_or(&ruri));
        let callid = format!("{:x}@127.0.0.1", rand::thread_rng().gen::<u64>());
        let extra = vec![
            format!("User-Agent: {agent}"),
            "Event: dialog".into(),
            "Accept: application/dialog-info+xml".into(),
            format!("Expires: {}", duration.as_secs() + 30),
        ];
        self.request("SUBSCRIBE", &ruri, &to, &callid, &extra, b"", None, user);
        let mut out = Vec::new();
        let mut authed = false;
        let deadline = Instant::now() + duration;
        while let Some(m) = self.recv(deadline.saturating_duration_since(Instant::now())) {
            if let Some(status) = m.status() {
                if !m.get_str("CSeq").unwrap_or_default().contains("SUBSCRIBE") {
                    continue;
                }
                if (status == 401 || status == 407) && !authed {
                    authed = true;
                    if let Some(a) = digest_authorization(&m, user, password, "SUBSCRIBE", &ruri) {
                        let mut e = extra.clone();
                        e.push(a);
                        self.request("SUBSCRIBE", &ruri, &to, &callid, &e, b"", None, user);
                    }
                } else if status >= 200 {
                    out.push(format!(
                        "SUBSCRIBE {}",
                        status_text(&m.first_line.to_str_lossy())
                    ));
                }
            } else if m.method().as_deref() == Some("NOTIFY") {
                out.push(notify_line(&m));
                self.reply(&m, 200, "OK", b"", &[], "ua");
            }
        }
        out
    }
}

/// `NOTIFY <body>` with the body on one line.
pub fn notify_line(m: &Message) -> String {
    let body = m.body.to_str_lossy();
    let body = Regex::new(r">\s+<").unwrap().replace_all(body.trim(), "><");
    let body = Regex::new(r#" version="\d+""#)
        .unwrap()
        .replace_all(&body, " version=\"N\"");
    format!("NOTIFY {body}")
}

/// The transcript lines for a received INFO: `INFO received:`, its `X-`,
/// `Content-Type`, and `Content-Length` header lines exactly as they
/// arrived (PJSIP pads `Content-Length`), and the body.  A message that
/// was not parsed from bytes (no [`Message::raw`]) shows its parsed
/// headers instead.
pub fn info_lines(m: &Message) -> Vec<String> {
    let wanted = |line: &str| {
        let l = line.to_ascii_lowercase();
        l.starts_with("x-") || l.starts_with("content-type") || l.starts_with("content-length")
    };
    let mut out = vec!["INFO received:".to_string()];
    let body = match m.raw.find(b"\r\n\r\n") {
        Some(end) => {
            let head = m.raw[..end].to_str_lossy();
            out.extend(
                head.split("\r\n")
                    .skip(1)
                    .filter(|l| wanted(l))
                    .map(|l| format!("  {l}")),
            );
            m.raw[end + 4..].to_str_lossy().into_owned()
        }
        None => {
            for (k, v) in &m.headers {
                if wanted(k) {
                    out.push(format!("  {k}: {}", v.to_str_lossy()));
                }
            }
            m.body.to_str_lossy().into_owned()
        }
    };
    out.push(format!("  body: {body}"));
    out
}

/// How a [`Uas`] treats INVITEs (re-INVITEs are always accepted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Answer every INVITE (200 with SDP).
    All,
    /// Answer the INVITEs with these numbers (from 1); leave the others
    /// ringing (180, never answered).
    Numbers(Vec<usize>),
    /// Refuse every INVITE with 486 Busy Here.
    Reject,
}

/// What a [`Uas`] does.
#[derive(Clone, Debug)]
pub struct UasConfig {
    /// The PJSIP endpoint (user) to register as.
    pub user: String,
    /// Its password.
    pub password: String,
    /// The `User-Agent` of the REGISTER (a Digium one makes the module
    /// treat the endpoint as a Digium phone).
    pub user_agent: String,
    /// How long to run.
    pub duration: Duration,
    /// The registration's `Expires`.
    pub expires: u32,
    /// How to treat INVITEs.
    pub answer: Answer,
    /// Keys to send as DTMF INFOs (`application/dtmf-relay`) in an
    /// answered call: the first 0.5 s after the ACK, the others 0.5 s
    /// apart.
    pub dtmf: String,
    /// Unregister at the end (Expires 0).
    pub unregister: bool,
}

impl UasConfig {
    /// Registers `user` with `password` and a Digium user agent for
    /// `duration`, answering every call.
    pub fn new(user: &str, password: &str, duration: Duration) -> UasConfig {
        UasConfig {
            user: user.into(),
            password: password.into(),
            user_agent: crate::sim::DEFAULT_UA.into(),
            duration,
            expires: 120,
            answer: Answer::All,
            dtmf: String::new(),
            unregister: true,
        }
    }
}

/// What happened to a [`Uas`].
#[derive(Clone, Debug)]
pub enum UaEvent {
    /// The final status line of the REGISTER (`SIP/2.0 200 OK` when
    /// registered).
    Registered(String),
    /// An INVITE (its number, from 1) and what was done: `"answered"`,
    /// `"ringing"`, or `"rejected"`.
    Invite(usize, Message, &'static str),
    /// A DTMF key sent as INFO.
    Dtmf(char),
    /// An INFO received.
    Info(Message),
    /// A MESSAGE received.
    Message(Message),
    /// A NOTIFY received.
    Notify(Message),
    /// A BYE received.
    Bye(Message),
    /// The final status line of the unregistration.
    Unregistered(String),
}

impl UaEvent {
    /// Whether this is a successful registration.
    pub fn is_registered(&self) -> bool {
        matches!(self, UaEvent::Registered(s) if s.starts_with("SIP/2.0 200"))
    }
}

/// A registered test phone running in a background thread.
pub struct Uas {
    events: Receiver<UaEvent>,
    seen: Vec<UaEvent>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

struct Dialog {
    callid: BString,
    remote: BString,
    local: BString,
    target: String,
}

impl Uas {
    /// Starts the phone against `host:port`.
    pub fn spawn(host: &str, port: u16, config: UasConfig) -> Result<Uas> {
        let mut ua = SipUa::new(host, port)?;
        let (tx, rx) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let handle = std::thread::spawn(move || {
            let send = |e: UaEvent| {
                let _ = tx.send(e);
            };
            let c = config;
            let status = ua.register(&c.user, &c.password, &c.user_agent, c.expires);
            send(UaEvent::Registered(status));
            let deadline = Instant::now() + c.duration;
            let mut invites = 0;
            let mut dialog: Option<Dialog> = None;
            let mut pending: Vec<(Instant, char)> = Vec::new();
            let mut info_cseq = 100;
            while Instant::now() < deadline && !st.load(Ordering::SeqCst) {
                while let (Some(&(at, key)), Some(d)) = (pending.first(), dialog.as_ref()) {
                    if at > Instant::now() {
                        break;
                    }
                    pending.remove(0);
                    info_cseq += 1;
                    let body = format!("Signal={key}\r\nDuration=250\r\n");
                    let mut msg = format!(
                        "INFO {} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{};branch=z9hG4bK{:x};rport\r\nMax-Forwards: 70\r\nFrom: ",
                        d.target,
                        ua.local_port(),
                        rand::thread_rng().gen::<u64>() >> 16
                    )
                    .into_bytes();
                    msg.extend_from_slice(&d.local);
                    msg.extend_from_slice(b"\r\nTo: ");
                    msg.extend_from_slice(&d.remote);
                    msg.extend_from_slice(b"\r\nCall-ID: ");
                    msg.extend_from_slice(&d.callid);
                    msg.extend_from_slice(
                        format!(
                            "\r\nCSeq: {info_cseq} INFO\r\nContact: <sip:{}@127.0.0.1:{}>\r\nContent-Type: application/dtmf-relay\r\nContent-Length: {}\r\n\r\n{body}",
                            c.user,
                            ua.local_port(),
                            body.len()
                        )
                        .as_bytes(),
                    );
                    ua.send(&msg);
                    send(UaEvent::Dtmf(key));
                }
                let Some(m) = ua.recv(Duration::from_millis(300)) else {
                    continue;
                };
                let Some(method) = m.method() else { continue };
                match method.as_str() {
                    "INVITE" => {
                        let to = m.get("To").cloned().unwrap_or_default();
                        if to.contains_str(";tag=") {
                            ua.reply(&m, 200, "OK", b"", &[], &c.user); // re-INVITE
                            continue;
                        }
                        invites += 1;
                        let what = match &c.answer {
                            Answer::Reject => {
                                ua.reply(&m, 486, "Busy Here", b"", &[], &c.user);
                                "rejected"
                            }
                            Answer::Numbers(n) if !n.contains(&invites) => {
                                ua.reply(&m, 180, "Ringing", b"", &[], &c.user);
                                "ringing"
                            }
                            _ => {
                                ua.reply(
                                    &m,
                                    200,
                                    "OK",
                                    SDP.as_bytes(),
                                    &["Content-Type: application/sdp".into()],
                                    &c.user,
                                );
                                let mut local = to.clone();
                                local.extend_from_slice(format!(";tag=uas{}", ua.tag).as_bytes());
                                let contact = m.get_str("Contact").unwrap_or_default();
                                let target = contact
                                    .split_once('<')
                                    .and_then(|(_, r)| r.split_once('>'))
                                    .map(|(t, _)| t.to_string())
                                    .unwrap_or_else(|| {
                                        format!("sip:{}:{}", ua.server().ip(), ua.server().port())
                                    });
                                dialog = Some(Dialog {
                                    callid: m.get("Call-ID").cloned().unwrap_or_default(),
                                    remote: m.get("From").cloned().unwrap_or_default(),
                                    local,
                                    target,
                                });
                                "answered"
                            }
                        };
                        send(UaEvent::Invite(invites, m, what));
                    }
                    "ACK" => {
                        if !c.dtmf.is_empty() && dialog.is_some() && pending.is_empty() {
                            let now = Instant::now();
                            pending = c
                                .dtmf
                                .chars()
                                .enumerate()
                                .map(|(i, k)| {
                                    (now + Duration::from_millis(500 * (i as u64 + 1)), k)
                                })
                                .collect();
                        }
                    }
                    "BYE" => {
                        ua.reply(&m, 200, "OK", b"", &[], &c.user);
                        send(UaEvent::Bye(m));
                    }
                    "INFO" => {
                        ua.reply(&m, 200, "OK", b"", &[], &c.user);
                        send(UaEvent::Info(m));
                    }
                    "MESSAGE" => {
                        ua.reply(&m, 200, "OK", b"", &[], &c.user);
                        send(UaEvent::Message(m));
                    }
                    "NOTIFY" => {
                        ua.reply(&m, 200, "OK", b"", &[], &c.user);
                        send(UaEvent::Notify(m));
                    }
                    "OPTIONS" | "CANCEL" => ua.reply(&m, 200, "OK", b"", &[], &c.user),
                    _ => {}
                }
            }
            if c.unregister {
                let status = ua.register(&c.user, &c.password, &c.user_agent, 0);
                send(UaEvent::Unregistered(status));
            }
        });
        Ok(Uas {
            events: rx,
            seen: Vec::new(),
            stop,
            handle: Some(handle),
        })
    }

    /// The next event, waiting up to `timeout`.
    pub fn next(&mut self, timeout: Duration) -> Option<UaEvent> {
        match self.events.recv_timeout(timeout) {
            Ok(e) => {
                self.seen.push(e.clone());
                Some(e)
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => None,
        }
    }

    /// Waits up to `timeout` for an event `pred` accepts (earlier events
    /// are kept for [`Uas::join`]).
    pub fn wait_for(
        &mut self,
        timeout: Duration,
        pred: impl Fn(&UaEvent) -> bool,
    ) -> Option<UaEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            let e = self.next(deadline.saturating_duration_since(Instant::now()))?;
            if pred(&e) {
                return Some(e);
            }
        }
    }

    /// Stops the phone early (it still unregisters when configured to)
    /// and returns every event.
    pub fn stop(mut self) -> Vec<UaEvent> {
        self.stop.store(true, Ordering::SeqCst);
        self.finish()
    }

    /// Waits until the phone's time is up and returns every event.
    pub fn join(mut self) -> Vec<UaEvent> {
        self.finish()
    }

    fn finish(&mut self) -> Vec<UaEvent> {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        while let Ok(e) = self.events.try_recv() {
            self.seen.push(e);
        }
        std::mem::take(&mut self.seen)
    }
}

impl Drop for Uas {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_response() {
        let m = sip::parse(
            b"SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"asterisk\",nonce=\"abc\",opaque=\"o1\",algorithm=MD5,qop=\"auth\"\r\n\r\n",
            None,
        )
        .unwrap();
        let a =
            digest_authorization(&m, "1001", "secret", "REGISTER", "sip:127.0.0.1:5060").unwrap();
        assert!(a.starts_with(
            "Authorization: Digest username=\"1001\", realm=\"asterisk\", nonce=\"abc\""
        ));
        assert!(a.ends_with(", opaque=\"o1\""));
        let cnonce = Regex::new(r#"cnonce="([^"]+)""#)
            .unwrap()
            .captures(&a)
            .unwrap()[1]
            .to_string();
        let ha1 = md5_hex("1001:asterisk:secret");
        let ha2 = md5_hex("REGISTER:sip:127.0.0.1:5060");
        let want = md5_hex(&format!("{ha1}:abc:00000001:{cnonce}:auth:{ha2}"));
        assert!(a.contains(&format!("response=\"{want}\"")));
    }

    #[test]
    fn uas_against_a_fake_server() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = server.local_addr().unwrap().port();
        let mut cfg = UasConfig::new("1001", "pw", Duration::from_secs(10));
        cfg.dtmf = "#*".into();
        cfg.unregister = false;
        let mut uas = Uas::spawn("127.0.0.1", port, cfg).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut recv = || {
            let (n, a) = server.recv_from(&mut buf).unwrap();
            (sip::parse(&buf[..n], Some(a)).unwrap(), a)
        };
        let respond = |req: &Message, line: &str, extra: &str, to: SocketAddr| {
            let mut out = format!("SIP/2.0 {line}\r\n");
            for (k, v) in &req.headers {
                if ["Via", "From", "To", "Call-ID", "CSeq"].contains(&k.as_str()) {
                    out.push_str(&format!("{k}: {}\r\n", v.to_str_lossy()));
                }
            }
            out.push_str(extra);
            out.push_str("Content-Length: 0\r\n\r\n");
            server.send_to(out.as_bytes(), to).unwrap();
        };
        let (reg, addr) = recv();
        assert_eq!(reg.method().as_deref(), Some("REGISTER"));
        respond(
            &reg,
            "401 Unauthorized",
            "WWW-Authenticate: Digest realm=\"r\",nonce=\"n1\",qop=\"auth\"\r\n",
            addr,
        );
        let (reg, addr) = recv();
        let auth = reg.get_str("Authorization").unwrap();
        let cnonce = Regex::new(r#"cnonce="([^"]+)""#)
            .unwrap()
            .captures(&auth)
            .unwrap()[1]
            .to_string();
        let uri = format!("sip:127.0.0.1:{port}");
        let ha1 = md5_hex("1001:r:pw");
        let ha2 = md5_hex(&format!("REGISTER:{uri}"));
        assert!(auth.contains(&md5_hex(&format!("{ha1}:n1:00000001:{cnonce}:auth:{ha2}"))));
        respond(&reg, "200 OK", "", addr);
        assert!(uas.next(Duration::from_secs(5)).unwrap().is_registered());

        let invite = format!(
            "INVITE sip:1001@127.0.0.1:{} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKx\r\n\
             From: <sip:caller@127.0.0.1>;tag=c1\r\nTo: <sip:1001@127.0.0.1>\r\nCall-ID: call1\r\n\
             CSeq: 1 INVITE\r\nContact: <sip:caller@127.0.0.1:{port}>\r\nX-Event-Name: test\r\nContent-Length: 0\r\n\r\n",
            addr.port()
        );
        server.send_to(invite.as_bytes(), addr).unwrap();
        let (ok, _) = recv();
        assert_eq!(ok.status(), Some(200));
        assert!(ok.body.contains_str("m=audio"));
        server
            .send_to(
                format!(
                    "ACK sip:1001@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKy\r\n\
                     From: <sip:caller@127.0.0.1>;tag=c1\r\nTo: <sip:1001@127.0.0.1>;tag=t\r\nCall-ID: call1\r\n\
                     CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
                )
                .as_bytes(),
                addr,
            )
            .unwrap();
        for key in ["#", "*"] {
            let (info, a) = recv();
            assert_eq!(info.method().as_deref(), Some("INFO"));
            assert_eq!(info.get_str("Call-ID").as_deref(), Some("call1"));
            assert!(info
                .body
                .starts_with(format!("Signal={key}\r\n").as_bytes()));
            respond(&info, "200 OK", "", a);
        }
        let bye = format!(
            "BYE sip:1001@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKz\r\n\
             From: <sip:caller@127.0.0.1>;tag=c1\r\nTo: <sip:1001@127.0.0.1>;tag=t\r\nCall-ID: call1\r\n\
             CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        );
        server.send_to(bye.as_bytes(), addr).unwrap();
        let (ok, _) = recv();
        assert_eq!(ok.status(), Some(200));
        let events = uas.stop();
        let kinds: Vec<String> = events
            .iter()
            .map(|e| match e {
                UaEvent::Invite(n, m, what) => format!(
                    "invite {n} {what} {}",
                    m.get_str("X-Event-Name").unwrap_or_default()
                ),
                UaEvent::Dtmf(k) => format!("dtmf {k}"),
                UaEvent::Bye(_) => "bye".into(),
                UaEvent::Unregistered(s) => format!("unregistered {s}"),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "Registered(\"SIP/2.0 200 OK\")",
                "invite 1 answered test",
                "dtmf #",
                "dtmf *",
                "bye"
            ]
        );
    }
}
