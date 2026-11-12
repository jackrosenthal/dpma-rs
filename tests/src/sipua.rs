//! Test user agents for the PJSIP helpers, on `rsipstack`: a client that
//! registers, sends a MESSAGE, and subscribes, and a scripted phone
//! ([`Uas`]) that registers and answers calls.
//!
//! The `*_line` functions write transcript lines that are stable across
//! runs (no ports, tags, or branches), which the pjsip-helpers suite
//! compares with its expected transcript.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bstr::ByteSlice;
use regex::Regex;
use rsipstack::dialog::authenticate::{handle_client_authenticate, Credential};
use rsipstack::dialog::dialog::DialogState;
use rsipstack::dialog::dialog_layer::DialogLayer;
use rsipstack::dialog::registration::Registration;
use rsipstack::sip::prelude::HeadersExt;
use rsipstack::sip::{Header, Method, Response, SipMessage, StatusCode, Uri};
use rsipstack::transaction::endpoint::EndpointInnerRef;
use rsipstack::transaction::key::{TransactionKey, TransactionRole};
use rsipstack::transaction::make_tag;
use rsipstack::transaction::transaction::Transaction;
use rsipstack::transaction::TransactionReceiver;
use rsipstack::transport::udp::UdpConnection;
use rsipstack::transport::SipAddr;
use rsipstack::EndpointBuilder;
use tokio_util::sync::CancellationToken;

use crate::sip::{self, runtime, Message};

/// The SDP of an answered call.
pub const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

fn uri(s: &str) -> Uri {
    Uri::try_from(s).expect("a SIP URI")
}

/// The status line of a response, or `"no response"`.
fn status_line(resp: Option<&Response>) -> String {
    match resp {
        Some(r) => {
            let reason = r.wire_reason.clone().unwrap_or_else(|| {
                let full = r.status_code.to_string();
                full.split_once(' ')
                    .map_or(full.clone(), |x| x.1.to_string())
            });
            format!("SIP/2.0 {} {}", r.status_code.code(), reason)
        }
        None => "no response".into(),
    }
}

/// A status line without the `SIP/2.0 ` prefix.
pub fn status_text(line: &str) -> &str {
    line.strip_prefix("SIP/2.0 ").unwrap_or(line)
}

/// A SIP endpoint on a UDP socket bound to 127.0.0.1.
struct Stack {
    inner: EndpointInnerRef,
    incoming: TransactionReceiver,
    addr: SocketAddr,
    cancel: CancellationToken,
}

impl Stack {
    fn start() -> Result<Stack> {
        runtime().block_on(async {
            let cancel = CancellationToken::new();
            let endpoint = EndpointBuilder::new()
                .with_cancel_token(cancel.clone())
                .with_user_agent("dpma-tests")
                .build();
            let c = UdpConnection::create_connection(
                "127.0.0.1:0".parse()?,
                None,
                Some(cancel.child_token()),
            )
            .await
            .map_err(|e| anyhow!("{e}"))?;
            let addr = SocketAddr::try_from(c.get_addr().addr.to_owned())?;
            endpoint.inner.transport_layer.add_transport(c.into());
            let incoming = endpoint
                .incoming_transactions()
                .map_err(|e| anyhow!("{e}"))?;
            let serving = endpoint.inner.clone();
            runtime().spawn(async move {
                let _ = serving.serve().await;
            });
            Ok(Stack {
                inner: endpoint.inner.clone(),
                incoming,
                addr,
                cancel,
            })
        })
    }

    /// A client transaction for a request to `server`.
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        server: SocketAddr,
        method: Method,
        ruri: &str,
        from: &str,
        to: &str,
        seq: u32,
        headers: Vec<Header>,
        body: &[u8],
    ) -> Result<Transaction> {
        let via = self.inner.get_via(None, None).map_err(|e| anyhow!("{e}"))?;
        let mut request = self.inner.make_request(
            method,
            uri(ruri),
            via,
            rsipstack::sip::typed::From {
                display_name: None,
                uri: uri(from),
                params: vec![],
            }
            .with_tag(make_tag()),
            rsipstack::sip::typed::To {
                display_name: None,
                uri: uri(to),
                params: vec![],
            },
            seq,
            None,
        );
        request.headers.push(Header::Contact(
            rsipstack::sip::typed::Contact {
                display_name: None,
                uri: uri(&format!("sip:{}", self.addr)),
                params: vec![],
            }
            .into(),
        ));
        for h in headers {
            request
                .headers
                .retain(|e| e.name() != h.name() || e.name() == "Contact");
            request.headers.push(h);
        }
        request.body = body.to_vec();
        let key = TransactionKey::from_request(&request, TransactionRole::Client)
            .map_err(|e| anyhow!("{e}"))?;
        let mut tx = Transaction::new_client(key, request, self.inner.clone(), None);
        tx.destination = Some(SipAddr {
            r#type: Some(rsipstack::sip::Transport::Udp),
            addr: server.into(),
        });
        Ok(tx)
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// The final response to a request that `tx` sent.
async fn final_response(tx: &mut Transaction) -> Option<Response> {
    while let Some(m) = tx.receive().await {
        if let SipMessage::Response(r) = m {
            if r.status_code.code() >= 200 {
                return Some(r);
            }
        }
    }
    None
}

/// A SIP user agent on a UDP socket bound to 127.0.0.1.
pub struct SipUa {
    stack: Stack,
    server: SocketAddr,
}

impl SipUa {
    /// A user agent talking to `host:port`.
    pub fn new(host: &str, port: u16) -> Result<SipUa> {
        let server = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {host}"))?;
        Ok(SipUa {
            stack: Stack::start()?,
            server,
        })
    }

    /// The local port.
    pub fn local_port(&self) -> u16 {
        self.stack.addr.port()
    }

    /// A REGISTER of `user` (digest authenticated when challenged) with
    /// `User-Agent: <agent>` and `Expires: <expires>`; returns the final
    /// status line.
    pub fn register(&mut self, user: &str, password: &str, agent: &str, expires: u32) -> String {
        runtime().block_on(register(
            &self.stack.inner,
            self.stack.addr,
            self.server,
            user,
            password,
            agent,
            expires,
        ))
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
        let mut headers = vec![
            Header::UserAgent(agent.to_string().into()),
            Header::ContentType("text/plain".to_string().into()),
        ];
        if let Some(d) = digium_ua {
            headers.push(Header::Other("X-Digium-User-Agent".into(), d.to_string()));
        }
        runtime().block_on(async {
            let Ok(mut tx) = self.stack.request(
                self.server,
                Method::Message,
                &ruri,
                &format!("sip:dpma-test@{}", self.server.ip()),
                &ruri,
                1,
                headers,
                body.as_bytes(),
            ) else {
                return status_line(None);
            };
            if tx.send().await.is_err() {
                return status_line(None);
            }
            match tokio::time::timeout(Duration::from_secs(5), final_response(&mut tx)).await {
                Ok(r) => status_line(r.as_ref()),
                Err(_) => status_line(None),
            }
        })
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
        let to = to.unwrap_or(&ruri).to_string();
        let headers = vec![
            Header::UserAgent(agent.to_string().into()),
            Header::Other("Event".into(), "dialog".into()),
            Header::Other("Accept".into(), "application/dialog-info+xml".into()),
            Header::Other("Expires".into(), (duration.as_secs() + 30).to_string()),
        ];
        let credential = Credential {
            username: user.into(),
            password: password.into(),
            realm: None,
            auth_username: None,
        };
        let Self { stack, server } = self;
        runtime().block_on(async {
            let mut out = Vec::new();
            let Ok(mut tx) = stack.request(
                *server,
                Method::Subscribe,
                &ruri,
                &format!("sip:{user}@{}", server.ip()),
                &to,
                1,
                headers,
                b"",
            ) else {
                return out;
            };
            if tx.send().await.is_err() {
                return out;
            }
            let mut authed = false;
            let mut tx_done = false;
            let deadline = tokio::time::Instant::now() + duration;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    m = tx.receive(), if !tx_done => {
                        match m {
                            Some(SipMessage::Response(r)) if r.status_code.code() >= 200 => {
                                let code = r.status_code.code();
                                if (code == 401 || code == 407) && !authed {
                                    authed = true;
                                    match handle_client_authenticate(2, &tx, r, &credential).await {
                                        Ok(mut next) => {
                                            if next.send().await.is_err() {
                                                break;
                                            }
                                            tx = next;
                                            tx_done = false;
                                        }
                                        Err(_) => break,
                                    }
                                } else {
                                    out.push(format!(
                                        "SUBSCRIBE {}",
                                        status_text(&status_line(Some(&r)))
                                    ));
                                }
                            }
                            Some(_) => {}
                            None => tx_done = true,
                        }
                    }
                    n = stack.incoming.recv() => {
                        let Some(mut n) = n else { break };
                        if n.original.method == Method::Notify {
                            out.push(notify_line(&sip::from_request(&n.original)));
                        }
                        let _ = n.reply(StatusCode::OK).await;
                    }
                }
            }
            out
        })
    }
}

/// A REGISTER of `user` through `inner`; the final status line.
async fn register(
    inner: &EndpointInnerRef,
    local: SocketAddr,
    server: SocketAddr,
    user: &str,
    password: &str,
    agent: &str,
    expires: u32,
) -> String {
    let credential = Credential {
        username: user.into(),
        password: password.into(),
        realm: None,
        auth_username: None,
    };
    let mut registration = Registration::new(inner.clone(), Some(credential));
    registration.extra_headers = vec![Header::UserAgent(agent.to_string().into())];
    // Phones write the transport in lower case; the typed parameter would
    // write it in upper case.
    let mut contact = uri(&format!("sip:{user}@{local}"));
    contact.params.push(rsipstack::sip::Param::Other(
        rsipstack::sip::param::OtherParam::new("transport"),
        Some(rsipstack::sip::param::OtherParamValue::new("udp")),
    ));
    registration.contact = Some(rsipstack::sip::typed::Contact {
        display_name: None,
        uri: contact,
        params: vec![],
    });
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        registration.register(uri(&format!("sip:{server}")), Some(expires)),
    )
    .await;
    match result {
        Ok(Ok(r)) => status_line(Some(&r)),
        _ => status_line(None),
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
/// `Content-Type`, and `Content-Length` header lines, and the body.
pub fn info_lines(m: &Message) -> Vec<String> {
    let mut out = vec!["INFO received:".to_string()];
    for (k, v) in &m.headers {
        let l = k.to_ascii_lowercase();
        if l.starts_with("x-") || l.starts_with("content-type") || l.starts_with("content-length") {
            out.push(format!("  {k}: {}", v.to_str_lossy()));
        }
    }
    out.push(format!("  body: {}", m.body.to_str_lossy()));
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

impl Uas {
    /// Starts the phone against `host:port`.
    pub fn spawn(host: &str, port: u16, config: UasConfig) -> Result<Uas> {
        let server = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {host}"))?;
        let stack = Stack::start()?;
        let (tx, rx) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let handle = std::thread::spawn(move || {
            runtime().block_on(run(stack, server, config, tx, st));
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

/// The phone: registers, then handles calls and in-dialog requests until
/// its time is up or it is stopped, then unregisters.
async fn run(
    mut stack: Stack,
    server: SocketAddr,
    c: UasConfig,
    events: std::sync::mpsc::Sender<UaEvent>,
    stop: Arc<AtomicBool>,
) {
    let send = |e: UaEvent| {
        let _ = events.send(e);
    };
    let status = register(
        &stack.inner,
        stack.addr,
        server,
        &c.user,
        &c.password,
        &c.user_agent,
        c.expires,
    )
    .await;
    send(UaEvent::Registered(status));

    let layer = Arc::new(DialogLayer::new(stack.inner.clone()));
    let (state_tx, mut state_rx) = layer.new_dialog_state_channel();
    let contact = uri(&format!("sip:{}@{}", c.user, stack.addr));
    let deadline = tokio::time::Instant::now() + c.duration;
    let mut invites = 0;
    let mut answered: Option<rsipstack::dialog::invite_dialog::InviteDialog> = None;
    let mut pending: Vec<(tokio::time::Instant, char)> = Vec::new();
    let mut dtmf_started = false;
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    while tokio::time::Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        tokio::select! {
            _ = tick.tick() => {
                while let (Some(&(at, key)), Some(d)) = (pending.first(), answered.as_ref()) {
                    if at > tokio::time::Instant::now() {
                        break;
                    }
                    pending.remove(0);
                    let body = format!("Signal={key}\r\nDuration=250\r\n");
                    let headers = vec![Header::ContentType("application/dtmf-relay".to_string().into())];
                    let _ = d.info(Some(headers), Some(body.into_bytes())).await;
                    send(UaEvent::Dtmf(key));
                }
            }
            n = stack.incoming.recv() => {
                let Some(mut tx) = n else { break };
                match tx.original.method {
                    Method::Invite if tx.original.to_header().ok().and_then(|t| t.tag().ok().flatten()).is_none() => {
                        let Ok(dialog) = layer.get_or_create_server_invite(
                            &tx,
                            state_tx.clone(),
                            None,
                            Some(contact.clone()),
                        ) else {
                            continue;
                        };
                        invites += 1;
                        let msg = sip::from_request(&tx.original);
                        let mut handler = dialog.clone();
                        runtime().spawn(async move {
                            let _ = handler.handle(&mut tx).await;
                        });
                        let what = match &c.answer {
                            Answer::Reject => {
                                let _ = dialog.reject(Some(StatusCode::BusyHere), None);
                                "rejected"
                            }
                            Answer::Numbers(n) if !n.contains(&invites) => {
                                let _ = dialog.ringing(None, None);
                                "ringing"
                            }
                            _ => {
                                let headers =
                                    vec![Header::ContentType("application/sdp".to_string().into())];
                                let _ = dialog.accept(Some(headers), Some(SDP.as_bytes().to_vec()));
                                answered = Some(dialog);
                                "answered"
                            }
                        };
                        send(UaEvent::Invite(invites, msg, what));
                    }
                    Method::Message | Method::Notify | Method::Info | Method::Bye | Method::Options | Method::Cancel | Method::Invite => {
                        let msg = sip::from_request(&tx.original);
                        let in_dialog = tx.original.to_header().ok().and_then(|t| t.tag().ok().flatten()).is_some();
                        match (&tx.original.method, layer.match_dialog(&tx)) {
                            (Method::Bye, Some(mut d)) => {
                                send(UaEvent::Bye(msg));
                                runtime().spawn(async move {
                                    let _ = d.handle(&mut tx).await;
                                });
                            }
                            (_, Some(mut d)) if in_dialog => {
                                runtime().spawn(async move {
                                    let _ = d.handle(&mut tx).await;
                                });
                            }
                            (method, _) => {
                                let method = method.clone();
                                let _ = tx.reply(StatusCode::OK).await;
                                match method {
                                    Method::Message => send(UaEvent::Message(msg)),
                                    Method::Notify => send(UaEvent::Notify(msg)),
                                    Method::Info => send(UaEvent::Info(msg)),
                                    Method::Bye => send(UaEvent::Bye(msg)),
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            s = state_rx.recv() => {
                match s {
                    Some(DialogState::Info(_, req, handle)) => {
                        let _ = handle.reply(StatusCode::OK).await;
                        send(UaEvent::Info(sip::from_request(&req)));
                    }
                    Some(DialogState::Message(_, req, handle)) => {
                        let _ = handle.reply(StatusCode::OK).await;
                        send(UaEvent::Message(sip::from_request(&req)));
                    }
                    Some(DialogState::Notify(_, req, handle)) => {
                        let _ = handle.reply(StatusCode::OK).await;
                        send(UaEvent::Notify(sip::from_request(&req)));
                    }
                    Some(DialogState::Options(_, _, handle)) => {
                        let _ = handle.reply(StatusCode::OK).await;
                    }
                    Some(DialogState::Updated(_, _, handle)) => {
                        let _ = handle.reply(StatusCode::OK).await;
                    }
                    Some(DialogState::Confirmed(..)) => {
                        if !c.dtmf.is_empty() && answered.is_some() && !dtmf_started {
                            dtmf_started = true;
                            let now = tokio::time::Instant::now();
                            pending = c
                                .dtmf
                                .chars()
                                .enumerate()
                                .map(|(i, k)| (now + Duration::from_millis(500 * (i as u64 + 1)), k))
                                .collect();
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        }
    }
    if c.unregister {
        let status = register(
            &stack.inner,
            stack.addr,
            server,
            &c.user,
            &c.password,
            &c.user_agent,
            0,
        )
        .await;
        send(UaEvent::Unregistered(status));
    }
}
