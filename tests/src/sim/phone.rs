//! The simulated phone: protocol state plus a SIP endpoint.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bstr::{BString, ByteSlice};
use rand::Rng;
use rsa::RsaPrivateKey;
use serde_json::json;

use dpma_proto::headers as h;
use dpma_proto::message::Transactions;
use dpma_proto::{cert, client, crypto, documents};

use super::certs;
use super::chunking::{self, ChunkStyle};
use super::reply::{proto_message, Exchange, Reply, ReplySlot};
use super::transport::SipEndpoint;
use super::{Logger, Output, DEFAULT_MAC, DEFAULT_TIMEOUT, DEFAULT_UA};
use crate::sip::{Message, Transport};

/// The certificate form of a handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Form {
    /// The phone's own certificate, as the legacy phones sent.
    Legacy,
    /// The legacy certificate, the CA certificate, and the phone's own.
    #[default]
    Chain,
}

impl FromStr for Form {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "legacy" => Ok(Form::Legacy),
            "chain" => Ok(Form::Chain),
            _ => bail!("unknown form {s:?}"),
        }
    }
}

/// Simulator settings; the command-line options of `dpma-sim` map onto
/// these.
#[derive(Clone)]
pub struct Options {
    /// Asterisk's address.
    pub server: String,
    /// Asterisk's SIP port (default: the test instance's,
    /// [`crate::harness::SIP_PORT`]).
    pub sip_port: u16,
    /// The simulator's address (`127.0.0.2` selects the loopback test
    /// path of the test configuration).
    pub local_host: String,
    /// The simulator's port (0: any).
    pub local_port: u16,
    /// UDP or TCP.
    pub transport: Transport,
    /// `X-Digium-AppServer-MACAddress`.
    pub mac: String,
    /// Sent as `User-Agent` and `X-Digium-User-Agent`; an empty one sends
    /// neither.
    pub user_agent: BString,
    /// Whether to send `X-Digium-User-Agent` (by which the module's
    /// endpoint identifier finds phones).
    pub digium_ua_header: bool,
    /// The Contact URI (default `sip:<mac>@<host>:<port>`).
    pub contact: Option<String>,
    /// Sent as `X-Origination-Network` when set.
    pub origination_network: Option<BString>,
    /// The handshake certificate form.
    pub form: Form,
    /// Whether a handshake fails when the AppServer certificate does not
    /// verify against the test AppServer CA.
    pub appserver_check: bool,
    /// Maximum body bytes per MESSAGE (default 600 over UDP, 900 over
    /// TCP).
    pub chunk_size: Option<usize>,
    /// How encrypted bodies are chunked.
    pub chunk_style: ChunkStyle,
    /// Pause between chunks.
    pub chunk_delay: Duration,
    /// Reply timeout (and SIP transaction timeout).
    pub timeout: Duration,
    /// Send requests unencrypted even with a session.
    pub plain: bool,
    /// Diagnostics: -1 quiet, 0 normal, 1 SIP summary, 2 full SIP.
    pub verbose: i32,
    /// Where diagnostics and descriptions go.
    pub output: Output,
    /// Whether [`Phone::ensure_session`] handshakes when there is no
    /// session.
    pub auto_handshake: bool,
    /// Load the session from this file at start and save it at close.
    pub state: Option<PathBuf>,
}

impl Default for Options {
    /// Settings for the test instance.
    fn default() -> Self {
        Options {
            server: "127.0.0.1".into(),
            sip_port: crate::harness::SIP_PORT,
            local_host: "127.0.0.1".into(),
            local_port: 0,
            transport: Transport::Udp,
            mac: DEFAULT_MAC.into(),
            user_agent: DEFAULT_UA.into(),
            digium_ua_header: true,
            contact: None,
            origination_network: None,
            form: Form::Chain,
            appserver_check: true,
            chunk_size: None,
            chunk_style: ChunkStyle::Split,
            chunk_delay: Duration::from_millis(5),
            timeout: DEFAULT_TIMEOUT,
            plain: false,
            verbose: 0,
            output: Output::Stdout,
            auto_handshake: true,
            state: None,
        }
    }
}

impl Options {
    /// Sets the MAC address (colons removed, lowercase).
    pub fn mac(mut self, mac: &str) -> Self {
        self.mac = mac.replace(':', "").to_lowercase();
        self
    }

    /// Sets the transport.
    pub fn transport(mut self, t: Transport) -> Self {
        self.transport = t;
        self
    }

    /// Sets where diagnostics go.
    pub fn output(mut self, o: Output) -> Self {
        self.output = o;
        self
    }

    /// No diagnostics at all.
    pub fn quiet(mut self) -> Self {
        self.output = Output::Quiet;
        self.verbose = -1;
        self
    }
}

/// Which session a request carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SessionChoice {
    /// The phone's session when the request type needs one.
    #[default]
    Auto,
    /// No session header.
    Omit,
    /// This session id.
    Id(String),
}

struct State {
    session: client::Session,
    key: Option<RsaPrivateKey>,
    next_id: u32,
}

/// The simulator's clock for dropping incomplete messages.
static START: OnceLock<Instant> = OnceLock::new();

struct Shared {
    log: Logger,
    state: Mutex<State>,
    partial: Mutex<Transactions<(), Message>>,
    waiting: Mutex<HashMap<String, Arc<ReplySlot>>>,
    events: Mutex<VecDeque<Reply>>,
    events_cv: Condvar,
}

impl Shared {
    fn add_part(&self, msg: Message) {
        let complete = {
            let mut p = self.partial.lock().unwrap();
            let clock = START.get_or_init(Instant::now).elapsed().as_secs() as i64;
            let dropped = p.prune(clock, 40).len();
            if dropped > 0 {
                self.log
                    .log(0, &format!("--- discarded {dropped} incomplete message(s)"));
            }
            p.add(proto_message(&msg), msg, clock, ())
        };
        if let Some(((), parts)) = complete {
            self.complete(Reply::new(parts.into_metas()));
        }
    }

    fn complete(&self, mut reply: Reply) {
        let pw = self
            .state
            .lock()
            .unwrap()
            .session
            .common_password()
            .map(<[u8]>::to_vec);
        reply.decode(pw.as_deref());
        let slot = reply.id.as_ref().filter(|i| !i.is_empty()).and_then(|id| {
            self.waiting
                .lock()
                .unwrap()
                .remove(&id.to_str_lossy().into_owned())
        });
        match slot {
            Some(s) => s.deliver(reply),
            None => {
                self.log.log(
                    1,
                    &format!(
                        "--- unsolicited {} queued",
                        reply.type_name().map(|t| t.to_string()).unwrap_or_default()
                    ),
                );
                self.events.lock().unwrap().push_back(reply);
                self.events_cv.notify_all();
            }
        }
    }
}

/// The simulated phone.
///
/// Requests are built with [`Phone::request`] (or a typed shortcut such
/// as [`Phone::ping`]) and sent with [`RequestBuilder::send`], which
/// returns the [`Exchange`].  Replies are matched to requests by
/// transaction id; everything else (events) is queued for
/// [`Phone::next_event`].
pub struct Phone {
    opts: Options,
    shared: Arc<Shared>,
    sip: Option<SipEndpoint>,
}

impl Phone {
    /// A phone that is not connected: for feeding messages with
    /// [`Phone::deliver`] (self-tests of reassembly).
    pub fn offline(opts: Options) -> Phone {
        let log = Logger::new(opts.verbose, &opts.output);
        let state = State {
            session: client::Session::new(opts.mac.as_bytes()),
            key: None,
            next_id: rand::thread_rng().gen_range(1..=50000),
        };
        Phone {
            shared: Arc::new(Shared {
                log,
                state: Mutex::new(state),
                partial: Mutex::new(Transactions::new(dpma_proto::message::Sender::Server)),
                waiting: Mutex::default(),
                events: Mutex::default(),
                events_cv: Condvar::new(),
            }),
            opts,
            sip: None,
        }
    }

    /// Binds the phone's SIP socket (over TCP: connects) and loads the
    /// state file, if any.
    pub fn start(opts: Options) -> Result<Phone> {
        let mut phone = Phone::offline(opts);
        let o = &phone.opts;
        let server = (o.server.as_str(), o.sip_port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {}", o.server))?;
        let local: SocketAddr = (o.local_host.as_str(), o.local_port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {}", o.local_host))?;
        let shared = phone.shared.clone();
        let sip = SipEndpoint::start(
            server,
            local,
            o.transport,
            o.timeout,
            shared.log.clone(),
            Box::new(move |m| shared.add_part(m)),
        )?;
        phone.sip = Some(sip);
        if let Some(path) = phone.opts.state.clone() {
            phone.load_state(&path)?;
        }
        let a = phone.local_addr();
        phone.shared.log.log(
            1,
            &format!(
                "--- phone {} at {}:{}/{}, server {}:{}",
                phone.opts.mac,
                a.ip(),
                a.port(),
                phone.opts.transport,
                phone.opts.server,
                phone.opts.sip_port
            ),
        );
        Ok(phone)
    }

    /// Saves the state file (if any) and closes the SIP endpoint.
    pub fn close(&mut self) {
        if let Some(path) = self.opts.state.clone() {
            if self.sip.is_some() {
                if let Err(e) = self.save_state(&path) {
                    self.shared
                        .log
                        .log(0, &format!("--- cannot save the state: {e}"));
                }
            }
        }
        if let Some(mut sip) = self.sip.take() {
            sip.close();
        }
    }

    /// The settings.
    pub fn opts(&self) -> &Options {
        &self.opts
    }

    /// The phone's logger (its diagnostics output).
    pub fn logger(&self) -> &Logger {
        &self.shared.log
    }

    /// The MAC address.
    pub fn mac(&self) -> &str {
        &self.opts.mac
    }

    /// The transport.
    pub fn transport(&self) -> Transport {
        self.opts.transport
    }

    /// The local address of the SIP socket (`0.0.0.0:0` when offline).
    pub fn local_addr(&self) -> SocketAddr {
        self.sip
            .as_ref()
            .map(SipEndpoint::local_addr)
            .unwrap_or_else(|| ([0, 0, 0, 0], 0).into())
    }

    /// The Contact URI the session is bound to.
    pub fn contact_uri(&self) -> String {
        if let Some(c) = &self.opts.contact {
            return c.clone();
        }
        let a = self.local_addr();
        let t = if self.opts.transport == Transport::Tcp {
            ";transport=tcp"
        } else {
            ""
        };
        format!("sip:{}@{}:{}{}", self.opts.mac, a.ip(), a.port(), t)
    }

    /// The URI requests are sent to: `sip:proxy@<server>:<port>`.
    pub fn server_uri(&self) -> String {
        let t = if self.opts.transport == Transport::Tcp {
            ";transport=tcp"
        } else {
            ""
        };
        format!("sip:proxy@{}:{}{}", self.opts.server, self.opts.sip_port, t)
    }

    /// The Response-URI the module derives for this phone's messages:
    /// `pjsip:<host>:<port>;transport=<udp|tcp>`.
    pub fn response_uri(&self) -> String {
        let a = self.local_addr();
        format!(
            "pjsip:{}:{};transport={}",
            a.ip(),
            a.port(),
            self.opts.transport
        )
    }

    /// The default chunk size: the option, else 900 over TCP and 600 over
    /// UDP.
    pub fn chunk_size(&self) -> usize {
        self.opts
            .chunk_size
            .unwrap_or(if self.opts.transport == Transport::Tcp {
                900
            } else {
                600
            })
    }

    /// The session id.
    pub fn session(&self) -> Option<String> {
        let st = self.shared.state.lock().unwrap();
        st.session
            .session_id()
            .map(|s| String::from_utf8_lossy(s).into_owned())
    }

    /// Replaces the session id.
    pub fn set_session(&self, s: Option<String>) {
        let mut st = self.shared.state.lock().unwrap();
        let password = st.session.common_password().unwrap_or_default().to_vec();
        st.session
            .resume(s.map(String::into_bytes).unwrap_or_default(), password);
    }

    /// The common password of the session.
    pub fn common_password(&self) -> Option<Vec<u8>> {
        let st = self.shared.state.lock().unwrap();
        st.session.common_password().map(<[u8]>::to_vec)
    }

    /// Replaces the common password.
    pub fn set_common_password(&self, pw: Option<Vec<u8>>) {
        let mut st = self.shared.state.lock().unwrap();
        let session_id = st.session.session_id().unwrap_or_default().to_vec();
        st.session.resume(session_id, pw.unwrap_or_default());
    }

    /// The configuration token of the last TokenResponse.
    pub fn token(&self) -> Option<BString> {
        let st = self.shared.state.lock().unwrap();
        st.session.config_token().map(BString::from)
    }

    /// Replaces the configuration token.
    pub fn set_token(&self, t: Option<BString>) {
        let mut st = self.shared.state.lock().unwrap();
        st.session
            .set_config_token(t.map(|t| t.to_vec()).unwrap_or_default());
    }

    /// `Handshake-Version` of the last HandshakeResponse.
    pub fn handshake_version(&self) -> Option<BString> {
        let st = self.shared.state.lock().unwrap();
        st.session.handshake_version().map(BString::from)
    }

    /// Drops the session, common password, and token (as a phone reboot
    /// would).
    pub fn forget(&self) {
        self.shared.state.lock().unwrap().session.forget();
    }

    /// A new transaction id (a counter from a random start, so that a
    /// restarted simulator does not collide with an incomplete transaction
    /// the server keeps).
    pub fn new_id(&self) -> String {
        let mut s = self.shared.state.lock().unwrap();
        s.next_id = s.next_id % 100000 + 1;
        s.next_id.to_string()
    }

    /// Feeds an incoming MESSAGE as if it had arrived from the server.
    pub fn deliver(&self, msg: Message) {
        self.shared.add_part(msg);
    }

    /// Writes the session to a JSON file.
    pub fn save_state(&self, path: &Path) -> Result<()> {
        let state = json!({
            "mac": self.opts.mac,
            "session": self.session(),
            "token": self.token().map(|t| t.to_str_lossy().into_owned()),
            "common_password": self.common_password().map(|p| crypto::base64_encode(&p)),
            "local_port": self.local_addr().port(),
            "contact": self.contact_uri(),
        });
        let text = serde_json::to_string_pretty(&state)? + "\n";
        std::fs::write(path, text).with_context(|| path.display().to_string())
    }

    /// Loads the session from a file written by [`Phone::save_state`] (a
    /// missing file is no error).
    pub fn load_state(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if let Some(mac) = v["mac"].as_str().filter(|m| !m.is_empty()) {
            if mac != self.opts.mac {
                self.shared.log.log(
                    0,
                    &format!(
                        "--- state file is for MAC {mac}, not {}; ignored",
                        self.opts.mac
                    ),
                );
                return Ok(());
            }
        }
        self.set_session(v["session"].as_str().map(str::to_string));
        self.set_token(v["token"].as_str().map(BString::from));
        self.set_common_password(
            v["common_password"]
                .as_str()
                .map(|cp| crypto::base64_decode(cp.as_bytes())),
        );
        if let Some(c) = v["contact"].as_str() {
            if c != self.contact_uri() {
                self.shared.log.log(
                    0,
                    &format!(
                        "--- warning: the saved contact {c} differs from {}; the server will not validate the \
                         session (use --local-port {})",
                        self.contact_uri(),
                        v["local_port"]
                    ),
                );
            }
        }
        Ok(())
    }

    /// The local port saved in a state file, if any.
    pub fn state_local_port(path: &Path) -> Option<u16> {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
        v["local_port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|&p| p != 0)
    }

    // Requests --------------------------------------------------------

    /// A request of any type (the general form; see [`RequestBuilder`]).
    pub fn request(&self, request_type: &str) -> RequestBuilder<'_> {
        RequestBuilder::new(self, request_type, Kind::Plain)
    }

    /// A `Handshake` with the phone's identity (default form: the
    /// options); [`RequestBuilder::send`] recovers the common password
    /// with its key and checks the AppServer certificate.
    pub fn handshake(&self) -> RequestBuilder<'_> {
        let mut b = RequestBuilder::new(self, "Handshake", Kind::Handshake);
        b.o.encrypt = Some(false);
        b.o.session = SessionChoice::Omit;
        b
    }

    /// A `PingRequest`.
    pub fn ping(&self) -> RequestBuilder<'_> {
        self.request("PingRequest")
    }

    /// An `Echo` (never encrypted, no session).
    pub fn echo(&self, body: impl AsRef<[u8]>) -> RequestBuilder<'_> {
        self.request("Echo").body(body)
    }

    /// A `ConfigRequest` with the configuration token (default: the last
    /// token).
    pub fn config(&self) -> RequestBuilder<'_> {
        self.request("ConfigRequest")
    }

    /// A `TokenRequest`; [`RequestBuilder::send`] keeps the returned
    /// `Config-Token` (see [`Phone::token`]).
    pub fn get_token(&self) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "TokenRequest", Kind::Token)
    }

    /// A `UserlistRequest`.
    pub fn userlist(&self) -> RequestBuilder<'_> {
        self.request("UserlistRequest")
    }

    /// A `FileRequest` for `file://<name>` (`default`, `null`, or a
    /// file).
    pub fn file(&self, name: impl AsRef<[u8]>) -> RequestBuilder<'_> {
        self.request("FileRequest")
            .body(documents::file_request(name))
    }

    /// A `VerifyRequest` with the configuration token (default: the last
    /// token).
    pub fn verify(&self) -> RequestBuilder<'_> {
        self.request("VerifyRequest")
    }

    /// An `AsteriskRequest` with the request document `doc`; add the
    /// credentials with [`RequestBuilder::auth`].
    pub fn asterisk(&self, doc: impl AsRef<[u8]>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "AsteriskRequest", Kind::Asterisk).body(doc)
    }

    /// An `HTTPRequest` with the request document `doc`; add the
    /// credentials with [`RequestBuilder::auth`].
    pub fn http(&self, doc: impl AsRef<[u8]>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "HTTPRequest", Kind::Asterisk).body(doc)
    }

    /// Registers an exchange for transaction `txid` without sending
    /// anything, so that a reply sent to hand-made chunks (see
    /// [`Phone::send_message`]) is caught; wait with
    /// [`Phone::wait_reply`].
    pub fn expect_reply(&self, request_type: &str, txid: &str) -> Exchange {
        let mut ex = Exchange::new(request_type, txid);
        let slot = Arc::new(ReplySlot::default());
        self.shared
            .waiting
            .lock()
            .unwrap()
            .insert(txid.to_string(), slot.clone());
        ex.slot = Some(slot);
        ex
    }

    /// Sends one MESSAGE to the server as this phone (Contact, User-Agent,
    /// and Content-Type added before `headers`); returns the SIP response.
    pub fn send_message(
        &self,
        headers: &[(String, BString)],
        body: &[u8],
    ) -> Result<Option<Message>> {
        let sip = self
            .sip
            .as_ref()
            .ok_or_else(|| anyhow!("the phone is not started"))?;
        let mut hdrs = self.common_headers(None);
        hdrs.extend(headers.iter().cloned());
        let from = self.sip_from_uri();
        Ok(sip.request(
            "MESSAGE",
            &self.server_uri(),
            &hdrs,
            body,
            Some(&from),
            None,
            self.opts.timeout,
        ))
    }

    fn sip_from_uri(&self) -> String {
        let mac = if self.opts.mac.is_empty() {
            "phone"
        } else {
            self.opts.mac.as_str()
        };
        format!("sip:{}@{}", mac, self.local_addr().ip())
    }

    fn common_headers(&self, contact: Option<&str>) -> Vec<(String, BString)> {
        let contact = contact
            .map(str::to_string)
            .unwrap_or_else(|| self.contact_uri());
        let mut h: Vec<(String, BString)> = vec![("Contact".into(), format!("<{contact}>").into())];
        if !self.opts.user_agent.is_empty() {
            h.push(("User-Agent".into(), self.opts.user_agent.clone()));
        }
        h.push(("Content-Type".into(), "text/plain".into()));
        h
    }

    fn send_request(&self, rtype: &str, body: &[u8], o: &ReqOpts) -> Result<Exchange> {
        let sip = self
            .sip
            .as_ref()
            .ok_or_else(|| anyhow!("the phone is not started"))?;
        // The session's defaults, and what this request overrides.
        let (mut request, common_password, encrypts) = {
            let st = self.shared.state.lock().unwrap();
            (
                st.session.request(rtype, body.to_vec()),
                st.session.common_password().map(<[u8]>::to_vec),
                st.session.encrypts(rtype),
            )
        };
        match &o.session {
            SessionChoice::Auto => {}
            SessionChoice::Omit => request.session_id.clear(),
            SessionChoice::Id(s) => request.session_id = s.clone().into_bytes(),
        }
        let encrypt = o.encrypt.unwrap_or(encrypts && !self.opts.plain);
        if encrypt && common_password.is_none() {
            bail!("cannot encrypt without a common password (no handshake)");
        }
        let txid = o
            .txid
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| self.new_id());
        let mut ex = Exchange::new(rtype, &txid);
        ex.encrypted = encrypt;
        let pw = if encrypt {
            common_password.as_deref()
        } else {
            None
        };

        let bytes = |v: &Option<BString>| v.as_ref().map(|v| v.to_vec());
        request.id = txid.clone().into_bytes();
        if let Some(mac) = o.mac.as_deref().filter(|m| !m.is_empty()) {
            request.mac = mac.as_bytes().to_vec();
        }
        request.origination_network = bytes(&self.opts.origination_network).unwrap_or_default();
        if self.opts.digium_ua_header {
            request.user_agent = self.opts.user_agent.to_vec();
        }
        request.username = bytes(&o.username).unwrap_or_default();
        request.password = bytes(&o.password).unwrap_or_default();
        request.config_password = bytes(&o.config_password).unwrap_or_default();
        if let Some(token) = bytes(&o.config_token) {
            request.config_token = token;
        }
        request.headers = o
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.to_vec()))
            .collect();
        let chunks = chunking::encode(
            &request,
            pw,
            o.chunk_size.unwrap_or_else(|| self.chunk_size()),
            o.chunk_style.unwrap_or(self.opts.chunk_style),
            o.pem_cuts,
        )?;
        ex.chunks = chunks.len();
        let slot = Arc::new(ReplySlot::default());
        self.shared
            .waiting
            .lock()
            .unwrap()
            .insert(txid.clone(), slot.clone());
        ex.slot = Some(slot);
        let common = self.common_headers(o.contact.as_deref());
        let from = self.sip_from_uri();
        let n = chunks.len();
        for (i, chunk) in chunks.iter().enumerate() {
            let mut hdrs = common.clone();
            hdrs.extend(
                chunk
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone().into())),
            );
            let resp = sip.request(
                "MESSAGE",
                &self.server_uri(),
                &hdrs,
                &chunk.body,
                Some(&from),
                None,
                self.opts.timeout,
            );
            let status = resp.as_ref().and_then(Message::status);
            ex.sip_statuses.push(status);
            if !status.is_some_and(|s| (200..300).contains(&s)) {
                let what = match (&resp, status) {
                    (Some(r), Some(s)) => format!("{s} {}", r.reason()),
                    _ => "no response".into(),
                };
                ex.problems
                    .push(format!("SIP MESSAGE {}/{}: {}", i + 1, n, what));
                break;
            }
            if i < n - 1 && !self.opts.chunk_delay.is_zero() {
                std::thread::sleep(self.opts.chunk_delay);
            }
        }
        if !ex.problems.is_empty() {
            self.shared.waiting.lock().unwrap().remove(&txid);
            ex.waited = true;
            return Ok(ex);
        }
        if !o.wait {
            return Ok(ex);
        }
        self.wait_reply(&mut ex, o.timeout);
        Ok(ex)
    }

    /// Waits for the reply to `ex` (sent without waiting, or still
    /// pending); `timeout` defaults to the option.
    pub fn wait_reply(&self, ex: &mut Exchange, timeout: Option<Duration>) {
        let timeout = timeout.unwrap_or(self.opts.timeout);
        if ex.reply.is_none() {
            if let Some(slot) = &ex.slot {
                ex.reply = slot.wait(timeout);
            }
        }
        self.shared.waiting.lock().unwrap().remove(&ex.id);
        ex.waited = true;
    }

    /// The next unsolicited message (with `name`, only events of that
    /// `X-Event-Name`; others are skipped and dropped), or `None` on
    /// timeout.
    pub fn next_event(&self, timeout: Duration, name: Option<&str>) -> Option<Reply> {
        self.next_event_bytes(timeout, name.map(str::as_bytes))
    }

    /// [`Phone::next_event`] with an event name given as bytes.
    pub fn next_event_bytes(&self, timeout: Duration, name: Option<&[u8]>) -> Option<Reply> {
        let deadline = Instant::now() + timeout;
        let mut q = self.shared.events.lock().unwrap();
        loop {
            while let Some(r) = q.pop_front() {
                match name {
                    None => return Some(r),
                    Some(n) if r.event.as_deref().map(|e| e.as_bytes()) == Some(n) => {
                        return Some(r)
                    }
                    Some(n) => self.shared.log.log(
                        0,
                        &format!(
                            "--- skipped {} while waiting for {}",
                            r.type_name()
                                .map(|t| t.to_string())
                                .unwrap_or_else(|| "None".into()),
                            n.to_str_lossy()
                        ),
                    ),
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            q = self
                .shared
                .events_cv
                .wait_timeout(q, deadline - now)
                .unwrap()
                .0;
        }
    }

    /// Drops the queued unsolicited messages; returns how many there were.
    pub fn drain_events(&self) -> usize {
        let mut q = self.shared.events.lock().unwrap();
        let n = q.len();
        q.clear();
        n
    }

    /// Handshakes when there is no session and the options allow it
    /// (printing the exchange); fails when that handshake fails.
    pub fn ensure_session(&self) -> Result<()> {
        if self.session().is_none() && self.opts.auto_handshake {
            let ex = self.handshake().send()?;
            self.shared.log.print(&ex.describe(self.opts.verbose));
            if !ex.ok() || self.session().is_none() {
                bail!("automatic handshake failed");
            }
        }
        Ok(())
    }

    fn finish_handshake(&self, ex: &mut Exchange, key: RsaPrivateKey) {
        let Some(r) = ex.reply.as_mut() else { return };
        if !r.is_response("HandshakeResponse") {
            r.problems.push("expected a HandshakeResponse".into());
            return;
        }
        if !r.ok() {
            return;
        }
        let Some(incoming) = r.incoming.clone() else {
            return;
        };
        {
            let mut st = self.shared.state.lock().unwrap();
            if let Err(e) = st.session.accept_handshake_response(&incoming, &key) {
                r.problems.push(e.message().to_string());
                return;
            }
            st.key = Some(key);
            if let Some(pw) = st.session.common_password() {
                r.fields.push((
                    "common password".into(),
                    format!("{} bytes {}", pw.len(), hex::encode(pw)).into(),
                ));
            }
        }
        let checked = cert::verify_appserver_certificate(&incoming.body);
        r.appserver_ok = Some(checked.is_ok());
        r.appserver_info = Some(match checked {
            Ok(_) => "signed by a CA the official DPMA trusts".into(),
            Err(e) => e.to_string(),
        });
        if r.appserver_ok == Some(false) && self.opts.appserver_check {
            r.problems.push("AppServer certificate check failed".into());
        }
    }
}

impl Drop for Phone {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone)]
struct ReqOpts {
    encrypt: Option<bool>,
    session: SessionChoice,
    username: Option<BString>,
    password: Option<BString>,
    config_password: Option<BString>,
    config_token: Option<BString>,
    headers: Vec<(String, BString)>,
    wait: bool,
    timeout: Option<Duration>,
    chunk_size: Option<usize>,
    chunk_style: Option<ChunkStyle>,
    txid: Option<String>,
    mac: Option<String>,
    contact: Option<String>,
    pem_cuts: bool,
}

impl Default for ReqOpts {
    fn default() -> Self {
        ReqOpts {
            encrypt: None,
            session: SessionChoice::Auto,
            username: None,
            password: None,
            config_password: None,
            config_token: None,
            headers: Vec::new(),
            wait: true,
            timeout: None,
            chunk_size: None,
            chunk_style: None,
            txid: None,
            mac: None,
            contact: None,
            pem_cuts: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    Handshake,
    Token,
    Asterisk,
}

/// A request being built: set what differs from the defaults, then
/// [`send`](RequestBuilder::send) it.
///
/// ```no_run
/// # use dpma_tests::sim::{Form, Options, Phone};
/// # fn main() -> anyhow::Result<()> {
/// # let phone = Phone::start(Options::default())?;
/// let ex = phone.request("PingRequest").body("x".repeat(500)).chunk_size(64).send()?;
/// let ex = phone.request("PingRequest").session("999999999").encrypt(false).send()?;
/// let ex = phone.handshake().form(Form::Legacy).pem_cuts().send()?;
/// # Ok(()) }
/// ```
#[must_use = "a request does nothing until it is sent"]
pub struct RequestBuilder<'p> {
    phone: &'p Phone,
    kind: Kind,
    rtype: String,
    body: Vec<u8>,
    form: Option<Form>,
    handshake: Option<(Vec<u8>, RsaPrivateKey)>,
    auth: Option<BString>,
    o: ReqOpts,
}

impl<'p> RequestBuilder<'p> {
    fn new(phone: &'p Phone, rtype: &str, kind: Kind) -> Self {
        RequestBuilder {
            phone,
            kind,
            rtype: rtype.into(),
            body: Vec::new(),
            form: None,
            handshake: None,
            auth: None,
            o: ReqOpts::default(),
        }
    }

    /// The body.
    pub fn body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = body.as_ref().to_vec();
        self
    }

    /// Encrypt (`true`) or not; default: when the type needs a session and
    /// there is a common password (and the options do not say `plain`).
    pub fn encrypt(mut self, yes: bool) -> Self {
        self.o.encrypt = Some(yes);
        self
    }

    /// Send this session id instead of the phone's.
    pub fn session(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.o.session = if id.is_empty() {
            SessionChoice::Omit
        } else {
            SessionChoice::Id(id)
        };
        self
    }

    /// Send no session header.
    pub fn no_session(mut self) -> Self {
        self.o.session = SessionChoice::Omit;
        self
    }

    /// `X-Digium-AppServer-Username`.
    pub fn username(mut self, v: impl AsRef<[u8]>) -> Self {
        self.o.username = Some(v.as_ref().into());
        self
    }

    /// Shorthand for [`RequestBuilder::username`] (TokenRequest: the phone
    /// name).
    pub fn user(self, v: impl AsRef<[u8]>) -> Self {
        self.username(v)
    }

    /// `X-Digium-AppServer-Password` (encrypted when the request is).
    pub fn password(mut self, v: impl AsRef<[u8]>) -> Self {
        self.o.password = Some(v.as_ref().into());
        self
    }

    /// Shorthand for [`RequestBuilder::password`] (TokenRequest: the
    /// phone's pin).
    pub fn pin(self, v: impl AsRef<[u8]>) -> Self {
        self.password(v)
    }

    /// `X-Digium-AppServer-ConfigPassword` (encrypted when the request
    /// is).
    pub fn config_password(mut self, v: impl AsRef<[u8]>) -> Self {
        self.o.config_password = Some(v.as_ref().into());
        self
    }

    /// `X-Digium-AppServer-Config-Token` (encrypted when the request is).
    pub fn config_token(mut self, v: impl AsRef<[u8]>) -> Self {
        self.o.config_token = Some(v.as_ref().into());
        self
    }

    /// An extra header for every chunk.
    pub fn header(mut self, name: &str, value: impl AsRef<[u8]>) -> Self {
        self.o.headers.push((name.into(), value.as_ref().into()));
        self
    }

    /// Send without waiting for the reply (see [`Phone::wait_reply`]).
    pub fn no_wait(mut self) -> Self {
        self.o.wait = false;
        self
    }

    /// Wait for the reply (the default) or not.
    pub fn wait(mut self, yes: bool) -> Self {
        self.o.wait = yes;
        self
    }

    /// The reply timeout for this request.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.o.timeout = Some(t);
        self
    }

    /// The reply timeout for this request, in seconds.
    pub fn timeout_secs(self, s: f64) -> Self {
        self.timeout(crate::util::secs(s))
    }

    /// The maximum body bytes per MESSAGE for this request.
    pub fn chunk_size(mut self, n: usize) -> Self {
        self.o.chunk_size = Some(n);
        self
    }

    /// How an encrypted body is chunked.
    pub fn chunk_style(mut self, s: ChunkStyle) -> Self {
        self.o.chunk_style = Some(s);
        self
    }

    /// The transaction id (default: the next counter value).
    pub fn txid(mut self, id: impl Into<String>) -> Self {
        self.o.txid = Some(id.into());
        self
    }

    /// The MAC header for this request only.
    pub fn mac(mut self, mac: impl Into<String>) -> Self {
        self.o.mac = Some(mac.into());
        self
    }

    /// The Contact URI for this request only.
    pub fn contact(mut self, uri: impl Into<String>) -> Self {
        self.o.contact = Some(uri.into());
        self
    }

    /// End plaintext chunks right before and after every PEM BEGIN and END
    /// line, so the server loses those line breaks.
    pub fn pem_cuts(mut self) -> Self {
        self.o.pem_cuts = true;
        self
    }

    /// Handshake: the certificate form (default: the option).
    pub fn form(mut self, form: Form) -> Self {
        self.form = Some(form);
        self
    }

    /// Handshake: sends this certificate chain and recovers the common
    /// password with `key`, instead of the phone's identity.
    pub fn handshake_body(mut self, body: impl AsRef<[u8]>, key: RsaPrivateKey) -> Self {
        self.handshake = Some((body.as_ref().to_vec(), key));
        self
    }

    /// AsteriskRequest and HTTPRequest: the credentials `USER:SECRET`,
    /// sent as the line `X-Digium-AppServer-Digest-Auth=USER:SECRET`
    /// before the document.
    pub fn auth(mut self, credentials: impl AsRef<[u8]>) -> Self {
        self.auth = Some(credentials.as_ref().into());
        self
    }

    /// Sends the request and, unless told not to, waits for the reply.
    /// Errors are setup errors; protocol failures are in the [`Exchange`].
    pub fn send(self) -> Result<Exchange> {
        let RequestBuilder {
            phone,
            kind,
            rtype,
            mut body,
            form,
            handshake,
            auth,
            o,
        } = self;
        match kind {
            Kind::Handshake => {
                let (body, key) = match handshake {
                    Some((b, k)) => (b, k),
                    None => {
                        let id = certs::identity(&phone.opts.mac)?;
                        (id.body(form.unwrap_or(phone.opts.form)), id.key())
                    }
                };
                let mut ex = phone.send_request(&rtype, &body, &o)?;
                if o.wait {
                    phone.finish_handshake(&mut ex, key);
                }
                Ok(ex)
            }
            Kind::Token => {
                let ex = phone.send_request(&rtype, &body, &o)?;
                if let Some(t) = ex
                    .reply
                    .as_ref()
                    .and_then(|r| r.field(h::CONFIG_TOKEN))
                    .filter(|t| !t.is_empty())
                {
                    phone.set_token(Some(t.clone()));
                }
                Ok(ex)
            }
            Kind::Asterisk => {
                if let Some(a) = auth {
                    body = documents::with_digest_auth(&a, &body);
                }
                phone.send_request(&rtype, &body, &o)
            }
            Kind::Plain => phone.send_request(&rtype, &body, &o),
        }
    }
}
