//! The simulator's SIP layer: a tiny user agent that sends out-of-dialog
//! requests and waits for their final response (UDP retransmissions as
//! RFC 3261 timer E), and answers every incoming request with 200 OK,
//! handing MESSAGEs to a callback.
//!
//! Over TCP it also listens for UDP on the same port, as phones do: the
//! official DPMA answers a session that fails validation ("Session
//! Timeout") at the bare Response-URI, without `;transport=tcp`, so over
//! UDP; dpma-rs answers over TCP (port plan section 8, item 11).

use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bstr::{BString, ByteSlice};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};

use super::Logger;
use crate::sip::{self, Message, Transport};
use crate::util::token_hex;

/// Called with every incoming MESSAGE (after it was answered).
pub type MessageHandler = Box<dyn Fn(Message) + Send + Sync>;

#[derive(Default)]
struct Slot {
    response: Mutex<Option<Message>>,
    cv: Condvar,
}

type SeenKey = (Option<BString>, Option<BString>, BString);

/// Answers already sent, by request, and their keys oldest first.
type Seen = (HashMap<SeenKey, Vec<u8>>, VecDeque<SeenKey>);

/// Sends a reply on the socket a request came in on.
type ReplyFn<'a> = &'a dyn Fn(&[u8], SocketAddr);

struct Inner {
    server: SocketAddr,
    transport: Transport,
    local: SocketAddr,
    udp: Option<UdpSocket>,
    tcp_write: Option<Mutex<TcpStream>>,
    udp_side: Option<UdpSocket>,
    log: Logger,
    on_message: MessageHandler,
    pending: Mutex<HashMap<String, Arc<Slot>>>,
    seen: Mutex<Seen>,
    send_lock: Mutex<()>,
    cseq: AtomicU32,
    closed: AtomicBool,
}

/// The simulator's SIP endpoint (see the module documentation).
pub struct SipEndpoint {
    inner: Arc<Inner>,
    threads: Vec<JoinHandle<()>>,
    tcp_shutdown: Option<TcpStream>,
}

const POLL: Duration = Duration::from_millis(100);

fn bind_socket(ty: Type, local: SocketAddr, reuse: bool) -> Result<Socket> {
    let proto = if ty == Type::DGRAM {
        Protocol::UDP
    } else {
        Protocol::TCP
    };
    let s = Socket::new(Domain::for_address(local), ty, Some(proto))?;
    if reuse {
        s.set_reuse_address(true)?;
    }
    s.bind(&local.into())
        .with_context(|| format!("binding {local}"))?;
    Ok(s)
}

impl SipEndpoint {
    /// Binds `local` (port 0: any) and, over TCP, connects to `server`;
    /// then starts the receiving threads.  `timeout` bounds the TCP
    /// connect.
    pub fn start(
        server: SocketAddr,
        local: SocketAddr,
        transport: Transport,
        timeout: Duration,
        log: Logger,
        on_message: MessageHandler,
    ) -> Result<Self> {
        let mut udp = None;
        let mut tcp_read = None;
        let mut tcp_write = None;
        let mut udp_side = None;
        let local_addr;
        match transport {
            Transport::Udp => {
                let s: UdpSocket = bind_socket(Type::DGRAM, local, false)?.into();
                s.set_read_timeout(Some(POLL))?;
                local_addr = s.local_addr()?;
                udp = Some(s);
            }
            Transport::Tcp => {
                let s = bind_socket(Type::STREAM, local, true)?;
                s.connect_timeout(&server.into(), timeout)
                    .map_err(|e| anyhow!("TCP connect to {server} failed: {e}"))?;
                let stream: TcpStream = s.into();
                local_addr = stream.local_addr()?;
                stream.set_read_timeout(Some(POLL))?;
                tcp_write = Some(Mutex::new(stream.try_clone()?));
                tcp_read = Some(stream);
                match bind_socket(Type::DGRAM, local_addr, false) {
                    Ok(u) => {
                        let u: UdpSocket = u.into();
                        u.set_read_timeout(Some(POLL))?;
                        udp_side = Some(u);
                    }
                    Err(e) => log.log(
                        1,
                        &format!("--- no UDP listener next to the TCP connection: {e}"),
                    ),
                }
            }
        }
        let tcp_shutdown = tcp_read.as_ref().map(TcpStream::try_clone).transpose()?;
        let inner = Arc::new(Inner {
            server,
            transport,
            local: local_addr,
            udp,
            tcp_write,
            udp_side,
            log,
            on_message,
            pending: Mutex::default(),
            seen: Mutex::default(),
            send_lock: Mutex::new(()),
            cseq: AtomicU32::new(rand::thread_rng().gen_range(1..=10000)),
            closed: AtomicBool::new(false),
        });
        let mut threads = Vec::new();
        if inner.udp.is_some() {
            let i = inner.clone();
            threads.push(std::thread::spawn(move || i.udp_loop(false)));
        }
        if inner.udp_side.is_some() {
            let i = inner.clone();
            threads.push(std::thread::spawn(move || i.udp_loop(true)));
        }
        if let Some(stream) = tcp_read {
            let i = inner.clone();
            threads.push(std::thread::spawn(move || i.tcp_loop(stream)));
        }
        Ok(SipEndpoint {
            inner,
            threads,
            tcp_shutdown,
        })
    }

    /// The local address (the port the server answers to).
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local
    }

    /// The transport.
    pub fn transport(&self) -> Transport {
        self.inner.transport
    }

    /// Sends a request and returns its final response (`None` on
    /// timeout).  `headers` go after Via, Max-Forwards, From, To, Call-ID,
    /// and CSeq; Content-Length is added.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        method: &str,
        ruri: &str,
        headers: &[(String, BString)],
        body: &[u8],
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        timeout: Duration,
    ) -> Option<Message> {
        self.inner
            .request(method, ruri, headers, body, from_uri, to_uri, timeout)
    }

    /// Stops the receiving threads and closes the sockets.
    pub fn close(&mut self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        if let Some(s) = &self.tcp_shutdown {
            let _ = s.shutdown(Shutdown::Both);
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for SipEndpoint {
    fn drop(&mut self) {
        self.close();
    }
}

impl Inner {
    fn send_raw(&self, data: &[u8], addr: Option<SocketAddr>) -> std::io::Result<()> {
        let _g = self.send_lock.lock().unwrap();
        match (&self.udp, &self.tcp_write) {
            (Some(u), _) => u.send_to(data, addr.unwrap_or(self.server)).map(|_| ()),
            (None, Some(t)) => t.lock().unwrap().write_all(data),
            _ => Ok(()),
        }
    }

    fn via(&self, branch: &str) -> String {
        format!(
            "SIP/2.0/{} {}:{};rport;branch={}",
            self.transport.as_str().to_uppercase(),
            self.local.ip(),
            self.local.port(),
            branch
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        method: &str,
        ruri: &str,
        headers: &[(String, BString)],
        body: &[u8],
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        timeout: Duration,
    ) -> Option<Message> {
        let branch = format!("z9hG4bK{}", token_hex(8));
        let cseq = self.cseq.fetch_add(1, Ordering::SeqCst) + 1;
        let host = self.local.ip().to_string();
        let from = from_uri
            .map(str::to_string)
            .unwrap_or_else(|| format!("sip:sim@{host}"));
        let mut hdrs: Vec<(String, BString)> = vec![
            ("Via".into(), self.via(&branch).into()),
            ("Max-Forwards".into(), "70".into()),
            (
                "From".into(),
                format!("<{from}>;tag={}", token_hex(6)).into(),
            ),
            ("To".into(), format!("<{}>", to_uri.unwrap_or(ruri)).into()),
            ("Call-ID".into(), format!("{}@{host}", token_hex(10)).into()),
            ("CSeq".into(), format!("{cseq} {method}").into()),
        ];
        hdrs.extend(headers.iter().cloned());
        hdrs.push(("Content-Length".into(), body.len().to_string().into()));
        let msg = Message::new(format!("{method} {ruri} SIP/2.0"), hdrs, body);
        let data = msg.encode();
        let slot = Arc::new(Slot::default());
        self.pending
            .lock()
            .unwrap()
            .insert(branch.clone(), slot.clone());
        self.log
            .log(2, &format!(">>> SIP to {}\n{}", self.server, msg.text()));
        self.log.log(
            1,
            &format!(">>> {method} {ruri} ({} body bytes)", body.len()),
        );
        let deadline = Instant::now() + timeout;
        let mut interval = Duration::from_millis(500);
        let result = (|| {
            self.send_raw(&data, None).ok()?;
            let mut guard = slot.response.lock().unwrap();
            loop {
                if let Some(r) = guard.take() {
                    return Some(r);
                }
                let now = Instant::now();
                if now >= deadline {
                    return None;
                }
                let wait = interval.min(deadline - now);
                let (g, res) = slot.cv.wait_timeout(guard, wait).unwrap();
                guard = g;
                if guard.is_some() {
                    continue;
                }
                if res.timed_out() && self.transport == Transport::Udp && Instant::now() < deadline
                {
                    drop(guard);
                    let _ = self.send_raw(&data, None);
                    interval = (interval * 2).min(Duration::from_secs(4));
                    guard = slot.response.lock().unwrap();
                }
            }
        })();
        self.pending.lock().unwrap().remove(&branch);
        result
    }

    fn udp_loop(&self, side: bool) {
        let sock = if side {
            self.udp_side.as_ref()
        } else {
            self.udp.as_ref()
        };
        let Some(sock) = sock else { return };
        let mut buf = vec![0u8; 65535];
        while !self.closed.load(Ordering::SeqCst) {
            match sock.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let data = &buf[..n];
                    if !data.trim_ascii().is_empty() {
                        let reply = |d: &[u8], a: SocketAddr| {
                            let _ = sock.send_to(d, a);
                        };
                        if side {
                            self.handle(data, addr, Some(&reply));
                        } else {
                            self.handle(data, addr, None);
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(_) => return,
            }
        }
    }

    fn tcp_loop(&self, mut stream: TcpStream) {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 65535];
        while !self.closed.load(Ordering::SeqCst) {
            let n = match stream.read(&mut chunk) {
                Ok(0) => {
                    if !self.closed.load(Ordering::SeqCst) {
                        self.log.log(1, "--- TCP connection closed by the server");
                    }
                    return;
                }
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(_) => return,
            };
            buf.extend_from_slice(&chunk[..n]);
            loop {
                let lead = buf
                    .iter()
                    .take_while(|&&c| c == b'\r' || c == b'\n')
                    .count();
                if lead > 0 {
                    if buf.starts_with(b"\r\n\r\n") {
                        let _ = self.send_raw(b"\r\n", None); // keepalive pong
                    }
                    buf.drain(..lead);
                }
                let Some(end) = buf.find(b"\r\n\r\n") else {
                    break;
                };
                let total = end + 4 + content_length(&buf[..end]);
                if buf.len() < total {
                    break;
                }
                let data: Vec<u8> = buf.drain(..total).collect();
                self.handle(&data, self.server, None);
            }
        }
    }

    fn handle(&self, data: &[u8], addr: SocketAddr, reply: Option<ReplyFn<'_>>) {
        let mut msg = match sip::parse(data, Some(addr)) {
            Ok(m) => m,
            Err(e) => {
                self.log
                    .log(1, &format!("--- unparsable SIP data from {addr}: {e}"));
                return;
            }
        };
        msg.transport = Some(if reply.is_some() {
            Transport::Udp
        } else {
            self.transport
        });
        self.log
            .log(2, &format!("<<< SIP from {addr}\n{}", msg.text()));
        let via = msg.get("Via").cloned().unwrap_or_default();
        let branch = sip::via_branch(&via);
        if !msg.is_request() {
            let (Some(status), Some(branch)) = (msg.status(), branch) else {
                return;
            };
            if status < 200 {
                return;
            }
            let slot = self.pending.lock().unwrap().get(&branch).cloned();
            if let Some(slot) = slot {
                let mut g = slot.response.lock().unwrap();
                if g.is_none() {
                    *g = Some(msg);
                    slot.cv.notify_all();
                }
            }
            return;
        }
        let method = msg.method().unwrap_or_default();
        if method == "ACK" {
            return;
        }
        let key: SeenKey = (
            msg.get("Call-ID").cloned(),
            msg.get("CSeq").cloned(),
            branch.map(BString::from).unwrap_or(via),
        );
        let send = |d: &[u8]| match reply {
            Some(r) => r(d, addr),
            None => {
                let _ = self.send_raw(d, Some(addr));
            }
        };
        let old = self.seen.lock().unwrap().0.get(&key).cloned();
        if let Some(old) = old {
            self.log
                .log(1, &format!("<<< retransmitted {method}, answered again"));
            send(&old);
            return;
        }
        let resp = response(&msg, 200, "OK");
        {
            let mut seen = self.seen.lock().unwrap();
            seen.0.insert(key.clone(), resp.clone());
            seen.1.push_back(key);
            if seen.1.len() > 2000 {
                for _ in 0..1000 {
                    if let Some(k) = seen.1.pop_front() {
                        seen.0.remove(&k);
                    }
                }
            }
        }
        send(&resp);
        self.log.log(
            1,
            &format!(
                "<<< {method} from {addr}{} ({} body bytes), answered 200 OK",
                if reply.is_some() { " (UDP)" } else { "" },
                msg.body.len()
            ),
        );
        if method == "MESSAGE" {
            (self.on_message)(msg);
        }
    }
}

/// The value of the Content-Length (or `l`) header in a message head.
fn content_length(head: &[u8]) -> usize {
    for line in head.lines() {
        let Some(colon) = line.find_byte(b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii();
        if name.eq_ignore_ascii_case(b"content-length") || name.eq_ignore_ascii_case(b"l") {
            if let Some(n) = line[colon + 1..]
                .trim_ascii()
                .to_str()
                .ok()
                .and_then(|s| s.parse().ok())
            {
                return n;
            }
        }
    }
    0
}

/// A response to `req` (Via, From, To with a tag, Call-ID, CSeq, and
/// `Server: dpma_sim`), with no body.
pub fn response(req: &Message, status: u16, reason: &str) -> Vec<u8> {
    let mut hdrs: Vec<(String, BString)> = req
        .get_all("Via")
        .into_iter()
        .map(|v| ("Via".to_string(), v.clone()))
        .collect();
    let mut to = req.get("To").cloned().unwrap_or_default();
    if !to.contains_str(";tag=") {
        to.extend_from_slice(format!(";tag={}", token_hex(6)).as_bytes());
    }
    hdrs.push(("From".into(), req.get("From").cloned().unwrap_or_default()));
    hdrs.push(("To".into(), to));
    hdrs.push((
        "Call-ID".into(),
        req.get("Call-ID").cloned().unwrap_or_default(),
    ));
    hdrs.push(("CSeq".into(), req.get("CSeq").cloned().unwrap_or_default()));
    hdrs.push(("Server".into(), "dpma_sim".into()));
    hdrs.push(("Content-Length".into(), "0".into()));
    Message::new(format!("SIP/2.0 {status} {reason}"), hdrs, Vec::new()).encode()
}
