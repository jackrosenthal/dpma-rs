//! A small Asterisk Manager Interface client.
//!
//! Text is bytes: action fields are sent as given and every message keeps
//! both its parsed fields and the bytes Asterisk sent, so responses
//! and events can be compared byte for byte.
//!
//! ```no_run
//! use dpma_tests::ami::AmiClient;
//! # fn main() -> anyhow::Result<()> {
//! let ami = dpma_tests::harness::Instance::new()?.ami()?;
//! let res = ami.action("DPMAShowPhones", [("ActionID", "x")]);
//! println!("{:?} {}", res.response.as_ref().and_then(|r| r.get_str("Response")), res.events.len());
//! let ev = ami.wait_event(Some("DPMAMessage"), &[], std::time::Duration::from_secs(30));
//! # Ok(()) }
//! ```

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bstr::{BString, ByteSlice};
use regex::bytes::Regex;

/// One AMI message: its fields in order (keys may repeat, for example
/// `Output` in a Command response) and the bytes it arrived as.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AmiMessage {
    fields: Vec<(BString, BString)>,
    raw: BString,
}

impl AmiMessage {
    /// A message from fields (not parsed from bytes).
    pub fn from_fields(fields: Vec<(BString, BString)>) -> AmiMessage {
        AmiMessage {
            fields,
            raw: BString::default(),
        }
    }

    /// The fields in order.
    pub fn fields(&self) -> &[(BString, BString)] {
        &self.fields
    }

    /// The message as Asterisk sent it, through the blank line that ends
    /// it (line breaks as received).
    pub fn raw(&self) -> &BString {
        &self.raw
    }

    /// The first value of `key` (case insensitive).
    pub fn get(&self, key: &str) -> Option<&BString> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes()))
            .map(|(_, v)| v)
    }

    /// The first value of `key`, as text (lossy).
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.get(key).map(|v| v.to_str_lossy().into_owned())
    }

    /// Every value of `key`, in order.
    pub fn get_all(&self, key: &str) -> Vec<&BString> {
        self.fields
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes()))
            .map(|(_, v)| v)
            .collect()
    }

    /// Every value of `key` joined with line breaks (`None` when there is
    /// none): how checks see repeated keys.
    pub fn joined(&self, key: &str) -> Option<BString> {
        let all = self.get_all(key);
        (!all.is_empty()).then(|| {
            BString::from(
                all.iter()
                    .map(|v| v.as_slice())
                    .collect::<Vec<_>>()
                    .join(&b"\n"[..]),
            )
        })
    }

    /// Whether `key` is present.
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Whether this is an event.
    pub fn is_event(&self) -> bool {
        self.has("Event")
    }

    /// The `Key: Value` lines (each ending in a line break).
    pub fn text(&self) -> BString {
        let mut out = Vec::new();
        for (k, v) in &self.fields {
            out.extend_from_slice(k);
            out.extend_from_slice(b": ");
            out.extend_from_slice(v);
            out.push(b'\n');
        }
        out.into()
    }

    /// This message's fields followed by those of `others`.
    pub fn merged<'a>(&self, others: impl IntoIterator<Item = &'a AmiMessage>) -> AmiMessage {
        let mut fields = self.fields.clone();
        for o in others {
            fields.extend(o.fields.iter().cloned());
        }
        AmiMessage::from_fields(fields)
    }

    fn parse_line(&mut self, line: &[u8]) {
        match line.find_byte(b':') {
            Some(i) => self.fields.push((
                line[..i].trim_ascii().into(),
                line[i + 1..].trim_ascii().into(),
            )),
            // Old-style command output without "Output:" keys.
            None => self.fields.push(("Output".into(), line.into())),
        }
    }
}

/// The response to an action and the events collected with it.
#[derive(Clone, Debug, Default)]
pub struct AmiResult {
    /// The response (`None`: no response in time).
    pub response: Option<AmiMessage>,
    /// For list actions, the events up to `EventList: Complete`.
    pub events: Vec<AmiMessage>,
}

impl AmiResult {
    /// The response is `Success` (or `Follows` or `Goodbye`).
    pub fn success(&self) -> bool {
        self.response
            .as_ref()
            .and_then(|r| r.get("Response"))
            .is_some_and(|v| {
                let v = v.to_ascii_lowercase();
                v == b"success" || v == b"follows" || v == b"goodbye"
            })
    }

    /// The response and events as `Key: Value` text, separated by blank
    /// lines.
    pub fn text(&self) -> BString {
        let mut parts: Vec<BString> = vec![self
            .response
            .as_ref()
            .map(AmiMessage::text)
            .unwrap_or_else(|| "(no response)\n".into())];
        parts.extend(self.events.iter().map(AmiMessage::text));
        parts
            .iter()
            .map(|p| p.as_slice())
            .collect::<Vec<_>>()
            .join(&b"\n"[..])
            .into()
    }

    /// The response's fields followed by every event's (empty without a
    /// response).
    pub fn merged(&self) -> AmiMessage {
        self.response
            .as_ref()
            .map(|r| r.merged(&self.events))
            .unwrap_or_default()
    }
}

/// How [`AmiClient::wait_event`] matches a field.
#[derive(Clone, Debug)]
pub enum Match {
    /// The value equals these bytes.
    Eq(BString),
    /// The regular expression matches somewhere in the value.
    Re(Regex),
}

impl Match {
    /// Equality with `v`.
    pub fn eq(v: impl AsRef<[u8]>) -> Match {
        Match::Eq(v.as_ref().into())
    }

    /// A regular expression (panics on an invalid one: they are written in
    /// tests).
    pub fn re(pattern: &str) -> Match {
        Match::Re(Regex::new(pattern).expect("invalid regular expression"))
    }

    fn matches(&self, value: Option<&BString>) -> bool {
        match (self, value) {
            (_, None) => false,
            (Match::Eq(w), Some(v)) => v == w,
            (Match::Re(r), Some(v)) => r.is_match(v),
        }
    }
}

#[derive(Default)]
struct Inbox {
    responses: VecDeque<(u64, AmiMessage)>,
    next_seq: u64,
    events: VecDeque<AmiMessage>,
    closed: bool,
}

struct Shared {
    inbox: Mutex<Inbox>,
    cv: Condvar,
}

/// An AMI connection with a reader thread that collects responses and
/// events.
pub struct AmiClient {
    stream: Mutex<TcpStream>,
    shared: Arc<Shared>,
    banner: String,
    timeout: Duration,
    seq: AtomicU64,
    reader: Option<std::thread::JoinHandle<()>>,
}

const MAX_EVENTS: usize = 20000;

impl AmiClient {
    /// Connects and logs in; `timeout` is the default action timeout.
    pub fn connect(
        host: &str,
        port: u16,
        user: &str,
        secret: &str,
        events: bool,
        timeout: Duration,
    ) -> Result<AmiClient> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("cannot resolve {host}"))?;
        let stream =
            TcpStream::connect_timeout(&addr, timeout).with_context(|| format!("AMI {addr}"))?;
        stream.set_read_timeout(Some(timeout))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut banner = Vec::new();
        reader.read_until(b'\n', &mut banner)?;
        let banner = banner.to_str_lossy().trim().to_string();
        if !banner.starts_with("Asterisk Call Manager") {
            bail!("unexpected AMI banner {banner:?}");
        }
        stream.set_read_timeout(None)?;
        let shared = Arc::new(Shared {
            inbox: Mutex::default(),
            cv: Condvar::new(),
        });
        let s = shared.clone();
        let handle = std::thread::spawn(move || read_loop(reader, &s));
        let client = AmiClient {
            stream: Mutex::new(stream),
            shared,
            banner,
            timeout,
            seq: AtomicU64::new(0),
            reader: Some(handle),
        };
        let res = client.action(
            "Login",
            [
                ("Username", user),
                ("Secret", secret),
                ("Events", if events { "on" } else { "off" }),
            ],
        );
        if !res.success() {
            bail!(
                "AMI login failed: {}",
                res.response
                    .and_then(|r| r.get_str("Message"))
                    .unwrap_or_else(|| "no response".into())
            );
        }
        Ok(client)
    }

    /// The banner line (`Asterisk Call Manager/...`).
    pub fn banner(&self) -> &str {
        &self.banner
    }

    /// Sends an action without waiting; returns its ActionID (generated
    /// unless `fields` has one).
    pub fn send<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        action: &str,
        fields: impl IntoIterator<Item = (K, V)>,
    ) -> Result<BString> {
        let fields: Vec<(Vec<u8>, Vec<u8>)> = fields
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_vec(), v.as_ref().to_vec()))
            .collect();
        let given = fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(b"ActionID"))
            .map(|(_, v)| BString::from(v.clone()));
        let action_id = given.clone().unwrap_or_else(|| {
            let n = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
            format!("sim-{}-{n}", std::process::id()).into()
        });
        let mut data = format!("Action: {action}\r\n").into_bytes();
        if given.is_none() {
            data.extend_from_slice(b"ActionID: ");
            data.extend_from_slice(&action_id);
            data.extend_from_slice(b"\r\n");
        }
        for (k, v) in fields {
            data.extend_from_slice(&k);
            data.extend_from_slice(b": ");
            data.extend_from_slice(&v);
            data.extend_from_slice(b"\r\n");
        }
        data.extend_from_slice(b"\r\n");
        self.stream.lock().unwrap().write_all(&data)?;
        Ok(action_id)
    }

    /// Sends an action and waits for its response (default timeout); for
    /// list actions (`EventList: start`) also collects the events up to
    /// `EventList: Complete`.
    pub fn action<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        action: &str,
        fields: impl IntoIterator<Item = (K, V)>,
    ) -> AmiResult {
        self.action_timeout(action, fields, self.timeout)
    }

    /// [`AmiClient::action`] with a timeout for the response and for the
    /// list events.
    pub fn action_timeout<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        action: &str,
        fields: impl IntoIterator<Item = (K, V)>,
        timeout: Duration,
    ) -> AmiResult {
        let Ok(action_id) = self.send(action, fields) else {
            return AmiResult::default();
        };
        let deadline = Instant::now() + timeout;
        let resp = {
            let mut inbox = self.shared.inbox.lock().unwrap();
            loop {
                if let Some(pos) = inbox
                    .responses
                    .iter()
                    .position(|(_, m)| m.get("ActionID") == Some(&action_id))
                {
                    break inbox.responses.remove(pos).map(|(_, m)| m);
                }
                let now = Instant::now();
                if now >= deadline || inbox.closed {
                    break None;
                }
                inbox = self
                    .shared
                    .cv
                    .wait_timeout(inbox, deadline - now)
                    .unwrap()
                    .0;
            }
        };
        let Some(resp) = resp else {
            return AmiResult::default();
        };
        let mut events = Vec::new();
        if resp
            .get("EventList")
            .is_some_and(|v| v.eq_ignore_ascii_case(b"start"))
        {
            let deadline = Instant::now() + timeout;
            let m = [("ActionID", Match::Eq(action_id.clone()))];
            while let Some(ev) =
                self.wait_event(None, &m, deadline.saturating_duration_since(Instant::now()))
            {
                let done = ev
                    .get("EventList")
                    .is_some_and(|v| v.eq_ignore_ascii_case(b"complete"));
                events.push(ev);
                if done {
                    break;
                }
            }
        }
        AmiResult {
            response: Some(resp),
            events,
        }
    }

    /// Sends raw action text (it must end in a blank line) and returns the
    /// next response that arrives after it, whatever its ActionID.
    pub fn send_raw(&self, data: &[u8], timeout: Duration) -> Option<AmiMessage> {
        let before = self.shared.inbox.lock().unwrap().next_seq;
        self.stream.lock().unwrap().write_all(data).ok()?;
        let deadline = Instant::now() + timeout;
        let mut inbox = self.shared.inbox.lock().unwrap();
        loop {
            if let Some(pos) = inbox.responses.iter().position(|(n, _)| *n >= before) {
                return inbox.responses.remove(pos).map(|(_, m)| m);
            }
            let now = Instant::now();
            if now >= deadline || inbox.closed {
                return None;
            }
            inbox = self
                .shared
                .cv
                .wait_timeout(inbox, deadline - now)
                .unwrap()
                .0;
        }
    }

    /// Runs a CLI command through the `Command` action; returns its output
    /// lines.
    pub fn command(&self, cli: &str) -> Result<Vec<BString>> {
        let res = self.action("Command", [("Command", cli)]);
        let resp = res
            .response
            .ok_or_else(|| anyhow!("no response to Command {cli:?}"))?;
        Ok(resp.get_all("Output").into_iter().cloned().collect())
    }

    /// [`AmiClient::command`] with the lines joined by line breaks (lossy
    /// text; empty on errors).
    pub fn command_text(&self, cli: &str) -> String {
        self.command(cli)
            .map(|l| {
                l.iter()
                    .map(|b| b.to_str_lossy())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }

    /// Removes and returns the oldest event named `name` (any event when
    /// `None`; case insensitive) whose fields match `matches`; `None` on
    /// timeout.
    pub fn wait_event(
        &self,
        name: Option<&str>,
        matches: &[(&str, Match)],
        timeout: Duration,
    ) -> Option<AmiMessage> {
        let deadline = Instant::now() + timeout;
        let mut inbox = self.shared.inbox.lock().unwrap();
        loop {
            let pos = inbox.events.iter().position(|ev| {
                name.is_none_or(|n| {
                    ev.get("Event")
                        .is_some_and(|e| e.eq_ignore_ascii_case(n.as_bytes()))
                }) && matches.iter().all(|(k, m)| m.matches(ev.get(k)))
            });
            if let Some(pos) = pos {
                return inbox.events.remove(pos);
            }
            let now = Instant::now();
            if now >= deadline || inbox.closed {
                return None;
            }
            inbox = self
                .shared
                .cv
                .wait_timeout(inbox, deadline - now)
                .unwrap()
                .0;
        }
    }

    /// Removes and returns every event received so far.
    pub fn drain_events(&self) -> Vec<AmiMessage> {
        self.shared.inbox.lock().unwrap().events.drain(..).collect()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.shared.inbox.lock().unwrap().closed
    }

    /// Logs off and closes the connection.
    pub fn close(&mut self) {
        if self.reader.is_none() {
            return;
        }
        let _ = self.action_timeout(
            "Logoff",
            std::iter::empty::<(&str, &str)>(),
            Duration::from_secs(2),
        );
        let _ = self.stream.lock().unwrap().shutdown(Shutdown::Both);
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

impl Drop for AmiClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn read_loop(mut reader: BufReader<TcpStream>, shared: &Shared) {
    let mut msg = AmiMessage::default();
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        msg.raw.extend_from_slice(&line);
        let text = line.trim_end_with(|c| c == '\r' || c == '\n');
        // A message ends at the first "\r\n\r\n": after a line that ends
        // in a bare "\n" (DigiumPhoneReconfigure's "not contacted"
        // message), a blank line does not end it yet.
        if text.is_empty()
            && !msg.fields.is_empty()
            && !msg.raw.ends_with(b"\r\n\r\n")
            && !msg.raw.ends_with(b"\n\n")
        {
            continue;
        }
        if text.is_empty() {
            if !msg.fields.is_empty() {
                let done = std::mem::take(&mut msg);
                let mut inbox = shared.inbox.lock().unwrap();
                if done.is_event() {
                    inbox.events.push_back(done);
                    if inbox.events.len() > MAX_EVENTS {
                        inbox.events.pop_front();
                    }
                } else {
                    let n = inbox.next_seq;
                    inbox.next_seq += 1;
                    inbox.responses.push_back((n, done));
                }
                shared.cv.notify_all();
            } else {
                msg.raw.clear();
            }
            continue;
        }
        msg.parse_line(text);
    }
    shared.inbox.lock().unwrap().closed = true;
    shared.cv.notify_all();
}

/// Turns `Key=Value` or `Key: Value` arguments into fields.
pub fn parse_fields(items: &[String]) -> Result<Vec<(String, String)>> {
    let re = regex::Regex::new(r"^([^:=\s]+)\s*(?::\s?|=)(.*)$").unwrap();
    items
        .iter()
        .map(|it| {
            let c = re
                .captures(it)
                .ok_or_else(|| anyhow!("bad field {it:?} (use Key=Value or 'Key: Value')"))?;
            Ok((c[1].to_string(), c[2].to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    /// A fake AMI server.
    fn fake_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"Asterisk Call Manager/11.0.0\r\n").unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let Ok(n) = s.read(&mut chunk) else { return };
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                while let Some(i) = buf.find(b"\r\n\r\n") {
                    let req: Vec<u8> = buf.drain(..i + 4).collect();
                    let id = ByteSlice::lines(req.as_slice())
                        .find_map(|l| l.strip_prefix(b"ActionID: "))
                        .map(<[u8]>::to_vec)
                        .unwrap_or_default();
                    let mut out = Vec::new();
                    let mut put = |t: &[u8]| out.extend_from_slice(t);
                    if req.starts_with(b"Action: Login") {
                        put(b"Response: Success\r\nActionID: ");
                        put(&id);
                        put(b"\r\nMessage: Authentication accepted\r\n\r\n");
                        put(b"Event: FullyBooted\r\nStatus: Fully Booted\r\n\r\n");
                    } else if req.starts_with(b"Action: Things") {
                        put(b"Response: Success\r\nActionID: ");
                        put(&id);
                        put(b"\r\nEventList: start\r\nMessage: list follows\r\n\r\n");
                        for i in 0..2 {
                            put(format!("Event: Thing\r\nN: {i}\r\nActionID: ").as_bytes());
                            put(&id);
                            put(b"\r\n\r\n");
                        }
                        put(b"Event: ThingsComplete\r\nEventList: Complete\r\nActionID: ");
                        put(&id);
                        put(b"\r\n\r\n");
                    } else if req.starts_with(b"Action: Bare") {
                        put(b"Response: Error\r\nActionID: ");
                        put(&id);
                        put(b"\r\nMessage: one line.\n\r\n\r\n");
                    } else if req.starts_with(b"Action: Command") {
                        put(b"Response: Success\r\nActionID: ");
                        put(&id);
                        put(b"\r\nOutput: line one\r\nOutput: line \xe9\r\n\r\n");
                        put(b"Event: Custom\r\nName: caf\xe9\r\n\r\n");
                    } else {
                        put(b"Response: Goodbye\r\nActionID: ");
                        put(&id);
                        put(b"\r\n\r\n");
                    }
                    s.write_all(&out).unwrap();
                }
            }
        });
        port
    }

    #[test]
    fn actions_lists_and_events() {
        let port = fake_server();
        let ami = AmiClient::connect(
            "127.0.0.1",
            port,
            "test",
            "test",
            true,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(ami.banner().starts_with("Asterisk Call Manager"));
        assert!(ami
            .wait_event(Some("fullybooted"), &[], Duration::from_secs(2))
            .is_some());
        let res = ami.action("Things", [("ActionID", "t1")]);
        assert!(res.success());
        assert_eq!(res.events.len(), 3);
        let m = res.merged();
        assert_eq!(m.joined("N").unwrap(), "0\n1");
        assert_eq!(m.get_str("Message").as_deref(), Some("list follows"));
        assert!(res
            .response
            .as_ref()
            .unwrap()
            .raw()
            .starts_with(b"Response: Success\r\nActionID: t1\r\n"));
        let res = ami.action("Bare", [("ActionID", "b1")]);
        assert_eq!(
            res.response.unwrap().raw(),
            &b"Response: Error\r\nActionID: b1\r\nMessage: one line.\n\r\n\r\n"[..]
        );
        let lines = ami.command("show things").unwrap();
        assert_eq!(
            lines,
            vec![BString::from("line one"), BString::from(&b"line \xe9"[..])]
        );
        let ev = ami
            .wait_event(
                Some("Custom"),
                &[("Name", Match::eq(b"caf\xe9"))],
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(ev.get("Name").unwrap(), &b"caf\xe9"[..]);
        assert!(ami
            .wait_event(
                Some("Custom"),
                &[("Name", Match::re("^x"))],
                Duration::from_millis(100)
            )
            .is_none());
    }

    #[test]
    fn fields_from_arguments() {
        let f = parse_fields(&["A=1".into(), "B: two words".into(), "C:x".into()]).unwrap();
        assert_eq!(
            f,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "x".into())
            ]
        );
        assert!(parse_fields(&["nothing".into()]).is_err());
    }
}
