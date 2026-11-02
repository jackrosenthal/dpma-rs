//! The methods-calls suite: the call methods of package P10 (queues,
//! parking, recording, phonebook, echo; the Rust form of
//! `tests/methods-calls/run.py`, `phone.py`, and `setup.sh`).
//!
//! ```text
//! cargo xtask test methods-calls methods-calls-phone methods-calls-http
//! ```
//!
//! runs it (`methods-calls-phone` with `--via phone`, `methods-calls-http`
//! with `--via http`) in the test container after building the devtest
//! module, as
//!
//! ```text
//! cargo test -p dpma-tests --test methods-calls -- --ignored [--via hook|phone|http] [PART...]
//! ```
//!
//! The suite prepares the instance (fresh configuration; the snippets of
//! `tests/data/methods-calls` are included from `res_digium_phone.conf`,
//! `queues.conf`, `res_parking.conf`, `extensions.conf`, and
//! `voicemail.conf`; `pjsip.conf` is changed so that AOR 1001 keeps one
//! contact (`remove_existing`) and endpoint 1001's mailbox is
//! `1001@p10vm`; the contacts files go into the file directory; with
//! `--via phone` or `--via http` also the test PKI; then the debug build is
//! installed and Asterisk restarted; `--no-prepare` skips this).  The
//! instance's `pjsip.conf` must have the endpoints 1001 (auth
//! 1001/secret1001) and 1002, as the scratch configuration has.
//!
//! The expected documents are the ones the original's
//! `phone_method_internal_api.c` builds.  How the methods are called
//! (`--via`):
//!
//! - `hook` (default): `dpmadev method call` (JSON) and `dpmadev calls
//!   xml` (XML) through the CLI; return codes are checked too.
//! - `phone` (package P12): encrypted AsteriskRequests from the phone
//!   simulator, authenticated as the phone (the test phones have no pin).
//! - `http`: HTTPRequests from the simulator.
//!
//! With `phone` and `http` the reply body must be the HTTP wrapper around
//! the same document; return codes are not visible that way.  The
//! simulator is identified by the module's PJSIP side (its
//! `X-Digium-User-Agent` header), so its test configuration is not
//! installed: its identify would also catch the test phone's REGISTER.
//!
//! Every part starts from a clean state (channels hung up, queue members
//! and statistics reset, the contacts files restored).  The recording
//! INFOs and the parked call MESSAGE are checked with a test phone (the
//! `sipua` UAS) registered as endpoint 1001 with a Digium user agent,
//! which needs the module's PJSIP side (`dpma_info_send` and
//! `dpma_pjsip_endpoint_is_dphone`).  The parts (about 25 seconds in all):
//!
//! | Part | Checks |
//! |---|---|
//! | `echo` | `test.dpma.api.echo` returns its parameters |
//! | `queues` | `switchvox.users.callQueues.*`: getList, login and logout (all queues, login and logout extensions, static members), pause and resume, getTodaysStatus with a call and a waiting caller, completed and abandoned calls, failures only logged |
//! | `phonebook` | `switchvox.users.phonebooks.entries.add`: required parameters, existing entries, empty lists, a second file, an unwritable file, the contact written |
//! | `parking` | `switchvox.users.parkingLots.getList` with parked calls, per parking application; the parked call event sent to the parker's phone, only for PARKED_CALL and PJSIP |
//! | `recording` | `switchvox.users.currentCalls.startRecording` and `stopRecording` (JSON and XML): MixMonitor, the INFOs sent to the phone, the errors |

mod calls;

use std::cell::{RefCell, RefMut};
use std::os::unix::fs::PermissionsExt;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bstr::ByteSlice;
use dpma_tests::harness::{fixtures, option_value, Checker, ConfFile, Ctx, Instance, Log, Suite};
use dpma_tests::sim::Phone;
use dpma_tests::sipua::{UaEvent, Uas, UasConfig};
use dpma_tests::util::{json_compact, json_python};
use regex::Regex;
use serde_json::{json, Value};

/// How the methods are called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// `dpmadev method call` and `dpmadev calls xml`.
    Hook,
    /// AsteriskRequests from the phone simulator.
    Phone,
    /// HTTPRequests from the phone simulator.
    Http,
}

/// The configuration snippets: the file that includes it, its name, and
/// its contents.
const SNIPPETS: [(&str, &str, &[u8]); 5] = [
    (
        "res_digium_phone.conf",
        "res_digium_phone_p10.conf",
        include_bytes!("../../data/methods-calls/res_digium_phone_p10.conf"),
    ),
    (
        "queues.conf",
        "queues_p10.conf",
        include_bytes!("../../data/methods-calls/queues_p10.conf"),
    ),
    (
        "res_parking.conf",
        "res_parking_p10.conf",
        include_bytes!("../../data/methods-calls/res_parking_p10.conf"),
    ),
    (
        "extensions.conf",
        "extensions_p10.conf",
        include_bytes!("../../data/methods-calls/extensions_p10.conf"),
    ),
    (
        "voicemail.conf",
        "voicemail_p10.conf",
        include_bytes!("../../data/methods-calls/voicemail_p10.conf"),
    ),
];

/// The contacts files (in the file directory).
const CONTACTS: [(&str, &[u8]); 2] = [
    (
        "p10contacts.xml",
        include_bytes!("../../data/methods-calls/p10contacts.xml"),
    ),
    (
        "p10contacts2.xml",
        include_bytes!("../../data/methods-calls/p10contacts2.xml"),
    ),
];

/// The file directory of an instance.
fn files_dir(inst: &Instance) -> std::path::PathBuf {
    inst.var_lib().join("digium_phones")
}

/// Writes the contacts files (writable again first).
fn install_contacts(inst: &Instance) -> Result<()> {
    let dir = files_dir(inst);
    std::fs::create_dir_all(&dir)?;
    for (name, data) in CONTACTS {
        let path = dir.join(name);
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        }
        std::fs::write(&path, data).with_context(|| path.display().to_string())?;
    }
    Ok(())
}

/// AOR 1001 keeps one contact and endpoint 1001's mailbox is
/// `1001@p10vm`.
fn edit_pjsip(conf: &ConfFile) -> Result<()> {
    let text = conf.read()?;
    let text = text.to_str_lossy();
    let section_re = Regex::new(r"^\[([^\]]+)\]").expect("regex");
    let type_re = Regex::new(r"^type\s*=").expect("regex");
    let max_re = Regex::new(r"^max_contacts\s*=").expect("regex");
    let mbox_re = Regex::new(r"^mailboxes\s*=").expect("regex");
    let mut out = Vec::new();
    let mut section: Option<(String, Option<String>)> = None;
    for line in text.split('\n') {
        let mut line = line.to_string();
        if let Some(c) = section_re.captures(&line) {
            section = Some((c[1].to_string(), None));
        } else if let (Some(s), true) = (section.as_mut(), type_re.is_match(&line)) {
            s.1 = line.split_once('=').map(|(_, v)| v.trim().to_string());
        }
        if let Some((name, ty)) = &section {
            if name == "1001" && ty.as_deref() == Some("aor") && max_re.is_match(&line) {
                line = "max_contacts=1\nremove_existing=yes".into();
            }
            if name == "1001" && mbox_re.is_match(&line) {
                line = "mailboxes=1001@p10vm".into();
            }
        }
        out.push(line);
    }
    conf.write(out.join("\n"))
}

/// Installs the test setup into the instance (the suite's `setup`).
fn setup(inst: &Instance, via: Via) -> Result<()> {
    for (main, snippet, data) in SNIPPETS {
        ConfFile::new(&inst.conf(snippet)).write(data)?;
        ConfFile::new(&inst.conf(main)).add_include(snippet)?;
    }
    edit_pjsip(&ConfFile::new(&inst.conf("pjsip.conf")))?;
    install_contacts(inst)?;
    if via != Via::Hook {
        fixtures::install_sim_pki(inst)?;
    }
    Ok(())
}

/// What the parts share.
pub struct State {
    via: Via,
    /// Whether the hooks were found (and the simulator started).
    ready: bool,
    /// The simulated phone (`--via phone` and `--via http`).
    phone: Option<Phone>,
}

/// A part's view of the suite.
pub struct T<'a> {
    ctx: &'a mut Ctx,
    st: RefMut<'a, State>,
}

/// A call's return code (`None` unless `--via hook`) and response.
pub type Got = (Option<i64>, String);

impl<'a> T<'a> {
    fn new(ctx: &'a mut Ctx, st: &'a RefCell<State>) -> T<'a> {
        T {
            ctx,
            st: st.borrow_mut(),
        }
    }

    /// The checks.
    pub fn c(&mut self) -> &mut Checker {
        &mut self.ctx.c
    }

    /// How the methods are called.
    pub fn via(&self) -> Via {
        self.st.via
    }

    /// The instance.
    pub fn inst(&self) -> &Instance {
        &self.ctx.inst
    }

    /// A CLI command (as `asterisk -rx`); its output.
    pub fn cli(&self, cmd: &str) -> String {
        self.ctx.cli_text(cmd)
    }

    /// The instance's `messages.log`.
    pub fn log(&self) -> Log {
        self.ctx.log()
    }

    /// Checks once that the hooks are there and, unless `--via hook`,
    /// handshakes as p10phone and gets a token (an authenticated session
    /// is never pruned).
    fn ready(&mut self) -> Result<()> {
        if self.st.ready {
            return Ok(());
        }
        if !self
            .cli("dpmadev method call p10phone test.dpma.api.echo {}")
            .contains("Return code")
        {
            bail!("dpmadev hooks not available (devtest build installed and Asterisk running?)");
        }
        if self.st.via != Via::Hook {
            let opts = self.ctx.sim_options().mac("000fd3000010");
            let phone = fixtures::phone_with_token(opts, "p10phone", fixtures::GLOBALPIN)?;
            self.st.phone = Some(phone);
        }
        self.st.ready = true;
        Ok(())
    }

    /// Return codes are only visible through the hooks.
    pub fn rc_ok(&self, rc: Option<i64>, want: i64) -> bool {
        rc == Some(want) || self.st.via != Via::Hook
    }

    /// Sends a request document as `phone` (no pin).
    fn call_phone(&mut self, phone: &str, doc: &str) -> Result<Got> {
        let http = self.st.via == Via::Http;
        let sim = self.st.phone.as_ref().expect("ready");
        let req = if http {
            sim.http(doc)
        } else {
            sim.asterisk(doc)
        };
        let ex = req
            .auth(format!("{phone}:"))
            .timeout(Duration::from_secs(10))
            .send()?;
        let want = if http {
            "HTTPResponse"
        } else {
            "AsteriskResponse"
        };
        let r = match ex.reply() {
            Some(r) if r.ok() && r.is_response(want) => r,
            _ => {
                let d = ex.describe(0).to_str_lossy().into_owned();
                return Ok((None, format!("(no reply or a bad one: {d})")));
            }
        };
        let body = &r.payload;
        let pre = fixtures::HTTP_PREAMBLE;
        if !body.starts_with(pre) || !body.ends_with(b"\r\n\r\n") {
            return Ok((None, format!("(not wrapped: {body:?})")));
        }
        let end = body.len() - 4;
        Ok((
            None,
            body.get(pre.len()..end)
                .unwrap_or_default()
                .to_str_lossy()
                .into_owned(),
        ))
    }

    /// Calls a JSON method as `phone`.
    pub fn call(&mut self, phone: &str, method: &str, params: &Value) -> Result<Got> {
        if self.st.via != Via::Hook {
            let doc = json_python(&json!({"request": {"method": method, "parameters": params}}));
            return self.call_phone(phone, &doc);
        }
        let out = self.cli(&format!(
            "dpmadev method call {phone} {method} {}",
            fixtures::cli_quote(&json_python(params))
        ));
        let re = Regex::new(r"(?s)^Return code: (-?\d+)\n(?:\(empty response body.*\n)?(.*)")
            .expect("regex");
        let Some(c) = re.captures(&out) else {
            return Ok((None, out));
        };
        let body = if out.contains("(empty response body") {
            String::new()
        } else {
            c[2].trim().to_string()
        };
        Ok((c[1].parse().ok(), body))
    }

    /// Calls an XML method as `phone` with a parameters element.
    pub fn call_xml(&mut self, phone: &str, method: &str, params: &str) -> Result<Got> {
        if self.st.via != Via::Hook {
            return self.call_phone(
                phone,
                &format!("<request method=\"{method}\">{params}</request>"),
            );
        }
        let out = self.cli(&format!(
            "dpmadev calls xml {phone} {method} {}",
            fixtures::cli_quote(params)
        ));
        let re = Regex::new(r"(?s)^Return code: (-?\d+)\n(.*)").expect("regex");
        let Some(c) = re.captures(&out) else {
            return Ok((None, out));
        };
        let body = c[2]
            .trim_end_matches('\n')
            .replace("\\r", "\r")
            .replace("\\n", "\n");
        Ok((c[1].parse().ok(), body))
    }

    /// Checks a call's return code and response (`want`: the expected
    /// document).
    pub fn expect(&mut self, name: &str, got: Got, code: i64, want: &str) {
        let (rc, body) = got;
        let ok = self.rc_ok(rc, code) && body == want;
        self.c().check_with(name, ok, || {
            format!("return {rc:?} (want {code})\ngot  {body}\nwant {want}")
        });
    }

    /// Whether `text` was logged since `mark`, waiting up to 3 s.
    pub fn logged(&self, mark: dpma_tests::harness::LogMark, text: &str) -> bool {
        self.log().wait_for(mark, text, Duration::from_secs(3))
    }

    /// Hangs up every channel, takes the dynamic queue members out, resets
    /// the queue statistics, and restores the contacts files.
    pub fn reset(&mut self) -> Result<()> {
        self.cli("channel request hangup all");
        for (q, iface) in [
            ("p10sales", "Local/agent@p10test"),
            ("p10support", "Local/1001@p10test"),
        ] {
            self.cli(&format!("queue remove member {iface} from {q}"));
        }
        self.cli("queue reset stats");
        install_contacts(self.inst())?;
        fixtures::sleep(1.0);
        Ok(())
    }
}

/// A successful response document.
pub fn ok(method: &str, result: Value) -> String {
    json_compact(&json!({"response": {"method": method, "result": result}}))
}

/// An error response document.
pub fn err(method: &str, code: u32, message: &str) -> String {
    json_compact(
        &json!({"response": {"method": method, "errors": {"error": {"code": code, "message": message}}}}),
    )
}

/// An XML error response document.
pub fn xml_err(method: &str, code: u32, text: &str) -> String {
    format!(
        "<response method=\"{method}\">\r\n<errors>\r\n<error code=\"{code}\" message=\"{text}\" />\r\n</errors>\r\n</response>\r\n"
    )
}

/// An XML success response document.
pub fn xml_ok(method: &str) -> String {
    format!(
        "<response method=\"{method}\">\r\n<result>\r\n<success />\r\n</result>\r\n</response>\r\n"
    )
}

/// The test phone: endpoint 1001 with a Digium user agent, answering
/// every call, and its transcript as `phone.py` wrote it.
pub struct PhoneLog {
    uas: Option<Uas>,
    text: String,
}

impl PhoneLog {
    /// Registers the phone (for 60 seconds at most) and waits for the
    /// registration.
    pub fn start(t: &T) -> Result<PhoneLog> {
        let mut cfg = UasConfig::new("1001", "secret1001", Duration::from_secs(60));
        cfg.user_agent = "Digium D65 2_9_17".into();
        cfg.expires = 65;
        let uas = Uas::spawn("127.0.0.1", t.inst().sip_port, cfg)?;
        let mut log = PhoneLog {
            uas: Some(uas),
            text: String::new(),
        };
        dpma_tests::util::wait_until(Duration::from_secs(10), Duration::from_millis(100), || {
            log.text().contains("registered")
        });
        Ok(log)
    }

    fn add(&mut self, e: &UaEvent) {
        let mut line = |s: String| {
            self.text.push_str(&s);
            self.text.push('\n');
        };
        match e {
            UaEvent::Registered(s) if s.starts_with("SIP/2.0 200") => line("registered".into()),
            UaEvent::Invite(_, m, _) => line(format!(
                "INVITE call-id={}",
                m.get_str("Call-ID").unwrap_or_default()
            )),
            UaEvent::Info(m) | UaEvent::Message(m) => {
                line(format!("{} received:", m.method().unwrap_or_default()));
                let head: Vec<String> = m
                    .headers
                    .iter()
                    .map(|(k, v)| format!("  {k}: {}", v.to_str_lossy()))
                    .collect();
                line(head.join("\n"));
                line(format!("  body: {}", m.body.to_str_lossy()));
            }
            UaEvent::Bye(_) => line("BYE".into()),
            _ => {}
        }
    }

    /// The transcript so far.
    pub fn text(&mut self) -> String {
        while let Some(e) = self.uas.as_mut().and_then(|u| u.next(Duration::ZERO)) {
            self.add(&e);
        }
        self.text.clone()
    }

    /// Stops the phone (it unregisters).
    pub fn stop(mut self) {
        if let Some(u) = self.uas.take() {
            u.stop();
        }
    }
}

type PartFn = fn(&mut T) -> Result<()>;

fn main() -> ExitCode {
    let via = match option_value("--via").as_deref() {
        None | Some("hook") => Via::Hook,
        Some("phone") => Via::Phone,
        Some("http") => Via::Http,
        Some(v) => {
            eprintln!("methods-calls: unknown --via {v} (hook, phone, or http)");
            return ExitCode::from(2);
        }
    };
    let state = Rc::new(RefCell::new(State {
        via,
        ready: false,
        phone: None,
    }));
    let parts: [(&str, PartFn); 5] = [
        ("echo", calls::echo),
        ("queues", calls::queues),
        ("phonebook", calls::phonebook),
        ("parking", calls::parking),
        ("recording", calls::recording),
    ];
    let mut suite = Suite::new("methods-calls")
        .value_option("--via")
        .prepare(move |inst| fixtures::prepare(inst, |i| setup(i, via)));
    for (name, f) in parts {
        let st = state.clone();
        suite = suite.part(name, move |ctx| {
            let mut t = T::new(ctx, &st);
            t.ready()?;
            t.reset()?;
            f(&mut t)
        });
    }
    suite.main()
}
