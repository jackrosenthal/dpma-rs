//! The methods-calls suite: the call methods (queues, parking, recording,
//! phonebook, and echo).
//!
//! ```text
//! cargo xtask test methods-calls
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test methods-calls -- --ignored [PART...]
//! ```
//!
//! The suite prepares the instance (`--no-prepare` skips this).  The
//! instance's `pjsip.conf` must have the endpoints 1001 (auth
//! 1001/secret1001) and 1002, as the scratch configuration has.
//!
//! The expected documents are the ones the official DPMA builds.  The
//! methods are called with `dpmadev method call` (JSON) and `dpmadev calls
//! xml` (XML) through the CLI, and their return codes are checked too.
//! (The method code does not depend on how a request arrives; the
//! request-handlers suite checks the AsteriskRequest and HTTPRequest
//! paths.)
//!
//! Every part starts from a clean state.  The recording INFOs and the
//! parked call MESSAGE are checked with a test phone registered as
//! endpoint 1001 with a Digium user agent, which needs the module's PJSIP
//! side.

mod calls;

use std::cell::{RefCell, RefMut};
use std::os::unix::fs::PermissionsExt;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bstr::ByteSlice;
use dpma_proto::json::dump as json_compact;
use dpma_tests::harness::{fixtures, Checker, ConfFile, Ctx, Instance, Log, Suite};
use dpma_tests::sipua::{UaEvent, Uas, UasConfig};
use regex::Regex;
use serde_json::{json, Value};

/// The configuration snippets: the file that includes it, its name, and
/// its contents.
const SNIPPETS: [(&str, &str, &[u8]); 5] = [
    (
        "res_digium_phone.conf",
        "res_digium_phone_calls.conf",
        include_bytes!("../../data/methods-calls/res_digium_phone_calls.conf"),
    ),
    (
        "queues.conf",
        "queues_calls.conf",
        include_bytes!("../../data/methods-calls/queues_calls.conf"),
    ),
    (
        "res_parking.conf",
        "res_parking_calls.conf",
        include_bytes!("../../data/methods-calls/res_parking_calls.conf"),
    ),
    (
        "extensions.conf",
        "extensions_calls.conf",
        include_bytes!("../../data/methods-calls/extensions_calls.conf"),
    ),
    (
        "voicemail.conf",
        "voicemail_calls.conf",
        include_bytes!("../../data/methods-calls/voicemail_calls.conf"),
    ),
];

/// The contacts files (in the file directory).
const CONTACTS: [(&str, &[u8]); 2] = [
    (
        "contacts.xml",
        include_bytes!("../../data/methods-calls/contacts.xml"),
    ),
    (
        "contacts2.xml",
        include_bytes!("../../data/methods-calls/contacts2.xml"),
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
/// `1001@testvm`.
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
                line = "mailboxes=1001@testvm".into();
            }
        }
        out.push(line);
    }
    conf.write(out.join("\n"))
}

/// Installs the test setup into the instance (the suite's `setup`).
fn setup(inst: &Instance) -> Result<()> {
    for (main, snippet, data) in SNIPPETS {
        ConfFile::new(&inst.conf(snippet)).write(data)?;
        ConfFile::new(&inst.conf(main)).add_include(snippet)?;
    }
    edit_pjsip(&ConfFile::new(&inst.conf("pjsip.conf")))?;
    install_contacts(inst)
}

/// What the parts share.
pub struct State {
    /// Whether the hooks were found.
    ready: bool,
}

/// A part's view of the suite.
pub struct T<'a> {
    ctx: &'a mut Ctx,
    st: RefMut<'a, State>,
}

/// A call's return code (`None` when the hook's output has none) and
/// response.
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

    /// Checks once that the hooks are there.
    fn ready(&mut self) -> Result<()> {
        if self.st.ready {
            return Ok(());
        }
        if !self
            .cli("dpmadev method call testphone test.dpma.api.echo {}")
            .contains("Return code")
        {
            bail!("dpmadev hooks not available (devtest build installed and Asterisk running?)");
        }
        self.st.ready = true;
        Ok(())
    }

    /// Whether the return code is `want`.
    pub fn rc_ok(&self, rc: Option<i64>, want: i64) -> bool {
        rc == Some(want)
    }

    /// Calls a JSON method as `phone`.
    pub fn call(&mut self, phone: &str, method: &str, params: &Value) -> Result<Got> {
        let out = self.cli(&format!(
            "dpmadev method call {phone} {method} {}",
            fixtures::cli_quote(&dpma_proto::json::dump(params))
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

    /// Hangs up every channel (waiting until they are gone), takes the
    /// dynamic queue members out, resets the queue statistics, and
    /// restores the contacts files.
    pub fn reset(&mut self) -> Result<()> {
        self.cli("channel request hangup all");
        let gone = until(5.0, || {
            self.cli("core show channels count")
                .contains("0 active channels")
        });
        if !gone {
            bail!("channels still up after hangup all");
        }
        for (q, iface) in [
            ("testsales", "Local/agent@calls"),
            ("testsupport", "Local/1001@calls"),
        ] {
            self.cli(&format!("queue remove member {iface} from {q}"));
        }
        self.cli("queue reset stats");
        install_contacts(self.inst())
    }
}

/// Polls `f` every 50 ms until it holds, for at most `secs` seconds;
/// whether it did.
pub fn until(secs: f64, f: impl FnMut() -> bool) -> bool {
    dpma_tests::util::wait_until(Duration::from_secs_f64(secs), Duration::from_millis(50), f)
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
/// every call, and its transcript.
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
    let state = Rc::new(RefCell::new(State { ready: false }));
    let parts: [(&str, PartFn); 5] = [
        ("echo", calls::echo),
        ("queues", calls::queues),
        ("phonebook", calls::phonebook),
        ("parking", calls::parking),
        ("recording", calls::recording),
    ];
    let mut suite = Suite::new("methods-calls").prepare(|inst| fixtures::prepare(inst, setup));
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
