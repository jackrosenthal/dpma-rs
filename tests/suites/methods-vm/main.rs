//! The methods-vm suite: end-to-end checks of the
//! `switchvox.users.voicemail.*` methods (packages P9, P12, and P14; the
//! Rust form of `tests/methods-vm/run.py`, `vm_uas.py`, and `setup.sh`).
//!
//! ```text
//! cargo xtask test methods-vm methods-vm-phone
//! ```
//!
//! runs it (`methods-vm-phone` with `--via phone`) in the test container
//! after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test methods-vm -- --ignored [--via hook|phone] [PART...]
//! ```
//!
//! The suite prepares the instance (fresh configuration; the test
//! `res_digium_phone.conf` and `voicemail.conf` of `tests/data/methods-vm`
//! replace the instance's, `extensions_dpma_vm.conf` is included from
//! `extensions.conf`, and the test mailboxes' spool is emptied; with
//! `--via phone` also the test PKI; then the debug build is installed and
//! Asterisk restarted; `--no-prepare` skips this).  The instance's
//! `pjsip.conf` must have the endpoint 1001 (auth 1001/secret1001), as
//! the scratch configuration has.
//!
//! It leaves messages with the dialplan (Local channels into
//! `VoiceMail()`), adds hand-made spool messages for unusual caller ids,
//! and calls every method.  Each response is compared, as text, with the
//! document the original builds (key order included), computed from the
//! spool and a model of the decompile; the spool and the message trackers
//! (`dpmadev vm trackers`) are checked after each change.
//!
//! How the methods are called (`--via`):
//!
//! - `hook` (default): `dpmadev method call` over AMI; return codes are
//!   checked too.
//! - `phone` (package P12): the way phones call them, as encrypted
//!   AsteriskRequests from the phone simulator with the phone's name and
//!   pin as the credentials.  The reply body must be the HTTP wrapper
//!   around the same document; return codes are not visible that way, and
//!   calls for phones that cannot authenticate are skipped.  This mode
//!   also checks that a phone's new session (a TokenRequest after a new
//!   handshake) drops its message trackers, and lists a page of 50 of 55
//!   messages (a reply of many chunks).  The simulator's test
//!   configuration is not installed: its identify would also catch the
//!   test phone's REGISTER, and the module's PJSIP side identifies the
//!   simulator.
//!
//! The parts run in this order and build on each other's spool and
//! trackers (about 50 seconds in all):
//!
//! | Part | Checks |
//! |---|---|
//! | `messages` | Empties the test mailboxes and leaves the messages (no checks) |
//! | `folder-list` | getFolderList: translated and plain names, counts, another voicemail context, the errors |
//! | `get-list` | getList: translated folders, sort orders, paging, caller id forms, the trackers, the errors (and the deviations from the original's crashes) |
//! | `mark` | markRead and markUnread: moves between INBOX and Old, Urgent, translated ids, Friends refused, the errors |
//! | `move` | move: the response ids, stale trackers, Recordings (Cust5), the errors |
//! | `forward` | forward: copies to other mailboxes and contexts, the errors |
//! | `remove` | remove: renumbering, stale trackers, the errors |
//! | `play` | play: a registered test phone (the `sipua` UAS) gets the INVITE with the event header, DigiumVoicemailPlayback plays the message, DTMF fast forward and rewind send location INFOs; a busy phone, an unregistered one, the errors |
//! | `trackers` | Trackers dropped with their phone on a reload, by `dpmadev vm forget`, and (with `--via phone`) by a new session |
//! | `big-list` | getList of 55 messages, two pages (with `--via phone`, replies of many chunks) |

mod model;
mod scenarios;
mod spool;

use std::cell::{RefCell, RefMut};
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{bail, Result};
use bstr::{BString, ByteSlice};
use dpma_tests::harness::{
    fixtures, option_value, Checker, ConfFile, Ctx, Instance, LogMark, Suite,
};
use dpma_tests::sim::Phone;
use regex::Regex;
use serde_json::Value;

use model::{err_doc, ok_doc, VM};
use spool::Spool;

/// How the methods are called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// `dpmadev method call`.
    Hook,
    /// AsteriskRequests from the phone simulator.
    Phone,
}

/// The test phones and their pins (`--via phone`).
const PINS: [(&str, &str); 5] = [
    ("vmphone", "1234"),
    ("vmphone2", "2222"),
    ("vmphone3", "3333"),
    ("nomboxphone", "4444"),
    ("ghostphone", "5555"),
];

fn pin(phone: &str) -> Option<&'static str> {
    PINS.iter().find(|(p, _)| *p == phone).map(|(_, pin)| *pin)
}

/// What the parts share.
pub struct State {
    via: Via,
    /// The simulated phone (`--via phone`).
    phone: Option<Phone>,
    /// The number of chunks of each reply received with `--via phone`.
    replies: Vec<usize>,
}

/// A part's view of the suite: the context, the shared state, and the
/// spool.
pub struct Vm<'a> {
    ctx: &'a mut Ctx,
    st: RefMut<'a, State>,
    /// The instance's voicemail spool.
    pub spool: Spool,
}

impl<'a> Vm<'a> {
    fn new(ctx: &'a mut Ctx, st: &'a RefCell<State>) -> Vm<'a> {
        let spool = Spool::new(ctx.inst.spool().join("voicemail"));
        Vm {
            ctx,
            st: st.borrow_mut(),
            spool,
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

    /// The chunk counts of the replies received so far.
    pub fn replies(&self) -> &[usize] {
        &self.st.replies
    }

    /// A CLI command over AMI; its output lines.
    pub fn cli(&mut self, cmd: &str) -> Result<Vec<String>> {
        let lines = self.ctx.ami()?.command(cmd)?;
        Ok(lines
            .iter()
            .map(|l| l.to_str_lossy().into_owned())
            .collect())
    }

    /// An AMI action.
    pub fn ami_action(&mut self, action: &str, fields: &[(&str, &str)]) -> Result<()> {
        self.ctx.ami()?.action(action, fields.iter().copied());
        Ok(())
    }

    /// Handshakes as vmphone and gets a token, so that the session is
    /// authenticated (and never pruned while the checks run); starts the
    /// simulator first if needed.
    pub fn start_phone(&mut self) -> Result<()> {
        if self.st.phone.is_none() {
            let opts = self.ctx.sim_options().mac("000fd3vm0001");
            self.st.phone = Some(Phone::start(opts)?);
        }
        let phone = self.st.phone.as_ref().expect("started");
        let ex = phone.handshake().send()?;
        if !ex.ok() {
            bail!("handshake failed:\n{}", ex.describe(0));
        }
        let ex = phone
            .get_token()
            .user("vmphone")
            .config_password(fixtures::GLOBALPIN)
            .send()?;
        if !ex.ok() {
            bail!("token failed:\n{}", ex.describe(0));
        }
        Ok(())
    }

    fn call_phone(&mut self, phone: &str, method: &str, text: &str) -> Result<String> {
        if self.st.phone.is_none() {
            self.start_phone()?;
        }
        let doc = format!(r#"{{"request": {{"method": "{VM}{method}", "parameters": {text}}}}}"#);
        let auth = format!("{phone}:{}", pin(phone).unwrap_or_default());
        let sim = self.st.phone.as_ref().expect("started");
        let ex = sim
            .asterisk(doc)
            .auth(auth)
            .timeout(Duration::from_secs(10))
            .send()?;
        let r = match ex.reply() {
            Some(r) if r.ok() => r,
            _ => {
                return Ok(format!(
                    "(no reply or a bad one: {})",
                    ex.describe(0).to_str_lossy()
                ))
            }
        };
        let parts = r.parts.len();
        let body: BString = r.payload.clone();
        self.st.replies.push(parts);
        let pre = fixtures::HTTP_PREAMBLE;
        if !body.starts_with(pre) || !body.ends_with(b"\r\n\r\n") {
            return Ok(format!("(not wrapped: {body:?})"));
        }
        let end = body.len() - 4;
        Ok(body
            .get(pre.len()..end)
            .unwrap_or_default()
            .to_str_lossy()
            .into_owned())
    }

    /// Calls a method as `phone`: (return code, response).  The return
    /// code is `None` with `--via phone`.
    pub fn call(
        &mut self,
        phone: &str,
        method: &str,
        params: &Value,
    ) -> Result<(Option<i64>, String)> {
        let text = dpma_tests::util::json_compact(params);
        if self.via() == Via::Phone {
            return Ok((None, self.call_phone(phone, method, &text)?));
        }
        let esc = text.replace('\\', "\\\\").replace('"', "\\\"");
        let out = self.cli(&format!("dpmadev method call {phone} {VM}{method} {esc}"))?;
        let re = Regex::new(r"^Return code: (-?\d+)").expect("regex");
        let rc = out
            .first()
            .and_then(|l| re.captures(l))
            .and_then(|c| c[1].parse().ok());
        Ok((rc, out.last().cloned().unwrap_or_default()))
    }

    /// With `--via phone`, a phone that cannot authenticate cannot call.
    fn skipped(&self, name: &str, phone: &str) -> bool {
        if self.via() == Via::Phone && pin(phone).is_none() {
            self.ctx.c.skip(name, format!("no credentials for {phone}"));
            return true;
        }
        false
    }

    /// Checks that a call fails with an error document.
    pub fn expect_error(
        &mut self,
        name: &str,
        phone: &str,
        method: &str,
        params: Value,
        code: u32,
        detail: &str,
    ) -> Result<()> {
        if self.skipped(name, phone) {
            return Ok(());
        }
        let (rc, body) = self.call(phone, method, &params)?;
        if self.via() == Via::Hook {
            self.c().same(format!("{name} (code)"), rc, Some(-1));
        }
        self.c().same(name, body, err_doc(method, code, detail));
        Ok(())
    }

    /// Checks that a call succeeds with `result`.
    pub fn expect_ok(
        &mut self,
        name: &str,
        phone: &str,
        method: &str,
        params: Value,
        result: Value,
    ) -> Result<()> {
        if self.skipped(name, phone) {
            return Ok(());
        }
        let (rc, body) = self.call(phone, method, &params)?;
        if self.via() == Via::Hook {
            self.c().same(format!("{name} (code)"), rc, Some(0));
        }
        self.c().same(name, body, ok_doc(method, result));
        Ok(())
    }

    /// The message trackers of a phone: (id, folder), or `None`.
    pub fn trackers(&mut self, phone: &str) -> Result<Option<Vec<(String, String)>>> {
        let out = self.cli(&format!("dpmadev vm trackers {phone}"))?;
        if out.len() < 2 {
            return Ok(None);
        }
        Ok(Some(
            out[2..]
                .iter()
                .map(|l| {
                    let l = l.trim();
                    match l.split_once(" => ") {
                        Some((a, b)) => (a.to_string(), b.to_string()),
                        None => (l.to_string(), String::new()),
                    }
                })
                .collect(),
        ))
    }

    /// The folder of a phone's tracker for message `id`.
    pub fn tracker(&mut self, phone: &str, id: &str) -> Result<Option<String>> {
        Ok(self
            .trackers(phone)?
            .unwrap_or_default()
            .into_iter()
            .rev()
            .find(|(i, _)| i == id)
            .map(|(_, f)| f))
    }

    /// The end of `messages.log`.
    pub fn log_mark(&self) -> LogMark {
        self.ctx.log().mark()
    }

    /// What was logged since `mark` (after a moment: Asterisk's logger
    /// writes from its own thread).
    pub fn log_since(&self, mark: LogMark) -> BString {
        fixtures::sleep(0.3);
        self.ctx.log().since(mark)
    }

    /// Leaves a 2 s message through `VoiceMail()` and waits until it is
    /// saved.
    pub fn leave(
        &mut self,
        exten: &str,
        cid: &str,
        context: &str,
        mbox: Option<&str>,
    ) -> Result<()> {
        let mbox = mbox
            .map(str::to_string)
            .unwrap_or_else(|| format!("default/{exten}"));
        let before = self.spool.all(&mbox).len();
        let channel = format!("Local/{exten}@{context}");
        self.ami_action(
            "Originate",
            &[
                ("Channel", &channel),
                ("Context", "dpma-vm-source"),
                ("Exten", "tone"),
                ("Priority", "1"),
                ("CallerID", cid),
                ("Async", "true"),
            ],
        )?;
        let saved = dpma_tests::util::wait_until(
            Duration::from_secs(15),
            Duration::from_millis(200),
            || {
                let msgs = self.spool.all(&mbox);
                msgs.len() > before && msgs.iter().all(|m| m.has("duration"))
            },
        );
        if !saved {
            bail!("message for {exten} was not saved");
        }
        fixtures::sleep(1.1); // distinct origtimes
        Ok(())
    }
}

/// Installs the test setup into the instance (the suite's `setup`).
fn setup(inst: &Instance, via: Via) -> Result<()> {
    let data: [(&str, &[u8]); 3] = [
        (
            "res_digium_phone.conf",
            include_bytes!("../../data/methods-vm/res_digium_phone.conf"),
        ),
        (
            "voicemail.conf",
            include_bytes!("../../data/methods-vm/voicemail.conf"),
        ),
        (
            "extensions_dpma_vm.conf",
            include_bytes!("../../data/methods-vm/extensions_dpma_vm.conf"),
        ),
    ];
    for (name, text) in data {
        ConfFile::new(&inst.conf(name)).write(text)?;
    }
    ConfFile::new(&inst.conf("extensions.conf")).add_include("extensions_dpma_vm.conf")?;
    let spool = Spool::new(inst.spool().join("voicemail"));
    for b in ["default/1001", "default/1002", "default/1003", "other/2001"] {
        spool.remove(b);
    }
    if via == Via::Phone {
        fixtures::install_sim_pki(inst)?;
    }
    Ok(())
}

type PartFn = fn(&mut Vm) -> Result<()>;

fn main() -> ExitCode {
    let via = match option_value("--via").as_deref() {
        None | Some("hook") => Via::Hook,
        Some("phone") => Via::Phone,
        Some(v) => {
            eprintln!("methods-vm: unknown --via {v} (hook or phone)");
            return ExitCode::from(2);
        }
    };
    let state = Rc::new(RefCell::new(State {
        via,
        phone: None,
        replies: Vec::new(),
    }));
    let parts: [(&str, PartFn); 10] = [
        ("messages", scenarios::messages),
        ("folder-list", scenarios::folder_list),
        ("get-list", scenarios::get_list),
        ("mark", scenarios::mark),
        ("move", scenarios::move_),
        ("forward", scenarios::forward),
        ("remove", scenarios::remove),
        ("play", scenarios::play),
        ("trackers", scenarios::tracker_lifecycle),
        ("big-list", scenarios::big_list),
    ];
    let mut suite = Suite::new("methods-vm")
        .value_option("--via")
        .prepare(move |inst| fixtures::prepare(inst, |i| setup(i, via)));
    for (name, f) in parts {
        let st = state.clone();
        suite = suite.part(name, move |ctx| f(&mut Vm::new(ctx, &st)));
    }
    suite.main()
}
