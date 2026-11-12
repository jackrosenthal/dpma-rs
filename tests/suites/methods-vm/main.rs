//! The methods-vm suite: end-to-end checks of the
//! `switchvox.users.voicemail.*` methods.
//!
//! ```text
//! cargo xtask test methods-vm
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test methods-vm -- --ignored [PART...]
//! ```
//!
//! The suite prepares the instance (`--no-prepare` skips this).  The
//! instance's `pjsip.conf` must have the endpoint 1001 (auth
//! 1001/secret1001), as the scratch configuration has.
//!
//! Each response is compared, as text, with the document the official
//! DPMA builds (key order included), computed from the spool and a model
//! of the decompile; the spool and the message trackers are checked after
//! each change.
//!
//! The methods are called with `dpmadev method call` over AMI, and their
//! return codes are checked too.  (No voicemail method depends on how a
//! request arrives; the request-handlers suite checks the AsteriskRequest
//! path.)  The simulator's test configuration is not installed: its
//! identify would also catch the test phone's REGISTER, and the module's
//! PJSIP side identifies the simulator.
//!
//! The parts run in order and build on each other's spool and trackers.

mod model;
mod scenarios;
mod spool;

use std::cell::{RefCell, RefMut};
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{bail, Result};
use bstr::{BString, ByteSlice};
use dpma_tests::harness::{fixtures, Checker, ConfFile, Ctx, Instance, LogMark, Suite};
use dpma_tests::sim::Phone;
use regex::Regex;
use serde_json::Value;

use model::{err_doc, ok_doc, VM};
use spool::Spool;

/// The simulated phone's credentials (an AsteriskRequest's).
const VMPHONE_AUTH: &str = "vmphone:1234";

/// What the parts share.
pub struct State {
    /// The simulated phone (vmphone), once started.
    phone: Option<Phone>,
}

/// A part's view of the suite.
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

    /// The instance.
    pub fn inst(&self) -> &Instance {
        &self.ctx.inst
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

    /// Calls a method as vmphone the way phones do, in an encrypted
    /// AsteriskRequest from the simulator (started first if needed): the
    /// response without the HTTP wrapper, and the number of chunks the
    /// reply came in.
    pub fn call_phone(&mut self, method: &str, params: &Value) -> Result<(String, usize)> {
        if self.st.phone.is_none() {
            self.start_phone()?;
        }
        let text = dpma_proto::json::dump(params);
        let doc = format!(r#"{{"request": {{"method": "{VM}{method}", "parameters": {text}}}}}"#);
        let sim = self.st.phone.as_ref().expect("started");
        let ex = sim
            .asterisk(doc)
            .auth(VMPHONE_AUTH)
            .timeout(Duration::from_secs(10))
            .send()?;
        let r = match ex.reply() {
            Some(r) if r.ok() => r,
            _ => {
                let d = ex.describe(0).to_str_lossy().into_owned();
                return Ok((format!("(no reply or a bad one: {d})"), 0));
            }
        };
        let parts = r.parts.len();
        let body: BString = r.payload.clone();
        let pre = fixtures::HTTP_PREAMBLE;
        if !body.starts_with(pre) || !body.ends_with(b"\r\n\r\n") {
            return Ok((format!("(not wrapped: {body:?})"), parts));
        }
        let end = body.len() - 4;
        let doc = body.get(pre.len()..end).unwrap_or_default();
        Ok((doc.to_str_lossy().into_owned(), parts))
    }

    /// Calls a method as `phone` (`dpmadev method call`): (return code,
    /// response).
    pub fn call(
        &mut self,
        phone: &str,
        method: &str,
        params: &Value,
    ) -> Result<(Option<i64>, String)> {
        let text = dpma_proto::json::dump(params);
        let esc = text.replace('\\', "\\\\").replace('"', "\\\"");
        let out = self.cli(&format!("dpmadev method call {phone} {VM}{method} {esc}"))?;
        let re = Regex::new(r"^Return code: (-?\d+)").expect("regex");
        let rc = out
            .first()
            .and_then(|l| re.captures(l))
            .and_then(|c| c[1].parse().ok());
        Ok((rc, out.last().cloned().unwrap_or_default()))
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
        let (rc, body) = self.call(phone, method, &params)?;
        self.c().same(format!("{name} (code)"), rc, Some(-1));
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
        let (rc, body) = self.call(phone, method, &params)?;
        self.c().same(format!("{name} (code)"), rc, Some(0));
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

    /// What was logged since `mark`, once `wanted` was (Asterisk's logger
    /// writes from its own thread; at most 3 s).
    pub fn log_since(&self, mark: LogMark, wanted: &str) -> BString {
        let log = self.ctx.log();
        log.wait_for(mark, wanted, Duration::from_secs(3));
        log.since(mark)
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
            Duration::from_millis(50),
            || {
                let msgs = self.spool.all(&mbox);
                msgs.len() > before && msgs.iter().all(|m| m.has("duration"))
            },
        );
        if !saved {
            bail!("message for {exten} was not saved");
        }
        Ok(())
    }
}

/// Installs the test setup into the instance (the suite's `setup`).
fn setup(inst: &Instance) -> Result<()> {
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
    Ok(())
}

type PartFn = fn(&mut Vm) -> Result<()>;

fn main() -> ExitCode {
    let state = Rc::new(RefCell::new(State { phone: None }));
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
    let mut suite = Suite::new("methods-vm").prepare(|inst| fixtures::prepare(inst, setup));
    for (name, f) in parts {
        let st = state.clone();
        suite = suite.part(name, move |ctx| f(&mut Vm::new(ctx, &st)));
    }
    suite.main()
}
