//! The pjsip-helpers suite: the module's PJSIP side, which does what the
//! official DPMA's two PJSIP helper modules do,
//! `res_pjsip_endpoint_identifier_dpma` and
//! `res_pjsip_dialog_info_digium_body_supplement`
//! (`crates/res_dpma_rs/src/pjsip/`).
//!
//! ```text
//! cargo xtask test pjsip-helpers
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test pjsip-helpers -- --ignored [--no-prepare] [-v] [PART...]
//! ```
//!
//! The suite prepares the instance (`--no-prepare` skips this) and runs
//! each part after restarting Asterisk.
//!
//! The transcripts, which do not depend on ports, addresses, tags, thread
//! IDs, or times, go to `<instance>/pjsip-helpers/`; `-v` also prints them
//! as they are made.  When the identifier transcript differs, the check
//! shows a unified diff (`-` expected, `+` now); to accept a new
//! transcript, copy `identifier.txt` over the expected one.
//!
//! `expected-identifier.txt` is the official DPMA helper's transcript,
//! byte for byte, except where merging the helpers into one module changes
//! it by design, and except for the last step, which the official DPMA
//! does not survive.
//!
//! The dialog-info transcript depends on timing (an intermediate NOTIFY
//! may or may not be sent), so the `dialog-info` part checks only what the
//! supplement adds.
//!
//! # Findings
//!
//! - The official DPMA's AOR observer (`pjsip_aor_changed`) reads the
//!   `aors` of each line's endpoint before checking that the endpoint
//!   exists, so any AOR update or deletion (ARI push configuration,
//!   realtime) crashes Asterisk in `ast_sorcery_objectset_create2` whenever
//!   a line has no PJSIP endpoint of its name (external lines, lines of
//!   other phones).  Ours skips such lines (deviation).
//! - The official DPMA sends INFO on a channel's PJSIP session without
//!   checking `ast_channel_tech_pvt()`; on a hung-up PJSIP channel it
//!   would crash.  Ours returns -1.
//! - The official DPMA fails to load (AST_MODULE_LOAD_FAILURE, which aborts
//!   Asterisk startup) when there is no default outbound endpoint
//!   (`default_outbound_endpoint` in pjsip.conf `[global]`); ours does the
//!   same.
//! - `pjsip_contact_update` always adds `;transport=` (it tests the
//!   address, never NULL, instead of the transport), so a contact without
//!   a transport gives `pjsip:<host:port>;transport=`.  Kept.
//! - After an observer update, a line's tech, context, callerid, secret,
//!   authname, pjsip_auth, and mailbox come from PJSIP even when its
//!   res_digium_phone.conf section sets them (`process_pjsip_line_info`
//!   applies the section first, then clears and sets those); a full pass
//!   applies the section last.  Kept (both helpers do this).
//!
//! # The dialog-info supplement
//!
//! Checked against the official DPMA's decompile:
//!
//! - Other user agents ("Not a digium or sangoma phone") and states
//!   without a ringing channel ("No Channel") are left alone.
//! - Early: Asterisk's generator already adds `<remote>` and `<local>`
//!   with `<identity>` and `<target>`; the supplement finds them ("Using
//!   existing ... node", "Skipping due to existing ...") and changes
//!   nothing.
//! - Ringing while in use: the generator writes
//!   `<state>confirmed</state>` only; the supplement (which asks for the
//!   state string with `notify_early_inuse_ringing` set, so it says
//!   "early" in its logs) adds `<local><target uri=.../><identity
//!   display=...>uri</identity></local>` from the ringing channel's caller
//!   and `<remote>` from its connected line, with
//!   `sip:anonymous@anonymous.invalid` and display "anonymous" for a
//!   restricted number and name, and the local URI's domain otherwise.
//! - "No domain in local uri" cannot happen with Asterisk 24 (a
//!   subscription's local URI is the Request-URI with the resource as its
//!   user), and the "Created dialog node" branch cannot either (the
//!   generator always adds `<dialog>`).

mod dialog_info;
mod identifier;
mod stress;

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result};
use bstr::ByteSlice;
use dpma_tests::ari::Ari;
use dpma_tests::harness::{fixtures, setup, ConfFile, Ctx, Instance, Suite};
use dpma_tests::sipua::{self, SipUa, UaEvent, Uas, UasConfig};
use regex::Regex;

/// The Digium user agent of the test phones.
pub const DIGIUM_UA: &str = "Digium D65 2_9_17";
/// The module.
pub const DPMA: &str = "res_dpma_rs.so";
/// The ARI user of `ari_helpers.conf`.
pub const ARI_USER: (&str, &str) = ("test", "test");

/// The configuration snippets: the configuration file that includes it,
/// the snippet's file name, and its contents.
const CONF: [(&str, &str, &str); 5] = [
    (
        "pjsip.conf",
        "pjsip_helpers.conf",
        include_str!("../../data/pjsip-helpers/pjsip_helpers.conf"),
    ),
    (
        "extensions.conf",
        "extensions_helpers.conf",
        include_str!("../../data/pjsip-helpers/extensions_helpers.conf"),
    ),
    (
        "res_digium_phone.conf",
        "res_digium_phone_helpers.conf",
        include_str!("../../data/pjsip-helpers/res_digium_phone_helpers.conf"),
    ),
    (
        "sorcery.conf",
        "sorcery_helpers.conf",
        include_str!("../../data/pjsip-helpers/sorcery_helpers.conf"),
    ),
    (
        "ari.conf",
        "ari_helpers.conf",
        include_str!("../../data/pjsip-helpers/ari_helpers.conf"),
    ),
];

/// The HTTP (ARI) port.
pub const HTTP_PORT: u16 = 15088;

/// Installs the test configuration.  Asterisk must be restarted afterwards
/// (`sorcery.conf` is read at startup only).
fn install_conf(inst: &Instance) -> Result<()> {
    for (main, snippet, text) in CONF {
        setup::install_snippet(inst, snippet, main, text.as_bytes())?;
    }
    ConfFile::new(&inst.conf("http.conf")).write(format!(
        "[general]\nenabled=yes\nbindaddr=127.0.0.1\nbindport={HTTP_PORT}\n"
    ))
}

/// Restarts Asterisk (which starts a new `messages.log`).
pub fn restart(ctx: &mut Ctx) -> Result<()> {
    ctx.drop_ami();
    ctx.inst.start()
}

/// The directory for the transcripts: `<instance>/pjsip-helpers`.
pub fn transcript_dir(inst: &Instance) -> Result<PathBuf> {
    let d = inst.dir.join("pjsip-helpers");
    std::fs::create_dir_all(&d).with_context(|| d.display().to_string())?;
    Ok(d)
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid regular expression")
}

static ADDR: LazyLock<Regex> = LazyLock::new(|| re(r"0x[0-9a-f]{6,}"));
static PORT: LazyLock<Regex> = LazyLock::new(|| re(r"127\.0\.0\.1:\d+"));
static CHAN: LazyLock<Regex> = LazyLock::new(|| re(r"(PJSIP|Local)/([\w@-]+?)-[0-9a-f]{8}(;\d)?"));
static LOG_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\[[^\]]*\] (\w+)\[\d+\](\[[^\]]*\])? "));
static LOG_SOURCE: LazyLock<Regex> = LazyLock::new(|| re(r"(\w+\.(c|rs)):\d+ "));
static LOG_KEEP: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"res_pjsip_endpoint_identifier_dpma|res_pjsip_dialog_info_digium|Reconfiguring triggered|Test probe",
    )
});
static LINE_OBJECT: LazyLock<Regex> = LazyLock::new(|| re(r"^object 0xADDR name "));

/// Takes out what changes from run to run: addresses, ports, and channel
/// IDs.
pub fn norm(text: &str) -> String {
    let t = ADDR.replace_all(text, "0xADDR");
    let t = PORT.replace_all(&t, "127.0.0.1:PORT");
    CHAN.replace_all(&t, "${1}/${2}-ID${3}").into_owned()
}

/// A scenario's transcript and the means to make it.
pub struct Scenario {
    /// The instance.
    pub inst: Instance,
    lines: Vec<String>,
    echo: bool,
    log_pos: u64,
    ari: Ari,
}

impl Scenario {
    /// A scenario on `inst`; its log starts at the current end of
    /// `messages.log`.  With `echo`, every transcript line is also
    /// printed.
    pub fn new(inst: &Instance, echo: bool) -> Scenario {
        let mut s = Scenario {
            inst: inst.clone(),
            lines: Vec::new(),
            echo,
            log_pos: 0,
            ari: Ari::new("127.0.0.1", HTTP_PORT, ARI_USER.0, ARI_USER.1),
        };
        s.log_mark();
        s
    }

    /// The transcript: every line with its line break.
    pub fn text(&self) -> String {
        self.lines.iter().map(|l| format!("{l}\n")).collect()
    }

    /// The transcript lines.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Adds a line to the transcript.
    pub fn out(&mut self, text: impl Into<String>) {
        let text = text.into();
        if self.echo {
            println!("     | {text}");
        }
        self.lines.push(text);
    }

    /// Starts a step: a blank line and `== <title>`.
    pub fn step(&mut self, title: &str) {
        self.out("");
        self.out(format!("== {title}"));
    }

    /// Runs a CLI command; its output without trailing line breaks,
    /// normalized.  Unless `quiet`, the command (`> command`) and its
    /// non-empty output lines go into the transcript.
    pub fn ast(&mut self, cmd: &str, quiet: bool) -> String {
        let out = self.inst.cli_text(cmd);
        let text = norm(out.trim_end_matches('\n'));
        if !quiet {
            self.out(format!("> {cmd}"));
            for line in text.split('\n').filter(|l| !l.is_empty()) {
                self.out(format!("  {line}"));
            }
        }
        text
    }

    /// Whether Asterisk answers.
    pub fn alive(&self) -> bool {
        self.inst
            .cli_text("core show uptime")
            .to_lowercase()
            .contains("uptime")
    }

    /// Moves the log mark to the current end of `messages.log`.
    pub fn log_mark(&mut self) {
        self.log_pos = std::fs::metadata(&self.inst.messages_log)
            .map(|m| m.len())
            .unwrap_or(0);
    }

    /// Reads the log from the start of `messages.log` on the next
    /// [`Scenario::log_show`].
    pub fn log_from_start(&mut self) {
        self.log_pos = 0;
    }

    /// Waits until Asterisk's logger thread is quiet (`messages.log` has
    /// not grown for 0.1 s), then adds the module's log lines since the
    /// mark as `log:` lines; moves the mark.
    pub fn log_show(&mut self) {
        let size = || std::fs::metadata(&self.inst.messages_log).map_or(0, |m| m.len());
        let mut last = size();
        loop {
            fixtures::sleep(0.1);
            let now = size();
            if now == last {
                break;
            }
            last = now;
        }
        let data = std::fs::read(&self.inst.messages_log).unwrap_or_default();
        let start = usize::try_from(self.log_pos).unwrap_or(usize::MAX);
        let new = data.get(start..).unwrap_or_default();
        self.log_pos += new.len() as u64;
        let text = new.to_str_lossy().into_owned();
        for line in text.split('\n') {
            if !LOG_KEEP.is_match(line) {
                continue;
            }
            let line = LOG_PREFIX.replace(line, "${1} ");
            let line = LOG_SOURCE.replace_all(&line, "${1} ");
            self.out(format!("  log: {}", norm(&line)));
        }
    }

    /// Adds the lines a SIP user agent printed: the whole text trimmed,
    /// then every non-empty line normalized, after `prefix`.
    pub fn emit(&mut self, prefix: &str, lines: &[String]) {
        let text = lines.join("\n");
        for line in text.trim().split('\n').filter(|l| !l.is_empty()) {
            self.out(format!("{prefix}{}", norm(line)));
        }
    }

    fn sip_ua(&self) -> Result<SipUa> {
        SipUa::new("127.0.0.1", self.inst.sip_port)
    }

    /// A REGISTER of `user` with `agent` (`REGISTER <user> <status>`).
    pub fn register(&mut self, user: &str, password: &str, agent: &str) -> Result<()> {
        let status = self.sip_ua()?.register(user, password, agent, 300);
        let line = format!("REGISTER {user} {}", sipua::status_text(&status));
        self.emit("  ", &[line]);
        Ok(())
    }

    /// A MESSAGE to `exten`, with `X-Digium-User-Agent: <digium_ua>` when
    /// given (`MESSAGE <exten> <kind> <status>`).
    pub fn message(&mut self, exten: &str, digium_ua: Option<&str>) -> Result<()> {
        let status = self
            .sip_ua()?
            .message(exten, digium_ua, "dpma-test", "test");
        let kind = if digium_ua.is_some() {
            "X-Digium-User-Agent"
        } else {
            "plain"
        };
        let line = format!("MESSAGE {exten} {kind} {}", sipua::status_text(&status));
        self.emit("  ", &[line]);
        Ok(())
    }

    /// A UAS in the background: registers `user` with `agent`, then for
    /// `seconds` answers the INVITEs numbered in `answer` and leaves the
    /// others ringing.
    pub fn uas(
        &self,
        user: &str,
        password: &str,
        agent: &str,
        seconds: f64,
        answer: &[usize],
    ) -> Result<Uas> {
        let mut c = UasConfig::new(user, password, Duration::from_secs_f64(seconds));
        c.user_agent = agent.into();
        c.answer = sipua::Answer::Numbers(answer.to_vec());
        c.unregister = false;
        Uas::spawn("127.0.0.1", self.inst.sip_port, c)
    }

    /// Adds what a background UAS printed (its `events`), as `<label>: `
    /// lines.
    pub fn collect_uas(&mut self, events: Vec<UaEvent>, user: &str, label: &str) {
        let mut lines = Vec::new();
        for e in events {
            match e {
                UaEvent::Registered(s) => {
                    lines.push(format!("REGISTER {user} {}", sipua::status_text(&s)));
                }
                UaEvent::Invite(n, _, what) => lines.push(format!("INVITE {n} {what}")),
                UaEvent::Info(m) => lines.extend(sipua::info_lines(&m)),
                _ => {}
            }
        }
        self.emit(&format!("  {label}: "), &lines);
    }

    /// A subscriber in the background: subscribes to `dialog` events of
    /// `exten` as `user` with `agent` for `seconds`; the thread returns
    /// the `SUBSCRIBE <status>` and `NOTIFY <body>` lines.
    pub fn subscribe(
        &self,
        user: &str,
        password: &str,
        agent: &str,
        exten: &str,
        seconds: f64,
    ) -> std::thread::JoinHandle<Vec<String>> {
        let port = self.inst.sip_port;
        let (user, password, agent, exten) = (
            user.to_string(),
            password.to_string(),
            agent.to_string(),
            exten.to_string(),
        );
        std::thread::spawn(move || match SipUa::new("127.0.0.1", port) {
            Ok(mut ua) => ua.subscribe(
                &user,
                &password,
                &agent,
                &exten,
                None,
                Duration::from_secs_f64(seconds),
            ),
            Err(e) => vec![format!("error: {e:#}")],
        })
    }

    /// Adds what a background subscriber printed, as `<label>: ` lines.
    pub fn collect_subscriber(&mut self, h: std::thread::JoinHandle<Vec<String>>, label: &str) {
        let lines = h
            .join()
            .unwrap_or_else(|_| vec!["error: the subscriber panicked".into()]);
        self.emit(&format!("  {label}: "), &lines);
    }

    /// The settings of lines `names` (`dpmadev pjsip line`), as `line
    /// <name>:` and the indented output, without the object's address and
    /// reference count (which depend on who holds it).
    pub fn line_settings(&mut self, names: &[&str]) {
        for n in names {
            let text = self.ast(&format!("dpmadev pjsip line {n}"), true);
            self.out(format!("line {n}:"));
            for line in text.split('\n') {
                let line = LINE_OBJECT.replace(line, "name ");
                if !line.is_empty() {
                    self.out(format!("  {line}"));
                }
            }
        }
    }

    /// Waits until the sorcery observers of `object_type` (`endpoint`,
    /// `auth`, `aor`, or `contact`) have handled every change so far: they
    /// run on that type's serializer (`sorcery/<type>-<n>`), so a ping
    /// (`core ping taskprocessor`) answers after them.
    pub fn settle(&self, object_type: &str) {
        let prefix = format!("sorcery/{object_type}-");
        let list = self
            .inst
            .cli_text(&format!("core show taskprocessors like {prefix}"));
        for name in list.split_whitespace().filter(|w| w.starts_with(&prefix)) {
            self.inst
                .cli_text(&format!("core ping taskprocessor {name}"));
        }
    }

    /// An ARI push configuration request on `res_pjsip/<path>` (fields:
    /// a JSON body; none: no body), as `ARI <method> <path>: <status>`;
    /// then waits until the observers have handled it.
    pub fn ari(&mut self, method: &str, path: &str, fields: &[(&str, &str)]) {
        let body = (!fields.is_empty()).then(|| Ari::config_fields(fields));
        let code = match self.ari.request(
            method,
            &format!("asterisk/config/dynamic/res_pjsip/{path}"),
            body.as_ref(),
        ) {
            Ok(r) => r.status.to_string(),
            Err(e) => format!("error {e:#}"),
        };
        self.out(format!("  ARI {method} {path}: {code}"));
        self.settle(path.split('/').next().unwrap_or_default());
    }

    /// Replaces every `old` with `new` in the configuration file `name`.
    pub fn edit(&self, name: &str, old: &str, new: &str) -> Result<()> {
        let f = ConfFile::new(&self.inst.conf(name));
        let data = f.read()?;
        f.write(data.replace(old.as_bytes(), new.as_bytes()))
    }

    /// Sets (or, with `None`, removes) `pjsip_message_context` in
    /// `res_digium_phone.conf`'s `[general]` section.
    pub fn set_message_context(&self, context: Option<&str>) -> Result<()> {
        let f = ConfFile::new(&self.inst.conf("res_digium_phone.conf"));
        let mut data = f
            .read()?
            .replace(&b"\npjsip_message_context=dpma-test\n"[..], &b"\n"[..]);
        if let Some(c) = context {
            data = data.replacen(
                &b"[general]\n"[..],
                format!("[general]\npjsip_message_context={c}\n").as_bytes(),
                1,
            );
        }
        f.write(data)
    }

    /// The first channel whose name starts with `prefix` (`core show
    /// channels concise`).
    pub fn channel(&self, prefix: &str) -> Option<String> {
        self.inst
            .cli_text("core show channels concise")
            .split('\n')
            .map(|l| l.split('!').next().unwrap_or_default())
            .find(|name| name.starts_with(prefix))
            .map(str::to_string)
    }

    /// Drops the contacts earlier runs left in AstDB (they survive
    /// restarts).
    pub fn forget_contacts(&mut self) {
        self.ast("database deltree registrar", true);
    }

    /// Writes the transcript to `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.text()).with_context(|| path.display().to_string())
    }
}

fn main() -> std::process::ExitCode {
    Suite::new("pjsip-helpers")
        .prepare(|inst| fixtures::prepare(inst, install_conf))
        .part("identifier", identifier::run)
        .part("dialog-info", dialog_info::run)
        .part("stress", |ctx| stress::run(ctx, 5.0))
        .main()
}
