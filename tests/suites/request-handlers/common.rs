//! What the request handler and users' flow parts share (was
//! `tests/request-handlers/p12lib.py`): the CLI through AMI, the
//! `[general]` settings, simulated phones, checks of replies, the log, and
//! the session flags.

use std::time::Duration;

use anyhow::Result;
use bstr::{BStr, BString, ByteSlice};
use dpma_tests::ami::AmiMessage;
use dpma_tests::harness::{fixtures, ConfFile, Ctx, LogMark};
use dpma_tests::sim::{Exchange, Phone, Reply};
use regex::bytes::Regex;

pub use dpma_tests::harness::fixtures::{
    http_wrap as http, json_error, token_hash, xml_error, GLOBALPIN,
};

/// The MAC of the test phone p12a.
pub const MAC_A: &str = "000fd3001201";
/// A MAC no phone has.
pub const MAC_BAD: &str = "000fd30012ff";
/// The wrapper of AsteriskResponse and HTTPResponse documents.
pub const HTTP: &[u8] = fixtures::HTTP_PREAMBLE;

/// The P12 test phones (`res_digium_phone_p12.conf`).
pub const P12_CONF: &str = include_str!("../../data/request-handlers/res_digium_phone_p12.conf");

// The bits of the authentication requirements of a `config_auth` mode.
/// A user name.
pub const USER: u32 = 1;
/// The phone's pin.
pub const PIN: u32 = 2;
/// The global pin (or a group pin) as the configuration password.
pub const GLOBAL: u32 = 4;
/// The phone's MAC.
pub const MAC: u32 = 8;

/// The `config_auth` modes and their requirements.
pub const MODES: [(&str, u32); 6] = [
    ("mac", MAC),
    ("pin", USER | PIN),
    ("globalpin", USER | GLOBAL),
    ("mac_pin", USER | PIN | MAC),
    ("mac_globalpin", USER | GLOBAL | MAC),
    ("disabled", USER),
];

/// The texts of the message errors (`<error msg="..." />`).
pub fn msg_text(code: i64) -> &'static str {
    match code {
        -98 => "The file requested was not found",
        -192 => "User Config token presented is invalid",
        -195 => "Specfied user not found",
        -198 => "An Invalid configuration password was provided",
        _ => "?",
    }
}

/// The body of a message error reply.
pub fn msg_error_body(code: i64) -> Vec<u8> {
    format!("<error msg=\"{}\" />", msg_text(code)).into_bytes()
}

/// Runs a CLI command through AMI's `Command` action; its output lines
/// joined with line breaks.
pub fn cli(ctx: &mut Ctx, cmd: &str) -> Result<BString> {
    let lines = ctx.ami()?.command(cmd)?;
    Ok(bstr::join("\n", lines).into())
}

/// [`cli`] as text (lossy).
pub fn cli_text(ctx: &mut Ctx, cmd: &str) -> Result<String> {
    Ok(cli(ctx, cmd)?.to_str_lossy().into_owned())
}

/// Rewrites `[general]` of `res_digium_phone.conf` with `options` (`None`
/// removes a key) and reloads the module.  Sessions keep the flags they
/// were created with, so callers handshake again afterwards.
pub fn set_general(ctx: &mut Ctx, options: &[(&str, Option<&str>)]) -> Result<()> {
    let opts: Vec<(&str, Option<&[u8]>)> = options
        .iter()
        .map(|(k, v)| (*k, v.map(str::as_bytes)))
        .collect();
    ConfFile::new(&ctx.inst.conf("res_digium_phone.conf")).set_options("general", &opts)?;
    cli(ctx, "module reload res_dpma_rs.so")?;
    fixtures::sleep(0.5);
    Ok(())
}

/// [`set_general`] with `config_auth`, `userlist_auth`, and the global
/// pin.
pub fn set_auth(ctx: &mut Ctx, config_auth: &str, userlist_auth: &str) -> Result<()> {
    set_general(
        ctx,
        &[
            ("config_auth", Some(config_auth)),
            ("userlist_auth", Some(userlist_auth)),
            ("globalpin", Some(GLOBALPIN)),
        ],
    )
}

/// A simulated phone with MAC `mac` and a fresh session.
pub fn phone(ctx: &Ctx, mac: &str) -> Result<Phone> {
    fixtures::phone(ctx.sim_options().mac(mac))
}

/// What the payload of a reply must be.
pub enum Body<'a> {
    /// The message error body for the expected error, else anything.
    Default,
    /// Exactly these bytes.
    Is(&'a [u8]),
    /// Matching this regular expression.
    Matches(&'a str),
}

/// Checks a reply, one check: its response type, `Error-ID` (a message
/// error code or `None`), that it is encrypted, and its payload.  Returns
/// the reply, if any.
pub fn expect<'e>(
    ctx: &mut Ctx,
    name: &str,
    ex: &'e Exchange,
    rtype: &str,
    error: Option<i64>,
    body: Body,
) -> Option<&'e Reply> {
    let Some(r) = ex.reply.as_ref() else {
        ctx.c.check(name, false, "no reply");
        return None;
    };
    let mut problems: Vec<String> = r.problems.clone();
    if r.response_type.as_ref().is_none_or(|t| t != rtype) {
        problems.push(format!("type {:?}, wanted {rtype:?}", r.response_type));
    }
    let got_err: Option<String> = r
        .error
        .as_ref()
        .filter(|e| !e.is_empty() && *e != "0")
        .map(|e| e.to_str_lossy().into_owned());
    let want_err = error.map(|e| e.to_string());
    if got_err != want_err {
        problems.push(format!("error {got_err:?}, wanted {want_err:?}"));
    }
    if !r.encrypted {
        problems.push("reply not encrypted".into());
    }
    let std_body;
    let body = match (body, error) {
        (Body::Default, Some(e)) => {
            std_body = msg_error_body(e);
            Body::Is(&std_body)
        }
        (b, _) => b,
    };
    let p = &r.payload;
    let short = |b: &[u8]| BStr::new(&b[..b.len().min(600)]).to_owned();
    match body {
        Body::Is(want) if p.as_slice() != want => problems.push(format!(
            "payload {:?}\n     wanted  {:?}",
            short(p),
            short(want)
        )),
        Body::Matches(re) if !Regex::new(re).expect("pattern").is_match(p) => {
            problems.push(format!("payload {:?} does not match {re:?}", short(p)))
        }
        _ => {}
    }
    ctx.c.check(name, problems.is_empty(), problems.join("\n"));
    Some(r)
}

/// Checks that `text` was logged since `mark` (waiting up to two
/// seconds for Asterisk's logger).
pub fn logged(ctx: &mut Ctx, name: &str, mark: LogMark, text: &str) {
    let ok = ctx.log().wait_for(mark, text, Duration::from_secs(2));
    ctx.c.check(name, ok, format!("not in the log: {text:?}"));
}

/// The current end of `messages.log`.
pub fn log_mark(ctx: &Ctx) -> LogMark {
    ctx.log().mark()
}

/// The first capture group of `pattern` in `text` (`.` does not match
/// line breaks).
pub fn capture(pattern: &str, text: &[u8]) -> Option<String> {
    let re = Regex::new(pattern).expect("pattern");
    let c = re.captures(text)?;
    Some(c.get(1)?.as_bytes().to_str_lossy().into_owned())
}

/// The line of `digium_phones show sessions` for session `sid` (empty
/// when there is none).
pub fn session_line(ctx: &mut Ctx, sid: &str) -> Result<String> {
    let out = cli_text(ctx, "digium_phones show sessions")?;
    let prefix = format!("SessionID:{sid} ");
    Ok(out
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_default()
        .to_string())
}

/// The `Configured` flag of session `sid`.
pub fn configured(ctx: &mut Ctx, sid: &str) -> Result<Option<String>> {
    let line = session_line(ctx, sid)?;
    Ok(capture(r"Configured: (\w+)", line.as_bytes()))
}

/// The `Auth` and `Inactive` flags of session `sid`.
pub fn flags(ctx: &mut Ctx, sid: &str) -> Result<Option<(String, String)>> {
    let line = session_line(ctx, sid)?;
    let re = Regex::new(r"Auth:(\w+)\s+Inactive:(\w+)").expect("pattern");
    Ok(re.captures(line.as_bytes()).map(|c| {
        (
            c[1].to_str_lossy().into_owned(),
            c[2].to_str_lossy().into_owned(),
        )
    }))
}

/// The session id of a phone (empty without one).
pub fn sid(p: &Phone) -> String {
    p.session().unwrap_or_default()
}

/// The auth incident of 127.0.0.1, if any.
pub fn local_incident(ctx: &mut Ctx) -> Result<Option<AmiMessage>> {
    Ok(fixtures::incidents(ctx.ami()?).remove(&b"127.0.0.1"[..]))
}

/// Removes every auth incident.
pub fn clear_incidents(ctx: &mut Ctx) -> Result<()> {
    fixtures::clear_incidents(ctx.ami()?);
    Ok(())
}

/// A field of an AMI message as text.
pub fn field(m: &AmiMessage, key: &str) -> Option<String> {
    m.get_str(key)
}

/// The response URI the module records for a phone (UDP).
pub fn uri_of(p: &Phone) -> String {
    format!("pjsip:127.0.0.1:{};transport=udp", p.local_addr().port())
}
