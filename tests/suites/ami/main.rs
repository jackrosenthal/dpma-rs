//! The ami suite: AMI messages to and from phones (package P13) and the
//! phone users runtime's messages to phones, end to end with the phone
//! simulator (the Rust form of the former `tests/ami/run.py`).
//!
//! ```text
//! cargo xtask test ami ami-expiry
//! ```
//!
//! runs it (`ami-expiry` with `--expiry`) in the test container after
//! building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test ami -- --ignored [--no-prepare] [-v] [--expiry] [--via phone|hook] [PART...]
//! ```
//!
//! Prerequisites: the test instance and a devtest build of the module.
//! The suite prepares the instance (fresh configuration, the
//! simulator's test PKI and configuration, the P13 test phones of
//! `tests/data/ami/res_digium_phone_p13.conf` included from
//! `res_digium_phone.conf`, the debug build installed, Asterisk
//! restarted; `--no-prepare` skips this).
//!
//! The first part that runs answers requests an earlier run left queued,
//! starts two simulated phones (p13phone and p13phone2), and records
//! where they are (a TokenRequest each).  The parts:
//!
//! | Part | Checks |
//! |---|---|
//! | `actions` | DPMAMessageRegister, DPMAMessageResponse, and DPMAMessageSend: privileges, responses byte for byte (an ActionID of 243 characters fits; one of 244 loses its line ending), failures and what they log |
//! | `forwarding` | AsteriskRequests for AMI-registered methods: the DPMAMessage event, the queue and its scheduler, JSON and XML results and errors, other formats, two requests answered out of order, a long (chunked) result, and an answer after the phone gave up waiting |
//! | `send` | DPMAMessageSend events as the phone decrypts them: an empty body, `digium.assignment.update` (sent as `bootcReset` with -398), and event names case sensitive |
//! | `reconfigure` | `digium_phones reconfigure` from the CLI and DigiumPhoneReconfigure(All) from AMI: texts, errors, and the `digium.config.update` events; both bodies of the reconfigure message |
//! | `reload` | A module reload that changes a phone's lines or removes a phone reconfigures only that phone |
//! | `session-gone` | A queued request and an event for a phone whose session a new handshake replaced |
//! | `expiry` | Only with `--expiry` (about six minutes): the AMI scheduler drops a request nobody answers after 300 s (port plan section 8, item 13; the original never runs its scheduler, so its requests never expire) |
//!
//! AMI responses and events are compared byte for byte with what the
//! original's `phone_ami.c` and `phone_request.c` write; replies and
//! events are checked as the simulated phone decrypts them.
//!
//! By default (`--via phone`) everything is driven from the simulator:
//! the TokenRequest records where the phone is, and an AsteriskRequest for
//! an AMI-registered method is forwarded to AMI by the request handler.
//! `--via hook` replaces those two steps with the devtest commands
//! `dpmadev token build` and `dpmadev ami forward`.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use bstr::{BStr, BString, ByteSlice};
use dpma_tests::ami::{AmiClient, Match};
use dpma_tests::harness::{fixtures, option_value, Checker, ConfFile, Ctx, Instance, Suite};
use dpma_tests::sim::proto::{method_request_json, method_request_xml};
use dpma_tests::sim::{Exchange, Phone, Reply};
use dpma_tests::util::{json_compact, secs};
use regex::Regex;
use serde_json::{json, Value};

/// The test phones' configuration file.
const CONF: &str = "res_digium_phone_p13.conf";
const CONF_TEXT: &str = include_str!("../../data/ami/res_digium_phone_p13.conf");
const DELETE_TOKEN_BODY: &[u8] =
    b"<config>\t<section id=\"all\"/>\t<option id=\"delete_token\" value=\"true\"/></config>";

/// How requests reach AMI.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Via {
    Phone,
    Hook,
}

impl Via {
    fn name(self) -> &'static str {
        match self {
            Via::Phone => "phone",
            Via::Hook => "hook",
        }
    }
}

/// The suite's own options.
#[derive(Clone, Copy)]
struct Opts {
    via: Via,
    expiry: bool,
}

fn parse_opts() -> Result<Opts, String> {
    let via = match option_value("--via").as_deref() {
        None | Some("phone") => Via::Phone,
        Some("hook") => Via::Hook,
        Some(v) => return Err(format!("unknown --via {v} (phone or hook)")),
    };
    Ok(Opts {
        via,
        expiry: std::env::args().skip(1).any(|a| a == "--expiry"),
    })
}

/// The simulator setup plus the P13 phones.
fn setup(inst: &Instance) -> Result<()> {
    fixtures::sim_setup(inst)?;
    std::fs::write(inst.conf(CONF), CONF_TEXT)?;
    ConfFile::new(&inst.conf("res_digium_phone.conf")).add_include(CONF)
}

/// What the parts share: an AMI connection and the two located phones.
struct State {
    ami: AmiClient,
    a: Phone,
    b: Phone,
}

type Shared = Rc<RefCell<Option<State>>>;

// ---------------------------------------------------------------------------
// AMI, byte for byte
// ---------------------------------------------------------------------------

/// Sends an action exactly as given (no ActionID unless `action_id`) and
/// returns the raw bytes of the next response.
fn raw(
    ami: &AmiClient,
    name: &str,
    action_id: Option<&[u8]>,
    fields: &[(&str, &[u8])],
) -> Option<BString> {
    let mut text = format!("Action: {name}\r\n").into_bytes();
    if let Some(id) = action_id {
        text.extend_from_slice(b"ActionID: ");
        text.extend_from_slice(id);
        text.extend_from_slice(b"\r\n");
    }
    for (k, v) in fields {
        text.extend_from_slice(k.as_bytes());
        text.extend_from_slice(b": ");
        text.extend_from_slice(v);
        text.extend_from_slice(b"\r\n");
    }
    text.extend_from_slice(b"\r\n");
    ami.send_raw(&text, Duration::from_secs(10))
        .map(|m| m.raw().clone())
}

/// The original's reply: `"Response: %s\r\n%s\r\n"` with the ActionID
/// line (or nothing).
fn resp(result: &str, action_id: Option<&str>) -> Vec<u8> {
    let id = action_id
        .map(|a| format!("ActionID: {a}\r\n"))
        .unwrap_or_default();
    format!("Response: {result}\r\n{id}\r\n").into_bytes()
}

/// Checks that an optional message is exactly `want`.
fn same_raw(c: &mut Checker, name: impl AsRef<str>, got: Option<BString>, want: &[u8]) -> bool {
    c.check_with(name, got.as_ref().is_some_and(|g| g == want), || {
        format!(
            "got  {}\nwant {:?}",
            got.as_ref().map_or("None".into(), |g| format!("{g:?}")),
            BStr::new(want)
        )
    })
}

fn describe(r: Option<&Reply>) -> String {
    r.map(|r| r.describe(0).to_str_lossy().into_owned())
        .unwrap_or_else(|| "no message".into())
}

fn is(v: &Option<BString>, want: &str) -> bool {
    v.as_ref().is_some_and(|v| v == want)
}

// ---------------------------------------------------------------------------
// Phones and forwarded requests
// ---------------------------------------------------------------------------

fn new_phone(ctx: &Ctx, mac: &str) -> Result<Phone> {
    fixtures::phone(ctx.sim_options().mac(mac))
}

/// Records where the phone is (TokenRequest, or the token hook).
fn authenticate(ctx: &Ctx, via: Via, phone: &Phone, name: &str) -> Result<(bool, String)> {
    if via == Via::Phone {
        let ex = phone
            .get_token()
            .user(name)
            .config_password(fixtures::GLOBALPIN)
            .send()?;
        return Ok((ex.ok(), ex.describe(0).to_str_lossy().into_owned()));
    }
    let out = ctx.cli_text(&format!(
        "dpmadev token build {name} {} {} {}",
        phone.mac(),
        phone.session().unwrap_or_default(),
        phone.response_uri()
    ));
    Ok((out.starts_with(&format!("token: {name}/")), out))
}

/// Drops whatever the phone receives until it is quiet for 0.2 s.
fn drain(phone: &Phone) {
    while phone.next_event(secs(0.2), None).is_some() {}
}

/// The parameters of a method call: a JSON value or an XML fragment.
enum Params<'a> {
    Json(Value),
    Xml(&'a str),
}

impl Params<'_> {
    fn format(&self) -> &'static str {
        match self {
            Params::Json(_) => "JSON",
            Params::Xml(_) => "XML",
        }
    }

    /// What the DPMAMessage event carries as Parameters: the compact JSON
    /// of the parameters, or the text content of the `<parameters>`
    /// element.
    fn text(&self) -> String {
        match self {
            Params::Json(v) => json_compact(v),
            Params::Xml(x) => xml_text(x),
        }
    }

    fn document(&self, method: &str) -> String {
        match self {
            Params::Json(v) => method_request_json(method, Some(v)),
            Params::Xml(x) => method_request_xml(method, x),
        }
    }
}

/// The text content of an XML fragment (Python's `itertext` of the
/// `<parameters>` element); empty when it is not well formed.
fn xml_text(fragment: &str) -> String {
    let doc = format!("<parameters>{fragment}</parameters>");
    roxmltree::Document::parse(&doc)
        .map(|d| {
            d.root()
                .descendants()
                .filter(|n| n.is_text())
                .map(|n| n.text().unwrap_or_default())
                .collect()
        })
        .unwrap_or_default()
}

/// A forwarded request: the exchange, its RequestID, and the Parameters
/// of its DPMAMessage event.
struct Forwarded {
    ex: Exchange,
    key: String,
    ptext: String,
}

/// A request for an AMI-registered method (not waited for).
fn forward(
    ctx: &Ctx,
    via: Via,
    phone: &Phone,
    method: &str,
    params: Params,
    auth: &str,
) -> Result<Forwarded> {
    let ptext = params.text();
    let ex = if via == Via::Phone {
        phone
            .asterisk(params.document(method))
            .auth(auth)
            .no_wait()
            .send()?
    } else {
        let txid = phone.new_id();
        let ex = phone.expect_reply("AsteriskRequest", &txid);
        let out = ctx.cli_text(&format!(
            "dpmadev ami forward {} {} {txid} {} {method} {}",
            phone.session().unwrap_or_default(),
            phone.response_uri(),
            params.format(),
            fixtures::cli_quote(&ptext)
        ));
        if !out.starts_with("Queued") {
            ctx.c.note(format!("dpmadev ami forward: {}", out.trim()));
        }
        ex
    };
    let key = format!("{}-{}", ex.id, phone.mac());
    Ok(Forwarded { ex, key, ptext })
}

/// Checks the DPMAMessage event of a forwarded request byte for byte.
fn dpma_message(
    c: &mut Checker,
    ami: &AmiClient,
    f: &Forwarded,
    method: &str,
    format: &str,
    label: &str,
) {
    let ev = ami.wait_event(
        Some("DPMAMessage"),
        &[("RequestID", Match::eq(&f.key))],
        Duration::from_secs(10),
    );
    let want = format!(
        "Event: DPMAMessage\r\nPrivilege: agent,all\r\nRequestID: {}\r\nMethod: {method}\r\nFormat: {format}\r\nParameters: {}\r\n\r\n",
        f.key, f.ptext
    );
    same_raw(
        c,
        format!("{label}: DPMAMessage event"),
        ev.map(|m| m.raw().clone()),
        want.as_bytes(),
    );
}

/// The queued AMI requests (`dpmadev ami queue`): RequestID, Method,
/// Session, and SchedID.
fn queued(ctx: &Ctx) -> Vec<(String, String, String, String)> {
    let out = ctx.cli_text("dpmadev ami queue");
    let re = Regex::new(r"(?m)^RequestID: (\S+)  Method: (\S*)  Session: (\S*)  SchedID: (-?\d+)")
        .expect("valid");
    re.captures_iter(&out)
        .map(|m| {
            (
                m[1].to_string(),
                m[2].to_string(),
                m[3].to_string(),
                m[4].to_string(),
            )
        })
        .collect()
}

fn queued_keys(ctx: &Ctx) -> Vec<String> {
    queued(ctx).into_iter().map(|q| q.0).collect()
}

fn reply_of(phone: &Phone, ex: &mut Exchange, timeout: f64) -> Option<Reply> {
    phone.wait_reply(ex, Some(secs(timeout)));
    ex.reply.clone()
}

fn check_reply(
    c: &mut Checker,
    label: &str,
    r: Option<&Reply>,
    ex: &Exchange,
    body: &[u8],
    session: &str,
) {
    let Some(r) = r else {
        c.check(
            format!("{label}: reply reaches the phone"),
            false,
            "no reply",
        );
        return;
    };
    c.same(
        format!("{label}: reply type"),
        r.response_type.as_ref().map(|v| v.to_string()),
        Some("AsteriskResponse".into()),
    );
    c.same(
        format!("{label}: reply id"),
        r.id.as_ref().map(|v| v.to_string()),
        Some(ex.id.clone()),
    );
    c.same(
        format!("{label}: reply session"),
        r.session.as_ref().map(|v| v.to_string()),
        Some(session.to_string()),
    );
    c.check(
        format!("{label}: reply encrypted, no error"),
        r.encrypted && r.error.is_none() && r.problems.is_empty(),
        format!(
            "encrypted={} error={:?} problems={:?}",
            r.encrypted, r.error, r.problems
        ),
    );
    c.same_bytes(format!("{label}: reply body"), &r.body, body);
}

/// A JSON document as the module wraps it in a reply.
fn json_doc(v: &Value) -> Vec<u8> {
    format!("\r\n\r\n{}\r\n", json_compact(v)).into_bytes()
}

fn preamble(doc: &[u8]) -> Vec<u8> {
    let mut v = fixtures::HTTP_PREAMBLE.to_vec();
    v.extend_from_slice(doc);
    v
}

// ---------------------------------------------------------------------------
// The parts
// ---------------------------------------------------------------------------

/// Answers requests an earlier run left queued, starts the two phones,
/// and records where they are.
fn init(ctx: &mut Ctx, o: Opts) -> Result<State> {
    if !ctx
        .cli_text("core show help dpmadev ami")
        .contains("dpmadev ami queue")
    {
        bail!(
            "needs a devtest build of res_dpma_rs running in the instance ({})",
            fixtures::DEVTEST_HINT
        );
    }
    let ami = ctx.inst.ami()?;
    // Requests left queued by an earlier run expire only after 300 s;
    // answer them.
    for key in queued_keys(ctx) {
        raw(
            &ami,
            "DPMAMessageResponse",
            None,
            &[("RequestID", key.as_bytes()), ("Format", b"flush")],
        );
    }
    let a = new_phone(ctx, "000fd3001301")?;
    let b = new_phone(ctx, "000fd3001302")?;
    for (phone, name) in [(&a, "p13phone"), (&b, "p13phone2")] {
        let (ok, detail) = authenticate(ctx, o.via, phone, name)?;
        ctx.c
            .check(format!("{name} located ({})", o.via.name()), ok, detail);
    }
    Ok(State { ami, a, b })
}

fn actions(ctx: &mut Ctx, st: &State) -> Result<()> {
    let ami = &st.ami;
    let log = ctx.log();
    let out = ctx
        .cli_text("manager show command DPMAMessageRegister DPMAMessageResponse DPMAMessageSend");
    ctx.c.check(
        "actions registered with privilege call",
        out.matches("Privilege: call,all").count() == 3,
        &out,
    );
    let c = &mut ctx.c;
    let reg = |id: Option<&str>, fields: &[(&str, &[u8])]| {
        raw(ami, "DPMAMessageRegister", id.map(str::as_bytes), fields)
    };
    same_raw(
        c,
        "Register: Success",
        reg(Some("r1"), &[("Method", b"com.p13.hello")]),
        &resp("Success", Some("r1")),
    );
    same_raw(
        c,
        "Register: no ActionID",
        reg(None, &[("Method", b"com.p13.hello")]),
        &resp("Success", None),
    );
    same_raw(
        c,
        "Register: empty Method",
        reg(Some("r2"), &[("Method", b"")]),
        &resp("Failure", Some("r2")),
    );
    same_raw(
        c,
        "Register: no Method",
        reg(Some("r3"), &[]),
        &resp("Failure", Some("r3")),
    );
    same_raw(
        c,
        "Register: second name",
        reg(Some("r4"), &[("Method", b"com.p13.Other")]),
        &resp("Success", Some("r4")),
    );
    let out = ctx.cli_text("dpmadev method list");
    ctx.c.check(
        "Register: names in the AMI registry",
        out.contains("com.p13.hello") && out.contains("com.p13.Other"),
        &out,
    );
    // snprintf(idtext, 0x100, "ActionID: %s\r\n"): 243 characters fit;
    // with 244 the "\n" is cut, so the response runs into the next one.
    let c = &mut ctx.c;
    let a243 = "a".repeat(243);
    same_raw(
        c,
        "ActionID of 243 characters",
        raw(
            ami,
            "DPMAMessageRegister",
            Some(a243.as_bytes()),
            &[("Method", b"com.p13.hello")],
        ),
        &resp("Success", Some(&a243)),
    );
    let a244 = "b".repeat(244);
    ami.send(
        "DPMAMessageRegister",
        [("ActionID", a244.as_str()), ("Method", "x")],
    )?;
    let got = raw(
        ami,
        "DPMAMessageRegister",
        Some(b"r5"),
        &[("Method", b"com.p13.hello")],
    );
    let mut want = format!("Response: Success\r\nActionID: {a244}\r\r\n").into_bytes();
    want.extend(resp("Success", Some("r5")));
    same_raw(
        c,
        "ActionID of 244 characters (truncated, unterminated)",
        got,
        &want,
    );

    same_raw(
        c,
        "Response: no RequestID",
        raw(
            ami,
            "DPMAMessageResponse",
            Some(b"n1"),
            &[("Format", b"json"), ("Response", b"x")],
        ),
        &resp("Failure", Some("n1")),
    );
    same_raw(
        c,
        "Response: unknown RequestID",
        raw(
            ami,
            "DPMAMessageResponse",
            None,
            &[
                ("RequestID", b"1-000000000000"),
                ("Format", b"json"),
                ("Response", b"x"),
            ],
        ),
        &resp("Failure", None),
    );

    let pos = log.mark();
    let send = |id: &str, fields: &[(&str, &[u8])]| {
        raw(ami, "DPMAMessageSend", Some(id.as_bytes()), fields)
    };
    same_raw(
        c,
        "Send: unknown phone",
        send("s1", &[("PhoneName", b"nobody"), ("Method", b"e")]),
        &resp("Failure", Some("s1")),
    );
    same_raw(
        c,
        "Send: no PhoneName",
        send("s2", &[("Method", b"e")]),
        &resp("Failure", Some("s2")),
    );
    same_raw(
        c,
        "Send: no Method",
        send("s3", &[("PhoneName", b"p13phone"), ("Message", b"m")]),
        &resp("Failure", Some("s3")),
    );
    let pos2 = log.mark();
    same_raw(
        c,
        "Send: phone that never contacted the server",
        send("s4", &[("PhoneName", b"p13phone3"), ("Method", b"e")]),
        &resp("Failure", Some("s4")),
    );
    fixtures::sleep(0.3);
    let text = log.since(pos);
    c.check(
        "Send: logs",
        text.contains_str("Phone 'nobody' could not be found.")
            && text.contains_str("Phone '' could not be found.")
            && text.contains_str("Message not supplied."),
        text.to_str_lossy(),
    );
    c.check(
        "Send: no uri logged",
        log.since(pos2)
            .contains_str("Unable to send event to 'p13phone3' with no uri"),
        "",
    );
    Ok(())
}

fn forwarding(ctx: &mut Ctx, o: Opts, st: &State) -> Result<()> {
    let (ami, a) = (&st.ami, &st.a);
    let s = a.session().unwrap_or_default();
    let auth = "p13phone:1313";
    let hello = "com.p13.hello";
    let other = "com.p13.Other";

    // JSON request answered with a JSON result.
    let mut f = forward(
        ctx,
        o.via,
        a,
        hello,
        Params::Json(json!({"a": 1, "b": "two words"})),
        auth,
    )?;
    dpma_message(&mut ctx.c, ami, &f, hello, "JSON", "JSON request");
    let q = queued(ctx);
    ctx.c.check(
        "JSON request: queued with an expiry",
        q.len() == 1 && q[0].0 == f.key && q[0].1 == hello && q[0].2 == s && q[0].3 != "-1",
        format!("{q:?}"),
    );
    let out = ctx.cli_text("dpmadev ami runq");
    ctx.c.check(
        "JSON request: nothing is due yet",
        out.starts_with("0 scheduled entries ran"),
        &out,
    );
    let response = |id: Option<&str>, fields: &[(&str, &[u8])]| {
        raw(ami, "DPMAMessageResponse", id.map(str::as_bytes), fields)
    };
    let k = f.key.clone();
    same_raw(
        &mut ctx.c,
        "JSON result: AMI response",
        response(
            Some("j1"),
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"json"),
                ("Response", b"hello \"world\""),
            ],
        ),
        &resp("Success", Some("j1")),
    );
    let r = reply_of(a, &mut f.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "JSON result",
        r.as_ref(),
        &f.ex,
        &preamble(&json_doc(
            &json!({"response": {"method": hello, "result": "hello \"world\""}}),
        )),
        &s,
    );
    let q = queued(ctx);
    ctx.c.same("JSON result: no longer queued", q, vec![]);
    same_raw(
        &mut ctx.c,
        "JSON result: second response fails",
        response(
            None,
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"json"),
                ("Response", b"x"),
            ],
        ),
        &resp("Failure", None),
    );

    // JSON error; RequestID and Format ignore case.
    let mut f = forward(
        ctx,
        o.via,
        a,
        hello,
        Params::Json(json!({"x": [1, 2]})),
        auth,
    )?;
    dpma_message(&mut ctx.c, ami, &f, hello, "JSON", "JSON error");
    let upper = f.key.to_uppercase();
    same_raw(
        &mut ctx.c,
        "JSON error: AMI response",
        response(
            None,
            &[
                ("RequestID", upper.as_bytes()),
                ("Format", b"Json"),
                ("ErrorNum", b"42"),
                ("ErrorMsg", b"it <failed>"),
            ],
        ),
        &resp("Success", None),
    );
    let r = reply_of(a, &mut f.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "JSON error",
        r.as_ref(),
        &f.ex,
        &preamble(&json_doc(&json!({"response": {"method": hello,
            "errors": {"error": {"code": 42, "message": "it <failed>"}}}}))),
        &s,
    );

    // JSON with neither a result nor a whole error: Failure, still queued.
    let mut f = forward(ctx, o.via, a, other, Params::Json(json!({})), auth)?;
    dpma_message(&mut ctx.c, ami, &f, other, "JSON", "JSON incomplete");
    let k = f.key.clone();
    same_raw(
        &mut ctx.c,
        "JSON incomplete: AMI response",
        response(
            Some("j3"),
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"JSON"),
                ("ErrorNum", b"7"),
            ],
        ),
        &resp("Failure", Some("j3")),
    );
    same_raw(
        &mut ctx.c,
        "JSON incomplete: invalid UTF-8 result fails",
        response(
            None,
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"JSON"),
                ("Response", b"\xff\xfe"),
            ],
        ),
        &resp("Failure", None),
    );
    let keys = queued_keys(ctx);
    ctx.c.check(
        "JSON incomplete: still queued",
        keys == [k.clone()],
        format!("{:?}", queued(ctx)),
    );
    // ... and then answered in XML with neither: an empty response
    // element.
    same_raw(
        &mut ctx.c,
        "XML empty: AMI response",
        response(None, &[("RequestID", k.as_bytes()), ("Format", b"xml")]),
        &resp("Success", None),
    );
    let r = reply_of(a, &mut f.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "XML empty",
        r.as_ref(),
        &f.ex,
        &preamble(b"\r\n\r\n<response method=\"com.p13.Other\">\r\n</response>\r\n"),
        &s,
    );

    // XML request answered with an XML result (not escaped), then an
    // error.
    let xml_params = "<id>17</id><name>x &amp; y</name>";
    let mut f = forward(ctx, o.via, a, hello, Params::Xml(xml_params), auth)?;
    dpma_message(&mut ctx.c, ami, &f, hello, "XML", "XML request");
    let k = f.key.clone();
    same_raw(
        &mut ctx.c,
        "XML result: AMI response",
        response(
            None,
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"XML"),
                ("Response", b"<ok a='1'/> & more"),
                ("ErrorNum", b"9"),
                ("ErrorMsg", b"ignored"),
            ],
        ),
        &resp("Success", None),
    );
    let r = reply_of(a, &mut f.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "XML result",
        r.as_ref(),
        &f.ex,
        &preamble(
            b"\r\n\r\n<response method=\"com.p13.hello\">\r\n<result><ok a='1'/> & more</result>\r\n</response>\r\n",
        ),
        &s,
    );
    let mut f = forward(ctx, o.via, a, hello, Params::Xml("<z/>"), auth)?;
    dpma_message(&mut ctx.c, ami, &f, hello, "XML", "XML error");
    let k = f.key.clone();
    same_raw(
        &mut ctx.c,
        "XML error: AMI response",
        response(
            None,
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"xml"),
                ("ErrorNum", b"abc"),
                ("ErrorMsg", b"bad \"thing\""),
            ],
        ),
        &resp("Success", None),
    );
    let r = reply_of(a, &mut f.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "XML error",
        r.as_ref(),
        &f.ex,
        &preamble(
            b"\r\n\r\n<response method=\"com.p13.hello\">\r\n<errors>\r\n<error code=\"abc\" message=\"bad \"thing\"\" />\r\n</errors>\r\n</response>\r\n",
        ),
        &s,
    );

    // Any other Format: only the preamble.
    let mut f = forward(ctx, o.via, a, hello, Params::Json(json!({"f": null})), auth)?;
    dpma_message(&mut ctx.c, ami, &f, hello, "JSON", "other format");
    let k = f.key.clone();
    same_raw(
        &mut ctx.c,
        "other format: AMI response",
        response(
            None,
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"text"),
                ("Response", b"r"),
            ],
        ),
        &resp("Success", None),
    );
    let r = reply_of(a, &mut f.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "other format",
        r.as_ref(),
        &f.ex,
        fixtures::HTTP_PREAMBLE,
        &s,
    );

    // Two queued at once, answered out of order; a long result is
    // chunked.
    let mut f1 = forward(ctx, o.via, a, hello, Params::Json(json!({"n": 1})), auth)?;
    let mut f2 = forward(ctx, o.via, a, other, Params::Json(json!({"n": 2})), auth)?;
    dpma_message(&mut ctx.c, ami, &f1, hello, "JSON", "first of two");
    dpma_message(&mut ctx.c, ami, &f2, other, "JSON", "second of two");
    let mut keys = queued_keys(ctx);
    keys.sort();
    let mut want = vec![f1.key.clone(), f2.key.clone()];
    want.sort();
    ctx.c
        .check("two queued", keys == want, format!("{:?}", queued(ctx)));
    // (AMI refuses header lines over 1024 bytes.)
    let long = "L".repeat(900);
    let (k1, k2) = (f1.key.clone(), f2.key.clone());
    same_raw(
        &mut ctx.c,
        "second answered first",
        response(
            None,
            &[
                ("RequestID", k2.as_bytes()),
                ("Format", b"json"),
                ("Response", long.as_bytes()),
            ],
        ),
        &resp("Success", None),
    );
    let r2 = reply_of(a, &mut f2.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "long result",
        r2.as_ref(),
        &f2.ex,
        &preamble(&json_doc(
            &json!({"response": {"method": other, "result": long}}),
        )),
        &s,
    );
    ctx.c.check(
        "long result: several chunks",
        r2.as_ref().is_some_and(|r| r.parts.len() > 1),
        format!("chunks={:?}", r2.as_ref().map(|r| r.parts.len())),
    );
    same_raw(
        &mut ctx.c,
        "first answered second",
        response(
            None,
            &[
                ("RequestID", k1.as_bytes()),
                ("Format", b"json"),
                ("Response", b"1"),
            ],
        ),
        &resp("Success", None),
    );
    let r1 = reply_of(a, &mut f1.ex, 5.0);
    check_reply(
        &mut ctx.c,
        "first of two",
        r1.as_ref(),
        &f1.ex,
        &preamble(&json_doc(
            &json!({"response": {"method": hello, "result": "1"}}),
        )),
        &s,
    );

    // The phone gives up waiting; the answer still arrives later.
    let mut f = forward(
        ctx,
        o.via,
        a,
        hello,
        Params::Json(json!({"late": true})),
        auth,
    )?;
    dpma_message(&mut ctx.c, ami, &f, hello, "JSON", "late answer");
    let r = reply_of(a, &mut f.ex, 1.5);
    ctx.c.check(
        "late answer: phone times out first",
        r.is_none(),
        describe(r.as_ref()),
    );
    drain(a);
    let k = f.key.clone();
    same_raw(
        &mut ctx.c,
        "late answer: AMI response",
        response(
            None,
            &[
                ("RequestID", k.as_bytes()),
                ("Format", b"json"),
                ("Response", b"late"),
            ],
        ),
        &resp("Success", None),
    );
    let r = a.next_event(secs(5.0), None);
    let want = preamble(&json_doc(
        &json!({"response": {"method": hello, "result": "late"}}),
    ));
    ctx.c.check(
        "late answer: reply arrives unsolicited",
        r.as_ref().is_some_and(|r| {
            is(&r.id, &f.ex.id) && is(&r.response_type, "AsteriskResponse") && r.body == want
        }),
        describe(r.as_ref()),
    );
    let q = queued(ctx);
    ctx.c.same("queue empty", q, vec![]);
    Ok(())
}

fn send(ctx: &mut Ctx, st: &State) -> Result<()> {
    let (ami, a) = (&st.ami, &st.a);
    let c = &mut ctx.c;
    let session = a.session().unwrap_or_default();
    let send = |id: Option<&str>, fields: &[(&str, &[u8])]| {
        raw(ami, "DPMAMessageSend", id.map(str::as_bytes), fields)
    };
    drain(a);
    same_raw(
        c,
        "Send: event",
        send(
            Some("e1"),
            &[
                ("PhoneName", b"P13PHONE"),
                ("Method", b"com.p13.event"),
                ("Message", b"<hello/>"),
            ],
        ),
        &resp("Success", Some("e1")),
    );
    let r = a.next_event(secs(5.0), None);
    c.check(
        "Send: event reaches the phone",
        r.as_ref().is_some_and(|r| {
            is(&r.event, "com.p13.event")
                && r.id.is_none()
                && r.error.is_none()
                && r.encrypted
                && r.payload == "<hello/>"
                && r.body == "Command: <hello/>"
                && is(&r.session, &session)
        }),
        describe(r.as_ref()),
    );
    same_raw(
        c,
        "Send: empty body",
        send(
            None,
            &[("PhoneName", b"p13phone"), ("Method", b"com.p13.empty")],
        ),
        &resp("Success", None),
    );
    let r = a.next_event(secs(5.0), None);
    c.check(
        "Send: empty body is 'empty body'",
        r.as_ref()
            .is_some_and(|r| is(&r.event, "com.p13.empty") && r.payload == "empty body"),
        describe(r.as_ref()),
    );
    same_raw(
        c,
        "Send: digium.assignment.update",
        send(
            None,
            &[
                ("PhoneName", b"p13phone"),
                ("Method", b"digium.assignment.update"),
                ("Message", b"<assign/>"),
            ],
        ),
        &resp("Success", None),
    );
    let r = a.next_event(secs(5.0), None);
    c.check(
        "Send: assignment update as bootcReset / -398",
        r.as_ref().is_some_and(|r| {
            r.event.is_none()
                && is(&r.id, "bootcReset")
                && is(&r.error, "-398")
                && r.response_type.is_none()
                && r.encrypted
                && r.payload == "<assign/><error msg=\"Session Timeout\" />"
        }),
        describe(r.as_ref()),
    );
    same_raw(
        c,
        "Send: event name is case sensitive",
        send(
            None,
            &[
                ("PhoneName", b"p13phone"),
                ("Method", b"Digium.Assignment.Update"),
                ("Message", b"x"),
            ],
        ),
        &resp("Success", None),
    );
    let r = a.next_event(secs(5.0), None);
    c.check(
        "Send: other case is a plain event",
        r.as_ref().is_some_and(|r| {
            is(&r.event, "Digium.Assignment.Update") && r.id.is_none() && r.error.is_none()
        }),
        describe(r.as_ref()),
    );
    Ok(())
}

fn expect_reconfigure(c: &mut Checker, phone: &Phone, label: &str, body: &[u8]) {
    let r = phone.next_event(secs(5.0), None);
    let session = phone.session().unwrap_or_default();
    c.check(
        format!("{label}: digium.config.update reaches the phone"),
        r.as_ref().is_some_and(|r| {
            is(&r.event, "digium.config.update")
                && r.id.is_none()
                && r.error.is_none()
                && r.encrypted
                && r.payload == body
                && is(&r.session, &session)
        }),
        describe(r.as_ref()),
    );
}

const PLAIN_BODY: &[u8] = b"<config></config>";

fn reconfigure(ctx: &mut Ctx, st: &State) -> Result<()> {
    let (ami, a, b) = (&st.ami, &st.a, &st.b);
    drain(a);
    drain(b);
    let out = ctx.cli_text("digium_phones reconfigure phone p13phone");
    ctx.c.same(
        "CLI reconfigure phone",
        out.as_str(),
        "Phone 'P13 Phone' will reconfigure shortly.\n",
    );
    expect_reconfigure(&mut ctx.c, a, "CLI reconfigure phone", PLAIN_BODY);
    let out = ctx.cli_text("digium_phones reconfigure phone p13phone3");
    ctx.c.same(
        "CLI reconfigure phone, not contacted",
        out.as_str(),
        "Phone 'p13phone3' has not contacted the server.  The server is unaware of the location of this device and can not reconfigure it at this time.\n",
    );
    let out = ctx.cli_text("digium_phones reconfigure all");
    ctx.c.same(
        "CLI reconfigure all",
        out.as_str(),
        "Reconfigure message successfully sent to all known device locations.\n",
    );
    expect_reconfigure(&mut ctx.c, a, "CLI reconfigure all (p13phone)", PLAIN_BODY);
    expect_reconfigure(&mut ctx.c, b, "CLI reconfigure all (p13phone2)", PLAIN_BODY);

    let c = &mut ctx.c;
    let rc = |name: &str, id: &str, fields: &[(&str, &[u8])]| {
        raw(ami, name, Some(id.as_bytes()), fields)
    };
    same_raw(
        c,
        "AMI DigiumPhoneReconfigure",
        rc("DigiumPhoneReconfigure", "c1", &[("PhoneName", b"p13phone")]),
        b"Response: Success\r\nActionID: c1\r\nMessage: Reconfigure message successfully sent\r\n\r\n",
    );
    expect_reconfigure(c, a, "AMI DigiumPhoneReconfigure", PLAIN_BODY);
    same_raw(
        c,
        "AMI DigiumPhoneReconfigure: empty",
        rc("DigiumPhoneReconfigure", "c2", &[]),
        b"Response: Error\r\nActionID: c2\r\nMessage: PhoneName argument is empty.\r\n\r\n",
    );
    same_raw(
        c,
        "AMI DigiumPhoneReconfigure: unknown",
        rc("DigiumPhoneReconfigure", "c3", &[("PhoneName", b"nobody")]),
        b"Response: Error\r\nActionID: c3\r\nMessage: Could not find user to reconfigure.\r\n\r\n",
    );
    same_raw(
        c,
        "AMI DigiumPhoneReconfigure: not contacted",
        rc("DigiumPhoneReconfigure", "c4", &[("PhoneName", b"p13phone3")]),
        b"Response: Error\r\nActionID: c4\r\nMessage: Phone has not contacted the server.  The server is unaware of the location of this device and can not reconfigure it at this time.\n\r\n\r\n",
    );
    same_raw(
        c,
        "AMI DigiumPhoneReconfigureAll",
        rc("DigiumPhoneReconfigureAll", "c5", &[]),
        b"Response: Success\r\nActionID: c5\r\nMessage: Reconfigure message successfully sent to all known device locations.\r\n\r\n",
    );
    expect_reconfigure(c, a, "AMI DigiumPhoneReconfigureAll (p13phone)", PLAIN_BODY);
    expect_reconfigure(
        c,
        b,
        "AMI DigiumPhoneReconfigureAll (p13phone2)",
        PLAIN_BODY,
    );

    // The two bodies of phone_user_send_reconfigure (the delete-token one
    // has no caller in the original).
    let la = a.local_addr();
    let uri = format!("pjsip:{}:{}", la.ip(), la.port());
    let session = a.session().unwrap_or_default();
    let out = ctx.cli_text(&format!("dpmadev token reconfigure {session} {uri}"));
    expect_reconfigure(
        &mut ctx.c,
        a,
        &format!("plain body ({})", out.trim()),
        PLAIN_BODY,
    );
    let out = ctx.cli_text(&format!("dpmadev token reconfigure {session} {uri} delete"));
    expect_reconfigure(
        &mut ctx.c,
        a,
        &format!("delete-token body ({})", out.trim()),
        DELETE_TOKEN_BODY,
    );
    Ok(())
}

fn reload(ctx: &mut Ctx, st: &State) -> Result<()> {
    let (a, b) = (&st.a, &st.b);
    let path = ctx.inst.conf(CONF);
    let lines_changed = CONF_TEXT.replace(
        "full_name=P13 Phone\nline=p13line\n",
        "full_name=P13 Phone\nline=p13line4\n",
    );
    let result = (|| -> Result<()> {
        drain(a);
        drain(b);
        let log = ctx.log();
        let pos = log.mark();
        std::fs::write(&path, &lines_changed)?;
        ctx.cli_text("module reload res_dpma_rs.so");
        expect_reconfigure(&mut ctx.c, a, "reload, lines changed", PLAIN_BODY);
        fixtures::sleep(0.3);
        let text = log.since(pos);
        let tail = &text[text.len().saturating_sub(2000)..];
        ctx.c.check(
            "reload, lines changed: logs",
            text.contains_str("Phone user 'p13phone' setting reconfigure due to change in lines")
                && text.contains_str("Sending reconfigure to user p13phone"),
            tail.to_str_lossy(),
        );
        let r = b.next_event(secs(1.0), None);
        ctx.c.check(
            "reload, lines changed: other phones untouched",
            r.is_none(),
            r.map(|r| r.describe(0).to_str_lossy().into_owned())
                .unwrap_or_default(),
        );

        std::fs::write(
            &path,
            lines_changed.replace(
                "[p13phone2]\ntype=phone\n",
                "[p13phone2-gone]\ntype=phone\n",
            ),
        )?;
        ctx.cli_text("module reload res_dpma_rs.so");
        expect_reconfigure(&mut ctx.c, b, "reload, phone removed", PLAIN_BODY);
        let r = a.next_event(secs(1.0), None);
        ctx.c.check(
            "reload, phone removed: other phones untouched",
            r.is_none(),
            r.map(|r| r.describe(0).to_str_lossy().into_owned())
                .unwrap_or_default(),
        );
        Ok(())
    })();
    std::fs::write(&path, CONF_TEXT)?;
    ctx.cli_text("module reload res_dpma_rs.so");
    result
}

/// A queued request and an event for a phone whose session was replaced
/// by a new handshake from the same MAC.
fn session_gone(ctx: &mut Ctx, o: Opts, st: &State) -> Result<()> {
    let (ami, b) = (&st.ami, &st.b);
    let (ok, detail) = authenticate(ctx, o.via, b, "p13phone2")?;
    ctx.c.check("p13phone2 located again", ok, detail);
    let mut f = forward(
        ctx,
        o.via,
        b,
        "com.p13.hello",
        Params::Json(json!({"gone": 1})),
        "p13phone2:2323",
    )?;
    dpma_message(&mut ctx.c, ami, &f, "com.p13.hello", "JSON", "session gone");
    // Prunes b's session.
    let _b2 = new_phone(ctx, b.mac())?;
    same_raw(
        &mut ctx.c,
        "session gone: AMI response",
        raw(
            ami,
            "DPMAMessageResponse",
            None,
            &[
                ("RequestID", f.key.as_bytes()),
                ("Format", b"json"),
                ("Response", b"x"),
            ],
        ),
        &resp("Failure", None),
    );
    let q = queued(ctx);
    ctx.c.same("session gone: no longer queued", q, vec![]);
    let r = reply_of(b, &mut f.ex, 1.0);
    ctx.c.check(
        "session gone: nothing sent",
        r.is_none(),
        r.map(|r| r.describe(0).to_str_lossy().into_owned())
            .unwrap_or_default(),
    );
    let log = ctx.log();
    let pos = log.mark();
    same_raw(
        &mut ctx.c,
        "Send: session gone",
        raw(
            ami,
            "DPMAMessageSend",
            None,
            &[("PhoneName", b"p13phone2"), ("Method", b"e")],
        ),
        &resp("Failure", None),
    );
    fixtures::sleep(0.3);
    let text = log.since(pos);
    ctx.c.check(
        "Send: session gone logged",
        text.contains_str("Unable to send event to 'p13phone2' without session"),
        text.to_str_lossy(),
    );
    Ok(())
}

fn expiry(ctx: &mut Ctx, o: Opts, st: &State) -> Result<()> {
    let (ami, a) = (&st.ami, &st.a);
    let log = ctx.log();
    let pos = log.mark();
    let mut f = forward(
        ctx,
        o.via,
        a,
        "com.p13.hello",
        Params::Json(json!({"expire": 1})),
        "p13phone:1313",
    )?;
    let t0 = Instant::now();
    dpma_message(&mut ctx.c, ami, &f, "com.p13.hello", "JSON", "expiry");
    ctx.c.note("waiting about 300 s for the expiry ...");
    while t0.elapsed() < secs(290.0) {
        fixtures::sleep(5.0);
        // Keep the session active.
        let _ = a.ping().send();
    }
    let keys = queued_keys(ctx);
    ctx.c.check(
        "expiry: still queued after 290 s",
        keys == [f.key.clone()],
        format!("{:?}", queued(ctx)),
    );
    while t0.elapsed() < secs(320.0) && !queued(ctx).is_empty() {
        fixtures::sleep(1.0);
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let q = queued(ctx);
    ctx.c.same("expiry: no longer queued", q, vec![]);
    ctx.c.check(
        "expiry: expired after 300 s",
        (295.0..320.0).contains(&elapsed),
        format!("{elapsed:.1} s"),
    );
    fixtures::sleep(0.3);
    let text = log.since(pos);
    ctx.c.check(
        "expiry: logged",
        text.contains_str(format!("No response to request ({}), expired.", f.key)),
        text.to_str_lossy(),
    );
    same_raw(
        &mut ctx.c,
        "expiry: later response fails",
        raw(
            ami,
            "DPMAMessageResponse",
            None,
            &[
                ("RequestID", f.key.as_bytes()),
                ("Format", b"json"),
                ("Response", b"x"),
            ],
        ),
        &resp("Failure", None),
    );
    let r = reply_of(a, &mut f.ex, 1.0);
    ctx.c.check(
        "expiry: nothing sent",
        r.is_none(),
        r.map(|r| r.describe(0).to_str_lossy().into_owned())
            .unwrap_or_default(),
    );
    Ok(())
}

/// A part that uses the shared state (made by the first part that runs).
fn part(
    shared: &Shared,
    o: Opts,
    f: impl Fn(&mut Ctx, Opts, &State) -> Result<()> + 'static,
) -> impl Fn(&mut Ctx) -> Result<()> + 'static {
    let shared = shared.clone();
    move |ctx| {
        let mut slot = shared.borrow_mut();
        if slot.is_none() {
            *slot = Some(init(ctx, o)?);
        }
        f(ctx, o, slot.as_ref().expect("initialized"))
    }
}

fn main() -> std::process::ExitCode {
    let o = match parse_opts() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("suite ami: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let shared: Shared = Rc::new(RefCell::new(None));
    let mut suite = Suite::new("ami")
        .value_option("--via")
        .prepare(|inst| fixtures::prepare(inst, setup))
        .part("actions", part(&shared, o, |ctx, _, st| actions(ctx, st)))
        .part("forwarding", part(&shared, o, forwarding))
        .part("send", part(&shared, o, |ctx, _, st| send(ctx, st)))
        .part(
            "reconfigure",
            part(&shared, o, |ctx, _, st| reconfigure(ctx, st)),
        )
        .part("reload", part(&shared, o, |ctx, _, st| reload(ctx, st)))
        .part("session-gone", part(&shared, o, session_gone));
    if o.expiry {
        suite = suite.part("expiry", part(&shared, o, expiry));
    }
    let code = suite.main();
    // Close the phones and the AMI connection.
    shared.borrow_mut().take();
    code
}
