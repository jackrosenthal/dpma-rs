//! The raw-bytes suite: text that is not UTF-8 passes through unchanged.
//!
//! ```text
//! cargo xtask test raw-bytes
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test raw-bytes -- --ignored [--no-prepare] [-v] [PART...]
//! ```
//!
//! The suite prepares the instance with the configuration of [`fixtures`]
//! (`--no-prepare` skips this).
//!
//! Where the official DPMA hands such text to jansson, the request fails
//! the way jansson makes the official DPMA fail; where it hands it to
//! libxml2, libxml2 refuses it as it does for the official DPMA.

mod fixtures;

use std::cell::Cell;
use std::time::Duration;

use anyhow::{bail, Result};
use base64::Engine;
use bstr::{BString, ByteSlice};
use dpma_tests::ami::{AmiClient, AmiMessage};
use dpma_tests::harness::{self, Checker, Ctx, Instance, LogMark, Suite};
use dpma_tests::sim::proto::{method_request_json, method_request_xml};
use dpma_tests::sim::{Exchange, Options, Phone, Reply};
use regex::bytes::Regex;
use serde_json::json;

use crate::fixtures as fx;

/// The wrapper around HTTPRequest and AsteriskResponse documents.
const HTTP: &[u8] = harness::fixtures::HTTP_PREAMBLE;

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A CLI command given as bytes; its exact output.
fn cli(ctx: &Ctx, cmd: &[u8]) -> BString {
    ctx.inst
        .cli()
        .and_then(|c| c.run_bytes(cmd))
        .unwrap_or_default()
}

/// What Asterisk logged since `mark`, once `wanted` was (Asterisk's
/// logger writes from its own thread; at most 3 s).
fn log_since(ctx: &Ctx, mark: LogMark, wanted: &[u8]) -> BString {
    let log = ctx.log();
    log.wait_for(mark, wanted, Duration::from_secs(3));
    log.since(mark)
}

/// A regular expression over bytes (Unicode off: `\xHH` is a byte).
fn bytes_re(pattern: &str) -> Regex {
    Regex::new(&format!("(?-u){pattern}")).expect("valid regular expression")
}

/// Escapes bytes for [`bytes_re`].
fn re_escape(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if c.is_ascii_alphanumeric() {
                char::from(c).to_string()
            } else {
                format!("\\x{c:02X}")
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// AMI, byte for byte
// ---------------------------------------------------------------------------

/// An AMI connection whose actions always carry an ActionID (given, or
/// `raw-<n>`) and return raw messages.
struct Ami {
    client: AmiClient,
    seq: Cell<u32>,
}

impl Ami {
    fn connect(inst: &Instance) -> Result<Ami> {
        Ok(Ami {
            client: inst.ami()?,
            seq: Cell::new(0),
        })
    }

    /// Sends an action; returns its response and, for list actions, the
    /// events up to `EventList: Complete`, as raw bytes.
    fn action(
        &self,
        fields: &[(&[u8], &[u8])],
        action: &str,
        action_id: Option<&[u8]>,
    ) -> Vec<BString> {
        self.seq.set(self.seq.get() + 1);
        let id = action_id
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| format!("raw-{}", self.seq.get()).into_bytes());
        let mut all: Vec<(&[u8], &[u8])> = vec![(&b"ActionID"[..], id.as_slice())];
        all.extend_from_slice(fields);
        let res = self
            .client
            .action_timeout(action, all, Duration::from_secs(5));
        res.response
            .iter()
            .chain(res.events.iter())
            .map(|m| m.raw().clone())
            .collect()
    }

    /// The first event `name` received (removed).
    fn event(&self, name: &str) -> Option<AmiMessage> {
        self.client
            .wait_event(Some(name), &[], Duration::from_secs(5))
    }
}

/// The value of header `name` in a raw message.
fn header(msg: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    msg.split_str("\r\n").find_map(|l| {
        l.strip_prefix(name)
            .and_then(|r| r.strip_prefix(b": "))
            .map(<[u8]>::to_vec)
    })
}

// ---------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------

/// A phone with a Latin-1 user agent and origination network, after its
/// handshake; its session is added to `sessions`.
fn phone(ctx: &Ctx, mac: &str, sessions: &mut Vec<BString>) -> Result<Phone> {
    let mut o = ctx.sim_options().mac(mac);
    o.user_agent = fx::USER_AGENT.into();
    o.origination_network = Some(fx::ORIGINATION.into());
    let p = Phone::start(o)?;
    let ex = p.handshake().send()?;
    if !ex.ok() {
        bail!("handshake failed:\n{}", ex.describe(0));
    }
    sessions.push(p.session().unwrap_or_default().into());
    Ok(p)
}

fn reply_of(c: &mut Checker, name: &str, ex: &Exchange) -> Option<Reply> {
    let r = ex.reply.clone();
    c.check_with(
        format!("{name} (reply)"),
        r.as_ref().is_some_and(|r| r.problems.is_empty()),
        || ex.describe(0).to_str_lossy().into_owned(),
    );
    r
}

/// The Latin-1 phone's credentials.
fn phone_auth() -> Vec<u8> {
    cat(&[fx::PHONE, b":", fx::PIN])
}

/// An AsteriskRequest; the reply payload.
fn asterisk(p: &Phone, doc: impl AsRef<[u8]>, auth: Option<&[u8]>) -> Result<Option<BString>> {
    let auth = auth.map_or_else(phone_auth, <[u8]>::to_vec);
    Ok(p.asterisk(doc).auth(auth).send()?.reply.map(|r| r.payload))
}

/// A JSON request error document in its HTTP wrapper.
fn json_error(method: &str, code: u32, detail: &str) -> Vec<u8> {
    harness::fixtures::http_wrap(harness::fixtures::json_error(method, code, detail).as_bytes())
}

/// The parse error (10002, "Error parsing request").
const PARSE: u32 = 10002;

fn describe(r: Option<&Reply>) -> String {
    r.map(|r| r.describe(0).to_str_lossy().into_owned())
        .unwrap_or_else(|| "no reply".into())
}

/// Forgets the test phones' sessions and locations in AstDB, so that
/// later suites do not restore them.
fn cleanup(ctx: &Ctx, sessions: &[BString]) {
    for sid in sessions {
        cli(ctx, &cat(&[b"database del DigiumPhoneSessions ", sid]));
    }
    for name in [fx::PHONE, fx::U_PHONE] {
        cli(ctx, &cat(&[b"database del DigiumPhoneUsers ", name]));
    }
}

/// Runs `f` with a list of sessions, then [`cleanup`].
fn with_cleanup(
    ctx: &mut Ctx,
    f: impl FnOnce(&mut Ctx, &mut Vec<BString>) -> Result<()>,
) -> Result<()> {
    let mut sessions = Vec::new();
    let r = f(ctx, &mut sessions);
    cleanup(ctx, &sessions);
    r
}

// ---------------------------------------------------------------------------
// The parts
// ---------------------------------------------------------------------------

fn check_cli(ctx: &mut Ctx) -> Result<()> {
    let show = |what: &[u8]| cli(ctx, &cat(&[b"digium_phones show ", what]));
    let out = show(b"phones");
    let out_phone = show(&cat(&[b"phone ", fx::PHONE]));
    let out_uphone = show(&cat(&[b"phone ", fx::U_PHONE]));
    let out_line = show(&cat(&[b"line ", fx::LINE]));
    let out_networks = show(b"networks");
    let out_network = show(&cat(&[b"network ", fx::NETWORK]));
    let out_apps = show(b"applications");
    let out_status_app = show(&cat(&[b"application ", fx::STATUS_APP]));
    let out_custom_app = show(&cat(&[b"application ", fx::CUSTOM_APP]));
    let out_alerts = show(b"alerts");
    let out_alert = show(&cat(&[b"alert ", fx::ALERT]));
    let out_page = show(&cat(&[b"multicastpage ", fx::PAGE]));
    let out_translations = show(b"translations");
    let out_translation = show(&cat(&[b"translation ", fx::TRANSLATION]));
    let out_status = show(&cat(&[b"status ", fx::PHONE]));
    let c = &mut ctx.c;
    c.contains(
        "show phones",
        &out,
        &[cat(&[fx::PHONE, b"\n"]), cat(&[fx::U_PHONE, b"\n"])],
    );
    c.contains(
        "show phone",
        &out_phone,
        &[
            cat(&[b"Name: ", fx::PHONE, b"\n"]),
            cat(&[b"Full Name: ", fx::FULL_NAME, b"\n"]),
            cat(&[b"Application: Status, ", fx::STATUS_APP, b"\n"]),
            cat(&[b"Application: Custom, ", fx::CUSTOM_APP, b"\n"]),
            cat(&[b"Contact: ", fx::CONTACT_FILE, b"\n"]),
            cat(&[b"Alert: ", fx::ALERT, b"\n"]),
            cat(&[b"Contacts Display Items: ", fx::RULES_FILE, b"\n"]),
        ],
    );
    c.contains(
        "show phone (UTF-8)",
        &out_uphone,
        &[cat(&[b"Full Name: ", fx::U_FULL_NAME, b"\n"])],
    );
    c.contains(
        "show line",
        &out_line,
        &[
            cat(&[b"Line Label: ", fx::LINE_LABEL, b"\n"]),
            cat(&[b"First Name: ", fx::FIRST_NAME, b"\n"]),
            cat(&[b"Last Name: ", fx::LAST_NAME, b"\n"]),
            cat(&[b"Location: ", fx::LOCATION, b"\n"]),
        ],
    );
    c.contains(
        "show networks",
        &out_networks,
        &[cat(&[b"    ", fx::NETWORK, b"\n"])],
    );
    c.contains(
        "show network",
        &out_network,
        &[
            cat(&[b"Name: ", fx::NETWORK, b"\n"]),
            cat(&[b"Alias: ", fx::NET_ALIAS, b"\n"]),
        ],
    );
    c.contains(
        "show applications",
        &out_apps,
        &[fx::STATUS_APP, fx::CUSTOM_APP, fx::VM_APP],
    );
    c.contains(
        "show application (status)",
        &out_status_app,
        &[cat(&[b"Substatuses:\n    ", fx::SUBSTATUS, b"\n"])],
    );
    c.contains(
        "show application (custom)",
        &out_custom_app,
        &[fx::CUSTOM_NAME],
    );
    c.contains(
        "show alerts",
        &out_alerts,
        &[cat(&[b"    ", fx::ALERT, b"\n"])],
    );
    c.contains(
        "show alert",
        &out_alert,
        &[cat(&[b"Alert Info: ", fx::ALERT_INFO, b"\n"])],
    );
    c.contains(
        "show multicastpage",
        &out_page,
        &[cat(&[b"Alias: ", fx::PAGE_ALIAS, b"\n"])],
    );
    c.contains(
        "show translations",
        &out_translations,
        &[cat(&[b"    ", fx::TRANSLATION, b"\n"])],
    );
    c.contains(
        "show translation",
        &out_translation,
        &[
            cat(&[b"--- ", fx::TRANSLATION, b" ---\n"]),
            cat(&[b"    INBOX ==> ", fx::INBOX_FR, b"\n"]),
        ],
    );
    c.contains(
        "show status",
        &out_status,
        &[cat(&[b" - ", fx::SUBSTATUS, b"\n"])],
    );
    Ok(())
}

fn check_phone(ctx: &mut Ctx, sessions: &mut Vec<BString>) -> Result<()> {
    let ami = Ami::connect(&ctx.inst)?;
    let p = phone(ctx, fx::MAC, sessions)?;

    // Echo: the body and the origination network come back unchanged.
    let body: &[u8] = b"\xc9cho: Jos\xe9 \xff\xfe";
    let ex = p.echo(body).send()?;
    if let Some(r) = reply_of(&mut ctx.c, "Echo", &ex) {
        ctx.c.same_bytes("Echo body", &r.payload, body);
        ctx.c.same(
            "Echo X-Origination-Network",
            r.header("X-Origination-Network").map(|v| v.to_vec()),
            Some(fx::ORIGINATION.to_vec()),
        );
    }

    let mark = ctx.log().mark();
    let ex = p.get_token().send()?;
    reply_of(&mut ctx.c, "TokenRequest", &ex);
    let token = p.token();
    ctx.c.check(
        "token names the phone",
        token
            .as_ref()
            .is_some_and(|t| t.starts_with(&cat(&[fx::PHONE, b"/", fx::MAC.as_bytes(), b"/"]))),
        format!("{token:?}"),
    );
    let want = cat(&[b"Phone user '", fx::PHONE, b"' now connected from '"]);
    let text = log_since(ctx, mark, &want);
    ctx.c.contains("log: now connected", &text, &[want]);

    // The configuration document.
    let mark = ctx.log().mark();
    let ex = p.config().send()?;
    let r = reply_of(&mut ctx.c, "ConfigRequest", &ex);
    let doc = r.map(|r| r.payload).unwrap_or_default();
    let want = cli(ctx, &cat(&[b"dpmadev config ", fx::PHONE, b" D65"]));
    ctx.c
        .same_bytes("ConfigRequest document = dpmadev config", &doc, &want);
    ctx.c.contains(
        "configuration document",
        &doc,
        &[
            cat(&[b"first_name=\"", fx::FIRST_NAME, b"\""]),
            cat(&[b"last_name=\"", fx::LAST_NAME, b"\""]),
            cat(&[b"line_label=\"", fx::LINE_LABEL, b"\""]),
            b"caller_id=\"&quot;Jos\xe9&quot; &lt;1001&gt;\"".to_vec(),
            cat(&[
                b"<network id=\"",
                fx::NETWORK,
                b"\" display_name=\"",
                fx::NET_ALIAS,
                b"\" cidr=\"0.0.0.0/0\" />",
            ]),
            cat(&[
                b"<setting id=\"idle_company_text\" value=\"",
                fx::IDLE_TEXT,
                b"\" />",
            ]),
            cat(&[b"label1=\"", fx::CUSTOM_NAME, b"\""]),
            cat(&[b"<contacts url=\"file://", fx::CONTACT_FILE, b"\""]),
            cat(&[b"alert_info=\"", fx::ALERT_INFO, b"\""]),
            fx::PAGE_ALIAS.to_vec(),
            cat(&[
                b"display=\"",
                fx::RINGTONE_ALIAS,
                b"\" url=\"",
                fx::FILE_URL,
                b"sonnerie.raw\"",
            ]),
        ],
    );
    // The display rules merge: libxml2 refuses the Latin-1 document, so
    // it goes out unmerged.
    ctx.c.check(
        "display rules: document not merged",
        doc.starts_with(b"<config>"),
        format!("{:?}", doc[..doc.len().min(80)].as_bstr()),
    );
    let want = "Error Parsing phone user config, phone configuration may be invalid.";
    let text = log_since(ctx, mark, want.as_bytes());
    ctx.c.contains(
        "display rules: libxml2 refused the document",
        &text,
        &[want],
    );

    // Files: a Latin-1 name, and the default contacts.
    let ex = p.file(fx::CONTACT_FILE).send()?;
    if let Some(r) = reply_of(&mut ctx.c, "FileRequest (Latin-1 name)", &ex) {
        ctx.c.same_bytes(
            "FileRequest (Latin-1 name) contents",
            &r.payload,
            fx::CONTACT_XML,
        );
    }
    let ex = p.file("default").send()?;
    if let Some(r) = reply_of(&mut ctx.c, "FileRequest file://default", &ex) {
        ctx.c.contains(
            "default contacts",
            &r.payload,
            &[
                cat(&[b"<contact first_name=\"", fx::FIRST_NAME, b"\" "]),
                cat(&[b"last_name=\"", fx::LAST_NAME, b"\" "]),
                cat(&[b"location=\"", fx::LOCATION, b"\" "]),
                cat(&[b"<contact first_name=\"", fx::U_FULL_NAME, b"\" "]),
            ],
        );
        let want = cli(ctx, b"dpmadev contacts");
        ctx.c
            .same_bytes("default contacts = dpmadev contacts", &r.payload, &want);
    }

    // The user list goes through jansson: the UTF-8 phone's group pin
    // lists it byte for byte; the Latin-1 phone's makes jansson fail,
    // which the official DPMA answers as a bad configuration password.
    let ex = p.userlist().config_password(fx::U_GROUP_PIN).send()?;
    if let Some(r) = reply_of(&mut ctx.c, "UserlistRequest (UTF-8 phone)", &ex) {
        // "assigned" is "1" when the phone has a session id (a run
        // before this one may have left one in AstDB).
        let info = cli(ctx, &cat(&[b"dpmadev token info ", fx::U_PHONE]));
        let assigned: &[u8] = if info.contains_str("last_session_id='' ") {
            b"0"
        } else {
            b"1"
        };
        let want = cat(&[
            b"{\"users\":[{\"extension\":\"1002\",\"name\":\"",
            fx::U_FULL_NAME,
            b"\",\"assigned\":\"",
            assigned,
            b"\"}]}",
        ]);
        ctx.c.same_bytes("user list (UTF-8)", &r.payload, &want);
    }
    for (label, pin) in [
        ("Latin-1 phone", fx::GROUP_PIN),
        ("everybody", fx::GLOBALPIN),
    ] {
        let r = p.userlist().config_password(pin).send()?.reply;
        ctx.c.check_with(
            format!("UserlistRequest ({label}): jansson fails, -198"),
            r.as_ref()
                .is_some_and(|r| r.error.as_ref().is_some_and(|e| e == "-198")),
            || describe(r.as_ref()),
        );
    }
    let out = cli(ctx, &cat(&[b"dpmadev userlist ", fx::GROUP_PIN]));
    ctx.c.same_bytes(
        "dpmadev userlist (Latin-1 phone)",
        &out,
        b"Failed to build the user list\n",
    );

    // Methods: jansson refuses the Latin-1 values the official DPMA packs.
    let call = |method: &str, params: serde_json::Value| -> Result<Option<BString>> {
        asterisk(&p, method_request_json(method, Some(&params)), None)
    };
    let same_opt = |c: &mut Checker, name: &str, got: Option<BString>, want: &[u8]| {
        c.same(name, got.map(|g| g.to_vec()), Some(want.to_vec()));
    };
    let m = "switchvox.users.presence.options.getList";
    let got = call(m, json!({}))?;
    same_opt(
        &mut ctx.c,
        "presence.options.getList: Latin-1 sub-state",
        got,
        &json_error(m, PARSE, "pack options array"),
    );
    let m = "switchvox.users.voicemail.getList";
    let got = call(m, json!({"account_id": "1001", "folder": "INBOX"}))?;
    same_opt(
        &mut ctx.c,
        "voicemail.getList INBOX: Latin-1 translation",
        got,
        &json_error(m, PARSE, "pack messages"),
    );
    let got = call(m, json!({"account_id": "1001", "folder": "Work"}))?;
    same_opt(
        &mut ctx.c,
        "voicemail.getList Work: Latin-1 caller id",
        got,
        &json_error(m, PARSE, "message_entry"),
    );
    let m = "switchvox.users.voicemail.getFolderList";
    let got = call(m, json!({"account_id": "1001"}))?;
    same_opt(
        &mut ctx.c,
        "voicemail.getFolderList: Latin-1 translation",
        got,
        &json_error(m, PARSE, "append folder"),
    );
    let got = call(
        "switchvox.users.voicemail.getList",
        json!({"account_id": "1001", "folder": "Family"}),
    )?;
    ctx.c.contains(
        "voicemail.getList Family: UTF-8 caller id",
        got.unwrap_or_default(),
        &[
            &b"\"caller_id\":\"\\\"Fr\xc3\xa9d\xc3\xa9ric\\\" <300>\""[..],
            b"\"caller_id_name\":\"Fr\xc3\xa9d\xc3\xa9ric\"",
        ],
    );
    // A request body that is not UTF-8: jansson and libxml2 refuse it.
    let got = asterisk(
        &p,
        b"{\"request\":{\"method\":\"x\",\"parameters\":{\"n\":\"Jos\xe9\"}}}",
        None,
    )?;
    same_opt(
        &mut ctx.c,
        "JSON request with Latin-1",
        got,
        &json_error("NA", PARSE, "json body"),
    );
    let xml_err: &[u8] = b"<response method=\"NA\">\r\n<errors>\r\n<error code=\"10002\" message=\"Error parsing request\" />\r\n</errors>\r\n</response>\r\n";
    let got = asterisk(
        &p,
        b"<request method=\"x\"><parameters>Jos\xe9</parameters></request>",
        None,
    )?;
    same_opt(
        &mut ctx.c,
        "XML request with Latin-1",
        got,
        &cat(&[HTTP, xml_err, b"\r\n\r\n"]),
    );
    // Latin-1 credentials that fail: the error document cannot be built
    // (jansson), so the reply is the bare HTTP header.
    let mark = ctx.log().mark();
    let got = asterisk(
        &p,
        method_request_json("x", Some(&json!({}))),
        Some(b"nob\xf6dy:x"),
    )?;
    same_opt(
        &mut ctx.c,
        "Latin-1 credentials: no error document",
        got,
        HTTP,
    );
    let want = "Unable to generate JSON for error response";
    let text = log_since(ctx, mark, want.as_bytes());
    ctx.c.contains(
        "log: Unable to generate JSON for error response",
        &text,
        &[want],
    );

    check_ami_phone(ctx, &ami, &p)?;
    check_astdb(ctx, &p);
    Ok(())
}

fn check_ami_phone(ctx: &mut Ctx, ami: &Ami, p: &Phone) -> Result<()> {
    ctx.c.say("-- AMI (Latin-1 headers)");
    let msgs = ami.action(&[], "DPMAShowPhones", Some(b"raw-\xe9"));
    let mac = cat(&[b"MAC: ", fx::MAC.as_bytes(), b"\r\n"]);
    let ev = msgs
        .iter()
        .find(|m| m.starts_with(b"Event: DPMAShowPhonesList") && m.contains_str(&mac))
        .cloned()
        .unwrap_or_default();
    ctx.c.contains(
        "DPMAShowPhones",
        &ev,
        &[
            b"ActionID: raw-\xe9\r\n".to_vec(),
            cat(&[b"UserAgent: ", fx::USER_AGENT, b"\r\n"]),
            cat(&[b"Username: ", fx::PHONE, b"\r\n"]),
            mac.clone(),
        ],
    );

    // DPMAMessageSend: event name and body reach the phone unchanged.
    let (method, message): (&[u8], &[u8]) =
        (b"\xe9v\xe9nement.test", b"Corps du message: \xe9\xe8\xe0");
    let r = ami.action(
        &[
            (b"PhoneName", fx::PHONE),
            (b"Method", method),
            (b"Message", message),
        ],
        "DPMAMessageSend",
        Some(b"send-\xe9"),
    );
    ctx.c.same(
        "DPMAMessageSend response",
        r.first().cloned(),
        Some(BString::from(
            &b"Response: Success\r\nActionID: send-\xe9\r\n\r\n"[..],
        )),
    );
    let e = p.next_event(p.opts().timeout, None);
    ctx.c
        .check("DPMAMessageSend event arrived", e.is_some(), "");
    if let Some(e) = e {
        ctx.c.same(
            "event name",
            e.event.as_ref().map(|v| v.to_vec()),
            Some(method.to_vec()),
        );
        ctx.c.same_bytes("event body", &e.payload, message);
    }

    // Reconfigure by a Latin-1 phone name.
    let r = ami.action(&[(b"PhoneName", fx::PHONE)], "DigiumPhoneReconfigure", None);
    ctx.c.contains(
        "DigiumPhoneReconfigure",
        r.first().cloned().unwrap_or_default(),
        &[
            &b"Response: Success\r\n"[..],
            b"Message: Reconfigure message successfully sent\r\n",
        ],
    );
    let e = p.next_event(p.opts().timeout, Some("digium.config.update"));
    ctx.c.check(
        "reconfigure reached the phone",
        e.as_ref().is_some_and(|e| e.payload == "<config></config>"),
        "",
    );

    // Latin-1 method names register; the registry shows them as they
    // came.
    let r = ami.action(
        &[(b"Method", b"p18.m\xe9thode")],
        "DPMAMessageRegister",
        None,
    );
    ctx.c.same(
        "DPMAMessageRegister (Latin-1)",
        r.first().cloned(),
        Some(BString::from(format!(
            "Response: Success\r\nActionID: raw-{}\r\n\r\n",
            ami.seq.get()
        ))),
    );
    let out = cli(ctx, b"dpmadev method list");
    ctx.c
        .contains("dpmadev method list", &out, &[&b"  p18.m\xe9thode\n"[..]]);

    // Requests forwarded to AMI: the XML answer passes as bytes; a JSON
    // answer that is not UTF-8 fails (jansson), and the request waits.
    ami.action(&[(b"Method", b"p18.raw")], "DPMAMessageRegister", None);
    let mut ex = p
        .asterisk(method_request_xml("p18.raw", "Ren&#xE9;"))
        .auth(phone_auth())
        .no_wait()
        .send()?;
    let ev = ami
        .event("DPMAMessage")
        .map(|m| m.raw().clone())
        .unwrap_or_default();
    ctx.c.contains(
        "DPMAMessage (XML)",
        &ev,
        &[
            &b"Method: p18.raw\r\n"[..],
            b"Format: XML\r\n",
            b"Parameters: Ren\xc3\xa9\r\n",
        ],
    );
    let rid = header(&ev, b"RequestID").unwrap_or_else(|| b"?".to_vec());
    let r = ami.action(
        &[
            (b"RequestID", &rid),
            (b"Format", b"XML"),
            (b"Response", b"<r>\xe9</r>"),
        ],
        "DPMAMessageResponse",
        None,
    );
    ctx.c.contains(
        "DPMAMessageResponse XML",
        r.first().cloned().unwrap_or_default(),
        &["Response: Success\r\n"],
    );
    p.wait_reply(&mut ex, None);
    ctx.c.same(
        "forwarded XML answer",
        ex.reply.as_ref().map(|r| r.payload.to_vec()),
        Some(cat(&[
            HTTP,
            b"\r\n\r\n<response method=\"p18.raw\">\r\n<result><r>\xe9</r></result>\r\n</response>\r\n",
        ])),
    );

    let mut ex = p
        .asterisk(method_request_json(
            "p18.raw",
            Some(&json!({"a": "\u{e9}"})),
        ))
        .auth(phone_auth())
        .no_wait()
        .send()?;
    let ev = ami
        .event("DPMAMessage")
        .map(|m| m.raw().clone())
        .unwrap_or_default();
    ctx.c.contains(
        "DPMAMessage (JSON)",
        &ev,
        &[&b"Parameters: {\"a\":\"\xc3\xa9\"}\r\n"[..]],
    );
    let rid = header(&ev, b"RequestID").unwrap_or_else(|| b"?".to_vec());
    let r = ami.action(
        &[
            (b"RequestID", &rid),
            (b"Format", b"JSON"),
            (b"Response", b"\"\xe9\""),
        ],
        "DPMAMessageResponse",
        None,
    );
    ctx.c.contains(
        "DPMAMessageResponse JSON, Latin-1: jansson fails",
        r.first().cloned().unwrap_or_default(),
        &["Response: Failure\r\n"],
    );
    let r = ami.action(
        &[
            (b"RequestID", &rid),
            (b"Format", b"JSON"),
            (b"Response", b"Ren\xc3\xa9"),
        ],
        "DPMAMessageResponse",
        None,
    );
    ctx.c.contains(
        "DPMAMessageResponse JSON, UTF-8",
        r.first().cloned().unwrap_or_default(),
        &["Response: Success\r\n"],
    );
    p.wait_reply(&mut ex, None);
    ctx.c.same(
        "forwarded JSON answer",
        ex.reply.as_ref().map(|r| r.payload.to_vec()),
        Some(cat(&[
            HTTP,
            b"\r\n\r\n{\"response\":{\"method\":\"p18.raw\",\"result\":\"Ren\xc3\xa9\"}}\r\n",
        ])),
    );
    Ok(())
}

fn check_astdb(ctx: &mut Ctx, p: &Phone) {
    ctx.c.say("-- AstDB");
    let session = BString::from(p.session().unwrap_or_default());
    let out = cli(ctx, b"database show DigiumPhoneUsers");
    let re = bytes_re(&format!(
        r"/DigiumPhoneUsers/{} +: last_mac=([^;]*);last_uri=([^;]*;transport=[^;]*);last_session_id=(\S*)",
        re_escape(fx::PHONE)
    ));
    let m = re.captures(&out);
    ctx.c.check_with(
        "DigiumPhoneUsers/<Latin-1 phone>",
        m.as_ref()
            .is_some_and(|m| &m[1] == fx::MAC.as_bytes() && &m[3] == session.as_slice()),
        || format!("{out:?}"),
    );
    let out = cli(ctx, &cat(&[b"database get DigiumPhoneSessions ", &session]));
    ctx.c.contains(
        "DigiumPhoneSessions: origination network",
        &out,
        &[cat(&[b";origination_network=", fx::ORIGINATION])],
    );
    let ua = bytes_re(r";ua=([A-Za-z0-9+/=]*);")
        .captures(&out)
        .and_then(|m| base64::engine::general_purpose::STANDARD.decode(&m[1]).ok());
    ctx.c.same(
        "DigiumPhoneSessions: user agent (base64)",
        ua,
        Some(fx::USER_AGENT.to_vec()),
    );
}

fn check_incident(ctx: &mut Ctx) -> Result<()> {
    let ami = Ami::connect(&ctx.inst)?;
    for m in ami.action(&[], "DPMAShowIncidents", None) {
        if let Some(ip) = header(&m, b"IPAddress") {
            ami.action(&[(b"IPAddress", &ip)], "DPMARemoveIncident", None);
        }
    }
    let mut o: Options = ctx.sim_options().mac("000fd30018ff");
    o.user_agent = fx::USER_AGENT.into();
    let p = Phone::start(o)?;
    // No reply comes; the incident is there once its log line is.
    let mark = ctx.log().mark();
    p.handshake().bundle("rogue").no_wait().send()?;
    ctx.log().wait_for(
        mark,
        "Auth failed for ip '127.0.0.1' mac '000fd30018ff'",
        Duration::from_secs(3),
    );
    drop(p);
    let msgs = ami.action(&[], "DPMAShowIncidents", None);
    let ev = msgs
        .iter()
        .find(|m| m.starts_with(b"Event: DPMAShowIncidentsList"))
        .cloned()
        .unwrap_or_default();
    ctx.c.contains(
        "DPMAShowIncidents",
        &ev,
        &[
            cat(&[b"UserAgent: ", fx::USER_AGENT, b"\r\n"]),
            b"MAC: 000fd30018ff\r\n".to_vec(),
        ],
    );
    Ok(())
}

/// The `line_label` attributes of the `account` elements of a document.
fn line_labels(doc: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(doc)?;
    let d = roxmltree::Document::parse(text)?;
    Ok(d.descendants()
        .filter(|n| n.has_tag_name("account"))
        .filter_map(|n| n.attribute("line_label").map(str::to_string))
        .collect())
}

fn check_utf8_phone(ctx: &mut Ctx, sessions: &mut Vec<BString>) -> Result<()> {
    let p = phone(ctx, fx::U_MAC, sessions)?;
    p.get_token().send()?;
    let ex = p.config().send()?;
    let r = reply_of(&mut ctx.c, "ConfigRequest", &ex);
    let doc = r.map(|r| r.payload).unwrap_or_default();
    let want = cli(ctx, &cat(&[b"dpmadev config ", fx::U_PHONE, b" D65"]));
    ctx.c
        .same_bytes("ConfigRequest document = dpmadev config", &doc, &want);
    ctx.c.check(
        "display rules merged",
        doc.starts_with(b"<?xml"),
        format!("{:?}", doc[..doc.len().min(80)].as_bstr()),
    );
    match line_labels(&doc) {
        Ok(labels) => {
            ctx.c.same(
                "line_label",
                labels.into_iter().take(1).collect::<Vec<_>>(),
                vec![fx::U_LINE_LABEL.to_string()],
            );
        }
        Err(e) => {
            ctx.c.check("document parses", false, format!("{e:#}"));
        }
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    Suite::new("raw-bytes")
        .prepare(|inst| {
            harness::fixtures::prepare(inst, |inst| {
                harness::fixtures::sim_setup(inst)?;
                fx::install(inst)
            })
        })
        .part("cli", check_cli)
        .part("phone", |ctx| with_cleanup(ctx, check_phone))
        .part("incident", check_incident)
        .part("utf8-phone", |ctx| with_cleanup(ctx, check_utf8_phone))
        .main()
}
