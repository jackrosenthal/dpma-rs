//! The phone users' runtime (package P8) over real sessions, with the
//! request handlers (P12) in place (was
//! `tests/request-handlers/users-flows.py`): reconfigure messages
//! reaching the phone (CLI, AMI, reload, deleted phone, MAC mismatch, the
//! delete-token form), events (including `digium.assignment.update`),
//! sessions marked authenticated and inactive by token builds and
//! lookups, orphaned and stale phones, the response URI following a phone
//! that moves, and the phones' sessions restored after an Asterisk
//! restart.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use bstr::{BString, ByteSlice};
use dpma_tests::harness::{fixtures, Ctx};
use dpma_tests::sim::{Phone, Reply};

use crate::common::*;

/// The event of a reconfigure message.
const UPDATE: &str = "digium.config.update";
/// The body of a reconfigure message.
const PLAIN: &[u8] = b"<config></config>";
/// The body of a reconfigure message that deletes the phone's token.
const DELETE_TOKEN: &[u8] =
    b"<config>\t<section id=\"all\"/>\t<option id=\"delete_token\" value=\"true\"/></config>";
/// The phones whose AstDB entries are deleted first.
const PHONES: [&str; 4] = ["p12a", "p12b", "p12c", "p12tmp"];

/// Whether the users' flows were set up (once per run, before the first
/// of their parts).
static READY: AtomicBool = AtomicBool::new(false);

/// Runs a part of the users' flows.  Before the first one, deletes the
/// test phones' AstDB entries, sets the authentication modes, and
/// restarts Asterisk, so that the runtime state starts out empty.
pub fn part(ctx: &mut Ctx, f: fn(&mut Ctx) -> Result<()>) -> Result<()> {
    if !READY.swap(true, Ordering::SeqCst) {
        for name in PHONES {
            cli(ctx, &format!("database del DigiumPhoneUsers {name}"))?;
        }
        set_auth(ctx, "mac_globalpin", "disabled")?;
        restart(ctx)?;
    }
    f(ctx)
}

/// Stops and starts Asterisk, and waits two seconds.
fn restart(ctx: &mut Ctx) -> Result<()> {
    ctx.drop_ami();
    ctx.inst.stop()?;
    ctx.inst.start()?;
    fixtures::sleep(2.0);
    Ok(())
}

/// A TokenRequest for `user` with the global pin, checked.
fn token_for(ctx: &mut Ctx, p: &Phone, user: &str) -> Result<()> {
    let ex = p.get_token().user(user).config_password(GLOBALPIN).send()?;
    let name = format!("token for {user} from {}", p.mac());
    expect(ctx, &name, &ex, "TokenResponse", None, Body::Default);
    Ok(())
}

/// The last-seen information of a phone, (last MAC, last URI, last
/// session id), and its AstDB value.
type LastInfo = (Option<(String, String, String)>, Option<String>);

fn last_info(ctx: &mut Ctx, phone: &str) -> Result<LastInfo> {
    let out = cli(ctx, &format!("dpmadev token info {phone}"))?;
    let re = regex::bytes::Regex::new(
        r"last_mac='([^']*)' last_uri='([^']*)' last_session_id='([^']*)'",
    )
    .expect("pattern");
    let info = re.captures(&out).map(|c| {
        let s = |i: usize| c[i].to_str_lossy().into_owned();
        (s(1), s(2), s(3))
    });
    let db = capture(r"AstDB: (.*)", &out).map(|s| s.trim().to_string());
    Ok((info, db))
}

/// (last MAC, last URI, last session id) as expected.
fn at(mac: &str, uri: &str, sid: &str) -> Option<(String, String, String)> {
    Some((mac.into(), uri.into(), sid.into()))
}

/// Flags as expected.
fn fl(auth: &str, inactive: &str) -> Option<(String, String)> {
    Some((auth.into(), inactive.into()))
}

/// The forgotten last-seen information.
fn forgotten() -> LastInfo {
    (at("", "", ""), Some("(none)".into()))
}

/// Checks the next unsolicited message: the event `event` (no
/// `X-Digium-AppServer-ID`), encrypted, with the payload `body`.
fn expect_event(ctx: &mut Ctx, name: &str, p: &Phone, body: &[u8], event: &str) -> Option<Reply> {
    let Some(r) = p.next_event(Duration::from_secs(5), None) else {
        ctx.c.check(name, false, "no event");
        return None;
    };
    let mut problems = Vec::new();
    if r.event.as_ref().is_none_or(|e| e != event) {
        problems.push(format!("event {:?}, wanted {event:?}", r.event));
    }
    if let Some(id) = &r.id {
        problems.push(format!(
            "events carry no X-Digium-AppServer-ID (got {id:?})"
        ));
    }
    if !r.encrypted {
        problems.push("not encrypted".into());
    }
    if r.payload != body {
        problems.push(format!(
            "payload {:?}, wanted {:?}",
            r.payload,
            BString::from(body)
        ));
    }
    ctx.c.check(name, problems.is_empty(), problems.join("\n"));
    Some(r)
}

/// Checks that no unsolicited message arrives within 1.5 s.
fn no_event(ctx: &mut Ctx, name: &str, p: &Phone) {
    let r = p.next_event(Duration::from_secs_f64(1.5), None);
    let detail = r.as_ref().map(|r| r.describe(0)).unwrap_or_default();
    ctx.c.check(name, r.is_none(), detail);
}

/// Writes the P12 test phones with `extra` appended and reloads.
fn edit_p12conf(ctx: &mut Ctx, extra: &str) -> Result<()> {
    std::fs::write(
        ctx.inst.conf("res_digium_phone_p12.conf"),
        format!("{P12_CONF}{extra}"),
    )?;
    cli(ctx, "module reload res_dpma_rs.so")?;
    fixtures::sleep(0.5);
    Ok(())
}

// ---------------------------------------------------------------------------

pub fn reconfigure(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    token_for(ctx, &p, "p12a")?;
    let out = cli_text(ctx, "digium_phones reconfigure phone p12a")?;
    ctx.c.same(
        "CLI reconfigure output (full name)",
        out.trim(),
        "Phone 'P12 Phone A' will reconfigure shortly.",
    );
    expect_event(ctx, "CLI reconfigure reaches the phone", &p, PLAIN, UPDATE);
    let out = cli_text(ctx, "digium_phones reconfigure phone p12c")?;
    ctx.c.check(
        "CLI reconfigure of a phone never seen",
        out.starts_with("Phone 'p12c' has not contacted the server."),
        &out,
    );
    let res = ctx
        .ami()?
        .action("DigiumPhoneReconfigure", [("PhoneName", "p12a")]);
    let resp = res.response.as_ref();
    ctx.c.same(
        "AMI DigiumPhoneReconfigure",
        (
            resp.and_then(|r| field(r, "Response")),
            resp.and_then(|r| field(r, "Message")),
        ),
        (
            Some("Success".into()),
            Some("Reconfigure message successfully sent".into()),
        ),
    );
    expect_event(
        ctx,
        "AMI DigiumPhoneReconfigure reaches the phone",
        &p,
        PLAIN,
        UPDATE,
    );
    let res = ctx
        .ami()?
        .action("DigiumPhoneReconfigure", [("PhoneName", "p12c")]);
    ctx.c.same(
        "AMI DigiumPhoneReconfigure of a phone never seen",
        res.response.as_ref().and_then(|r| field(r, "Response")),
        Some("Error".into()),
    );
    let res = ctx.ami()?.action(
        "DigiumPhoneReconfigureAll",
        std::iter::empty::<(&str, &str)>(),
    );
    ctx.c.same(
        "AMI DigiumPhoneReconfigureAll",
        res.response.as_ref().and_then(|r| field(r, "Response")),
        Some("Success".into()),
    );
    expect_event(
        ctx,
        "AMI DigiumPhoneReconfigureAll reaches the phone",
        &p,
        PLAIN,
        UPDATE,
    );
    no_event(ctx, "one reconfigure per phone", &p);
    cli(
        ctx,
        &format!(
            "dpmadev token reconfigure {} {} delete",
            sid(&p),
            uri_of(&p)
        ),
    )?;
    expect_event(
        ctx,
        "reconfigure with delete_token",
        &p,
        DELETE_TOKEN,
        UPDATE,
    );
    Ok(())
}

pub fn reload(ctx: &mut Ctx) -> Result<()> {
    let res = reload_checks(ctx);
    edit_p12conf(ctx, "")?;
    res
}

fn reload_checks(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    token_for(ctx, &p, "p12a")?;
    let mark = log_mark(ctx);
    edit_p12conf(ctx, "\n[p12a-line2]\ntype=line\n")?;
    // Adding a line section alone changes nothing for p12a.
    no_event(ctx, "unrelated change: no reconfigure", &p);
    edit_p12conf(
        ctx,
        "\n[p12a-line2]\ntype=line\n[p12a](+)\nline=p12a-line2\n",
    )?;
    expect_event(ctx, "lines changed: reconfigure", &p, PLAIN, UPDATE);
    logged(
        ctx,
        "lines changed (log)",
        mark,
        "Phone user 'p12a' setting reconfigure due to change in lines",
    );
    logged(
        ctx,
        "lines changed: sending (log)",
        mark,
        "Sending reconfigure to user p12a",
    );
    edit_p12conf(ctx, "")?;
    expect_event(ctx, "lines changed back: reconfigure", &p, PLAIN, UPDATE);

    edit_p12conf(
        ctx,
        "\n[p12tmp]\ntype=phone\nmac=000fd30012aa\nline=p12tmp-line\n[p12tmp-line]\ntype=line\n",
    )?;
    let t = phone(ctx, "000fd30012aa")?;
    token_for(ctx, &t, "p12tmp")?;
    let (_, db) = last_info(ctx, "p12tmp")?;
    ctx.c.check(
        "p12tmp in AstDB",
        db.as_ref()
            .is_some_and(|d| d.starts_with("last_mac=000fd30012aa;")),
        format!("{db:?}"),
    );
    let got = flags(ctx, &sid(&t))?;
    ctx.c.same("p12tmp's session active", got, fl("Yes", "No"));
    edit_p12conf(ctx, "")?;
    expect_event(ctx, "deleted phone: reconfigure", &t, PLAIN, UPDATE);
    let out = cli_text(ctx, "database get DigiumPhoneUsers p12tmp")?;
    ctx.c.check(
        "deleted phone: AstDB entry removed",
        out.to_lowercase().contains("not found"),
        &out,
    );
    let got = flags(ctx, &sid(&t))?;
    ctx.c
        .same("deleted phone: session inactive", got, fl("Yes", "Yes"));
    no_event(ctx, "deleted phone: others not reconfigured", &p);
    Ok(())
}

pub fn mismatch(ctx: &mut Ctx) -> Result<()> {
    set_auth(ctx, "disabled", "disabled")?;
    let res = mismatch_checks(ctx);
    set_auth(ctx, "mac_globalpin", "disabled")?;
    res
}

fn mismatch_checks(ctx: &mut Ctx) -> Result<()> {
    let a = phone(ctx, MAC_A)?;
    let b = phone(ctx, MAC_BAD)?;
    token_for(ctx, &a, "p12a")?;
    let got = last_info(ctx, "p12a")?.0;
    ctx.c
        .same("p12a at A", got, at(MAC_A, &uri_of(&a), &sid(&a)));
    let mark = log_mark(ctx);
    token_for(ctx, &b, "p12a")?;
    logged(
        ctx,
        "MAC mismatch (log)",
        mark,
        &format!(
            "Phone user 'p12a' reconfigure due to mac mismatch - was '{MAC_A}' now '{MAC_BAD}'"
        ),
    );
    logged(
        ctx,
        "now connected (log)",
        mark,
        &format!(
            "Phone user 'p12a' now connected from '{}' mac '{MAC_BAD}'",
            uri_of(&b)
        ),
    );
    expect_event(
        ctx,
        "MAC mismatch: the old location is reconfigured",
        &a,
        PLAIN,
        UPDATE,
    );
    no_event(ctx, "MAC mismatch: the new location is not", &b);
    let got = last_info(ctx, "p12a")?.0;
    ctx.c
        .same("p12a at B", got, at(MAC_BAD, &uri_of(&b), &sid(&b)));
    let got = flags(ctx, &sid(&a))?;
    ctx.c
        .same("A's session marked inactive", got, fl("Yes", "Yes"));
    let got = flags(ctx, &sid(&b))?;
    ctx.c
        .same("B's session authenticated", got, fl("Yes", "No"));

    let mark = log_mark(ctx);
    token_for(ctx, &b, "p12b")?;
    logged(
        ctx,
        "orphaned (log)",
        mark,
        &format!("Phone user 'p12a' configuration orphaned by mac '{MAC_BAD}'"),
    );
    let got = last_info(ctx, "p12a")?;
    ctx.c
        .same("orphaned phone forgets its location", got, forgotten());
    let got = last_info(ctx, "p12b")?.0;
    ctx.c
        .same("p12b at B", got, at(MAC_BAD, &uri_of(&b), &sid(&b)));
    let got = flags(ctx, &sid(&b))?;
    ctx.c.same(
        "B's session still authenticated and active",
        got,
        fl("Yes", "No"),
    );
    Ok(())
}

pub fn stale(ctx: &mut Ctx) -> Result<()> {
    set_auth(ctx, "disabled", "disabled")?;
    let res = stale_checks(ctx);
    set_auth(ctx, "mac_globalpin", "disabled")?;
    res
}

fn stale_checks(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    token_for(ctx, &p, "p12a")?;
    let old = sid(&p);
    // Another phone behind the same address (the same socket here): a new
    // session with another MAC (and the Contact that goes with it), set
    // per request (the From header keeps the first MAC; the module only
    // logs it).
    let contact = format!("sip:{MAC_BAD}@127.0.0.1:{}", p.local_addr().port());
    let ex = p.handshake().mac(MAC_BAD).contact(&contact).send()?;
    ctx.c.check("second handshake", ex.ok(), ex.describe(0));
    let mark = log_mark(ctx);
    let ex = p
        .get_token()
        .user("p12b")
        .config_password(GLOBALPIN)
        .mac(MAC_BAD)
        .contact(&contact)
        .send()?;
    expect(
        ctx,
        &format!("token for p12b from {MAC_BAD}"),
        &ex,
        "TokenResponse",
        None,
        Body::Default,
    );
    logged(
        ctx,
        "stale phone removed (log)",
        mark,
        &format!("Removing stale user 'p12a' from '{}'", uri_of(&p)),
    );
    let got = last_info(ctx, "p12a")?;
    ctx.c
        .same("stale phone forgets its location", got, forgotten());
    let got = flags(ctx, &old)?;
    ctx.c
        .same("stale phone's session inactive", got, fl("Yes", "Yes"));
    Ok(())
}

pub fn uri(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    token_for(ctx, &p, "p12a")?;
    let old_uri = uri_of(&p);
    // The same phone (contact, session, key, token) from another port.
    let mut o = ctx.sim_options().mac(MAC_A);
    o.contact = Some(p.contact_uri());
    let q = Phone::start(o)?;
    q.set_session(p.session());
    q.set_common_password(p.common_password());
    q.set_token(p.token());
    let mark = log_mark(ctx);
    let ex = q.config().send()?;
    expect(
        ctx,
        "config from the new address",
        &ex,
        "ConfigResponse",
        None,
        Body::Matches(r"\A<config>"),
    );
    logged(
        ctx,
        "now connected (log)",
        mark,
        &format!(
            "Phone user 'p12a' now connected from '{}' mac '{MAC_A}'",
            uri_of(&q)
        ),
    );
    logged(
        ctx,
        "session update (log)",
        mark,
        &format!(
            "Phone user 'p12a' session update due to uri change - was '{old_uri}' now '{}'",
            uri_of(&q)
        ),
    );
    let got = last_info(ctx, "p12a")?.0;
    ctx.c
        .same("last info follows", got, at(MAC_A, &uri_of(&q), &sid(&p)));
    let line = session_line(ctx, &sid(&p))?;
    ctx.c.check(
        "show sessions: the new URI",
        line.contains(&format!("URI:{} ", uri_of(&q))),
        &line,
    );
    cli(ctx, "digium_phones reconfigure phone p12a")?;
    expect_event(
        ctx,
        "reconfigure goes to the new address",
        &q,
        PLAIN,
        UPDATE,
    );
    no_event(ctx, "not to the old one", &p);
    Ok(())
}

pub fn events(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    token_for(ctx, &p, "p12a")?;
    let out = cli_text(
        ctx,
        "dpmadev token event p12a digium.p12.test hello <b>world</b>",
    )?;
    ctx.c
        .same("send_event result", out.trim(), "send_event: Ok(())");
    expect_event(
        ctx,
        "event reaches the phone",
        &p,
        b"hello <b>world</b>",
        "digium.p12.test",
    );
    cli(
        ctx,
        "dpmadev token event p12a digium.assignment.update <assign/>",
    )?;
    let r = p.next_event(Duration::from_secs(5), None);
    ctx.c.check("assignment update arrives", r.is_some(), "");
    if let Some(r) = r {
        ctx.c.same(
            "assignment update: id",
            r.id.clone(),
            Some(BString::from("bootcReset")),
        );
        ctx.c
            .same("assignment update: no event name", r.event.clone(), None);
        ctx.c.same(
            "assignment update: Error-ID",
            r.error.clone(),
            Some(BString::from("-398")),
        );
        ctx.c.same_bytes(
            "assignment update: body",
            &r.payload,
            b"<assign/><error msg=\"Session Timeout\" />",
        );
    }
    let out = cli_text(ctx, "dpmadev token event p12c digium.p12.test x")?;
    ctx.c.same(
        "event to a phone never seen",
        out.trim(),
        r#"send_event: Err("Phone has not contacted server")"#,
    );
    Ok(())
}

pub fn marks(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    let got = flags(ctx, &sid(&p))?;
    ctx.c
        .same("new session: not authenticated", got, fl("No", "No"));
    token_for(ctx, &p, "p12a")?;
    let got = flags(ctx, &sid(&p))?;
    ctx.c.same(
        "token build authenticates the session",
        got,
        fl("Yes", "No"),
    );
    let (old, token) = (sid(&p), p.token());
    let mark = log_mark(ctx);
    let ex = p.handshake().send()?; // a reboot: same MAC, new session
    ctx.c.check("handshake again", ex.ok(), "");
    logged(
        ctx,
        "old session pruned (log)",
        mark,
        &format!("on new handshake from mac '{MAC_A}'"),
    );
    let line = session_line(ctx, &old)?;
    ctx.c.same("old session gone", line.as_str(), "");
    let got = flags(ctx, &sid(&p))?;
    ctx.c
        .same("new session: not authenticated", got, fl("No", "No"));
    p.set_token(token);
    let ex = p.config().send()?;
    expect(
        ctx,
        "config with the old token",
        &ex,
        "ConfigResponse",
        None,
        Body::Matches(r"\A<config>"),
    );
    let got = flags(ctx, &sid(&p))?;
    ctx.c.same(
        "token lookup authenticates the new session",
        got,
        fl("Yes", "No"),
    );
    let got = last_info(ctx, "p12a")?.0.map(|i| i.2);
    ctx.c.same("phone's session follows", got, Some(sid(&p)));
    Ok(())
}

pub fn restore(ctx: &mut Ctx) -> Result<()> {
    let port = u16::try_from(16290 + ctx.inst.slot)?;
    let mut opts = ctx.sim_options().mac(MAC_A);
    opts.local_port = port;
    let (rsid, pw, token) = {
        let p = Phone::start(opts.clone())?;
        let ex = p.handshake().send()?;
        ctx.c.check("handshake", ex.ok(), "");
        token_for(ctx, &p, "p12a")?;
        (sid(&p), p.common_password(), p.token())
    };
    // Another session that never authenticates is not saved.
    let xsid = {
        let x = phone(ctx, "000fd30012bb")?;
        sid(&x)
    };
    restart(ctx)?;
    let got = flags(ctx, &rsid)?;
    ctx.c.same(
        "phone's session restored authenticated and active",
        got,
        fl("Yes", "No"),
    );
    let line = session_line(ctx, &xsid)?;
    ctx.c
        .same("unauthenticated session not restored", line.as_str(), "");
    let got = last_info(ctx, "p12a")?.0;
    ctx.c.same(
        "last info restored",
        got,
        at(
            MAC_A,
            &format!("pjsip:127.0.0.1:{port};transport=udp"),
            &rsid,
        ),
    );
    let p = Phone::start(opts)?;
    p.set_session((!rsid.is_empty()).then(|| rsid.clone()));
    p.set_common_password(pw);
    p.set_token(token);
    let ex = p.ping().send()?;
    expect(
        ctx,
        "restored session: ping",
        &ex,
        "PingResponse",
        None,
        Body::Is(b"empty body"),
    );
    let ex = p.config().send()?;
    expect(
        ctx,
        "restored session: config with the token",
        &ex,
        "ConfigResponse",
        None,
        Body::Matches(r"\A<config>"),
    );
    cli(ctx, "digium_phones reconfigure phone p12a")?;
    expect_event(ctx, "restored session: reconfigure", &p, PLAIN, UPDATE);
    ctx.c
        .note("(waiting 65 s: the idle pruning removes inactive sessions after 59 s)");
    fixtures::sleep(65.0);
    let got = flags(ctx, &rsid)?;
    ctx.c.same(
        "restored session survives the idle pruning",
        got,
        fl("Yes", "No"),
    );
    Ok(())
}
