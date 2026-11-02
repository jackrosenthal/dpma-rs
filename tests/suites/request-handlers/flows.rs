//! The phone users' runtime over real sessions, with the request handlers
//! in place.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use bstr::{BString, ByteSlice};
use dpma_tests::harness::Ctx;
use dpma_tests::sim::{Phone, Reply};

use crate::common::*;

/// The event of a reconfigure message.
const UPDATE: &str = "digium.config.update";
/// The body of a reconfigure message.
const PLAIN: &[u8] = b"<config></config>";
/// The phones whose AstDB entries are deleted first.
const PHONES: [&str; 4] = ["phonea", "phoneb", "phonec", "phonetmp"];

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

/// Stops and starts Asterisk (sessions and phone users are restored while
/// the module loads, before Asterisk is fully booted).
fn restart(ctx: &mut Ctx) -> Result<()> {
    ctx.drop_ami();
    ctx.inst.stop()?;
    ctx.inst.start()
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

/// Writes the test phones with `extra` appended and reloads.
fn edit_phones_conf(ctx: &mut Ctx, extra: &str) -> Result<()> {
    std::fs::write(
        ctx.inst.conf("res_digium_phone_handlers.conf"),
        format!("{PHONES_CONF}{extra}"),
    )?;
    cli(ctx, "module reload res_dpma_rs.so")?;
    Ok(())
}

// ---------------------------------------------------------------------------

pub fn reload(ctx: &mut Ctx) -> Result<()> {
    let res = reload_checks(ctx);
    edit_phones_conf(ctx, "")?;
    res
}

fn reload_checks(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    token_for(ctx, &p, "phonea")?;
    let mark = log_mark(ctx);
    edit_phones_conf(ctx, "\n[phonea-line2]\ntype=line\n")?;
    // Adding a line section alone changes nothing for phonea.
    no_event(ctx, "unrelated change: no reconfigure", &p);
    edit_phones_conf(
        ctx,
        "\n[phonea-line2]\ntype=line\n[phonea](+)\nline=phonea-line2\n",
    )?;
    expect_event(ctx, "lines changed: reconfigure", &p, PLAIN, UPDATE);
    logged(
        ctx,
        "lines changed (log)",
        mark,
        "Phone user 'phonea' setting reconfigure due to change in lines",
    );
    logged(
        ctx,
        "lines changed: sending (log)",
        mark,
        "Sending reconfigure to user phonea",
    );
    edit_phones_conf(ctx, "")?;
    expect_event(ctx, "lines changed back: reconfigure", &p, PLAIN, UPDATE);

    edit_phones_conf(
        ctx,
        "\n[phonetmp]\ntype=phone\nmac=000fd30012aa\nline=phonetmp-line\n[phonetmp-line]\ntype=line\n",
    )?;
    let t = phone(ctx, "000fd30012aa")?;
    token_for(ctx, &t, "phonetmp")?;
    let (_, db) = last_info(ctx, "phonetmp")?;
    ctx.c.check(
        "phonetmp in AstDB",
        db.as_ref()
            .is_some_and(|d| d.starts_with("last_mac=000fd30012aa;")),
        format!("{db:?}"),
    );
    let got = flags(ctx, &sid(&t))?;
    ctx.c
        .same("phonetmp's session active", got, fl("Yes", "No"));
    edit_phones_conf(ctx, "")?;
    expect_event(ctx, "deleted phone: reconfigure", &t, PLAIN, UPDATE);
    let out = cli_text(ctx, "database get DigiumPhoneUsers phonetmp")?;
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
    token_for(ctx, &a, "phonea")?;
    let got = last_info(ctx, "phonea")?.0;
    ctx.c
        .same("phonea at A", got, at(MAC_A, &uri_of(&a), &sid(&a)));
    let mark = log_mark(ctx);
    token_for(ctx, &b, "phonea")?;
    logged(
        ctx,
        "MAC mismatch (log)",
        mark,
        &format!(
            "Phone user 'phonea' reconfigure due to mac mismatch - was '{MAC_A}' now '{MAC_BAD}'"
        ),
    );
    logged(
        ctx,
        "now connected (log)",
        mark,
        &format!(
            "Phone user 'phonea' now connected from '{}' mac '{MAC_BAD}'",
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
    let got = last_info(ctx, "phonea")?.0;
    ctx.c
        .same("phonea at B", got, at(MAC_BAD, &uri_of(&b), &sid(&b)));
    let got = flags(ctx, &sid(&a))?;
    ctx.c
        .same("A's session marked inactive", got, fl("Yes", "Yes"));
    let got = flags(ctx, &sid(&b))?;
    ctx.c
        .same("B's session authenticated", got, fl("Yes", "No"));

    let mark = log_mark(ctx);
    token_for(ctx, &b, "phoneb")?;
    logged(
        ctx,
        "orphaned (log)",
        mark,
        &format!("Phone user 'phonea' configuration orphaned by mac '{MAC_BAD}'"),
    );
    let got = last_info(ctx, "phonea")?;
    ctx.c
        .same("orphaned phone forgets its location", got, forgotten());
    let got = last_info(ctx, "phoneb")?.0;
    ctx.c
        .same("phoneb at B", got, at(MAC_BAD, &uri_of(&b), &sid(&b)));
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
    token_for(ctx, &p, "phonea")?;
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
        .user("phoneb")
        .config_password(GLOBALPIN)
        .mac(MAC_BAD)
        .contact(&contact)
        .send()?;
    expect(
        ctx,
        &format!("token for phoneb from {MAC_BAD}"),
        &ex,
        "TokenResponse",
        None,
        Body::Default,
    );
    logged(
        ctx,
        "stale phone removed (log)",
        mark,
        &format!("Removing stale user 'phonea' from '{}'", uri_of(&p)),
    );
    let got = last_info(ctx, "phonea")?;
    ctx.c
        .same("stale phone forgets its location", got, forgotten());
    let got = flags(ctx, &old)?;
    ctx.c
        .same("stale phone's session inactive", got, fl("Yes", "Yes"));
    Ok(())
}

pub fn uri(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    token_for(ctx, &p, "phonea")?;
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
            "Phone user 'phonea' now connected from '{}' mac '{MAC_A}'",
            uri_of(&q)
        ),
    );
    logged(
        ctx,
        "session update (log)",
        mark,
        &format!(
            "Phone user 'phonea' session update due to uri change - was '{old_uri}' now '{}'",
            uri_of(&q)
        ),
    );
    let got = last_info(ctx, "phonea")?.0;
    ctx.c
        .same("last info follows", got, at(MAC_A, &uri_of(&q), &sid(&p)));
    let line = session_line(ctx, &sid(&p))?;
    ctx.c.check(
        "show sessions: the new URI",
        line.contains(&format!("URI:{} ", uri_of(&q))),
        &line,
    );
    cli(ctx, "digium_phones reconfigure phone phonea")?;
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

pub fn marks(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    let got = flags(ctx, &sid(&p))?;
    ctx.c
        .same("new session: not authenticated", got, fl("No", "No"));
    token_for(ctx, &p, "phonea")?;
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
    let got = last_info(ctx, "phonea")?.0.map(|i| i.2);
    ctx.c.same("phone's session follows", got, Some(sid(&p)));
    Ok(())
}

/// The simulator's port in [`restore`], fixed so that the restored phone
/// is at the same address after the restart.
const RESTORE_PORT: u16 = 16291;

pub fn restore(ctx: &mut Ctx) -> Result<()> {
    let mut opts = ctx.sim_options().mac(MAC_A);
    opts.local_port = RESTORE_PORT;
    let (rsid, pw, token) = {
        let p = Phone::start(opts.clone())?;
        let ex = p.handshake().send()?;
        ctx.c.check("handshake", ex.ok(), "");
        token_for(ctx, &p, "phonea")?;
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
    let got = last_info(ctx, "phonea")?.0;
    ctx.c.same(
        "last info restored",
        got,
        at(
            MAC_A,
            &format!("pjsip:127.0.0.1:{RESTORE_PORT};transport=udp"),
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
    cli(ctx, "digium_phones reconfigure phone phonea")?;
    expect_event(ctx, "restored session: reconfigure", &p, PLAIN, UPDATE);
    // Idle for 65 s (inactive sessions are pruned after 59 s); an Echo
    // starts the read cycle that prunes, and the ping comes after it.
    cli(ctx, &format!("dpmadev session idle {rsid} 65"))?;
    let ex = p.echo("cycle").send()?;
    ctx.c.check("echo after 65 s idle", ex.ok(), ex.describe(0));
    let ex = p.ping().send()?;
    expect(
        ctx,
        "restored session: ping after 65 s idle",
        &ex,
        "PingResponse",
        None,
        Body::Is(b"empty body"),
    );
    let got = flags(ctx, &rsid)?;
    ctx.c.same(
        "restored session survives the idle pruning",
        got,
        fl("Yes", "No"),
    );
    Ok(())
}
