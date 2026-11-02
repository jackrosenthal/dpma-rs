//! Sessions persisted in AstDB (`DigiumPhoneSessions`) survive an
//! Asterisk restart, come back authenticated but inactive, keep working
//! with the same common password, and expire after 59 idle seconds;
//! entries that do not decrypt are dropped (`session-restart.sh`).  Also
//! checks the user details of `DPMAShowPhones` (a phone whose last token
//! MAC is the session's) and the `message_delay` pause between chunks.
//!
//! As the shell script ran a new simulator for every step, every step
//! here starts a new phone from a state file (session, common password,
//! and local port), which also exercises the simulator's `--state`.
//! Restarts Asterisk twice.

use std::path::Path;
use std::time::Instant;

use anyhow::{anyhow, Result};
use dpma_tests::harness::{contains_bytes, fixtures, regex_search, ConfFile, Ctx};
use dpma_tests::sim::Phone;

use crate::ami_cli;

/// A simulator run with the state file, as `dpma_sim.py --state FILE`.
fn sim(ctx: &Ctx, state: &Path, auto_handshake: bool) -> Result<Phone> {
    let mut o = ctx.sim_options();
    o.state = Some(state.to_path_buf());
    o.auto_handshake = auto_handshake;
    if let Some(p) = Phone::state_local_port(state) {
        o.local_port = p;
    }
    Phone::start(o)
}

fn session_of(state: &Path) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(state)?)?;
    v["session"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("no session in {}", state.display()))
}

/// Whether some line of a CLI command's output matches `pattern` (as
/// `grep -E`).
fn has_line(ctx: &Ctx, command: &str, pattern: &str) -> bool {
    ctx.cli(command)
        .split(|&b| b == b'\n')
        .any(|l| regex_search(pattern, l))
}

/// The time a CLI command takes, in milliseconds.
fn timed_cli(ctx: &Ctx, command: &str) -> u128 {
    let t = Instant::now();
    ctx.cli(command);
    t.elapsed().as_millis()
}

/// Starts Asterisk again (the module restores the sessions while it
/// loads, before Asterisk is fully booted).
fn restart(ctx: &mut Ctx, label: &str) {
    ctx.drop_ami();
    let res = ctx.inst.start();
    ctx.c.check(
        label,
        res.is_ok(),
        res.err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );
}

pub fn run(ctx: &mut Ctx) -> Result<()> {
    let work = fixtures::TempDir::new("p7-restart")?;
    let state = work.path().join("state.json");

    // A session, authenticated (so it is saved) and configured.
    let ex = sim(ctx, &state, true)?.handshake().send()?;
    ctx.c.exchange("handshake", &ex).ok();
    let sid = session_of(&state)?;
    let a = ctx
        .inst
        .cli_run(&format!("dpmadev session mark {sid} authenticated"));
    let b = ctx
        .inst
        .cli_run(&format!("dpmadev session mark {sid} configured"));
    ctx.c.check(
        "authenticated session saved",
        a.is_ok() && b.is_ok(),
        format!("{a:?} {b:?}"),
    );
    let db = ctx.cli("database show DigiumPhoneSessions");
    let entry = format!(
        "/DigiumPhoneSessions/{sid} +: mac=000fd3000001;auth_flags=[0-9]+;data=[A-Za-z0-9+/]{{64}};data_len=40;ran=[0-9A-F]{{16}};contact=[A-Za-z0-9+/=]+;uri=[A-Za-z0-9+/=]+;cfgd=-1;ua=[A-Za-z0-9+/=]+;client_cert=-----BEGIN CERTIFICATE-----"
    );
    let ok = db.split(|&b| b == b'\n').any(|l| regex_search(&entry, l));
    ctx.c.check("AstDB entry format", ok, &db);

    // A phone user whose last token MAC is the simulator's (DPMAShowPhones
    // user details), and an entry that cannot be decrypted.
    ctx.cli("database put DigiumPhoneUsers simphone last_mac=000fd3000001;last_uri=pjsip:127.0.0.1:5999;last_session_id=");
    ctx.cli(&format!(
        "database put DigiumPhoneSessions 4242 mac=000fd3000042;auth_flags=1;data={};data_len=40;ran=0011223344556677;contact=c2lwOng=;uri=cGpzaXA6eA==;cfgd=0;ua=;client_cert=x;origination_network=",
        "A".repeat(64)
    ));

    restart(ctx, "restart");
    let pattern =
        format!("^SessionID:{sid} .* Auth:Yes Inactive:Yes Configured: Yes MAC:000fd3000001$");
    let ok = has_line(ctx, "digium_phones show sessions", &pattern);
    ctx.c.check(
        "restored: authenticated, inactive, configured",
        ok,
        ctx.cli("digium_phones show sessions"),
    );
    let db = ctx.cli("database show DigiumPhoneSessions");
    ctx.c.lacks(
        "restored entry removed from AstDB until saved again",
        &db,
        &[sid.as_str()],
    );
    ctx.c.lacks("undecryptable entry dropped", &db, &["/4242 "]);
    let log = ctx.log().all();
    ctx.c.check(
        "undecryptable entry logged",
        contains_bytes(&log, b"Call to decrypt_msg_field failed"),
        "not in messages.log",
    );
    let res = ctx
        .ami()?
        .action("DPMAShowPhones", std::iter::empty::<(&str, &str)>());
    let m = res.merged();
    ctx.c.check("DPMAShowPhones", res.success(), res.text());
    ctx.c
        .ami("DPMAShowPhones user details", Some(&m))
        .matches("SessionID", &format!("(?m)^{sid}$"))
        .matches("Username", "(?m)^simphone$")
        .matches("TokenURI", r"(?m)^pjsip:127\.0\.0\.1:5999$")
        .matches("Auth", "(?m)^1$")
        .matches("Inactive", "(?m)^1$");

    // The restored common password still works.
    let ex = sim(ctx, &state, false)?.ping().send()?;
    ctx.c
        .exchange("encrypted ping on the restored session", &ex)
        .ok();

    // Saved again once authenticated (as a phone user's last_session_id
    // does at load), and survives a second restart.
    let out = ctx.cli(&format!("dpmadev session mark {sid} authenticated"));
    ctx.c.contains("re-activated", &out, &["marked"]);
    ok_line(
        ctx,
        "saved again",
        "database show DigiumPhoneSessions",
        &format!("/DigiumPhoneSessions/{sid} "),
    );
    restart(ctx, "second restart");
    let pattern = format!("^SessionID:{sid} .* Auth:Yes Inactive:Yes");
    let ok = has_line(ctx, "digium_phones show sessions", &pattern);
    ctx.c
        .check("restored again", ok, ctx.cli("digium_phones show sessions"));
    let ex = sim(ctx, &state, false)?.ping().send()?;
    ctx.c
        .exchange("encrypted ping after the second restart", &ex)
        .ok();

    // A restored session nobody re-activates expires after 59 idle
    // seconds.
    for (secs, kept) in [(58, true), (61, false)] {
        let phone = sim(ctx, &state, true)?;
        ami_cli(ctx, &format!("dpmadev session idle {sid} {secs}"))?;
        let ex = phone.echo("cycle").send()?;
        ctx.c
            .exchange(format!("echo after {secs} s idle"), &ex)
            .ok();
        if kept {
            let ex = phone.ping().send()?;
            ctx.c
                .exchange(format!("restored session kept at {secs} s"), &ex)
                .ok()
                .ty("PingResponse")
                .no_error();
        } else {
            let ex = phone.request("PingRequest").encrypt(false).send()?;
            ctx.c
                .exchange(format!("restored session expires at {secs} s"), &ex)
                .raw_ok()
                .ty("HandshakeResponse")
                .error("-398");
        }
    }

    // message_delay: the sender pauses between chunks while holding the
    // session (a 2000-byte event is 5 chunks over UDP).
    std::fs::remove_file(&state)?;
    let ex = sim(ctx, &state, true)?.handshake().send()?;
    ctx.c.exchange("handshake for message_delay", &ex).ok();
    let sid = session_of(&state)?;
    let event = format!("dpmadev session event {sid} digium.config.update 2000");
    let fast = timed_cli(ctx, &event);
    let conf = ConfFile::new(&ctx.inst.conf("res_digium_phone.conf"));
    let backup = conf.backup()?;
    conf.set_options("general", &[("message_delay", Some(b"300"))])?;
    ctx.cli("module reload res_dpma_rs.so");
    let slow = timed_cli(ctx, &event);
    backup.restore()?;
    ctx.cli("module reload res_dpma_rs.so");
    ctx.c.check(
        format!("message_delay=300 pauses 4 x 300 ms (5 ms: {fast} ms, 300 ms: {slow} ms)"),
        slow >= 1200 && fast < 1000,
        "",
    );

    ctx.cli("database del DigiumPhoneUsers simphone");
    Ok(())
}

fn ok_line(ctx: &mut Ctx, label: &str, command: &str, needle: &str) {
    let out = ctx.cli(command);
    ctx.c.contains(label, &out, &[needle]);
}
