//! Session layer checks (`session.sim`): handshakes, encryption, session
//! validation, the CLI and AMI, reloads, and pruning on a new handshake.
//! Every reply must arrive over the transport the simulator uses, Session
//! Timeout replies included (port plan section 8, item 11; the original
//! sends those over UDP).

use std::time::Duration;

use anyhow::Result;
use dpma_tests::harness::Ctx;
use dpma_tests::sim::{Phone, Transport};

use crate::{ami_action, ami_cli};

pub fn run(ctx: &mut Ctx, t: Transport) -> Result<()> {
    let phone = Phone::start(ctx.sim_options().transport(t))?;
    let c = &mut ctx.c;

    // Chain form: Handshake-Version 1, unencrypted, the AppServer
    // certificate in the body (about 1.3 KB: 3 chunks over UDP, 2 over
    // TCP).
    let ex = phone.handshake().bundle("chain").send()?;
    c.exchange("handshake chain", &ex)
        .ok()
        .ty("HandshakeResponse")
        .no_error()
        .encrypted(false)
        .appserver_ok()
        .chunks_matches("^[23]$")
        .header("Handshake-Version", "1")
        .header_present("Session")
        .header_present("Password")
        .header_present("Token-Auth-Requirements")
        .header_present("Userlist-Auth-Requirements");
    c.require("a session", phone.session().is_some(), "")?;

    // Encrypted Ping: PingResponse with the body "empty body".
    let ex = phone.ping().send()?;
    c.exchange("ping", &ex)
        .ok()
        .ty("PingResponse")
        .no_error()
        .encrypted(true)
        .body("empty body")
        .transport(t);

    // Echo: answered directly, unencrypted, Error-ID 0, body echoed.
    let ex = phone.echo("plain echo").send()?;
    c.exchange("echo", &ex)
        .ok()
        .ty("EchoResponse")
        .error("0")
        .encrypted(false)
        .body("plain echo");

    // An encrypted request in many chunks (the Ping handler ignores the
    // body).
    let body = "0123456789abcdefghijklmnopqrstuvwxyz".repeat(4);
    let ex = phone
        .request("PingRequest")
        .body(&body)
        .chunk_size(64)
        .send()?;
    c.exchange("multi-chunk ping", &ex)
        .raw_ok()
        .ty("PingResponse")
        .no_error()
        .encrypted(true);

    // Unknown session: a HandshakeResponse with Error-ID -398 (no body),
    // so the phone handshakes again.
    let ex = phone
        .request("PingRequest")
        .session("999999999")
        .encrypt(false)
        .send()?;
    c.exchange("unknown session", &ex)
        .raw_ok()
        .ty("HandshakeResponse")
        .error("-398");

    // MAC or contact mismatch: "Session Timeout" (-398) in the request's
    // own response type, encrypted, prefixed "Command: ".
    let ex = phone.request("PingRequest").mac("000fd3999999").send()?;
    c.exchange("MAC mismatch", &ex)
        .raw_ok()
        .ty("PingResponse")
        .error("-398")
        .encrypted(true)
        .payload_matches("Session Timeout")
        .transport(t);
    let ex = phone
        .request("PingRequest")
        .contact("sip:000fd3000001@127.0.0.1:9")
        .send()?;
    c.exchange("contact mismatch", &ex)
        .raw_ok()
        .ty("PingResponse")
        .error("-398")
        .transport(t);

    // An unencrypted AsteriskRequest with a body is dropped.
    let ex = phone
        .request("AsteriskRequest")
        .encrypt(false)
        .body("X-Digium-AppServer-Digest-Auth=a:b")
        .timeout(Duration::from_secs(2))
        .send()?;
    c.exchange("unencrypted AsteriskRequest", &ex).no_reply();

    // The session in the CLI and AMI.
    let session = phone.session().unwrap_or_default();
    let res = ami_cli(ctx, "digium_phones show sessions")?;
    ctx.c
        .ami("show sessions", res.response.as_ref())
        .matches("Output", &regex::escape(&session))
        .matches("Output", &regex::escape(phone.mac()));
    let m = ami_action(ctx, "DPMAShowPhones", &[])?;
    ctx.c
        .ami("DPMAShowPhones", Some(&m))
        .eq("Response", "Success")
        .matches("EventList", "Complete");

    // Sessions survive a module reload (AstDB).
    ami_cli(ctx, "module reload res_dpma_rs.so")?;
    std::thread::sleep(Duration::from_secs(1));
    let c = &mut ctx.c;
    let ex = phone.ping().send()?;
    c.exchange("ping after a reload", &ex)
        .ok()
        .ty("PingResponse")
        .no_error();

    // A new handshake prunes the phone's old session.
    let old = phone.session().unwrap_or_default();
    let ex = phone.handshake().bundle("legacy").send()?;
    c.exchange("handshake legacy", &ex)
        .ok()
        .ty("HandshakeResponse")
        .header_absent("Handshake-Version")
        .appserver_ok();
    let ex = phone
        .request("PingRequest")
        .session(old)
        .encrypt(false)
        .send()?;
    c.exchange("old session after a new handshake", &ex)
        .raw_ok()
        .ty("HandshakeResponse")
        .error("-398");
    let ex = phone.ping().send()?;
    c.exchange("ping on the new session", &ex)
        .ok()
        .ty("PingResponse");

    // Handshake bodies in chunks that end right before and after every
    // BEGIN and END line: Asterisk strips those line breaks and the
    // module restores them (port plan section 8, item 12; the original
    // rejects these).
    let ex = phone.handshake().bundle("legacy").pem_cuts().send()?;
    c.exchange("handshake legacy, PEM cuts", &ex)
        .ok()
        .ty("HandshakeResponse")
        .no_error()
        .header_absent("Handshake-Version")
        .appserver_ok();
    let ex = phone.ping().send()?;
    c.exchange("ping after legacy PEM cuts", &ex)
        .ok()
        .ty("PingResponse")
        .no_error();
    let ex = phone.handshake().bundle("chain").pem_cuts().send()?;
    c.exchange("handshake chain, PEM cuts", &ex)
        .ok()
        .ty("HandshakeResponse")
        .no_error()
        .header("Handshake-Version", "1")
        .appserver_ok();
    let ex = phone.ping().send()?;
    c.exchange("ping after chain PEM cuts", &ex)
        .ok()
        .ty("PingResponse")
        .no_error();

    // Accepted: expired certificates (errors 9 and 10 are ignored) and a
    // 512-bit SHA-1 legacy certificate.
    for bundle in ["chain-expired", "legacy-expired", "weak"] {
        let ex = phone.handshake().bundle(bundle).send()?;
        c.exchange(format!("handshake {bundle}"), &ex).ok();
    }

    // Rejected: untrusted CA, two or four certificates.  No reply at all
    // (and an auth incident for 127.0.0.1).
    for bundle in ["rogue", "two", "four"] {
        let ex = phone
            .handshake()
            .bundle(bundle)
            .timeout(Duration::from_secs(2))
            .send()?;
        c.exchange(format!("handshake {bundle}"), &ex).no_reply();
    }
    let m = ami_action(ctx, "DPMAShowIncidents", &[])?;
    ctx.c
        .ami("DPMAShowIncidents", Some(&m))
        .eq("Response", "Success")
        .matches("EventList", "Complete");

    // Leave a working session behind.
    let c = &mut ctx.c;
    let ex = phone.handshake().send()?;
    c.exchange("final handshake", &ex).ok();
    let ex = phone.ping().send()?;
    c.exchange("final ping", &ex).ok().ty("PingResponse");
    Ok(())
}
