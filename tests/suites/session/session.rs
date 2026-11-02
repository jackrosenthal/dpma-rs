//! Session layer checks (`session.sim`): handshakes, encryption, session
//! validation, what validation drops, reloads, and pruning on a new
//! handshake.  Every reply must arrive over the transport the simulator
//! uses, Session Timeout replies included (port plan section 8, item 11;
//! the original sends those over UDP).  Over TCP, only what depends on
//! the transport runs: chunking (the handshakes), the reply URI's
//! transport (encrypted replies, Echo, -398 replies), and the PEM cuts.

use std::time::Duration;

use anyhow::Result;
use bstr::BString;
use dpma_tests::harness::{Ctx, LogMark};
use dpma_tests::sim::proto::{
    method_request_json, H_FINISHED, H_ID, H_MAC, H_RESPONSE_TYPE, H_SEQUENCE, H_SESSION,
};
use dpma_tests::sim::{Exchange, Phone, Transport};

use crate::ami_cli;

/// Checks that the module dropped a request: `text` (its last log line
/// about it) is logged since `mark`, and then no reply comes.
fn dropped(ctx: &mut Ctx, label: &str, phone: &Phone, mut ex: Exchange, mark: LogMark, text: &str) {
    let ok = ctx.log().wait_for(mark, text, Duration::from_secs(2));
    ctx.c.check(
        format!("{label}: logged"),
        ok,
        format!("not in the log: {text:?}"),
    );
    phone.wait_reply(&mut ex, Some(Duration::from_millis(200)));
    ctx.c.exchange(label, &ex).no_reply();
}

/// Sends one hand-made MESSAGE on the phone's session with `headers`
/// (besides the ID, MAC, and session, and sequence 0, finished) and
/// `body`, unencrypted; the exchange that catches a reply to its ID.
fn raw_message(phone: &Phone, headers: &[(&str, &str)], body: &str) -> Result<Exchange> {
    let txid = phone.new_id();
    let ex = phone.expect_reply("(none)", &txid);
    let mut h: Vec<(String, BString)> = vec![
        (H_ID.into(), txid.as_str().into()),
        (H_MAC.into(), phone.mac().into()),
        (H_SESSION.into(), phone.session().unwrap_or_default().into()),
        (H_SEQUENCE.into(), "0".into()),
        (H_FINISHED.into(), "1".into()),
    ];
    h.extend(
        headers
            .iter()
            .map(|(k, v)| (k.to_string(), BString::from(*v))),
    );
    phone.send_message(&h, body.as_bytes())?;
    Ok(ex)
}

/// What validation drops before a request reaches its handler (UDP only:
/// none of it depends on the transport).
fn drops(ctx: &mut Ctx, phone: &Phone) -> Result<()> {
    let log = ctx.log();

    // An unencrypted AsteriskRequest with a body.
    let mark = log.mark();
    let ex = phone
        .request("AsteriskRequest")
        .encrypt(false)
        .body("X-Digium-AppServer-Digest-Auth=a:b")
        .no_wait()
        .send()?;
    let text = "AsteriskRequest dropped due to lack of encryption.";
    dropped(ctx, "unencrypted AsteriskRequest", phone, ex, mark, text);

    // An unencrypted HTTPRequest is not dropped.
    let doc = method_request_json("test.dpma.api.echo", Some(&serde_json::json!({"x": 1})));
    let ex = phone
        .http(doc)
        .auth("simphone:1234")
        .encrypt(false)
        .send()?;
    ctx.c
        .exchange("unencrypted HTTPRequest answered", &ex)
        .raw_ok()
        .ty("HTTPResponse")
        .payload_matches(r#""result":\{"x":1\}"#);

    // An unencrypted UserlistResponse with a body.
    let mark = log.mark();
    let ex = raw_message(phone, &[(H_RESPONSE_TYPE, "UserlistResponse")], "x")?;
    let text = "UserlistResponse dropped due to lack of encryption.";
    dropped(ctx, "unencrypted UserlistResponse", phone, ex, mark, text);

    // Neither a request type nor a response type.
    let mark = log.mark();
    let ex = raw_message(phone, &[], "x")?;
    let text = "Message dropped due to lack of response or request type.";
    dropped(ctx, "no request or response type", phone, ex, mark, text);

    // A request that needs a session, without one.
    let mark = log.mark();
    let ex = phone
        .request("PingRequest")
        .no_session()
        .encrypt(false)
        .no_wait()
        .send()?;
    let text = "Message 'PingRequest' dropped because of lacking session id";
    dropped(ctx, "no session", phone, ex, mark, text);

    // A request type nobody handles.
    let mark = log.mark();
    let ex = phone.request("BogusRequest").no_wait().send()?;
    let text = "Received request with unknown type 'BogusRequest'";
    dropped(ctx, "unknown request type", phone, ex, mark, text);
    Ok(())
}

pub fn run(ctx: &mut Ctx, t: Transport) -> Result<()> {
    let udp = t == Transport::Udp;
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
        .body("plain echo")
        .transport(t);

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
        .error("-398")
        .transport(t);

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

    if udp {
        drops(ctx, &phone)?;

        // Sessions survive a module reload (AstDB).
        ami_cli(ctx, "module reload res_dpma_rs.so")?;
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
    }

    // Handshake bodies in chunks that end right before and after every
    // BEGIN and END line: Asterisk strips those line breaks and the
    // module restores them (port plan section 8, item 12; the original
    // rejects these).
    let c = &mut ctx.c;
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
    if !udp {
        return Ok(());
    }

    // Accepted: expired certificates (errors 9 and 10 are ignored) and a
    // 512-bit SHA-1 legacy certificate.
    for bundle in ["chain-expired", "legacy-expired", "weak"] {
        let ex = phone.handshake().bundle(bundle).send()?;
        c.exchange(format!("handshake {bundle}"), &ex).ok();
    }

    // Rejected: untrusted CA, two or four certificates.  No reply at all,
    // and an auth incident for 127.0.0.1 (its log line is the handshake
    // handler's last).
    for bundle in ["rogue", "two", "four"] {
        let mark = ctx.log().mark();
        let ex = phone.handshake().bundle(bundle).no_wait().send()?;
        let label = format!("handshake {bundle}");
        dropped(
            ctx,
            &label,
            &phone,
            ex,
            mark,
            "Auth failed for ip '127.0.0.1'",
        );
    }

    // Leave a working session behind.
    let c = &mut ctx.c;
    let ex = phone.handshake().send()?;
    c.exchange("final handshake", &ex).ok();
    let ex = phone.ping().send()?;
    c.exchange("final ping", &ex).ok().ty("PingResponse");
    Ok(())
}
