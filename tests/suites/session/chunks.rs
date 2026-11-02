//! Multi-chunk messages in both directions (`session-chunks.sim`).
//! `event_chunks` is the number of chunks of a 2000-byte event: 5 over
//! UDP (0x1a4 bytes of plaintext per chunk), 3 over TCP (0x384).  Over
//! TCP only the replies are checked: reassembling a request and the
//! assignment update do not depend on the transport.

use std::time::Duration;

use anyhow::Result;
use dpma_tests::harness::Ctx;
use dpma_tests::sim::{Phone, Transport};

use crate::ami_cli;

pub fn run(ctx: &mut Ctx, t: Transport, event_chunks: usize) -> Result<()> {
    let udp = t == Transport::Udp;
    let phone = Phone::start(ctx.sim_options().transport(t))?;
    let ex = phone.handshake().send()?;
    ctx.c
        .exchange("handshake", &ex)
        .ok()
        .ty("HandshakeResponse");
    let session = phone.session().unwrap_or_default();
    if udp {
        to_server(ctx, &phone)?;
    }

    // Server to phone, encrypted: an event of 2000 bytes, every chunk with
    // the "Command: " prefix inside the encryption, each chunk's
    // ciphertext base64 encoded on its own.
    ami_cli(
        ctx,
        &format!("dpmadev session event {session} digium.config.update 2000"),
    )?;
    let ev = phone.next_event(Duration::from_secs(5), None);
    let c = &mut ctx.c;
    c.check("event arrived", ev.is_some(), "(no message)");
    c.reply("2000-byte event", ev.as_ref())
        .event("digium.config.update")
        .encrypted(true)
        .chunks(event_chunks)
        .payload_matches("^<config>0123")
        .payload_matches("</config>$")
        .no_problems()
        .header_present("Message-Salt")
        .header("Session", &session)
        .header_absent("ID");

    if udp {
        // digium.assignment.update goes out as the original sends it: no
        // event name, ID bootcReset, Error-ID -398, and the Session
        // Timeout error body after the event body.
        ami_cli(
            ctx,
            &format!("dpmadev session event {session} digium.assignment.update hello"),
        )?;
        let ev = phone.next_event(Duration::from_secs(5), None);
        let c = &mut ctx.c;
        c.check("assignment update arrived", ev.is_some(), "(no message)");
        c.reply("digium.assignment.update", ev.as_ref())
            .error("-398")
            .header("ID", "bootcReset")
            .no_event()
            .encrypted(true)
            .payload_matches("^hello<error");
    }

    // Server to phone, plaintext: the HandshakeResponse (AppServer
    // certificate) in several chunks with sequence numbers.
    let ex = phone.handshake().send()?;
    ctx.c
        .exchange("handshake response in chunks", &ex)
        .ok()
        .ty("HandshakeResponse")
        .chunks_matches("^[23]$")
        .header("Message-Sequence", "0");
    Ok(())
}

/// Phone to server: requests in many chunks.
fn to_server(ctx: &mut Ctx, phone: &Phone) -> Result<()> {
    let l = "abcdefghij".repeat(10);
    let c = &mut ctx.c;

    // Encrypted: one base64 text split over many MESSAGEs (the server
    // joins the chunk bodies and decodes once).
    let ex = phone
        .request("PingRequest")
        .body(l.repeat(20))
        .chunk_size(100)
        .send()?;
    c.exchange(format!("2000 bytes in {} chunks", ex.chunks), &ex)
        .raw_ok()
        .ty("PingResponse")
        .no_error()
        .encrypted(true);
    let ex = phone
        .request("PingRequest")
        .body(l.repeat(10))
        .chunk_size(7)
        .send()?;
    c.exchange(format!("1000 bytes in {} chunks", ex.chunks), &ex)
        .raw_ok()
        .ty("PingResponse")
        .no_error()
        .encrypted(true);

    // Plaintext: Echo in ten chunks, one reply with the whole body.
    let ex = phone.echo(l.repeat(10)).chunk_size(100).send()?;
    c.exchange("echo in ten chunks", &ex)
        .ok()
        .ty("EchoResponse")
        .error("0")
        .encrypted(false)
        .chunks(1)
        .body(l.repeat(10));
    Ok(())
}
