//! The simulator's SIP layer against the loopback path of the test
//! configuration (`loopback.sim`), which works with or without the
//! module: MESSAGEs from 127.0.0.2 without `X-Digium-User-Agent` go to the
//! static `[dpma-sim-loopback]` context, which answers Echo the way the
//! module's `handle_request_echo` does.

use std::time::Duration;

use anyhow::Result;
use dpma_tests::harness::Ctx;
use dpma_tests::sim::Phone;

use crate::{ami_action, ami_cli};

pub fn run(ctx: &mut Ctx) -> Result<()> {
    let mut o = ctx.sim_options();
    o.local_host = "127.0.0.2".into();
    // With the module loaded, a request carrying X-Digium-User-Agent goes
    // to the module instead of the loopback context.
    o.digium_ua_header = false;
    let phone = Phone::start(o)?;
    let c = &mut ctx.c;

    let ex = phone.echo("hello loopback").send()?;
    c.exchange("echo", &ex)
        .ok()
        .ty("EchoResponse")
        .error("0")
        .body("hello loopback")
        .encrypted(false)
        .chunks(1)
        .status(202);
    c.note(format!("sent id {}", ex.id));

    // A multi-chunk plaintext request: the loopback answers each chunk,
    // the first answer completes the exchange.
    let ex = phone
        .echo("0123456789abcdefghijklmnopqrstuvwxyz")
        .chunk_size(10)
        .header("X-Test", "chunked")
        .send()?;
    c.exchange("echo in chunks", &ex)
        .ok()
        .ty("EchoResponse")
        .body_matches("^0123");

    // Every chunk reaches the dialplan with its sequence headers.
    let res = ami_cli(ctx, "dialplan show proxy@dpma-sim-loopback")?;
    ctx.c
        .ami("loopback dialplan", res.response.as_ref())
        .matches("Output", "MessageSend");

    // A request type the loopback ignores: accepted by SIP, no reply.
    let ex = phone
        .request("PingRequest")
        .session("1")
        .encrypt(false)
        .timeout(Duration::from_secs(1))
        .send()?;
    ctx.c
        .exchange("ignored request", &ex)
        .no_reply()
        .status(202);

    // AMI round trip.
    let m = ami_action(ctx, "Ping", &[])?;
    ctx.c
        .ami("AMI Ping", Some(&m))
        .eq("Response", "Success")
        .eq("Ping", "Pong");
    Ok(())
}
