//! Idle sessions are pruned (`session-prune.sim`; prune_inactive in
//! FUN_0014f280): unauthenticated ones idle more than 119 s,
//! authenticated but inactive ones idle more than 59 s; authenticated
//! active sessions are kept.  Pruning runs at the start of a read cycle,
//! so each check backdates the session (`dpmadev session idle`, which
//! also lets the next cycle prune at once), completes a transaction (an
//! Echo) to start a new cycle, then pings.

use anyhow::Result;
use dpma_tests::harness::Ctx;
use dpma_tests::sim::Phone;

use crate::ami_cli;

/// Backdates the session by `secs`, runs a read cycle, and checks whether
/// the session survived.
fn idle_then_ping(ctx: &mut Ctx, phone: &Phone, secs: u32, kept: bool) -> Result<()> {
    let session = phone.session().unwrap_or_default();
    ami_cli(ctx, &format!("dpmadev session idle {session} {secs}"))?;
    let ex = phone.echo("cycle").send()?;
    ctx.c
        .exchange(format!("echo after {secs} s idle"), &ex)
        .ok();
    if kept {
        let ex = phone.ping().send()?;
        ctx.c
            .exchange(format!("kept at {secs} s"), &ex)
            .ok()
            .ty("PingResponse")
            .no_error();
    } else {
        let ex = phone.request("PingRequest").encrypt(false).send()?;
        ctx.c
            .exchange(format!("pruned at {secs} s"), &ex)
            .raw_ok()
            .ty("HandshakeResponse")
            .error("-398");
    }
    Ok(())
}

pub fn run(ctx: &mut Ctx) -> Result<()> {
    let phone = Phone::start(ctx.sim_options())?;

    // Unauthenticated: kept at 118 s, pruned at 121 s.
    let ex = phone.handshake().send()?;
    ctx.c.exchange("handshake", &ex).ok();
    idle_then_ping(ctx, &phone, 118, true)?;
    idle_then_ping(ctx, &phone, 121, false)?;

    // Authenticated and active: never pruned.
    let ex = phone.handshake().send()?;
    ctx.c.exchange("handshake again", &ex).ok();
    let session = phone.session().unwrap_or_default();
    ami_cli(
        ctx,
        &format!("dpmadev session mark {session} authenticated"),
    )?;
    idle_then_ping(ctx, &phone, 100000, true)?;

    // Authenticated but inactive: kept at 58 s, pruned at 61 s.
    ami_cli(ctx, &format!("dpmadev session mark {session} inactive"))?;
    idle_then_ping(ctx, &phone, 58, true)?;
    idle_then_ping(ctx, &phone, 61, false)?;

    // The phone handshakes again.
    let ex = phone.handshake().send()?;
    ctx.c.exchange("final handshake", &ex).ok();
    let ex = phone.ping().send()?;
    ctx.c.exchange("final ping", &ex).ok().ty("PingResponse");
    Ok(())
}
