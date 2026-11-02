//! The session suite: sessions, handshake, encryption, and framing with
//! the phone simulator.
//!
//! ```text
//! cargo xtask test session
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test session -- --ignored [PART...]
//! ```
//!
//! The suite prepares the instance (`--no-prepare` skips this).  The
//! simulator itself is tested by the unit tests (`cargo test -p
//! dpma-tests`).

mod chunks;
mod output;
mod prune;
mod reassembly;
mod restart;
mod session;

use std::process::ExitCode;

use anyhow::Result;
use dpma_tests::ami::AmiResult;
use dpma_tests::harness::{fixtures, Ctx, Suite};
use dpma_tests::sim::Transport;

/// A CLI command through AMI's `Command` action; records that the action
/// succeeded.
pub fn ami_cli(ctx: &mut Ctx, command: &str) -> Result<AmiResult> {
    let res = ctx.ami()?.action("Command", [("Command", command)]);
    let ok = res.success();
    ctx.c.check(format!("cli {command}"), ok, res.text());
    Ok(res)
}

/// An AMI action: records that it succeeded and returns the response
/// merged with its list events.
pub fn ami_action(
    ctx: &mut Ctx,
    action: &str,
    fields: &[(&str, &str)],
) -> Result<dpma_tests::ami::AmiMessage> {
    let res = ctx.ami()?.action(action, fields.iter().copied());
    ctx.c
        .check(format!("ami {action}"), res.success(), res.text());
    Ok(res.merged())
}

fn main() -> ExitCode {
    Suite::new("session")
        .prepare(|inst| fixtures::prepare(inst, fixtures::sim_setup))
        .part("session-udp", |ctx| session::run(ctx, Transport::Udp))
        .part("session-tcp", |ctx| session::run(ctx, Transport::Tcp))
        .part("chunks-udp", |ctx| chunks::run(ctx, Transport::Udp, 5))
        .part("chunks-tcp", |ctx| chunks::run(ctx, Transport::Tcp, 3))
        .part("output", output::run)
        .part("prune", prune::run)
        .part("reassembly", reassembly::run)
        .part("restart", restart::run)
        .main()
}
