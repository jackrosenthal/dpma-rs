//! The session suite: sessions, handshake, encryption, and framing with
//! the phone simulator (package P7; the Rust form of the former
//! `tests/sim/scripts/session-all.sh` and the scripts it ran).
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
//! The suite prepares the instance (fresh configuration, the test PKI and
//! the simulator's test configuration, the debug build installed,
//! Asterisk restarted; `--no-prepare` skips this) and runs these parts
//! (about ten seconds in all).  The simulator itself, its cross-check with
//! dpma-proto's vectors included, is tested by the unit tests (`cargo
//! test -p dpma-tests`).
//!
//! | Part | Was | Checks |
//! |---|---|---|
//! | `session-udp` | `session.sim` | Both handshake forms and the rejected bundles (no reply, logged), handshakes whose chunks end at PEM BEGIN and END lines, encrypted Ping, Echo, a multi-chunk request, unknown session (-398 HandshakeResponse), MAC and contact mismatch (Session Timeout), what validation drops (logged, no reply: an unencrypted AsteriskRequest or UserlistResponse, a message with neither a request nor a response type, a request without a session, an unknown request type) and what it lets through (an unencrypted HTTPRequest), a module reload, pruning the old session on a new handshake |
//! | `session-tcp` | `session.sim` | What depends on the transport, over TCP: the chain handshake, Ping, Echo, a multi-chunk request, unknown session, MAC and contact mismatch, and the PEM-cut handshakes, every reply over TCP |
//! | `chunks-udp` | `session-chunks.sim` | Multi-chunk requests (encrypted and plaintext) and replies (an encrypted 2000-byte event in 5 chunks, `digium.assignment.update`, the HandshakeResponse) |
//! | `chunks-tcp` | `session-chunks.sim` | Replies over TCP: an encrypted 2000-byte event in 3 chunks, the HandshakeResponse |
//! | `output` | `session-output.sim` | `digium_phones show sessions` and `DPMAShowPhones` field by field, with each flag |
//! | `prune` | `session-prune.sim` | Idle pruning: unauthenticated sessions after 119 s, authenticated but inactive ones after 59 s, never authenticated active ones |
//! | `reassembly` | `session-reassembly.py` | Incoming chunks out of order, transactions keyed by ID and MAC, incomplete transactions kept at 39 s and dropped at 41 s (`dpmadev session txage`) |
//! | `restart` | `session-restart.sh` | AstDB persistence across two Asterisk restarts (restored authenticated and inactive, same common password, expiry at 59 s), an undecryptable entry dropped, `DPMAShowPhones` user details, and the `message_delay` pause |

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

/// A CLI command through AMI's `Command` action, as the `.sim` scripts'
/// `cli` lines ran it; records that the action succeeded.
pub fn ami_cli(ctx: &mut Ctx, command: &str) -> Result<AmiResult> {
    let res = ctx.ami()?.action("Command", [("Command", command)]);
    let ok = res.success();
    ctx.c.check(format!("cli {command}"), ok, res.text());
    Ok(res)
}

/// An AMI action as the `.sim` scripts' `ami` lines ran it: records that
/// it succeeded and returns the response merged with its list events.
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
