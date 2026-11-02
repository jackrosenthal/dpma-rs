//! The session suite: sessions, handshake, encryption, and framing with
//! the phone simulator (package P7; the Rust form of the former
//! `tests/sim/scripts/session-all.sh` and the scripts it ran).
//!
//! ```text
//! export DPMA_SLOT=<n> ASTERISK_SOURCE_DIR=$PWD/dev/asterisk-builds/<release>/src
//! cargo build -p res_dpma_rs --features devtest
//! cargo test -p dpma-tests --test session -- --ignored [PART...]
//! ```
//!
//! (or `cargo xtask test session`, which builds the devtest module first).
//!
//! The suite prepares the instance (fresh configuration, the test PKI and
//! the simulator's test configuration, the debug build installed,
//! Asterisk restarted; `--no-prepare` skips this) and runs these parts
//! (about a minute and a half in all):
//!
//! | Part | Was | Checks |
//! |---|---|---|
//! | `selftest` | `dpma_sim.py selftest` | The simulator's crypto, framing, PKI, and an in-process round trip, cross-checked with dpma-proto's vectors |
//! | `loopback` | `loopback.sim` (not run by `session-all.sh`) | The simulator's SIP layer against the test configuration's loopback context (no module needed): Echo in one and in many chunks, an ignored request, AMI |
//! | `session-udp`, `session-tcp` | `session.sim` | Both handshake forms and the rejected bundles, handshakes whose chunks end at PEM BEGIN and END lines, encrypted Ping, Echo, a multi-chunk request, unknown session (-398 HandshakeResponse), MAC and contact mismatch (Session Timeout, over the simulator's transport), an unencrypted AsteriskRequest dropped, the CLI and AMI, a module reload, pruning the old session on a new handshake |
//! | `chunks-udp`, `chunks-tcp` | `session-chunks.sim` | Multi-chunk requests (encrypted and plaintext) and replies (an encrypted 2000-byte event in 5 chunks over UDP and 3 over TCP, `digium.assignment.update`, the HandshakeResponse) |
//! | `output` | `session-output.sim` | `digium_phones show sessions` and `DPMAShowPhones` field by field, with each flag |
//! | `prune` | `session-prune.sim` | Idle pruning: unauthenticated sessions after 119 s, authenticated but inactive ones after 59 s, never authenticated active ones |
//! | `reassembly` | `session-reassembly.py` | Incoming chunks out of order, transactions keyed by ID and MAC, incomplete transactions dropped after 40 s (takes about 50 s) |
//! | `restart` | `session-restart.sh` | AstDB persistence across two Asterisk restarts (restored authenticated and inactive, same common password, expiry at 59 s), an undecryptable entry dropped, `DPMAShowPhones` user details, and the `message_delay` pause |

mod chunks;
mod loopback;
mod output;
mod prune;
mod reassembly;
mod restart;
mod session;

use std::process::ExitCode;

use anyhow::Result;
use dpma_tests::ami::AmiResult;
use dpma_tests::harness::{fixtures, Ctx, Suite};
use dpma_tests::sim::{self, selftest, Transport};

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
        .part("selftest", |ctx| {
            selftest::run(&mut ctx.c, &sim::default_pki_dir());
            Ok(())
        })
        .part("loopback", loopback::run)
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
