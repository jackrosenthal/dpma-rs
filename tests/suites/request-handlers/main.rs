//! The request-handlers suite: the phone request handlers end to end
//! with the phone simulator, then the phone users' runtime over real
//! sessions.
//!
//! ```text
//! cargo xtask test request-handlers
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test request-handlers -- --ignored [--no-prepare] [-v] [PART...]
//! ```
//!
//! The suite prepares the instance (`--no-prepare` skips this).
//!
//! The request handler parts rewrite `[general]` of the instance's
//! `res_digium_phone.conf` for each authentication mode, reload the
//! module, and put the file back at the end of the part.  Replies are
//! compared byte for byte with what the decompile builds.

mod common;
mod flows;
mod handlers;

use std::process::ExitCode;

use dpma_tests::harness::{fixtures, setup, Suite};

fn main() -> ExitCode {
    let mut suite = Suite::new("request-handlers").prepare(|inst| {
        fixtures::prepare(inst, |inst| {
            fixtures::sim_setup(inst)?;
            setup::install_snippet(
                inst,
                "res_digium_phone_p12.conf",
                "res_digium_phone.conf",
                common::P12_CONF.as_bytes(),
            )
        })
    });
    let handler_parts: [(&str, fn(&mut _) -> _); 8] = [
        ("token", handlers::token),
        ("config", handlers::config),
        ("userlist", handlers::userlist),
        ("file", handlers::file),
        ("asterisk", handlers::asterisk),
        ("xml", handlers::xml),
        ("ami", handlers::ami),
        ("handshake", handlers::handshake),
    ];
    for (name, f) in handler_parts {
        suite = suite.part(name, move |ctx| handlers::part(ctx, f));
    }
    let flow_parts: [(&str, fn(&mut _) -> _); 6] = [
        ("flows-reload", flows::reload),
        ("flows-mismatch", flows::mismatch),
        ("flows-stale", flows::stale),
        ("flows-uri", flows::uri),
        ("flows-marks", flows::marks),
        ("flows-restore", flows::restore),
    ];
    for (name, f) in flow_parts {
        suite = suite.part(name, move |ctx| flows::part(ctx, f));
    }
    suite.main()
}
