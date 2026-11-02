//! The request-handlers suite: the phone request handlers end to end
//! with the phone simulator (package P12, `phone_request.c`; was
//! `tests/request-handlers/run.py`), then the phone users' runtime over
//! real sessions (package P8; was `tests/request-handlers/users-flows.py`).
//!
//! ```text
//! export DPMA_SLOT=<n>
//! cargo build -p res_dpma_rs --features devtest
//! cargo test -p dpma-tests --test request-handlers -- --ignored [--no-prepare] [-v] [PART...]
//! ```
//!
//! Prerequisites: a private instance (`DPMA_SLOT`) and the devtest build
//! of the module (the checks use its `dpmadev` CLI commands).  The suite
//! prepares the instance (fresh configuration; the simulator's test PKI
//! and configuration; the P12 test phones of
//! `tests/data/request-handlers/res_digium_phone_p12.conf` included from
//! `res_digium_phone.conf`; the debug build installed; Asterisk
//! restarted; `--no-prepare` skips this).  It takes about two minutes,
//! more than one of them in `flows-restore`.
//!
//! The request handler parts rewrite `[general]` of the instance's
//! `res_digium_phone.conf` for each authentication mode (and a test
//! `file_directory`, `<instance>/var/lib/asterisk/p12_files`, with the
//! test files), reload the module, and put the file back at the end of
//! the part.  Replies are compared byte for byte with what the decompile
//! builds.
//!
//! | Part | Checks |
//! |---|---|
//! | `token` | TokenRequest in every `config_auth` mode with good and bad MACs, pins, and configuration passwords; the token; selecting the phone by line name, extension, and MAC; the session's Configured flag; the last-seen information in AstDB; unknown users and MACs |
//! | `config` | ConfigRequest and VerifyRequest with and without (good, bad, `-` form) tokens, the Configured flag, the document (`dpmadev config`), a `config_file` from `file_directory` |
//! | `userlist` | UserlistRequest with `userlist_auth` disabled and globalpin: the document (`dpmadev userlist`), group pins, invalid configuration passwords (the log and the auth incident) |
//! | `file` | FileRequest: the contacts documents, small and multi-chunk files, `file://` inside a body, missing files, subdirectories, absolute names, and names outside `file_directory` (refused, logged) |
//! | `asterisk` | AsteriskRequest and HTTPRequest with JSON documents: the HTTP wrapper, credentials (phone and pin, line and secret, blanks, before or after the document, bad ones logged), JSON request errors, an empty method response, a multi-chunk request and reply |
//! | `xml` | AsteriskRequest with XML documents: an XML method (and the debug log), XML request errors, text before the request, a built-in XML method, a JSON-only method |
//! | `ami` | Methods registered by AMI: the DPMAMessage event (RequestID, Method, Format, Parameters, Privilege), the answer through DPMAMessageResponse, scalar parameters, a built-in method shadowing an AMI registration |
//! | `handshake` | A handshake without a User-Agent: no reply, the log, the auth incident |
//!
//! The users' flow parts start (before the first of them) by deleting the
//! test phones' AstDB entries, setting `config_auth=mac_globalpin`, and
//! restarting Asterisk, so that the runtime state starts out empty:
//!
//! | Part | Checks |
//! |---|---|
//! | `flows-reconfigure` | Reconfigure from the CLI and AMI (`DigiumPhoneReconfigure`, `DigiumPhoneReconfigureAll`) reaching the phone once, the delete-token form |
//! | `flows-reload` | Reconfigure on reload: changed lines, a deleted phone (its AstDB entry and session) |
//! | `flows-mismatch` | A MAC mismatch reconfiguring the old location, an orphaned phone forgetting its location |
//! | `flows-stale` | A stale phone at the same address |
//! | `flows-uri` | The session and the reconfigure messages following a phone that moves |
//! | `flows-events` | Events, including `digium.assignment.update` |
//! | `flows-marks` | Sessions marked authenticated by token builds and lookups, the old session pruned on a new handshake |
//! | `flows-restore` | Sessions restored after an Asterisk restart (authenticated and active, the last-seen information, ping, config, reconfigure) and surviving the idle pruning (waits 65 s) |

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
    let flow_parts: [(&str, fn(&mut _) -> _); 8] = [
        ("flows-reconfigure", flows::reconfigure),
        ("flows-reload", flows::reload),
        ("flows-mismatch", flows::mismatch),
        ("flows-stale", flows::stale),
        ("flows-uri", flows::uri),
        ("flows-events", flows::events),
        ("flows-marks", flows::marks),
        ("flows-restore", flows::restore),
    ];
    for (name, f) in flow_parts {
        suite = suite.part(name, move |ctx| flows::part(ctx, f));
    }
    suite.main()
}
