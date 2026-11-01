//! `digium_phones show sessions` (`handle_cli_show_sessions` FUN_00148e40).

use super::now;
use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

/// "NONE" for an empty value.
fn or_none(s: &str) -> &str {
    if s.is_empty() {
        "NONE"
    } else {
        s
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "Yes"
    } else {
        "No"
    }
}

/// `handle_cli_show_sessions`: one line per session, in container order.
fn show_sessions(a: &CliArgs) -> CliResult {
    let t = now();
    a.out("---- Digium Phone Module Active Sessions ---- \n");
    let mut count = 0;
    for s in super::store::all() {
        let line = {
            let st = s.lock();
            format!(
                "SessionID:{:<20} SecondsAlive:{:<7} SecondsLastActivity:{:<7} URI:{:<28} Auth:{:<3} Inactive:{:<3} Configured: {:<3} MAC:{}\n",
                s.id,
                t - st.created,
                t - st.last_activity,
                or_none(&st.response_uri),
                yes_no(st.authenticated),
                yes_no(st.inactive),
                yes_no(st.configured),
                or_none(&st.mac)
            )
        };
        count += 1;
        a.out(&line);
    }
    a.out(&format!("--- Total active sessions:{} ---\n", count));
    CliResult::Success
}

/// Commands registered by `phone_msg_load`.
pub fn commands() -> Vec<CliCommand> {
    vec![CliCommand {
        command: "digium_phones show sessions",
        summary: "digium_phones show sessions",
        usage: "Usage digium_phones show sessions\n",
        exec: show_sessions,
        complete: None,
    }]
}
