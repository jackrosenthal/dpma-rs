//! `digium_phones show status <phone>` (`handle_cli_show_status`
//! 0x1659d0), the 18th command of the phone users CLI group.

use super::read;
use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

/// List the phone's presence options, marking the current one with
/// `(*)`.  The phone name is matched case sensitively; an unknown phone
/// prints nothing.
fn show_status(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let name = {
        let g = read();
        g.as_ref().and_then(|r| {
            r.phones
                .values()
                .find(|p| p.name == a.argv[3])
                .map(|p| p.name.clone())
        })
    };
    let Some(name) = name else {
        return CliResult::Success;
    };
    for line in super::presence::status_lines(&name).unwrap_or_default() {
        a.out(&line);
    }
    CliResult::Success
}

pub fn commands() -> Vec<CliCommand> {
    vec![CliCommand {
        command: "digium_phones show status",
        summary: "digium_phones show status",
        usage: "Usage digium_phones show status <phone name>\n",
        exec: show_status,
        complete: Some(super::cli::complete_phone),
    }]
}
