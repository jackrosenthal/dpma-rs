//! The CLI commands registered at module load, before the full
//! components: `digium_phones show settings` and `digium_phones show
//! version` (phone_settings_cli.c, 0x174570..0x174950).  The original's
//! third command, `digium_phones license status` (FUN_001748c0), is
//! intentionally not ported (no license handling in this rewrite).
//!
//! Owner: P14 "apps-discovery" (wave 3).  Only `show version` exists yet.

use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

fn cli_show_version(a: &CliArgs) -> CliResult {
    if a.argc() != 3 {
        return CliResult::ShowUsage;
    }
    a.out(&format!("dpma-rs version {}\n", crate::VERSION));
    CliResult::Success
}

/// The commands registered by `load_module` (FUN_00174950).
pub fn commands() -> Vec<CliCommand> {
    vec![CliCommand {
        command: "digium_phones show version",
        summary: "Show the Digium Phone Module version",
        usage: "Usage: digium_phones show version\n       Displays Digium Phone Module for Asterisk version\n",
        exec: cli_show_version,
        complete: None,
    }]
}
