//! Test-only CLI commands, compiled with `--features devtest` and never
//! part of a release build.  They exist so packages can be exercised in
//! the scratch Asterisk before the code that would normally drive them
//! (sessions, phone requests) is in place.
//!
//! Each package contributes commands from its own `devtest_commands()`;
//! use the command prefix `dpmadev` (e.g., `dpmadev config <phone>`).
//! This file only aggregates them.

use dpma_ast::cli::CliCommand;

pub fn commands() -> Vec<CliCommand> {
    let mut v = Vec::new();
    v.extend(crate::transport::devtest_commands());
    v.extend(crate::session::devtest_commands());
    v.extend(crate::method::devtest_commands());
    v.extend(crate::request::devtest_commands());
    v.extend(crate::auth::devtest_commands());
    v.extend(crate::users::build_config::devtest_commands());
    v.extend(crate::users::runtime::devtest_commands());
    v.extend(crate::method_api::voicemail::devtest_commands());
    v.extend(crate::method_api::calls::devtest_commands());
    v
}
