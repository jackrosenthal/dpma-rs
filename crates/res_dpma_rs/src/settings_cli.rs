//! The CLI commands registered at module load, before the full
//! components: `digium_phones show settings` (FUN_00174570) and
//! `digium_phones show version` (FUN_00174870) (phone_settings_cli.c;
//! register FUN_00174950, unregister FUN_00174930).  The official DPMA's
//! third command, `digium_phones license status` (FUN_001748c0), is
//! intentionally not ported (no license handling in this rewrite).
//!
//! Each command's summary is its own command text, as in the official
//! DPMA's `ast_cli_entry` table (DAT_005e9100).

use crate::config::{self, auth};
use dpma_ast::bformat;
use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

/// `value`, or `<Not Set>` when empty.
fn or_not_set(value: Vec<u8>) -> Vec<u8> {
    if value.is_empty() {
        "<Not Set>".into()
    } else {
        value
    }
}

/// "Config Authentication": `snprintf(buf, 0x80, "%s%s%s%s", mac, sep,
/// pin, globalpin)`, where `sep` is a space after `mac`.
fn config_auth_text(flags: u32) -> String {
    let (mac, sep) = if flags & auth::MAC != 0 {
        ("mac", " ")
    } else {
        ("", "")
    };
    let pin = if flags & auth::PIN != 0 { "pin" } else { "" };
    let globalpin = if flags & auth::GLOBALPIN != 0 {
        "globalpin"
    } else {
        ""
    };
    let s = format!("{}{}{}{}", mac, sep, pin, globalpin);
    if s.is_empty() {
        "disabled".into()
    } else {
        s
    }
}

/// `digium_phones show settings` (FUN_00174570).  The official DPMA takes
/// any number of arguments.  It reads the configuration object (see
/// `config::Settings`); without one, the getters' defaults.
fn cli_show_settings(a: &CliArgs) -> CliResult {
    let s = config::settings();
    let s = s.as_ref();
    let text = |f: fn(&config::Settings) -> &Vec<u8>| s.map(|s| f(s).clone()).unwrap_or_default();
    let defaulted = |f: fn(&config::Settings) -> &Vec<u8>, default: &str| {
        s.map_or_else(|| default.as_bytes().to_vec(), |s| f(s).clone())
    };
    let flags = s.map_or(1, |s| s.auth_flags);
    a.out("---- Digium Phone Module Global Settings ---- \n");
    a.out(bformat!(
        "Server UUID: {}\n",
        or_not_set(text(|s| &s.server_uuid))
    ));
    let pin_set = !text(|s| &s.password).is_empty();
    a.out(bformat!(
        "GlobalPin: {}\n",
        if pin_set { "<Set>" } else { "<Not Set>" }
    ));
    let discovery = s.is_none_or(|s| s.enable_discovery);
    a.out(bformat!(
        "Service Discovery: {}\n",
        if discovery { "Enabled" } else { "Disabled" }
    ));
    a.out(bformat!(
        "Service Disc. Name: {}\n",
        defaulted(|s| &s.service_name, config::DEFAULT_SERVICE_NAME)
    ));
    a.out(bformat!(
        "Service Disc. Addr: {}\n",
        or_not_set(text(|s| &s.mdns_addr))
    ));
    a.out(bformat!(
        "Service Disc. Port: {}\n",
        defaulted(|s| &s.mdns_port, config::DEFAULT_PORT)
    ));
    let userlist = if flags & auth::USERLIST_GLOBALPIN != 0 {
        "globalpin"
    } else {
        "disabled"
    };
    a.out(bformat!("Userlist Authentication: {}\n", userlist));
    a.out(bformat!(
        "Config Authentication: {}\n",
        config_auth_text(flags)
    ));
    a.out(bformat!(
        "Firmware Package Directory: {}\n",
        or_not_set(text(|s| &s.firmware_package_dir))
    ));
    let file_dir = s.map_or_else(config::default_file_dir, |s| s.file_dir.clone());
    a.out(bformat!("File Directory: {}\n", file_dir));
    a.out(bformat!(
        "PJSIP message context: {}\n",
        defaulted(
            |s| &s.pjsip_message_context,
            config::DEFAULT_PJSIP_MESSAGE_CONTEXT
        )
    ));
    a.out(bformat!(
        "Message Delay: {} ms\n",
        s.map_or(config::DEFAULT_MESSAGE_DELAY, |s| s.delay)
    ));
    CliResult::Success
}

/// `digium_phones show version` (FUN_00174870; this rewrite prints its own
/// version, plan section 8, item 5).  Like `show settings`, it takes any
/// number of arguments.
fn cli_show_version(a: &CliArgs) -> CliResult {
    a.out(bformat!("dpma-rs version {}\n", crate::VERSION));
    CliResult::Success
}

/// The commands registered by `load_module` (FUN_00174950).
pub fn commands() -> Vec<CliCommand> {
    vec![
        CliCommand {
            command: "digium_phones show settings",
            summary: "digium_phones show settings",
            usage: "Usage digium_phones show settings\n",
            exec: cli_show_settings,
            complete: None,
        },
        CliCommand {
            command: "digium_phones show version",
            summary: "digium_phones show version",
            usage: "Usage: digium_phones show version\n       Displays Digium Phone Module for Asterisk version\n",
            exec: cli_show_version,
            complete: None,
        },
    ]
}
