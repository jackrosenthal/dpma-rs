//! The CLI commands registered at module load, before the full
//! components: `digium_phones show settings` (FUN_00174570) and
//! `digium_phones show version` (FUN_00174870) (phone_settings_cli.c;
//! register FUN_00174950, unregister FUN_00174930).  The original's
//! third command, `digium_phones license status` (FUN_001748c0), is
//! intentionally not ported (no license handling in this rewrite).
//!
//! Each command's summary is its own command text, as in the original's
//! `ast_cli_entry` table (DAT_005e9100).

use crate::config::auth;
use crate::exports::config_api::{self as c, DpmaConfig};
use dpma_ast::cli::{CliArgs, CliCommand, CliResult};
use std::ffi::CStr;
use std::os::raw::c_char;

/// A string from the C configuration object; "" when the configuration
/// is gone (the original would read through a NULL pointer there).
unsafe fn text(cfg: *mut DpmaConfig, get: unsafe fn(*mut DpmaConfig) -> *const c_char) -> String {
    if cfg.is_null() {
        return String::new();
    }
    let p = get(cfg);
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// `value`, or `<Not Set>` when empty.
fn or_not_set(value: String) -> String {
    if value.is_empty() {
        "<Not Set>".into()
    } else {
        value
    }
}

/// "Config Authentication": `snprintf(buf, 0x80, "%s%s%s%s", mac, sep,
/// pin, globalpin)`, where `sep` is a space after `mac`.
fn config_auth_text(flags: u32) -> String {
    let (mac, sep) = if flags & auth::MAC != 0 { ("mac", " ") } else { ("", "") };
    let pin = if flags & auth::PIN != 0 { "pin" } else { "" };
    let globalpin = if flags & auth::GLOBALPIN != 0 { "globalpin" } else { "" };
    let s = format!("{}{}{}{}", mac, sep, pin, globalpin);
    if s.is_empty() {
        "disabled".into()
    } else {
        s
    }
}

/// `digium_phones show settings` (FUN_00174570).  The original takes any
/// number of arguments.
fn cli_show_settings(a: &CliArgs) -> CliResult {
    unsafe {
        let cfg = c::dpma_config_get();
        let flags = c::dpma_config_auth_flags(cfg) as u32;
        // The getters with built-in defaults; on a NULL configuration they
        // would yield their defaults for an empty field.
        let defaulted = |get: unsafe extern "C" fn(*mut DpmaConfig) -> *const c_char, default: &str| {
            if cfg.is_null() {
                default.to_string()
            } else {
                CStr::from_ptr(get(cfg)).to_string_lossy().into_owned()
            }
        };
        a.out("---- Digium Phone Module Global Settings ---- \n");
        a.out(&format!("Server UUID: {}\n", or_not_set(text(cfg, |p| c::dpma_config_server_uuid(p)))));
        let pin_set = !text(cfg, |p| c::dpma_config_password(p)).is_empty();
        a.out(&format!("GlobalPin: {}\n", if pin_set { "<Set>" } else { "<Not Set>" }));
        let discovery = c::dpma_config_enable_discovery(cfg) != 0;
        a.out(&format!("Service Discovery: {}\n", if discovery { "Enabled" } else { "Disabled" }));
        a.out(&format!(
            "Service Disc. Name: {}\n",
            defaulted(c::dpma_config_service_name, crate::config::DEFAULT_SERVICE_NAME)
        ));
        a.out(&format!("Service Disc. Addr: {}\n", or_not_set(text(cfg, |p| c::dpma_config_mdns_addr(p)))));
        a.out(&format!("Service Disc. Port: {}\n", defaulted(c::dpma_config_mdns_port, crate::config::DEFAULT_PORT)));
        let userlist = if flags & auth::USERLIST_GLOBALPIN != 0 { "globalpin" } else { "disabled" };
        a.out(&format!("Userlist Authentication: {}\n", userlist));
        a.out(&format!("Config Authentication: {}\n", config_auth_text(flags)));
        a.out(&format!(
            "Firmware Package Directory: {}\n",
            or_not_set(text(cfg, |p| c::dpma_config_firmware_package_dir(p)))
        ));
        a.out(&format!("File Directory: {}\n", CStr::from_ptr(c::dpma_config_file_dir(cfg)).to_string_lossy()));
        a.out(&format!(
            "PJSIP message context: {}\n",
            defaulted(c::dpma_config_pjsip_message_context, crate::config::DEFAULT_PJSIP_MESSAGE_CONTEXT)
        ));
        a.out(&format!("Message Delay: {} ms\n", c::dpma_config_delay(cfg) as u32));
        c::dpma_config_unref(cfg);
    }
    CliResult::Success
}

/// `digium_phones show version` (FUN_00174870; this rewrite prints its own
/// version, plan section 8, item 5).  Like `show settings`, it takes any
/// number of arguments.
fn cli_show_version(a: &CliArgs) -> CliResult {
    a.out(&format!("dpma-rs version {}\n", crate::VERSION));
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
