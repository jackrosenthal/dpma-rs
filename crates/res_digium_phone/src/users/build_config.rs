//! The phone configuration document (`phone_user_build_config`
//! FUN_0016ae70 with `add_firmware_settings`, `add_internal_line_account`,
//! `add_option_firmware_settings`, `phone_user_has_queue`;
//! `phone_user_get_config` FUN_00170070; `phone_user_read_config`
//! FUN_00156d10; `phone_user_get_primary_line_tech` FUN_00170190;
//! `phone_user_get_show_call_parking` FUN_0016ab70;
//! `phone_user_get_application_settings` FUN_0016add0;
//! `insert_display_rules` FUN_001558e0).
//!
//! Owner: P4 "config-xml" (wave 1).

/// `phone_user_get_config`: append the configuration for phone `phone`
/// to `out`.  When the phone has `config_file` set, that file (from the
/// file directory) is sent instead.  `file_url` is the file URL prefix
/// computed by `dpma_append_config_file_dir`; `request_user` is the user
/// part of the request's To header.  Calls
/// `users::presence::user_application_sync` first, as the original does.
pub fn get_config(_phone: &str, _out: &mut String, _file_url: &str, _request_user: &str) -> Result<(), ()> {
    Err(())
}

/// The technology ("SIP", "PJSIP") of the phone's primary line.
pub fn primary_line_tech(_phone: &str) -> String {
    String::new()
}

/// Test hooks (feature "devtest"), e.g., printing a phone's document.
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
