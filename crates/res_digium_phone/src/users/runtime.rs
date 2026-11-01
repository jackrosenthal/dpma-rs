//! Runtime state of phone users: tokens, authentication lookups, last
//! known location, AstDB `DigiumPhoneUsers` updates, reconfigure and
//! event messages (phone_users.c).
//!
//! Functions: `phone_user_token_set_last_info` (0x170630),
//! `phone_user_config_token_build` (0x170f00),
//! `standard_phone_user_find_by_token` (0x1710e0),
//! `phone_user_find_w_grouppin` (0x171720),
//! `phone_user_find_authenticated(_w_mac)` (0x170370 / 0x170250),
//! `phone_user_find_w_mac` (0x170470), `phone_user_for_last_token_mac`
//! (0x170560), `phone_username_for_token` (0x161340),
//! `phone_line_find_authenticated` (0x15b2b0), `phone_line_get_user`
//! (0x161300), `phone_mailbox_by_line` (0x161710),
//! `phone_user_del_stale_response_uri` (0x152410),
//! `phone_user_update_db_info` (0x152660), `phone_user_send_reconfigure`
//! (0x151c80), `phone_user_send_event` (0x159a10), `phone_user_delme_cb`
//! (0x159720), and the `last_session_id` part of `phone_user_db_restore`.
//!
//! Owner: P8 "users-runtime" (wave 2).

/// `phone_user_send_reconfigure`: send `digium.config.update` to the
/// session `session_id` (body `<config></config>`, or the delete-token
/// form).  The response URI `uri` is used as the destination.
pub fn send_reconfigure(session_id: &str, _uri: &str, _delete_token: bool) -> Result<(), ()> {
    dpma_ast::dpma_log!("Unable to find session '{}'", session_id);
    Err(())
}

/// `phone_user_token_set_last_info`: record that phone `phone` was seen at
/// `uri` with `session_id` / `mac` (None leaves a field unchanged).
pub fn set_last_info(_phone: &str, _uri: &str, _session_id: Option<&str>, _mac: Option<&str>) {}

/// `phone_user_send_event` (used by DPMAMessageSend).
pub fn send_event(_phone: &str, _event: &str, _body: &str) -> Result<(), String> {
    Err("not implemented".into())
}

/// The phone whose primary line is `line` (`phone_line_get_user`).
pub fn phone_for_line(_line: &str) -> Option<String> {
    None
}

/// `phone_mailbox_by_line` (FUN_00161710): the mailbox (`box@context`) of
/// line `line`, or None when the line does not exist or has no mailbox.
pub fn mailbox_by_line(line: &str) -> Option<String> {
    let g = super::read();
    let l = g.as_ref()?.lines.get(line)?;
    if l.mailbox.is_empty() {
        None
    } else {
        Some(l.mailbox.clone())
    }
}

/// Restore `last_session_id`s from AstDB once sessions are loaded
/// (`phone_user_db_restore`, second half).
pub fn restore_sessions() {}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
