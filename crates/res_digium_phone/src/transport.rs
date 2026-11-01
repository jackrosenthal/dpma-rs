//! Message transport between phones and the module
//! (phone_network_handler2.c, plus the dialplan routing and outgoing
//! message construction from phone_message.c).
//!
//! Phones send SIP MESSAGE requests.  res_pjsip delivers them to the
//! dialplan context `pjsip_message_context` (via the endpoint identifier
//! helper module), whose `proxy` extension, built here, records the
//! response address and hands them to the `digium_phone` message
//! technology with `MessageSend(digium_phone:blah)`.  The technology
//! callback queues them; the phone_main thread reads them with
//! [`read_msg`].  Replies are `ast_msg`s queued into the same context at
//! extension `digium_phone_module`, which sends them back with
//! `MessageSend(${TMP_RESPONSE_URI},proxy)`.
//!
//! Owner: P2 "transport" (wave 1).

use crate::config::General;
use dpma_ast::msg::Msg;

/// Registrar of the routing contexts and their extensions.
pub const REGISTRAR: &str = "digium_phone_module";
/// Message technology name.
pub const MSG_TECH: &str = "digium_phone";
/// Extension that sends replies.
pub const SEND_EXTEN: &str = "digium_phone_module";
/// Extension that receives phone messages.
pub const PROXY_EXTEN: &str = "proxy";

/// `phone_network_handler2` init (FUN_00148040): register the message
/// technology and create the read queue.  Called at the end of
/// `session::load` (as the original does from `phone_msg_load`).
pub fn load() -> Result<(), ()> {
    Ok(())
}

/// `network_handler_destroy` (FUN_00147d70): unregister the technology
/// and drop queued messages.
pub fn unload() {}

/// `phone_network_handler2_read_msg` (FUN_00147eb0): wait up to
/// `timeout_ms` for the next incoming message.
pub fn read_msg(_timeout_ms: i32) -> Option<Msg> {
    None
}

/// Wake a thread blocked in [`read_msg`] (used to stop phone_main).
pub fn wake_reader() {}

/// `phone_network_handler2_write_msg` (FUN_00147e60): queue an outgoing
/// message into the dialplan (`ast_msg_queue`).
pub fn write_msg(_msg: Msg) -> Result<(), ()> {
    Err(())
}

/// FUN_0014be60: allocate an outgoing message for `response_uri`, with
/// its context set from the URI scheme ("pjsip" → `pjsip_message_context`,
/// "sip" → the chan_sip `outofcall_message_context`).  None for other
/// schemes.
pub fn new_outgoing(_response_uri: &str) -> Option<Msg> {
    None
}

/// Called after every successful `config::load()` (`config_replace`):
/// when `pjsip_message_context` changed, destroy the old routing context
/// and build the new one (`msg_build_dialplan_routing(ctx, "pjsip")`).
pub fn config_changed(_old: Option<&General>, _new: &General) {}

/// Called from the users layer (`process_message_config`) with sip.conf's
/// `outofcall_message_context` ("" when unset): rebuild the chan_sip
/// routing context when it changed (`msg_build_dialplan_routing(ctx,
/// "sip")`).
pub fn sip_message_context_changed(_context: &str) {}

/// The current chan_sip message context ("" when none).
pub fn sip_message_context() -> String {
    String::new()
}

/// Destroy both routing contexts (`phone_msg_unload`).
pub fn destroy_routing() {}

/// Test hooks (feature "devtest"), e.g., popping queued messages or
/// sending one to a URI.
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
