//! Outgoing messages: `phone_msg_outgoing_send` (FUN_0014c6b0),
//! `phone_msg_send_and_destroy` (FUN_0014e590), `phone_msg_send_timeout`
//! (FUN_0014e7e0), `phone_msg_send_event` (FUN_0014e030), and the
//! handshake error reply (FUN_0014bf10).
//!
//! Owner: P7 "session" (wave 2).

use super::{Outgoing, Session, Transaction};
use dpma_ast::msg::Msg;
use std::sync::Arc;

/// Send `out` to the phone of `session` (chunking, encryption, headers).
pub fn send(_out: &Outgoing, _session: &Arc<Session>) -> Result<(), ()> {
    Err(())
}

/// Send the transaction's outgoing message with its session, then free it.
pub fn send_and_destroy(_tx: &Arc<Transaction>) {}

/// Reply "Session Timeout" (-398) to a message whose session failed
/// validation.
pub fn send_timeout(_msg: &Msg) -> Result<(), ()> {
    Err(())
}

/// Send an event (`X-Event-Name`) with `body` to the session's phone.
/// The error text matches the original's error buffer.
pub fn send_event(_session: &Arc<Session>, _event: &str, _body: &str) -> Result<(), String> {
    Err("Memory allocation error".into())
}

/// FUN_0014bf10: reply `HandshakeResponse` with Error-ID -398 to a
/// message for an unknown session.
pub fn send_handshake_required(
    _id: &str,
    _response_uri: &str,
    _session: Option<&Arc<Session>>,
    _salt: &str,
    _body: &str,
    _origination_network: &str,
) {
}
