//! The Handshake request (`handle_request_handshake` FUN_0014dbe0,
//! `prune_session_by_mac`, `phone_msg_session_alloc` FUN_0014b450,
//! `session_verify_cert` FUN_00148230, `phone_msg_set_common_password`
//! FUN_0014bb00, `set_auth_requirements` FUN_00149710).
//!
//! Owner: P7 "session" (wave 2).

use super::Transaction;
use std::sync::Arc;

/// Request handler for "Handshake" (registered by
/// `request::handlers::load`).
pub fn handle_handshake(_tx: Arc<Transaction>) -> i32 {
    0
}
