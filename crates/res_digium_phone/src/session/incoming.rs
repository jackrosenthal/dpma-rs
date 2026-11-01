//! Incoming messages: `validate_message`, `incoming_build_transaction`,
//! `incoming_add_msg`, `incoming_check_finalize`, `validate_session`,
//! `prune_inactive`, `find_transaction` (FUN_0014f280, FUN_0014a000,
//! FUN_0014ed90).
//!
//! Owner: P7 "session" (wave 2).

use super::Transaction;
use std::sync::Arc;

/// Read messages (via `transport::read_msg`) until one completes a
/// transaction or `timeout_ms` passes.  Also prunes idle sessions and
/// transactions and calls `auth::expire_problems()`.
pub fn next_transaction(_timeout_ms: i32) -> Option<Arc<Transaction>> {
    None
}
