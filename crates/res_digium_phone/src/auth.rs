//! Authentication incidents (phone_auth.c): failed handshakes and bad
//! credentials are recorded per IP address, logged, expired, and exposed
//! through `DPMAShowIncidents` / `DPMARemoveIncident`.
//!
//! Owner: P3 "request" (wave 1).

use crate::ami::AmiAction;
use crate::session::Transaction;

/// `phone_auth_init` (FUN_00178300).
pub fn load() -> Result<(), ()> {
    Ok(())
}

/// `phone_auth_unload` (FUN_00178380).
pub fn unload() {}

/// `phone_auth_issue_alert` (FUN_00177920): record a failure for the
/// transaction's source address.  `reason` is, e.g., "invalid credentials"
/// or "invalid config pass".
pub fn issue_alert(_tx: &Transaction, _reason: &str) {}

/// `phone_auth_expire_problems` (FUN_00177d30); called by
/// `session::next_transaction` on every pass.
pub fn expire_problems() {}

/// AMI actions DPMAShowIncidents and DPMARemoveIncident.
pub fn ami_actions() -> Vec<AmiAction> {
    Vec::new()
}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
