//! Session persistence in AstDB family `DigiumPhoneSessions`
//! (`phone_session_update_db_info` FUN_00149250,
//! `phone_session_db_restore_entry` in FUN_00150440).
//!
//! The original encrypts the stored common password with a passphrase
//! embedded in the binary; this implementation must not reuse it (see
//! open questions Q1 and Q2 in dev/notes/port-plan.md).
//!
//! Owner: P7 "session" (wave 2).

use super::Session;
use std::sync::Arc;

/// Write (or delete, when inactive) the session's AstDB entry.
pub fn update_db_info(_s: &Arc<Session>) {}

/// Restore every session found in AstDB.
pub fn restore_all() {}
