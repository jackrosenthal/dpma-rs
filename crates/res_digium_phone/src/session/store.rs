//! The session container (`phone_msg_load`, `phone_msg_unload`,
//! `phone_msg_session_find*`, `phone_msg_session_mark_*`,
//! `phone_msg_session_invalidate`, `phone_msg_set/get_global_auth_flags`).
//!
//! Owner: P7 "session" (wave 2).

use super::Session;
use std::sync::Arc;

/// `phone_msg_load` (FUN_00150440): load the CA store from
/// `phone_ca_file`, prepare the AstDB crypto key, create the containers,
/// set the global auth flags, register `digium_phones show sessions`,
/// restore sessions from AstDB, then `transport::load()`.
pub fn load(_config_file: &str) -> Result<(), ()> {
    crate::transport::load()
}

/// `phone_msg_reload` (FUN_00150420): refresh the global auth flags.
pub fn reload(_config_file: &str) -> Result<(), ()> {
    Ok(())
}

/// `phone_msg_unload` (FUN_001510f0).
pub fn unload() {
    crate::transport::unload();
}

pub fn find(_id: &str) -> Option<Arc<Session>> {
    None
}

pub fn find_by_mac(_mac: &str) -> Option<Arc<Session>> {
    None
}

/// Every session (for the CLI and AMI listings).
pub fn all() -> Vec<Arc<Session>> {
    Vec::new()
}

/// `phone_msg_session_mark_authenticated`: set authenticated (clearing
/// inactive), optionally replace the response URI, save to AstDB.
pub fn mark_authenticated(_s: &Arc<Session>, _response_uri: Option<&str>) {}

/// `phone_msg_session_mark_inactive`: set inactive, delete from AstDB.
pub fn mark_inactive(_s: &Arc<Session>) {}

/// `phone_msg_session_mark_unconfigured_by_mac`.
pub fn mark_unconfigured_by_mac(_mac: &str) {}

/// `phone_msg_session_invalidate`: delete from AstDB and the container.
pub fn invalidate(_s: &Arc<Session>) {}

/// `phone_msg_set_global_auth_flags`.
pub fn set_global_auth_flags(_flags: u32) {}

pub fn global_auth_flags() -> u32 {
    crate::config::auth::USER
}
