//! Per-user presence options and current presence (phone_users.c
//! `phone_presence_*` 0x160740..0x1610e0, `phone_pres_destroy_cb`,
//! `phone_presence_user_application_sync` 0x1648d0).
//!
//! Owner: P8 "users-runtime" (wave 2).

/// `phone_presence_user_application_sync`: refresh the presence options
/// of phone `phone` from its status applications.
pub fn user_application_sync(_phone: &str) {}
