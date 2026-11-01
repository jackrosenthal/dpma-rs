//! DPMAMessageSend / DPMAMessageRegister / DPMAMessageResponse, the
//! queued AMI-forwarded requests, and the AMI scheduler (phone_ami.c
//! 0x174a00..0x175750; phone_request.c 0x175840..0x1758c0, 0x176490).
//! (`DPMALicenseStatus`, FUN_00174d20, is intentionally not ported.)
//!
//! Owner: P13 "ami" (wave 3).

use super::AmiAction;

/// Actions contributed to `ami::register_actions`.
pub fn actions() -> Vec<AmiAction> {
    Vec::new()
}

/// FUN_00175880: create the scheduler context ("Failed to create ami
/// schedule context" on error).
pub fn sched_create() -> Result<(), ()> {
    Ok(())
}

/// FUN_001758a0.
pub fn sched_destroy() {}

/// `phone_ami_queued_msg_container_initialize` (FUN_001755b0).
pub fn queue_init() -> Result<(), ()> {
    Ok(())
}

/// `phone_ami_queued_msg_container_dispose` (FUN_00175610).
pub fn queue_dispose() {}

use crate::session::Transaction;
use std::sync::Arc;

/// A phone request forwarded to AMI as a `DPMAMessage` event, waiting for
/// `DPMAMessageResponse` (`struct queued_msg`; container keyed by
/// RequestID, case insensitive).
pub struct QueuedMsg {
    /// The transaction key ("<AppServer-ID>-<MAC>").
    pub request_id: String,
    pub method: String,
    /// "XML" or "JSON".
    pub format: String,
    pub tx: Arc<Transaction>,
}

/// `phone_ami_queued_msg_link`.
pub fn queue_link(_msg: QueuedMsg) -> Result<(), ()> {
    Err(())
}

/// `phone_ami_queued_msg_unlink` (find and remove by RequestID).
pub fn queue_unlink(_request_id: &str) -> Option<QueuedMsg> {
    None
}

/// Delay used for `sched_expire_queued` (FUN_001758c0 schedules after
/// 300000 ms).
pub const QUEUED_EXPIRY_MS: i32 = 300_000;

/// FUN_001758c0: schedule `sched_expire_queued` for `request_id` (the
/// callback replies "No response to request (%s), expired." in the log
/// and drops the queued message).
pub fn schedule_expiry(_request_id: &str) -> Result<(), ()> {
    Err(())
}
