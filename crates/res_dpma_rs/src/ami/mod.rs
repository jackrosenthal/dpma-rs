//! AMI action registration for the DPMA actions (FUN_00175750 /
//! FUN_00175840) plus the AMI scheduler and queued-message container
//! (phone_ami.c, phone_request.c).
//!
//! The official DPMA registers seven actions in one place, all with
//! authority `call` (EVENT_FLAG_CALL).  `DPMALicenseStatus` is not
//! implemented (no license handling in this rewrite); the other six are:
//!
//! | Action              | Implemented in  |
//! |---------------------|-----------------|
//! | DPMAShowPhones      | `session::ami`  |
//! | DPMAMessageRegister | `ami::messages` |
//! | DPMAMessageResponse | `ami::messages` |
//! | DPMAMessageSend     | `ami::messages` |
//! | DPMAShowIncidents   | `auth`          |
//! | DPMARemoveIncident  | `auth`          |
//!
//! Each of those modules returns its actions from an `actions()`
//! function; this module registers them in the official DPMA's order.
//! Unlike the official DPMA, which unregisters only some of them at unload
//! (leaving dangling handlers), every registered action is unregistered.

pub mod messages;

use dpma_ast::manager::{self, ActionFn};
use std::sync::Mutex;

/// One AMI action.
pub struct AmiAction {
    pub name: &'static str,
    pub authority: i32,
    pub handler: ActionFn,
}

static REGISTERED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

/// The official DPMA's registration order.
const ORDER: &[&str] = &[
    "DPMAShowPhones",
    "DPMAMessageRegister",
    "DPMAMessageResponse",
    "DPMAMessageSend",
    "DPMAShowIncidents",
    "DPMARemoveIncident",
];

/// FUN_00175750: register every DPMA action.
pub fn register_actions() {
    let mut all = messages::actions();
    all.extend(crate::session::ami::actions());
    all.extend(crate::auth::ami_actions());
    all.sort_by_key(|a| ORDER.iter().position(|n| *n == a.name).unwrap_or(ORDER.len()));
    let mut reg = REGISTERED.lock().unwrap();
    for a in all {
        if manager::register(a.name, a.authority, "", "", a.handler) {
            reg.push(a.name);
        }
    }
}

/// FUN_00175840 (fixed): unregister every action registered above.
pub fn unregister_actions() {
    let names: Vec<&'static str> = std::mem::take(&mut *REGISTERED.lock().unwrap());
    for n in names {
        manager::unregister(n);
    }
}

pub use messages::{queue_dispose, queue_init, sched_create, sched_destroy};
