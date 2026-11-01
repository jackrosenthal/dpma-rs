//! Stasis topics and message routers: the parking topic subscription of
//! res_digium_phone (glue in `glue/stasis.c`).

use crate::util::{cstr, from_ptr};
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::RwLock;

type ParkedCallC = unsafe extern "C" fn(parker_dial_string: *const c_char, event_type: c_int, parkingspace: c_uint);

extern "C" {
    fn dpma_glue_stasis_parking_subscribe(topic_name: *const c_char, f: ParkedCallC) -> c_int;
    fn dpma_glue_stasis_parking_unsubscribe();
}

/// `enum ast_parked_call_event_type` value `PARKED_CALL`.
pub const PARKED_CALL: i32 = 0;

/// Receives a parked call message: the payload's `parker_dial_string`,
/// `event_type`, and `parkingspace`.
pub type ParkedCallFn = fn(parker_dial_string: &[u8], event_type: i32, parkingspace: u32);

static PARKED_CALL_FN: RwLock<Option<ParkedCallFn>> = RwLock::new(None);

unsafe extern "C" fn parked_call_trampoline(dial: *const c_char, event_type: c_int, space: c_uint) {
    crate::guard((), || {
        let f = *PARKED_CALL_FN.read().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = f {
            let dial = from_ptr(dial).unwrap_or_default();
            f(&dial, event_type, space);
        }
    })
}

/// Create the Stasis topic `topic_name`, forward `ast_parking_topic()` to
/// it, and route its `ast_parked_call_type()` messages to `f` (on the
/// router's own thread).  False on failure, when nothing is left
/// subscribed.
pub fn parking_subscribe(topic_name: &str, f: ParkedCallFn) -> bool {
    *PARKED_CALL_FN.write().unwrap_or_else(|e| e.into_inner()) = Some(f);
    let t = cstr(topic_name);
    if unsafe { dpma_glue_stasis_parking_subscribe(t.as_ptr(), parked_call_trampoline) } == 0 {
        return true;
    }
    *PARKED_CALL_FN.write().unwrap_or_else(|e| e.into_inner()) = None;
    false
}

/// Cancel the forwarding, unsubscribe the router (waiting for it to
/// finish), and drop the topic.
pub fn parking_unsubscribe() {
    unsafe { dpma_glue_stasis_parking_unsubscribe() };
    *PARKED_CALL_FN.write().unwrap_or_else(|e| e.into_inner()) = None;
}
