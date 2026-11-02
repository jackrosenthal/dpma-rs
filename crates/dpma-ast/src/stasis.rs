//! Stasis topics and message routers: the parking topic subscription of
//! res_digium_phone (phone_method_internal_api.c, FUN_00186920 /
//! FUN_00186840).  A topic of the module's own forwards everything
//! published on `ast_parking_topic()`, and a message router on it hands
//! `ast_parked_call_type()` messages to a callback.

use crate::sys;
use crate::util::{cstr, from_ptr};
use std::os::raw::c_void;
use std::sync::{Mutex, RwLock};

/// `enum ast_parked_call_event_type` value `PARKED_CALL`.
pub const PARKED_CALL: i32 = sys::PARKED_CALL as i32;

/// Receives a parked call message: the payload's `parker_dial_string`,
/// `event_type`, and `parkingspace`.
pub type ParkedCallFn = fn(parker_dial_string: &[u8], event_type: i32, parkingspace: u32);

static PARKED_CALL_FN: RwLock<Option<ParkedCallFn>> = RwLock::new(None);

/// The subscription: topic, forward, and router (raw pointers as
/// addresses).
#[derive(Default)]
struct Subscription {
    topic: usize,
    forward: usize,
    router: usize,
}

static SUBSCRIPTION: Mutex<Subscription> = Mutex::new(Subscription {
    topic: 0,
    forward: 0,
    router: 0,
});

/// The router's callback for parked call messages.
unsafe extern "C" fn parked_call_message(
    _data: *mut c_void,
    _sub: *mut sys::stasis_subscription,
    message: *mut sys::stasis_message,
) {
    crate::guard((), || {
        // SAFETY: the router hands over a parked call message, whose data
        // is a `struct ast_parked_call_payload`.
        let payload = sys::stasis_message_data(message) as *const sys::ast_parked_call_payload;
        if payload.is_null() {
            return;
        }
        let f = *PARKED_CALL_FN.read().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = f {
            let dial = from_ptr((*payload).parker_dial_string).unwrap_or_default();
            f(&dial, (*payload).event_type as i32, (*payload).parkingspace);
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
    let ok = {
        let mut s = SUBSCRIPTION.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: each object is checked before the next step uses it and
        // kept in `SUBSCRIPTION` for `parking_unsubscribe`.
        unsafe {
            let topic = sys::stasis_topic_create(t.as_ptr());
            s.topic = topic as usize;
            !topic.is_null()
                && {
                    let forward = sys::stasis_forward_all(sys::ast_parking_topic(), topic);
                    s.forward = forward as usize;
                    !forward.is_null()
                }
                && {
                    let (file, line, func) = crate::here!("parking_subscribe");
                    let router = sys::__stasis_message_router_create(topic, file, line, func);
                    s.router = router as usize;
                    !router.is_null()
                }
                && sys::stasis_message_router_add(
                    s.router as *mut sys::stasis_message_router,
                    sys::ast_parked_call_type(),
                    Some(parked_call_message),
                    std::ptr::null_mut(),
                ) == 0
        }
    };
    if !ok {
        parking_unsubscribe();
    }
    ok
}

/// Cancel the forwarding, unsubscribe the router (waiting for it to
/// finish), and drop the topic.
pub fn parking_unsubscribe() {
    let s = std::mem::take(&mut *SUBSCRIPTION.lock().unwrap_or_else(|e| e.into_inner()));
    // SAFETY: the objects `parking_subscribe` made (each may be NULL).
    unsafe {
        sys::stasis_forward_cancel(s.forward as *mut sys::stasis_forward);
        sys::stasis_message_router_unsubscribe_and_join(
            s.router as *mut sys::stasis_message_router,
        );
        crate::ao2::cleanup(s.topic as *mut sys::stasis_topic);
    }
    *PARKED_CALL_FN.write().unwrap_or_else(|e| e.into_inner()) = None;
}
