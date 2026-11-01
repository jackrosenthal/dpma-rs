//! Presence state helpers.

use crate::ffi;
use crate::util::{cstr, from_ptr, take_ast_string};

pub const NOT_SET: i32 = 0;
pub const UNAVAILABLE: i32 = 1;
pub const AVAILABLE: i32 = 2;
pub const AWAY: i32 = 3;
pub const XA: i32 = 4;
pub const CHAT: i32 = 5;
pub const DND: i32 = 6;
pub const INVALID: i32 = 7;

/// Asterisk's name for a presence state.
pub fn state2str(state: i32) -> String {
    unsafe { from_ptr(ffi::ast_presence_state2str(state)).unwrap_or_default() }
}

/// Asterisk's presence state for a name (INVALID when unknown).
pub fn state_val(name: &str) -> i32 {
    let c = cstr(name);
    unsafe { ffi::ast_presence_state_val(c.as_ptr()) }
}

/// Query a presence provider, returning (state, subtype, message).
pub fn query(provider: &str) -> (i32, Option<String>, Option<String>) {
    let p = cstr(provider);
    let mut subtype = std::ptr::null_mut();
    let mut message = std::ptr::null_mut();
    unsafe {
        let state = ffi::ast_presence_state(p.as_ptr(), &mut subtype, &mut message);
        (state, take_ast_string(subtype), take_ast_string(message))
    }
}
