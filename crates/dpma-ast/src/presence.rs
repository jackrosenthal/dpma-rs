//! Presence state helpers.

use crate::sys;
use crate::util::{cstr, from_ptr, take_ast_string};

pub const NOT_SET: i32 = 0;
pub const UNAVAILABLE: i32 = 1;
pub const AVAILABLE: i32 = 2;
pub const AWAY: i32 = 3;
pub const XA: i32 = 4;
pub const CHAT: i32 = 5;
pub const DND: i32 = 6;
pub const INVALID: i32 = 7;

/// Asterisk's name for a presence state (from its static table).
pub fn state2str(state: i32) -> Vec<u8> {
    // SAFETY: returns a static string.
    unsafe { from_ptr(sys::ast_presence_state2str(state as sys::ast_presence_state)).unwrap_or_default() }
}

/// Asterisk's presence state for a name (INVALID when unknown).
pub fn state_val(name: impl AsRef<[u8]>) -> i32 {
    let c = cstr(name);
    // SAFETY: a valid C string.
    unsafe { sys::ast_presence_state_val(c.as_ptr()) as i32 }
}

/// Query a presence provider, returning (state, subtype, message).
pub fn query(provider: impl AsRef<[u8]>) -> (i32, Option<Vec<u8>>, Option<Vec<u8>>) {
    let p = cstr(provider);
    let mut subtype = std::ptr::null_mut();
    let mut message = std::ptr::null_mut();
    // SAFETY: the provider fills in ast_malloc'ed strings or leaves them
    // NULL; they are copied and freed.
    unsafe {
        let state = sys::ast_presence_state(p.as_ptr(), &mut subtype, &mut message) as i32;
        (state, take_ast_string(subtype), take_ast_string(message))
    }
}
