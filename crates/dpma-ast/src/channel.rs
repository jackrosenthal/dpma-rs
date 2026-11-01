//! Channels: lookup by name prefix and technology call id, the name and
//! unique id under the channel lock, the queue member call scan (glue in
//! `glue/channel.c`), and channel names, variables, state, and answering.

use crate::types::AstChannel;
use crate::util::{cstr, from_ptr, take_ast_string};
use crate::vm::c_bytes;
use std::os::raw::{c_char, c_int, c_long};

extern "C" {
    fn dpma_glue_channel_find_by_callid(prefix: *const c_char, callid: *const c_char) -> *mut AstChannel;
    fn dpma_glue_channel_unref(chan: *mut AstChannel);
    fn dpma_glue_channel_name_uniqueid(chan: *mut AstChannel, name: *mut *mut c_char, uniqueid: *mut *mut c_char);
    fn dpma_glue_channel_queue_member_call(interface: *const c_char, created: *mut c_long) -> c_int;
    fn ast_channel_state(chan: *const AstChannel) -> c_int;
    fn ast_channel_name(chan: *const AstChannel) -> *const c_char;
    fn ast_answer(chan: *mut AstChannel) -> c_int;
}

/// `ast_channel_name` (copied; "" for NULL).
///
/// # Safety
/// `chan` must be NULL or a live channel.
pub unsafe fn name(chan: *const AstChannel) -> Vec<u8> {
    if chan.is_null() {
        return Vec::new();
    }
    from_ptr(ast_channel_name(chan)).unwrap_or_default()
}

/// `pbx_builtin_setvar_helper(chan, name, value)`: set a variable, or
/// write a dialplan function when `name` is one (e.g., `PJSIP_HEADER(...)`).
///
/// # Safety
/// `chan` must be NULL or a live channel.
pub unsafe fn setvar(chan: *mut AstChannel, name: &str, value: &[u8]) -> c_int {
    let (name, value) = (cstr(name), c_bytes(value));
    crate::ffi::pbx_builtin_setvar_helper(chan, name.as_ptr(), value.as_ptr())
}

/// `AST_STATE_UP`.
pub const STATE_UP: i32 = 6;

/// `ast_channel_state(chan)` (`enum ast_channel_state`).
///
/// # Safety
/// `chan` must be a live channel.
pub unsafe fn state(chan: *const AstChannel) -> i32 {
    ast_channel_state(chan)
}

/// `ast_answer(chan)`: 0 on success.
///
/// # Safety
/// `chan` must be a live channel the caller is running on.
pub unsafe fn answer(chan: *mut AstChannel) -> i32 {
    ast_answer(chan)
}

/// An owned channel reference, dropped with `ast_channel_unref`.
pub struct Channel(*mut AstChannel);

unsafe impl Send for Channel {}

impl Channel {
    /// The first channel whose name starts with `prefix` (case
    /// insensitive, as Asterisk's by-name iterator compares) and whose
    /// technology's `get_pvt_uniqueid` equals `callid`
    /// (`find_channel_by_callid_tech`).
    pub fn find_by_callid(prefix: &[u8], callid: &[u8]) -> Option<Channel> {
        if prefix.is_empty() {
            return None;
        }
        let p = cstr(prefix);
        let c = cstr(callid);
        let chan = unsafe { dpma_glue_channel_find_by_callid(p.as_ptr(), c.as_ptr()) };
        (!chan.is_null()).then_some(Channel(chan))
    }

    /// The channel's name and unique id, read under its lock.
    pub fn name_and_uniqueid(&self) -> (Vec<u8>, Vec<u8>) {
        let mut name: *mut c_char = std::ptr::null_mut();
        let mut uid: *mut c_char = std::ptr::null_mut();
        unsafe {
            dpma_glue_channel_name_uniqueid(self.0, &mut name, &mut uid);
            (take_ast_string(name).unwrap_or_default(), take_ast_string(uid).unwrap_or_default())
        }
    }

    pub fn as_ptr(&self) -> *mut AstChannel {
        self.0
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { dpma_glue_channel_unref(self.0) };
    }
}

/// The creation time (seconds since the epoch) of the first channel whose
/// `MEMBERINTERFACE` equals `interface` (case insensitive) and whose
/// `QUEUEPOSITION` is empty: the queue member's current queue call.
pub fn queue_member_call_created(interface: &[u8]) -> Option<i64> {
    let c = cstr(interface);
    let mut created: c_long = 0;
    let found = unsafe { dpma_glue_channel_queue_member_call(c.as_ptr(), &mut created) };
    (found != 0).then_some(created as i64)
}
