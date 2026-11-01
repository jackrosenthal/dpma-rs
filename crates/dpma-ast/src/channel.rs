//! Channels: lookup by name prefix and technology call id, the name and
//! unique id under the channel lock, and the queue member call scan
//! (glue in `glue/channel.c`).
//!
//! Filled in by P10 "methods-calls" (wave 2).

use crate::types::AstChannel;
use crate::util::{cstr, take_ast_string};
use std::os::raw::{c_char, c_int, c_long};

extern "C" {
    fn dpma_glue_channel_find_by_callid(prefix: *const c_char, callid: *const c_char) -> *mut AstChannel;
    fn dpma_glue_channel_unref(chan: *mut AstChannel);
    fn dpma_glue_channel_name_uniqueid(chan: *mut AstChannel, name: *mut *mut c_char, uniqueid: *mut *mut c_char);
    fn dpma_glue_channel_queue_member_call(interface: *const c_char, created: *mut c_long) -> c_int;
}

/// An owned channel reference, dropped with `ast_channel_unref`.
pub struct Channel(*mut AstChannel);

unsafe impl Send for Channel {}

impl Channel {
    /// The first channel whose name starts with `prefix` (case
    /// insensitive, as Asterisk's by-name iterator compares) and whose
    /// technology's `get_pvt_uniqueid` equals `callid`
    /// (`find_channel_by_callid_tech`).
    pub fn find_by_callid(prefix: &str, callid: &str) -> Option<Channel> {
        if prefix.is_empty() {
            return None;
        }
        let p = cstr(prefix);
        let c = cstr(callid);
        let chan = unsafe { dpma_glue_channel_find_by_callid(p.as_ptr(), c.as_ptr()) };
        (!chan.is_null()).then_some(Channel(chan))
    }

    /// The channel's name and unique id, read under its lock.
    pub fn name_and_uniqueid(&self) -> (String, String) {
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
pub fn queue_member_call_created(interface: &str) -> Option<i64> {
    let c = cstr(interface);
    let mut created: c_long = 0;
    let found = unsafe { dpma_glue_channel_queue_member_call(c.as_ptr(), &mut created) };
    (found != 0).then_some(created as i64)
}
