//! Channels: lookups by name and by technology call id, the name and
//! unique id under the channel lock, the queue member call scan, channel
//! variables, state, answering, and party information.

use crate::here;
use crate::sys;
use crate::types::AstChannel;
use crate::util::{bytes_or_empty, cstr, from_ptr};
use crate::vm::c_bytes;
use std::os::raw::c_int;

/// `ast_channel_lock(chan)`.
///
/// # Safety
/// `chan` must be a live channel.
pub unsafe fn lock(chan: *mut AstChannel) {
    let (file, line, func) = here!("channel::lock");
    sys::__ao2_lock(
        chan.cast(),
        sys::AO2_LOCK_REQ_MUTEX,
        file,
        func,
        line,
        c"chan".as_ptr(),
    );
}

/// `ast_channel_unlock(chan)`.
///
/// # Safety
/// `chan` must be a live channel locked by this thread.
pub unsafe fn unlock(chan: *mut AstChannel) {
    let (file, line, func) = here!("channel::unlock");
    sys::__ao2_unlock(chan.cast(), file, func, line, c"chan".as_ptr());
}

/// `ast_channel_name` (copied; "" for NULL).
///
/// # Safety
/// `chan` must be NULL or a live channel.
pub unsafe fn name(chan: *const AstChannel) -> Vec<u8> {
    if chan.is_null() {
        return Vec::new();
    }
    from_ptr(sys::ast_channel_name(chan)).unwrap_or_default()
}

/// `ast_channel_tech(chan)->type`: the channel technology's name (e.g.,
/// "PJSIP"), "" without a technology.
///
/// # Safety
/// `chan` must be a live channel.
pub unsafe fn tech_type(chan: *const AstChannel) -> Vec<u8> {
    let tech = sys::ast_channel_tech(chan);
    if tech.is_null() {
        return Vec::new();
    }
    from_ptr((*tech).type_).unwrap_or_default()
}

/// `pbx_builtin_setvar_helper(chan, name, value)`: set a variable, or
/// write a dialplan function when `name` is one (e.g., `PJSIP_HEADER(...)`).
///
/// # Safety
/// `chan` must be NULL or a live channel.
pub unsafe fn setvar(chan: *mut AstChannel, name: &str, value: &[u8]) -> c_int {
    let (name, value) = (cstr(name), c_bytes(value));
    sys::pbx_builtin_setvar_helper(chan, name.as_ptr(), value.as_ptr())
}

/// `AST_STATE_UP`.
pub const STATE_UP: i32 = sys::AST_STATE_UP as i32;

/// `ast_channel_state(chan)` (`enum ast_channel_state`).
///
/// # Safety
/// `chan` must be a live channel.
pub unsafe fn state(chan: *const AstChannel) -> i32 {
    sys::ast_channel_state(chan) as i32
}

/// `ast_answer(chan)`: 0 on success.
///
/// # Safety
/// `chan` must be a live channel the caller is running on.
pub unsafe fn answer(chan: *mut AstChannel) -> i32 {
    sys::ast_answer(chan)
}

/// `ast_channel_creationtime(chan)`.
///
/// # Safety
/// `chan` must be a live channel, locked by the caller.
pub unsafe fn creationtime(chan: *mut AstChannel) -> sys::timeval {
    sys::ast_channel_creationtime(chan)
}

/// The name and number of a channel's caller or connected line, as
/// `struct ast_party_id` holds them.
#[derive(Debug, Clone, Default)]
pub struct Party {
    /// `(number.presentation & AST_PRES_RESTRICTION) == AST_PRES_RESTRICTED`.
    pub number_restricted: bool,
    pub number_valid: bool,
    pub number: Option<Vec<u8>>,
    /// As `number_restricted`, for the name.
    pub name_restricted: bool,
    pub name_valid: bool,
    pub name: Option<Vec<u8>>,
}

unsafe fn party(id: &sys::ast_party_id) -> Party {
    let restricted = |presentation: c_int| {
        (presentation as u32 & sys::AST_PRES_RESTRICTION) == sys::AST_PRES_RESTRICTED
    };
    Party {
        number_restricted: restricted(id.number.presentation),
        number_valid: id.number.valid != 0,
        number: from_ptr(id.number.str_),
        name_restricted: restricted(id.name.presentation),
        name_valid: id.name.valid != 0,
        name: from_ptr(id.name.str_),
    }
}

/// The caller party (`ast_channel_caller(chan)->id`).
///
/// # Safety
/// `chan` must be a live channel, locked by the caller.
pub unsafe fn caller(chan: *mut AstChannel) -> Party {
    party(&(*sys::ast_channel_caller(chan)).id)
}

/// The connected line party (`ast_channel_connected(chan)->id`).
///
/// # Safety
/// `chan` must be a live channel, locked by the caller.
pub unsafe fn connected(chan: *mut AstChannel) -> Party {
    party(&(*sys::ast_channel_connected(chan)).id)
}

/// An owned channel reference, dropped with `ast_channel_unref`.
pub struct Channel(*mut AstChannel);

// SAFETY: a channel is a reference-counted ao2 object; the wrapper only
// holds the reference, and the channel API locks the channel itself.
unsafe impl Send for Channel {}

impl Channel {
    /// Take over a reference the caller holds.
    ///
    /// # Safety
    /// `chan` must be NULL or a channel reference the caller owns.
    pub unsafe fn from_raw(chan: *mut AstChannel) -> Option<Channel> {
        (!chan.is_null()).then_some(Channel(chan))
    }

    /// `ast_channel_get_by_name(name)`.
    pub fn get_by_name(name: &[u8]) -> Option<Channel> {
        let n = cstr(name);
        // SAFETY: returns a new reference or NULL.
        unsafe { Channel::from_raw(sys::ast_channel_get_by_name(n.as_ptr())) }
    }

    /// The first channel whose name starts with `prefix` (case
    /// insensitive, as Asterisk's by-name iterator compares) and whose
    /// technology's `get_pvt_uniqueid` equals `callid`
    /// (`find_channel_by_callid_tech`; for PJSIP the SIP Call-ID).
    pub fn find_by_callid(prefix: &[u8], callid: &[u8]) -> Option<Channel> {
        if prefix.is_empty() {
            return None;
        }
        let p = cstr(prefix);
        // SAFETY: the iterator hands out channel references, each locked
        // while its technology is asked for the call id and released
        // unless it is the one returned.
        unsafe {
            let iter = sys::ast_channel_iterator_by_name_new(p.as_ptr(), p.as_bytes().len());
            if iter.is_null() {
                return None;
            }
            let mut found = None;
            loop {
                let chan = sys::ast_channel_iterator_next(iter);
                if chan.is_null() {
                    break;
                }
                lock(chan);
                let tech = sys::ast_channel_tech(chan);
                let matches = !tech.is_null()
                    && (*tech).get_pvt_uniqueid.is_some_and(|f| {
                        let id = f(chan);
                        !id.is_null()
                            && std::ffi::CStr::from_ptr(id).to_bytes()
                                == crate::dpma_bytes::c_view(callid)
                    });
                unlock(chan);
                if matches {
                    found = Some(Channel(chan));
                    break;
                }
                crate::ao2::cleanup(chan);
            }
            sys::ast_channel_iterator_destroy(iter);
            found
        }
    }

    /// The channel's name and unique id, read under its lock.
    pub fn name_and_uniqueid(&self) -> (Vec<u8>, Vec<u8>) {
        // SAFETY: we hold a reference; the strings are copied under the
        // channel lock.
        unsafe {
            lock(self.0);
            let name = from_ptr(sys::ast_channel_name(self.0)).unwrap_or_default();
            let uid = from_ptr(sys::ast_channel_uniqueid(self.0)).unwrap_or_default();
            unlock(self.0);
            (name, uid)
        }
    }

    pub fn as_ptr(&self) -> *mut AstChannel {
        self.0
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        // SAFETY: the reference this wrapper owns.
        unsafe { crate::ao2::cleanup(self.0) };
    }
}

/// The creation time (seconds since the epoch) of the first channel whose
/// `MEMBERINTERFACE` equals `interface` (case insensitive; unset counts as
/// "") and whose `QUEUEPOSITION` is unset or empty: the queue member's leg
/// of a queue call (the scan in `handle_request_json_queue_gettodaysstatus`).
pub fn queue_member_call_created(interface: &[u8]) -> Option<i64> {
    let interface = crate::dpma_bytes::c_view(interface);
    // SAFETY: as in `find_by_callid`; the variables are read under the
    // channel lock.
    unsafe {
        let iter = sys::ast_channel_iterator_all_new();
        if iter.is_null() {
            return None;
        }
        let mut found = None;
        loop {
            let chan = sys::ast_channel_iterator_next(iter);
            if chan.is_null() {
                break;
            }
            lock(chan);
            let member = bytes_or_empty(sys::pbx_builtin_getvar_helper(
                chan,
                c"MEMBERINTERFACE".as_ptr(),
            ));
            if crate::dpma_bytes::eq_ic(member, interface) {
                let position = sys::pbx_builtin_getvar_helper(chan, c"QUEUEPOSITION".as_ptr());
                if crate::util::strlen_zero(position) {
                    found = Some(creationtime(chan).tv_sec as i64);
                }
            }
            unlock(chan);
            crate::ao2::cleanup(chan);
            if found.is_some() {
                break;
            }
        }
        sys::ast_channel_iterator_destroy(iter);
        found
    }
}
