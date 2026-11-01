//! Outbound dialing (`ast_dial_*`), plus the channel and thread helpers
//! that go with it: `ast_channel_name`, `pbx_builtin_setvar_helper`, and
//! `ast_pthread_create_detached_stack`.
//!
//! A dial is a raw pointer whose ownership the caller manages, because the
//! original hands it to a detached thread that runs and destroys it.

use crate::types::AstChannel;
use crate::vm::c_bytes;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

/// Opaque `struct ast_dial`.
#[repr(C)]
pub struct AstDial {
    _private: [u8; 0],
}

/// `AST_DIAL_OPTION_ANSWER_EXEC`: run "app,args" on the answered channel.
pub const OPTION_ANSWER_EXEC: c_int = 1;

/// `AST_DIAL_RESULT_ANSWERED`.
pub const RESULT_ANSWERED: c_int = 6;

/// A thread start routine.
pub type StartFn = unsafe extern "C" fn(data: *mut c_void) -> *mut c_void;

extern "C" {
    fn ast_dial_create() -> *mut AstDial;
    fn ast_dial_append(dial: *mut AstDial, tech: *const c_char, device: *const c_char, assignedids: *const c_void) -> c_int;
    fn ast_dial_prerun(dial: *mut AstDial, chan: *mut AstChannel, cap: *mut c_void) -> c_int;
    fn ast_dial_run(dial: *mut AstDial, chan: *mut AstChannel, async_: c_int) -> c_int;
    fn ast_dial_get_channel(dial: *mut AstDial, num: c_int) -> *mut AstChannel;
    fn ast_dial_set_user_data(dial: *mut AstDial, user_data: *mut c_void);
    fn ast_dial_get_user_data(dial: *mut AstDial) -> *mut c_void;
    fn ast_dial_option_global_enable(dial: *mut AstDial, option: c_int, data: *mut c_void) -> c_int;
    fn ast_dial_destroy(dial: *mut AstDial) -> c_int;
    fn ast_channel_name(chan: *const AstChannel) -> *const c_char;
    fn pbx_builtin_setvar_helper(chan: *mut AstChannel, name: *const c_char, value: *const c_char) -> c_int;
    fn ast_pthread_create_detached_stack(
        thread: *mut libc_pthread_t,
        attr: *mut c_void,
        start_routine: StartFn,
        data: *mut c_void,
        stacksize: usize,
        file: *const c_char,
        caller: *const c_char,
        line: c_int,
        start_fn: *const c_char,
    ) -> c_int;
}

/// `pthread_t` on the supported (Linux) targets.
#[allow(non_camel_case_types)]
type libc_pthread_t = std::os::raw::c_ulong;

/// `ast_dial_create`.
pub fn create() -> *mut AstDial {
    unsafe { ast_dial_create() }
}

/// `ast_dial_append(dial, tech, device, NULL)`.
///
/// # Safety
/// `dial` must be NULL or a live dial.
pub unsafe fn append(dial: *mut AstDial, tech: &[u8], device: &[u8]) -> c_int {
    let (tech, device) = (c_bytes(tech), c_bytes(device));
    ast_dial_append(dial, tech.as_ptr(), device.as_ptr(), ptr::null())
}

/// `ast_dial_prerun(dial, NULL, NULL)`: request the channels.
///
/// # Safety
/// `dial` must be NULL or a live dial.
pub unsafe fn prerun(dial: *mut AstDial) -> c_int {
    ast_dial_prerun(dial, ptr::null_mut(), ptr::null_mut())
}

/// `ast_dial_run(dial, NULL, async)`.
///
/// # Safety
/// `dial` must be a live dial.
pub unsafe fn run(dial: *mut AstDial, async_: bool) -> c_int {
    ast_dial_run(dial, ptr::null_mut(), async_ as c_int)
}

/// `ast_dial_get_channel` (borrowed).
///
/// # Safety
/// `dial` must be NULL or a live dial.
pub unsafe fn get_channel(dial: *mut AstDial, num: c_int) -> *mut AstChannel {
    ast_dial_get_channel(dial, num)
}

/// # Safety
/// `dial` must be a live dial.
pub unsafe fn set_user_data(dial: *mut AstDial, data: *mut c_void) {
    ast_dial_set_user_data(dial, data)
}

/// # Safety
/// `dial` must be a live dial.
pub unsafe fn get_user_data(dial: *mut AstDial) -> *mut c_void {
    ast_dial_get_user_data(dial)
}

/// `ast_dial_option_global_enable` with a string argument (copied by the
/// option's enable callback).
///
/// # Safety
/// `dial` must be a live dial.
pub unsafe fn option_global_enable(dial: *mut AstDial, option: c_int, data: &[u8]) -> c_int {
    let data = c_bytes(data);
    ast_dial_option_global_enable(dial, option, data.as_ptr() as *mut c_void)
}

/// `ast_dial_destroy`.
///
/// # Safety
/// `dial` must be NULL or a live dial, not used afterwards.
pub unsafe fn destroy(dial: *mut AstDial) -> c_int {
    ast_dial_destroy(dial)
}

/// `ast_channel_name` (copied; "" for NULL).
///
/// # Safety
/// `chan` must be NULL or a live channel.
pub unsafe fn channel_name(chan: *const AstChannel) -> String {
    if chan.is_null() {
        return String::new();
    }
    let p = ast_channel_name(chan);
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// `pbx_builtin_setvar_helper(chan, name, value)`: set a variable, or
/// write a dialplan function when `name` is one (e.g., `PJSIP_HEADER(...)`).
///
/// # Safety
/// `chan` must be NULL or a live channel.
pub unsafe fn setvar(chan: *mut AstChannel, name: &str, value: &[u8]) -> c_int {
    let (name, value) = (crate::cstr(name), c_bytes(value));
    pbx_builtin_setvar_helper(chan, name.as_ptr(), value.as_ptr())
}

/// `ast_pthread_create_detached_stack` with the default stack size: start
/// a detached, Asterisk-registered thread running `start(data)`.  `file`,
/// `caller`, `line`, and `start_fn` are what `core show threads` shows.
/// Returns 0 on success.
///
/// # Safety
/// `start` must be safe to run with `data` on another thread.
pub unsafe fn spawn_detached(start: StartFn, data: *mut c_void, file: &str, caller: &str, line: i32, start_fn: &str) -> c_int {
    let (file, caller, start_fn) = (crate::cstr(file), crate::cstr(caller), crate::cstr(start_fn));
    let mut thread: libc_pthread_t = 0;
    ast_pthread_create_detached_stack(
        &mut thread,
        ptr::null_mut(),
        start,
        data,
        0,
        file.as_ptr(),
        caller.as_ptr(),
        line as c_int,
        start_fn.as_ptr(),
    )
}
