//! Outbound dialing (`ast_dial_*`), plus the thread helper that goes with
//! it (`ast_pthread_create_detached_stack`).
//!
//! A dial is a raw pointer whose ownership the caller manages, because the
//! original hands it to a detached thread that runs and destroys it.

use crate::sys;
use crate::vm::c_bytes;
use std::os::raw::{c_int, c_void};
use std::ptr;

/// `struct ast_dial`.
pub type AstDial = sys::ast_dial;

/// `AST_DIAL_OPTION_ANSWER_EXEC`: run "app,args" on the answered channel.
pub const OPTION_ANSWER_EXEC: sys::ast_dial_option = sys::AST_DIAL_OPTION_ANSWER_EXEC;

/// `AST_DIAL_RESULT_ANSWERED`.
pub const RESULT_ANSWERED: c_int = sys::AST_DIAL_RESULT_ANSWERED as c_int;

/// A thread start routine.
pub type StartFn = unsafe extern "C" fn(data: *mut c_void) -> *mut c_void;

/// `ast_dial_create`.
pub fn create() -> *mut AstDial {
    unsafe { sys::ast_dial_create() }
}

/// `ast_dial_append(dial, tech, device, NULL)`.
///
/// # Safety
/// `dial` must be NULL or a live dial.
pub unsafe fn append(dial: *mut AstDial, tech: &[u8], device: &[u8]) -> c_int {
    let (tech, device) = (c_bytes(tech), c_bytes(device));
    sys::ast_dial_append(dial, tech.as_ptr(), device.as_ptr(), ptr::null())
}

/// `ast_dial_prerun(dial, NULL, NULL)`: request the channels.
///
/// # Safety
/// `dial` must be NULL or a live dial.
pub unsafe fn prerun(dial: *mut AstDial) -> c_int {
    sys::ast_dial_prerun(dial, ptr::null_mut(), ptr::null_mut())
}

/// `ast_dial_run(dial, NULL, async)`.
///
/// # Safety
/// `dial` must be a live dial.
pub unsafe fn run(dial: *mut AstDial, async_: bool) -> c_int {
    sys::ast_dial_run(dial, ptr::null_mut(), async_ as c_int) as c_int
}

/// `ast_dial_get_channel` (borrowed).
///
/// # Safety
/// `dial` must be NULL or a live dial.
pub unsafe fn get_channel(dial: *mut AstDial, num: c_int) -> *mut sys::ast_channel {
    sys::ast_dial_get_channel(dial, num)
}

/// # Safety
/// `dial` must be a live dial.
pub unsafe fn set_user_data(dial: *mut AstDial, data: *mut c_void) {
    sys::ast_dial_set_user_data(dial, data)
}

/// # Safety
/// `dial` must be a live dial.
pub unsafe fn get_user_data(dial: *mut AstDial) -> *mut c_void {
    sys::ast_dial_get_user_data(dial)
}

/// `ast_dial_option_global_enable` with a string argument (copied by the
/// option's enable callback).
///
/// # Safety
/// `dial` must be a live dial.
pub unsafe fn option_global_enable(dial: *mut AstDial, option: sys::ast_dial_option, data: &[u8]) -> c_int {
    let data = c_bytes(data);
    sys::ast_dial_option_global_enable(dial, option, data.as_ptr() as *mut c_void)
}

/// `ast_dial_destroy`.
///
/// # Safety
/// `dial` must be NULL or a live dial, not used afterwards.
pub unsafe fn destroy(dial: *mut AstDial) -> c_int {
    sys::ast_dial_destroy(dial)
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
    let mut thread: sys::pthread_t = 0;
    sys::ast_pthread_create_detached_stack(
        &mut thread,
        ptr::null_mut(),
        Some(start),
        data,
        0,
        file.as_ptr(),
        caller.as_ptr(),
        line as c_int,
        start_fn.as_ptr(),
    )
}
