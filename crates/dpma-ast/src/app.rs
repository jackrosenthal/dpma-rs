//! Dialplan applications: registration (`ast_register_application2`),
//! argument and option parsing (`__ast_app_separate_args`,
//! `ast_app_parse_options`), and controlled playback
//! (`ast_control_streamfile`, `ast_control_streamfile_w_cb`).
//!
//! Strings are passed as bytes (dialplan data need not be UTF-8) and cut
//! at their first NUL byte, as C would see them.

use crate::sys;
use crate::types::AstChannel;
use crate::vm::c_bytes;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_long, c_uint};
use std::ptr;

/// An application's `execute` callback.
pub type ExecFn = unsafe extern "C" fn(chan: *mut AstChannel, data: *const c_char) -> c_int;

/// `ast_waitstream_fr_cb`: called by the playback functions with the
/// position in milliseconds and one of the `WAITSTREAM_CB_*` values.
pub type WaitstreamFrCb = unsafe extern "C" fn(chan: *mut AstChannel, ms: c_long, val: sys::ast_waitstream_fr_cb_values);

/// `AST_WAITSTREAM_CB_REWIND`.
pub const WAITSTREAM_CB_REWIND: sys::ast_waitstream_fr_cb_values = sys::AST_WAITSTREAM_CB_REWIND;
/// `AST_WAITSTREAM_CB_FASTFORWARD`.
pub const WAITSTREAM_CB_FASTFORWARD: sys::ast_waitstream_fr_cb_values = sys::AST_WAITSTREAM_CB_FASTFORWARD;
/// `AST_WAITSTREAM_CB_START`.
pub const WAITSTREAM_CB_START: sys::ast_waitstream_fr_cb_values = sys::AST_WAITSTREAM_CB_START;

/// An option table as `AST_APP_OPTIONS` declares it: one
/// `struct ast_app_option` per option letter (128).
#[repr(C)]
pub struct AppOptions(pub [sys::ast_app_option; 128]);

impl AppOptions {
    /// An empty table.
    pub const fn new() -> AppOptions {
        AppOptions([sys::ast_app_option { flag: 0, arg_index: 0 }; 128])
    }

    /// `AST_APP_OPTION(letter, flag)`.
    pub const fn option(mut self, letter: u8, flag: u64) -> AppOptions {
        self.0[(letter & 0x7f) as usize] = sys::ast_app_option { flag, arg_index: 0 };
        self
    }

    /// `AST_APP_OPTION_ARG(letter, flag, argno)`: the option's argument goes
    /// to slot `argno` of the argument array.
    pub const fn option_arg(mut self, letter: u8, flag: u64, argno: u32) -> AppOptions {
        self.0[(letter & 0x7f) as usize] = sys::ast_app_option { flag, arg_index: argno + 1 };
        self
    }
}

impl Default for AppOptions {
    fn default() -> Self {
        AppOptions::new()
    }
}

/// `ast_register_application2(name, execute, NULL, NULL, NULL)`: register
/// an application with no synopsis, description, or owning module.
/// Returns 0 on success, -1 when the name is taken.
pub fn register(name: &str, execute: ExecFn) -> i32 {
    let n = crate::cstr(name);
    // SAFETY: Asterisk copies the name; the application is unregistered at
    // unload.
    unsafe { sys::ast_register_application2(n.as_ptr(), Some(execute), ptr::null(), ptr::null(), ptr::null_mut()) }
}

/// `ast_unregister_application(name)`.
pub fn unregister(name: &str) -> i32 {
    let n = crate::cstr(name);
    // SAFETY: a valid C string.
    unsafe { sys::ast_unregister_application(n.as_ptr()) }
}

/// A NUL-terminated, writable copy of `s` (cut at its first NUL).
fn buffer(s: &[u8]) -> Vec<u8> {
    let mut b = c_bytes(s).into_bytes_with_nul();
    b.shrink_to_fit();
    b
}

/// Copy out the strings an argument array points at.
unsafe fn collect(array: &[*mut c_char]) -> Vec<Option<Vec<u8>>> {
    array.iter().map(|&p| (!p.is_null()).then(|| CStr::from_ptr(p).to_bytes().to_vec())).collect()
}

/// `__ast_app_separate_args` on a copy of `data` (what
/// `AST_STANDARD_APP_ARGS` does with `remove_chars` set): the argument
/// count and `n` argument slots, None for the arguments not given.
pub fn separate_args(data: &[u8], delim: u8, remove_chars: bool, n: usize) -> (u32, Vec<Option<Vec<u8>>>) {
    let mut buf = buffer(data);
    let mut array: Vec<*mut c_char> = vec![ptr::null_mut(); n];
    unsafe {
        let argc = sys::__ast_app_separate_args(
            buf.as_mut_ptr() as *mut c_char,
            delim as c_char,
            c_int::from(remove_chars),
            array.as_mut_ptr(),
            n as c_int,
        );
        (argc, collect(&array))
    }
}

/// `ast_app_parse_options(options, &flags, args, optstr)` on a copy of
/// `optstr`: the result, the flags, and `nargs` option argument slots
/// (None for the ones not set).
pub fn parse_options(options: &AppOptions, optstr: &[u8], nargs: usize) -> (i32, u32, Vec<Option<Vec<u8>>>) {
    let mut buf = buffer(optstr);
    let mut args: Vec<*mut c_char> = vec![ptr::null_mut(); nargs.max(1)];
    let mut flags = sys::ast_flags { flags: 0 };
    unsafe {
        let res =
            sys::ast_app_parse_options(options.0.as_ptr(), &mut flags, args.as_mut_ptr(), buf.as_mut_ptr() as *mut c_char);
        let mut out = collect(&args);
        out.truncate(nargs);
        (res, flags.flags as c_uint, out)
    }
}

fn opt_c(s: Option<&[u8]>) -> Option<CString> {
    s.map(c_bytes)
}

fn opt_ptr(c: &Option<CString>) -> *const c_char {
    c.as_ref().map_or(ptr::null(), |c| c.as_ptr())
}

/// `ast_control_streamfile` (no `cb`) or `ast_control_streamfile_w_cb`:
/// play `file` with the given control keys (None is NULL).  `offsetms`
/// is the start position on entry and where playback stopped on return.
/// Returns the key that ended playback, 0, or -1.
///
/// # Safety
/// `chan` must be a live channel the caller is running on.
#[allow(clippy::too_many_arguments)]
pub unsafe fn control_streamfile(
    chan: *mut AstChannel,
    file: &[u8],
    fwd: Option<&[u8]>,
    rev: Option<&[u8]>,
    stop: Option<&[u8]>,
    pause: Option<&[u8]>,
    restart: Option<&[u8]>,
    skipms: i32,
    offsetms: &mut c_long,
    cb: Option<WaitstreamFrCb>,
) -> i32 {
    let file = c_bytes(file);
    let (fwd, rev, stop) = (opt_c(fwd), opt_c(rev), opt_c(stop));
    let (pause, restart) = (opt_c(pause), opt_c(restart));
    match cb {
        None => sys::ast_control_streamfile(
            chan,
            file.as_ptr(),
            opt_ptr(&fwd),
            opt_ptr(&rev),
            opt_ptr(&stop),
            opt_ptr(&pause),
            opt_ptr(&restart),
            skipms,
            offsetms,
        ),
        Some(_) => sys::ast_control_streamfile_w_cb(
            chan,
            file.as_ptr(),
            opt_ptr(&fwd),
            opt_ptr(&rev),
            opt_ptr(&stop),
            opt_ptr(&pause),
            opt_ptr(&restart),
            skipms,
            offsetms,
            cb,
        ),
    }
}
