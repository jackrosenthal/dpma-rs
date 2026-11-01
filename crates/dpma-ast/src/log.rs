//! Logging helpers.
//!
//! The original module logs most of its activity to a custom logger level
//! named "DPMA"; the same level is registered here so that existing
//! logger.conf setups keep working.

use crate::ffi;
use crate::util::cstr;
use std::sync::atomic::{AtomicI32, Ordering};

pub const LOG_DEBUG: i32 = 0;
pub const LOG_NOTICE: i32 = 2;
pub const LOG_WARNING: i32 = 3;
pub const LOG_ERROR: i32 = 4;
pub const LOG_VERBOSE: i32 = 5;

static CUSTOM_LEVEL: AtomicI32 = AtomicI32::new(LOG_NOTICE);

/// Register a custom logger level and use it for `dpma_log!`.
pub fn register_custom_level(name: &str) -> bool {
    let c = cstr(name);
    let level = unsafe { ffi::ast_logger_register_level(c.as_ptr()) };
    if level < 0 {
        return false;
    }
    CUSTOM_LEVEL.store(level, Ordering::SeqCst);
    true
}

pub fn unregister_custom_level(name: &str) {
    let c = cstr(name);
    unsafe { ffi::ast_logger_unregister_level(c.as_ptr()) };
    CUSTOM_LEVEL.store(LOG_NOTICE, Ordering::SeqCst);
}

pub fn custom_level() -> i32 {
    CUSTOM_LEVEL.load(Ordering::Relaxed)
}

pub fn log(level: i32, file: &str, line: u32, func: &str, msg: &str) {
    let file = cstr(file.rsplit('/').next().unwrap_or(file));
    let func = cstr(func);
    let msg = cstr(msg);
    unsafe { ffi::dpma_glue_log(level, file.as_ptr(), line as i32, func.as_ptr(), msg.as_ptr()) };
}

pub fn debug_atleast(level: i32) -> bool {
    unsafe { ffi::dpma_glue_debug_atleast(level) != 0 }
}

extern "C" {
    static ast_verb_sys_level: std::os::raw::c_int;
}

/// `ast_verb_sys_level`: the highest verbosity of any console or logger
/// channel (what `VERBOSITY_ATLEAST` tests).
pub fn verb_sys_level() -> i32 {
    unsafe { std::ptr::addr_of!(ast_verb_sys_level).read_volatile() }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __func {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        let mut name = name.strip_suffix("::f").unwrap_or(name);
        while let Some(n) = name.strip_suffix("::{{closure}}") {
            name = n;
        }
        name.rsplit("::").next().unwrap_or(name)
    }};
}

/// Log at an explicit Asterisk level. A trailing newline is added.
#[macro_export]
macro_rules! ast_log {
    ($level:expr, $($arg:tt)*) => {
        $crate::log::log($level, file!(), line!(), $crate::__func!(), &format!("{}\n", format_args!($($arg)*)))
    };
}

/// Log to the module's custom "DPMA" logger level.
#[macro_export]
macro_rules! dpma_log {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::custom_level(), file!(), line!(), $crate::__func!(), &format!("{}\n", format_args!($($arg)*)))
    };
}

/// Debug log, emitted when core or module debug is at least `level`.
#[macro_export]
macro_rules! ast_debug {
    ($level:expr, $($arg:tt)*) => {
        if $crate::log::debug_atleast($level) {
            $crate::log::log($crate::log::LOG_DEBUG, file!(), line!(), $crate::__func!(), &format!("{}\n", format_args!($($arg)*)))
        }
    };
}

/// Debug log routed to the custom DPMA level (the original module does this).
#[macro_export]
macro_rules! dpma_debug {
    ($level:expr, $($arg:tt)*) => {
        if $crate::log::debug_atleast($level) {
            $crate::log::log($crate::log::custom_level(), file!(), line!(), $crate::__func!(), &format!("{}\n", format_args!($($arg)*)))
        }
    };
}
