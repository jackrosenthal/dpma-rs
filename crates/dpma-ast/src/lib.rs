//! Thin, mostly safe Rust wrappers around the parts of the Asterisk C API
//! used by dpma-rs.
//!
//! The raw declarations (functions, structures, and constants) come from
//! the Asterisk and pjproject headers through `dpma-sys` (bindgen).  What
//! the headers provide as macros or static inline functions (`ao2_ref`,
//! `ast_free`, `ast_channel_lock`, `AST_MODULE_INFO`, ...) is reimplemented
//! here in Rust, next to the wrappers that need it: the `asterisk_module!`
//! macro in `module.rs`, the astobj2 macros in `ao2.rs`, the memory macros
//! in `util.rs`, and so on.
//!
//! Calls into C are `unsafe` at the boundary, each with the reason it is
//! sound; callbacks from C are `extern "C"` functions that run their Rust
//! code inside [`guard`] so a panic never unwinds into C.

#![allow(clippy::missing_safety_doc)]

pub mod ao2;
pub mod app;
pub mod astxml;
pub mod channel;
pub mod cli;
pub mod config;
pub mod db;
pub mod dial;
pub mod hooks;
pub mod json;
pub mod log;
pub mod manager;
pub mod module;
pub mod msg;
pub mod pbx;
pub mod presence;
pub mod sched;
pub mod stasis;
pub mod threadpool;
pub mod util;
pub mod vm;
pub mod xml;

pub use dpma_bytes;
pub use dpma_bytes::{bformat, bwrite, bwriteln};
pub use dpma_sys as sys;
pub use util::{cstr, from_ptr};

/// Short names for the Asterisk types the wrappers hand around.
pub mod types {
    pub use dpma_sys::{
        ast_channel as AstChannel, ast_config as AstConfig, ast_db_entry as AstDbEntry, ast_module as AstModule,
        ast_msg as AstMsg, ast_variable as AstVariable, mansession as Mansession, message as Message,
    };
}

/// Returns true once Asterisk has finished booting (`ast_fully_booted`).
pub fn fully_booted() -> bool {
    // SAFETY: `ast_options` is a plain global of the Asterisk binary; it is
    // read without a lock, as the `ast_fully_booted` macro does.
    let flags = unsafe { std::ptr::addr_of!(sys::ast_options).read_volatile() }.flags;
    flags & sys::AST_OPT_FLAG_FULLY_BOOTED as u64 != 0
}

/// The Asterisk variable data directory (normally /var/lib/asterisk).
pub fn var_dir() -> Vec<u8> {
    // SAFETY: set at startup to a string that lives as long as Asterisk.
    unsafe { from_ptr(std::ptr::addr_of!(sys::ast_config_AST_VAR_DIR).read()).unwrap_or_default() }
}

/// The Asterisk configuration directory (normally /etc/asterisk).
pub fn config_dir() -> Vec<u8> {
    // SAFETY: as in `var_dir`.
    unsafe { from_ptr(std::ptr::addr_of!(sys::ast_config_AST_CONFIG_DIR).read()).unwrap_or_default() }
}

/// Run `f`, catching any panic so it can never unwind into C.
pub fn guard<R>(default: R, f: impl FnOnce() -> R) -> R {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(e) => {
            let what = e
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            crate::log::log(
                crate::log::LOG_ERROR,
                file!(),
                line!(),
                "guard",
                format!("Internal error (panic): {}\n", what).as_bytes(),
            );
            default
        }
    }
}
