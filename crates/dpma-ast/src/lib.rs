//! Thin, mostly safe Rust wrappers around the parts of the Asterisk C API
//! used by the dpma-rs modules.
//!
//! Anything that depends on Asterisk macros or struct layouts is implemented
//! in C glue under `glue/` (every `*.c` there is compiled into every module
//! with that module's own `AST_MODULE` definition; see the `dpma-build`
//! crate).
//!
//! Raw declarations live in `ffi.rs` or in the per-area modules
//! (`threadpool.rs`, `ao2.rs`, ...); glue lives in `glue/common.c` or in a
//! per-area `glue/<area>.c`.

#![allow(clippy::missing_safety_doc)]

pub mod ao2;
pub mod app;
pub mod channel;
pub mod cli;
pub mod config;
pub mod db;
pub mod dial;
pub mod ffi;
pub mod hooks;
pub mod log;
pub mod manager;
pub mod msg;
pub mod pbx;
pub mod presence;
pub mod sched;
pub mod stasis;
pub mod threadpool;
pub mod util;
pub mod vm;
pub mod xml;

pub use util::{cstr, from_ptr};

/// Opaque Asterisk types.
pub mod types {
    macro_rules! opaque {
        ($($name:ident),*) => {
            $(
                #[repr(C)]
                pub struct $name {
                    _private: [u8; 0],
                }
            )*
        };
    }
    opaque!(
        AstConfig,
        AstVariable,
        AstMsg,
        AstDbEntry,
        Mansession,
        Message,
        AstChannel,
        AstModule
    );
}

/// Returns true once Asterisk has finished booting.
pub fn fully_booted() -> bool {
    unsafe { ffi::dpma_glue_fully_booted() != 0 }
}

/// The Asterisk variable data directory (normally /var/lib/asterisk).
pub fn var_dir() -> String {
    unsafe { from_ptr(ffi::dpma_glue_var_dir()).unwrap_or_default() }
}

/// The Asterisk configuration directory (normally /etc/asterisk).
pub fn config_dir() -> String {
    unsafe { from_ptr(ffi::dpma_glue_config_dir()).unwrap_or_default() }
}

/// Take a reference on the calling module.
pub fn module_ref() {
    unsafe { ffi::dpma_glue_module_ref() }
}

/// Release a reference on the calling module.
pub fn module_unref() {
    unsafe { ffi::dpma_glue_module_unref() }
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
                &format!("Internal error (panic): {}\n", what),
            );
            default
        }
    }
}
