//! Configuration file hooks (`ast_config_hook_register`).
//!
//! Asterisk calls a hook whenever a module loads the hooked file; the hook
//! receives a private copy of the parsed configuration.  Hook callbacks
//! carry no user data, so there is a fixed number of slots, each an
//! `extern "C"` function that forwards to the Rust hook registered in it.

use crate::config::{copy_config, is_loaded, Category};
use crate::sys;
use crate::types::AstConfig;
use crate::util::cstr;
use std::os::raw::c_int;
use std::sync::Mutex;

pub type HookFn = fn(Option<Vec<Category>>);

struct Slot {
    name: String,
    f: HookFn,
}

const SLOTS: usize = 8;

static HOOKS: Mutex<[Option<Slot>; SLOTS]> = Mutex::new([const { None }; SLOTS]);

/// Run the hook in `slot` with `cfg` (a copy the hook owns).
unsafe fn run(slot: usize, cfg: *mut AstConfig) {
    crate::guard((), || {
        let cats = if is_loaded(cfg) {
            // SAFETY: a loaded configuration Asterisk handed over.
            let c = copy_config(cfg);
            sys::ast_config_destroy(cfg);
            Some(c)
        } else {
            None
        };
        let f = HOOKS.lock().unwrap_or_else(|e| e.into_inner())[slot].as_ref().map(|s| s.f);
        if let Some(f) = f {
            f(cats);
        }
    })
}

macro_rules! slots {
    ($($n:literal => $f:ident),*) => {
        $(
            unsafe extern "C" fn $f(cfg: *mut AstConfig) -> c_int {
                run($n, cfg);
                0
            }
        )*
        const SLOT_FNS: [unsafe extern "C" fn(*mut AstConfig) -> c_int; SLOTS] = [$($f),*];
    };
}

slots!(0 => hook0, 1 => hook1, 2 => hook2, 3 => hook3, 4 => hook4, 5 => hook5, 6 => hook6, 7 => hook7);

/// Register `f` to be called when `module` loads `filename`.
pub fn register(name: &str, filename: &str, module: &str, f: HookFn) -> bool {
    let slot = {
        let mut slots = HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let Some(i) = slots.iter().position(Option::is_none) else {
            return false;
        };
        slots[i] = Some(Slot { name: name.into(), f });
        i
    };
    let (n, fname, m) = (cstr(name), cstr(filename), cstr(module));
    // SAFETY: Asterisk copies the strings; the slot function stays valid
    // until `unregister`.
    unsafe {
        sys::ast_config_hook_register(n.as_ptr(), fname.as_ptr(), m.as_ptr(), 0, Some(SLOT_FNS[slot])) == 0
    }
}

pub fn unregister(name: &str) {
    let n = cstr(name);
    // SAFETY: a valid C string.
    unsafe { sys::ast_config_hook_unregister(n.as_ptr()) };
    let mut slots = HOOKS.lock().unwrap_or_else(|e| e.into_inner());
    for s in slots.iter_mut() {
        if s.as_ref().is_some_and(|s| s.name == name) {
            *s = None;
        }
    }
}
