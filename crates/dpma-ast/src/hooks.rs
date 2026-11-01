//! Configuration file hooks (`ast_config_hook_register`).
//!
//! Asterisk calls a hook whenever another module loads the hooked file; the
//! hook receives a private copy of the parsed configuration.

use crate::config::{copy_config, Category};
use crate::ffi;
use crate::types::AstConfig;
use crate::util::cstr;
use std::sync::Mutex;

pub type HookFn = fn(Option<Vec<Category>>);

struct Slot {
    name: String,
    f: HookFn,
}

static SLOTS: Mutex<Vec<Option<Slot>>> = Mutex::new(Vec::new());

/// Register `f` to be called when `module` loads `filename`.
pub fn register(name: &str, filename: &str, module: &str, f: HookFn) -> bool {
    let max = unsafe { ffi::dpma_glue_config_hook_slots() } as usize;
    let slot = {
        let mut slots = SLOTS.lock().unwrap();
        if slots.len() < max {
            slots.resize_with(max, || None);
        }
        match slots.iter().position(|s| s.is_none()) {
            Some(i) => {
                slots[i] = Some(Slot { name: name.into(), f });
                i
            }
            None => return false,
        }
    };
    let n = cstr(name);
    let fname = cstr(filename);
    let m = cstr(module);
    unsafe { ffi::dpma_glue_config_hook_register(slot as i32, n.as_ptr(), fname.as_ptr(), m.as_ptr()) == 0 }
}

pub fn unregister(name: &str) {
    let n = cstr(name);
    unsafe { ffi::ast_config_hook_unregister(n.as_ptr()) };
    let mut slots = SLOTS.lock().unwrap();
    for s in slots.iter_mut() {
        if s.as_ref().is_some_and(|s| s.name == name) {
            *s = None;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpma_rust_config_hook(slot: i32, cfg: *mut AstConfig) {
    crate::guard((), || {
        let cats = match ffi::dpma_glue_config_status(cfg) {
            3 => {
                let c = copy_config(cfg);
                ffi::ast_config_destroy(cfg);
                Some(c)
            }
            _ => None,
        };
        let f = SLOTS
            .lock()
            .unwrap()
            .get(slot as usize)
            .and_then(|s| s.as_ref().map(|s| s.f));
        if let Some(f) = f {
            f(cats);
        }
    })
}
