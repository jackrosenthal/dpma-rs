//! The PJSIP side of the module: what the official DPMA ships as helper
//! modules, loaded after and unloaded before the rest of the module, as
//! Asterisk loads and unloads those helpers.
//!
//! The helpers talked to res_digium_phone through its exported C API.
//! Here they are plain Rust calls, each active between the identifier
//! side's registration and its cleanup, as the official DPMA's
//! registrations were; outside that window they behave as the official
//! DPMA does with nothing registered.  The registries' locks are kept: a
//! processing pass holds the config handler lock while the PJSIP lines
//! pass runs, and an INFO is sent under the info handler lock, so
//! unloading waits for both.

pub mod dialog_info;
pub mod identifier;

#[cfg(feature = "devtest")]
pub mod devtest;

use dpma_ast::sys;
use dpma_ast::types::AstChannel;
use dpma_ast::{dpma_bytes, dpma_log};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

/// The config handler (`pjsip_process_lines`) is registered.  Written
/// under the list's write lock, which a pass holds while it runs.
static CONFIG_HANDLER: RwLock<bool> = RwLock::new(false);
/// The "PJSIP" info handler is registered.
static INFO_HANDLER: RwLock<bool> = RwLock::new(false);
/// `pjsip_endpoint_is_dphone` is registered (no lock, as in the official
/// DPMA).
static IS_DPHONE: AtomicBool = AtomicBool::new(false);

fn set(lock: &RwLock<bool>, value: bool) {
    *lock.write().unwrap_or_else(|e| e.into_inner()) = value;
}

/// `dpma_register_config_handler` (`true`) and
/// `dpma_unregister_config_handler` (`false`).
fn set_config_handler(registered: bool) {
    set(&CONFIG_HANDLER, registered);
}

/// `dpma_register_info_handler` (`true`) and
/// `dpma_unregister_info_handler` (`false`).
fn set_info_handler(registered: bool) {
    set(&INFO_HANDLER, registered);
}

/// `dpma_register_pjsip_endpoint_is_dphone`: false (and a log) when it is
/// registered already.
fn register_is_dphone() -> bool {
    if IS_DPHONE.swap(true, Ordering::SeqCst) {
        dpma_log!("Attempted to register dpma_pjsip_endpoint_is_dphone, but the function is already registerd.");
        return false;
    }
    true
}

/// `dpma_unregister_pjsip_endpoint_is_dphone`.
fn unregister_is_dphone() {
    IS_DPHONE.store(false, Ordering::SeqCst);
}

/// `load_module` of both helpers, in their load order: AST_MODULE_LOAD_*
/// (the identifier fails with AST_MODULE_LOAD_FAILURE, as in the official
/// DPMA, when there is no default outbound endpoint; the supplement
/// declines when it cannot register).
pub fn load() -> sys::ast_module_load_result {
    let res = identifier::load();
    if res != sys::AST_MODULE_LOAD_SUCCESS {
        return res;
    }
    let res = dialog_info::load();
    if res != sys::AST_MODULE_LOAD_SUCCESS {
        identifier::unload();
    }
    res
}

/// `unload_module` of both helpers.
pub fn unload() {
    dialog_info::unload();
    identifier::unload();
}

/// `dpma_process_config_handlers`, run by every processing pass of the
/// phone configuration (`users::load::process`): the PJSIP lines pass, if
/// registered, with the list's write lock held as the official DPMA does.
pub fn process_lines() {
    let registered = CONFIG_HANDLER.write().unwrap_or_else(|e| e.into_inner());
    if *registered {
        identifier::process_lines();
    }
}

/// `dpma_info_send(chan, headers, content_type, body, NULL)`: send a SIP
/// INFO on `chan` with extra `headers`, `content_type`, and `body` (empty
/// ones are left out).  -1 when the channel's technology is not PJSIP (no
/// handler for it), else the result of the PJSIP send (0 when sent).
///
/// # Safety
/// `chan` must be a live channel the caller holds a reference on.
pub unsafe fn info_send(
    chan: *mut AstChannel,
    headers: &[(&str, &str)],
    content_type: &str,
    body: &[u8],
) -> i32 {
    let registered = INFO_HANDLER.read().unwrap_or_else(|e| e.into_inner());
    if !*registered || !dpma_bytes::eq_ic(&dpma_ast::channel::tech_type(chan), b"PJSIP") {
        return -1;
    }
    identifier::send_info(chan, headers, content_type.as_bytes(), body)
}

/// `dpma_pjsip_endpoint_is_dphone(endpoint)`: 1 when one of the endpoint's
/// AORs has a contact registered by a Digium or Sangoma phone; 0 (and a
/// log) when the function is not registered.
pub fn endpoint_is_dphone(endpoint: &[u8]) -> i32 {
    if IS_DPHONE.load(Ordering::SeqCst) {
        return identifier::endpoint_is_dphone(endpoint);
    }
    dpma_log!("dpma_pjsip_endpoint_is_dphone was invoked but the function is unregistered.");
    0
}
