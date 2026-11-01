//! res_digium_phone.c exports: config and info handler registries,
//! `dpma_info_send`, and the PJSIP "is a Digium phone" hook
//! (0x1476b0..0x147bb0).  `get_license_status` (0x147650) is deliberately
//! not exported: this rewrite has no license handling.
//!
//! Owner: P6 "exports" (wave 1).

use dpma_ast::types::{AstChannel, AstVariable};
use std::os::raw::{c_char, c_int, c_void};

/// `struct dpma_config_handler` (16 bytes): called with the lines
/// container whenever the phone users configuration is processed.
#[repr(C)]
pub struct DpmaConfigHandler {
    pub handler: Option<unsafe extern "C" fn(lines: *mut c_void)>,
    pub next: *mut DpmaConfigHandler,
}

/// The `send` callback of an info handler: send a SIP INFO on `chan` with
/// extra `headers`, `content_type`, and `body`.
pub type InfoSendFn = unsafe extern "C" fn(
    chan: *mut AstChannel,
    headers: *mut AstVariable,
    content_type: *const c_char,
    body: *const c_char,
    flags: c_int,
) -> c_int;

/// `struct dpma_info_handler` (24 bytes): `tech` is matched
/// case-insensitively against the channel technology name.
#[repr(C)]
pub struct DpmaInfoHandler {
    pub tech: *const c_char,
    pub send: Option<InfoSendFn>,
    pub next: *mut DpmaInfoHandler,
}

/// `int dpma_register_config_handler(struct dpma_config_handler *)` (H):
/// append to the list and take a reference on this module.
pub extern "C" fn dpma_register_config_handler(_h: *mut DpmaConfigHandler) -> c_int {
    -1
}

/// `void dpma_unregister_config_handler(struct dpma_config_handler *)` (H).
pub extern "C" fn dpma_unregister_config_handler(_h: *mut DpmaConfigHandler) {}

/// `void dpma_process_config_handlers(struct ao2_container *lines)`.
pub extern "C" fn dpma_process_config_handlers(_lines: *mut c_void) {}

/// `int dpma_register_info_handler(struct dpma_info_handler *)` (H).
pub extern "C" fn dpma_register_info_handler(_h: *mut DpmaInfoHandler) -> c_int {
    -1
}

/// `void dpma_unregister_info_handler(struct dpma_info_handler *)` (H).
pub extern "C" fn dpma_unregister_info_handler(_h: *mut DpmaInfoHandler) {}

/// `int dpma_info_send(chan, headers, content_type, body, flags)`: -1
/// when no handler matches the channel technology.
pub extern "C" fn dpma_info_send(
    _chan: *mut AstChannel,
    _headers: *mut AstVariable,
    _content_type: *const c_char,
    _body: *const c_char,
    _flags: c_int,
) -> c_int {
    -1
}

/// `int dpma_register_pjsip_endpoint_is_dphone(int (*)(const char *))` (H).
pub extern "C" fn dpma_register_pjsip_endpoint_is_dphone(
    _f: Option<unsafe extern "C" fn(endpoint: *const c_char) -> c_int>,
) -> c_int {
    -1
}

/// `void dpma_unregister_pjsip_endpoint_is_dphone(void)` (H).
pub extern "C" fn dpma_unregister_pjsip_endpoint_is_dphone() {}

/// `int dpma_pjsip_endpoint_is_dphone(const char *endpoint)`.
pub extern "C" fn dpma_pjsip_endpoint_is_dphone(_endpoint: *const c_char) -> c_int {
    0
}

/// Register the built-in "SIP" (chan_sip) info handler
/// (`__dpma_register_info_handler` in `load_full_components`).
pub fn register_builtin_info_handler() {}

pub fn unregister_builtin_info_handler() {}

/// Rust-side `dpma_info_send`.
pub fn info_send(_chan: *mut AstChannel, _headers: &[(&str, &str)], _content_type: &str, _body: &str) -> i32 {
    -1
}

/// Rust-side `dpma_process_config_handlers` with the lines container;
/// called by `users::load::process` after the lines are rebuilt and with
/// the registry lock released.
pub fn process_config_handlers() {}
