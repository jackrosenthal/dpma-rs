//! res_pjsip_endpoint_identifier_dpma: DPMA PJSIP Support.
//!
//! Skeleton: the module declines to load until it is implemented.
//!
//! This module must use res_digium_phone only through its exported C API
//! (`extern "C"` declarations in this crate), never by linking to the
//! res_digium_phone Rust crate, so that it also works with the original
//! res_digium_phone.so and vice versa.  See dev/notes/port-plan.md.
//!
//! Owner: P11 "pjsip-helpers" (wave 2).

use dpma_ast::ast_log;
use dpma_ast::log::LOG_NOTICE;

#[no_mangle]
pub extern "C" fn dpma_eid_rust_load() -> i32 {
    dpma_ast::guard(1, || {
        ast_log!(LOG_NOTICE, "res_pjsip_endpoint_identifier_dpma is not implemented yet; declining to load");
        1
    })
}

#[no_mangle]
pub extern "C" fn dpma_eid_rust_unload() -> i32 {
    dpma_ast::guard(0, || 0)
}
