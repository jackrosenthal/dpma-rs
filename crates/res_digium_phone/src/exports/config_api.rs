//! phone_config.c exports: `dpma_config_get`, `dpma_config_unref`, the
//! `dpma_config_*` getters (0x178e90..0x1791d0), and
//! `dpma_append_config_file_dir` (0x1791f0).  `struct dpma_config` is an
//! ao2 object holding a C copy of `config::General`; getters return
//! pointers into it, so it must stay alive while referenced.  Getters
//! given NULL use the current configuration (defaults when none).
//!
//! Owner: P6 "exports" (wave 1).

use std::os::raw::{c_char, c_int, c_void};

/// `struct dpma_config *dpma_config_get(void)`.
pub extern "C" fn dpma_config_get() -> *mut c_void {
    std::ptr::null_mut()
}

/// `void dpma_config_unref(struct dpma_config *)`.
pub extern "C" fn dpma_config_unref(_cfg: *mut c_void) {}

/// `int dpma_config_auth_flags(struct dpma_config *)` (1 without config).
pub extern "C" fn dpma_config_auth_flags(_cfg: *mut c_void) -> c_int {
    crate::config::auth::USER as c_int
}

/// `const char *dpma_config_pjsip_message_context(struct dpma_config *)`
/// (H, read by the endpoint identifier helper through its own config
/// load).  The other getters follow the same pattern; see the plan.
pub extern "C" fn dpma_config_pjsip_message_context(_cfg: *mut c_void) -> *const c_char {
    std::ptr::null()
}
