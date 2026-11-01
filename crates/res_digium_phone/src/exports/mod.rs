//! The C API exported by res_digium_phone.so for its helper modules (and
//! anything else linking against it).  The original exports 66 symbols
//! (`nm -D --defined-only res_digium_phone.so`); the ones the original
//! helper modules import are marked (H) in the plan.  All are exported
//! except `get_license_status` (no license handling in this rewrite).
//!
//! Rules for this package:
//!
//! * Every export is a Rust `#[no_mangle] pub extern "C"` item (or
//!   `#[no_mangle] pub static`): symbols defined in C glue are hidden by
//!   the cdylib's version script and cannot be exported.  C-variadic
//!   `dpma_asprintf` uses Rust's `...` parameter.
//! * The stubs below deliberately have no `#[no_mangle]` yet, so the
//!   module exports nothing until the real implementations exist (a stub
//!   export would let the original helper binaries load and then crash).
//! * Objects handed to C (`struct phone_line`, `struct phone_user`,
//!   `struct dpma_config`, the lines container) must be real astobj2
//!   objects: the original helpers call `ao2_ref`, `ao2_lock`, and
//!   `ao2_iterator_*` on them.  A line object's first bytes are its
//!   NUL-terminated name (`phone_users_line_get_name` returns the object
//!   pointer itself).
//!
//! Acceptance includes loading the *original* helper binaries against
//! this module (see the plan).
//!
//! Owner: P6 "exports" (wave 1).

pub mod config_api;
pub mod handlers;
pub mod users_api;
pub mod utils_api;

pub use handlers::{info_send, process_config_handlers, register_builtin_info_handler, unregister_builtin_info_handler};
