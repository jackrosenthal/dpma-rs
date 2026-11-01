//! The C API exported by res_digium_phone.so for its helper modules (and
//! anything else linking against it).  The original exports 66 symbols
//! (`nm -D --defined-only res_digium_phone.so`); all are exported except
//! `get_license_status` (no license handling in this rewrite): 62
//! functions and 3 data tables.
//!
//! * Every export is a Rust `#[no_mangle] pub extern "C"` item (or
//!   `#[no_mangle] pub static`): symbols defined in C glue are hidden by
//!   the cdylib's version script.  `dpma_asprintf` uses Rust's C-variadic
//!   `...` parameter.
//! * Objects handed to C (`struct phone_line`, `struct phone_user`,
//!   `struct dpma_config`, the lines container) are real astobj2 objects:
//!   the original helpers call `ao2_ref`, `ao2_lock`, and `ao2_iterator_*`
//!   on them.  A line or phone object starts with its NUL-terminated name
//!   (`phone_users_line_get_name` returns the object pointer itself).
//!   See `objects.rs` for how they map onto `users::Registry`.
//! * Return values, reference counting, and ownership follow the original
//!   exactly; the few places where the original would crash on a NULL
//!   argument are noted at each function.
//!
//! The `unsafe extern "C"` functions here are C entry points: their safety
//! contract is the C prototype documented with each (valid pointers to the
//! objects named, NUL-terminated strings).

#![allow(clippy::missing_safety_doc)]

pub mod config_api;
#[cfg(feature = "devtest")]
mod devtest;
pub mod handlers;
pub mod objects;
pub mod users_api;
pub mod utils_api;

pub use handlers::{info_send, process_config_handlers};
pub use objects::sync as sync_objects;

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    devtest::devtest_commands()
}
