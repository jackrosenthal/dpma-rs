//! Raw bindings to the Asterisk and pjproject headers, generated at build
//! time by `build.rs` with `bindgen` (see there for the headers read and
//! the environment variables that locate them).
//!
//! Only declarations: the functions are resolved when Asterisk loads the
//! module.  Static inline functions and function-like macros of the headers
//! are not here; `dpma-ast` reimplements the ones dpma-rs uses.

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// `ASTERISK_GPL_KEY`: the key every module must carry in its
/// `struct ast_module_info` (read from module.h by `build.rs`).
pub use DPMA_SYS_GPL_KEY as ASTERISK_GPL_KEY;
