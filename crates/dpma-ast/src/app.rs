//! Dialplan applications (`ast_register_application2`, argument parsing, `ast_control_streamfile_w_cb`).
//!
//! Owner: P14 "apps-discovery" (wave 3).  Put the raw `extern "C"` declarations this area needs in
//! this file (not in `ffi.rs`), and any C glue in
//! `crates/dpma-ast/glue/app.c` (core Asterisk headers only; it is
//! compiled into every module).  See dev/notes/port-plan.md, "Ground rules".
