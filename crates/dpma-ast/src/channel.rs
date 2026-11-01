//! Channels: iteration, lookup by name or call id, variables, `ast_func_read`, `ast_dial_*`.
//!
//! Owner: P10 "methods-calls" (wave 2).  Put the raw `extern "C"` declarations this area needs in
//! this file (not in `ffi.rs`), and any C glue in
//! `crates/dpma-ast/glue/channel.c` (core Asterisk headers only; it is
//! compiled into every module).  See dev/notes/port-plan.md, "Ground rules".
