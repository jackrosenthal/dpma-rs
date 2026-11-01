//! Asterisk thread pools (`ast_threadpool_*`) and thread registration (`ast_register_thread`).
//!
//! Owner: P3 "request" (wave 1).  Put the raw `extern "C"` declarations this area needs in
//! this file (not in `ffi.rs`), and any C glue in
//! `crates/dpma-ast/glue/threadpool.c` (core Asterisk headers only; it is
//! compiled into every module).  See dev/notes/port-plan.md, "Ground rules".
