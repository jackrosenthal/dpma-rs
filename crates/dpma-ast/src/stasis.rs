//! Stasis topics and message routers (parking topic forwarding).
//!
//! Owner: P10 "methods-calls" (wave 2).  Put the raw `extern "C"` declarations this area needs in
//! this file (not in `ffi.rs`), and any C glue in
//! `crates/dpma-ast/glue/stasis.c` (core Asterisk headers only; it is
//! compiled into every module).  See dev/notes/port-plan.md, "Ground rules".
