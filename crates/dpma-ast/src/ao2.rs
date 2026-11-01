//! astobj2 objects and containers, for the exported C API shims (`ao2_alloc`, `ao2_container_alloc_hash`, iterators, locking).
//!
//! Owner: P6 "exports" (wave 1).  Put the raw `extern "C"` declarations this area needs in
//! this file (not in `ffi.rs`), and any C glue in
//! `crates/dpma-ast/glue/ao2.c` (core Asterisk headers only; it is
//! compiled into every module).  See dev/notes/port-plan.md, "Ground rules".
