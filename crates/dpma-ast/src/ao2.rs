//! astobj2 objects and containers, for the exported C API objects (`ao2_alloc`, `ao2_container_alloc_hash`, iterators, locking).
//!
//! Expected to be filled in by P6 "exports" (wave 1).  Raw `extern "C"` declarations for
//! this area and wrappers around them go here; C glue can go in
//! `crates/dpma-ast/glue/ao2.c` (core Asterisk headers only, since it is
//! compiled into every module).
