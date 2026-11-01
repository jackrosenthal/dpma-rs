//! Channels: iteration, lookup by name or call id, variables, `ast_func_read`, `ast_dial_*`.
//!
//! Expected to be filled in by P10 "methods-calls" (wave 2).  Raw `extern "C"` declarations for
//! this area and wrappers around them go here; C glue can go in
//! `crates/dpma-ast/glue/channel.c` (core Asterisk headers only, since it is
//! compiled into every module).
