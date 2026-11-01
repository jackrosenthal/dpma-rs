//! Voicemail API (`ast_vm_*`: mailbox snapshots, move, remove, forward, play).
//!
//! Owner: P9 "methods-vm" (wave 2).  Put the raw `extern "C"` declarations this area needs in
//! this file (not in `ffi.rs`), and any C glue in
//! `crates/dpma-ast/glue/vm.c` (core Asterisk headers only; it is
//! compiled into every module).  See dev/notes/port-plan.md, "Ground rules".
