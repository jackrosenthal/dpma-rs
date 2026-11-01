//! Voicemail API (`ast_vm_*`: mailbox snapshots, move, remove, forward, play).
//!
//! Expected to be filled in by P9 "methods-vm" (wave 2).  Raw `extern "C"` declarations for
//! this area and wrappers around them go here; C glue can go in
//! `crates/dpma-ast/glue/vm.c` (core Asterisk headers only, since it is
//! compiled into every module).
