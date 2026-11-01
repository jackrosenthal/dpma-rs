//! Asterisk XML API wrappers (`ast_xml_*`, libxml2 behind Asterisk).
//!
//! Owner: P4 "config-xml" (wave 1).  Put the raw `extern "C"` declarations this area needs in
//! this file (not in `ffi.rs`), and any C glue in
//! `crates/dpma-ast/glue/xml.c` (core Asterisk headers only; it is
//! compiled into every module).  See dev/notes/port-plan.md, "Ground rules".
