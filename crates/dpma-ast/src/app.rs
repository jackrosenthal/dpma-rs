//! Dialplan applications (`ast_register_application2`, argument parsing, `ast_control_streamfile_w_cb`).
//!
//! Expected to be filled in by P14 "apps-discovery" (wave 3).  Raw `extern "C"` declarations for
//! this area and wrappers around them go here; C glue can go in
//! `crates/dpma-ast/glue/app.c` (core Asterisk headers only, since it is
//! compiled into every module).
