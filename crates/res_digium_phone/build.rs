//! Compiles the C glue for this module against the Asterisk headers.
//!
//! Every `*.c` in `crates/dpma-ast/glue/` and in `glue/` is compiled; see
//! the `dpma-build` crate.

fn main() {
    dpma_build::Module::new("res_digium_phone").compile();
}
