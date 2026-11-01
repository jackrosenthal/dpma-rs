//! Compiles the C glue for this module (every `*.c` in
//! `crates/dpma-ast/glue/` and `glue/`; see the `dpma-build` crate), with
//! the pjproject headers that Asterisk's PJSIP headers need
//! (`$PJPROJECT_DIR`; see `dpma_build::Module::pjproject`).
//!
//! `-Bsymbolic`: res_digium_phone.so is loaded with RTLD_GLOBAL and
//! exports the same Rust callback names (`dpma_rust_cli_exec`, ...) as
//! every dpma-rs module; this module's own references must bind to its own
//! definitions.

fn main() {
    println!("cargo:rustc-link-arg=-Wl,-Bsymbolic");
    dpma_build::Module::new("res_pjsip_endpoint_identifier_dpma").pjproject().compile();
}
