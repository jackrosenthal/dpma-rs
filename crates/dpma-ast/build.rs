//! Locates the Asterisk headers and publishes their location (and the
//! location of the shared C glue) to dependent crates through the
//! `DEP_DPMA_AST_*` environment variables.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=ASTERISK_INCLUDE_DIR");
    println!("cargo:rerun-if-changed=glue");

    let include = std::env::var("ASTERISK_INCLUDE_DIR").unwrap_or_else(|_| "/usr/include".into());
    let include = PathBuf::from(include);
    if !include.join("asterisk.h").exists() {
        println!(
            "cargo:warning=asterisk.h not found in {} (set ASTERISK_INCLUDE_DIR)",
            include.display()
        );
    }
    let glue = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("glue");

    println!("cargo:include={}", include.display());
    println!("cargo:glue={}", glue.display());
}
