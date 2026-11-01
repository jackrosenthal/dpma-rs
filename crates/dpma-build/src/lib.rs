//! Shared build-script logic for the dpma-rs Asterisk modules.
//!
//! Every module crate compiles
//!
//! * every `*.c` file in `crates/dpma-ast/glue/` (shared glue: core Asterisk
//!   headers only), and
//! * every `*.c` file in its own `glue/` directory (module specific glue),
//!
//! with that module's `AST_MODULE` and `AST_MODULE_SELF_SYM` definitions.
//! New glue therefore goes into a new `.c` file; no build script needs to
//! change.  Files are compiled in name order.
//!
//! Usage from a module's `build.rs` (the crate must depend on `dpma-ast`
//! so that the `DEP_DPMA_AST_*` variables are set):
//!
//! ```ignore
//! fn main() {
//!     dpma_build::Module::new("res_digium_phone").compile();
//! }
//! ```

use std::path::{Path, PathBuf};

/// One Asterisk module's C glue build.
pub struct Module {
    name: String,
    build: cc::Build,
}

fn c_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "c"))
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

impl Module {
    /// Prepare the glue build for the Asterisk module `name`
    /// (e.g., "res_digium_phone").
    pub fn new(name: &str) -> Module {
        let include = PathBuf::from(std::env::var("DEP_DPMA_AST_INCLUDE").expect("dpma-ast include (DEP_DPMA_AST_INCLUDE)"));
        let shared = PathBuf::from(std::env::var("DEP_DPMA_AST_GLUE").expect("dpma-ast glue (DEP_DPMA_AST_GLUE)"));
        let local = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("glue");

        let mut build = cc::Build::new();
        for dir in [&shared, &local] {
            println!("cargo:rerun-if-changed={}", dir.display());
            for f in c_files(dir) {
                println!("cargo:rerun-if-changed={}", f.display());
                build.file(f);
            }
        }
        println!("cargo:rerun-if-env-changed=ASTERISK_INCLUDE_DIR");

        build
            .include(&include)
            .define("AST_MODULE", format!("\"{}\"", name).as_str())
            .define("AST_MODULE_SELF_SYM", format!("__internal_{}_self", name).as_str())
            .define("_GNU_SOURCE", None)
            .define("_REENTRANT", None)
            .flag_if_supported("-fno-strict-aliasing")
            .flag_if_supported("-Wno-unused-parameter")
            .flag_if_supported("-Wno-missing-field-initializers")
            .flag_if_supported("-Wno-old-style-declaration")
            .flag_if_supported("-Wno-compare-distinct-pointer-types")
            .link_lib_modifier("+whole-archive");
        Module { name: name.to_string(), build }
    }

    /// Access the underlying `cc::Build` (extra include paths, defines).
    pub fn build(&mut self) -> &mut cc::Build {
        &mut self.build
    }

    /// Add the pjproject headers and defines that Asterisk's PJSIP headers
    /// (`asterisk/res_pjsip.h`, ...) need, for glue in the PJSIP helper
    /// modules.  The headers come from `$PJPROJECT_DIR`: either a pjproject
    /// source tree (its `pjlib/include`, `pjlib-util/include`,
    /// `pjnath/include`, `pjmedia/include`, and `pjsip/include` are added)
    /// or a single directory holding installed headers (`pjsip.h`, ...).
    /// The default is the pjproject bundled with the Asterisk source tree
    /// in `dev/asterisk-24-src` (`PJPROJECT_INCLUDE` in its `makeopts` has
    /// the same defines).
    pub fn pjproject(mut self) -> Module {
        println!("cargo:rerun-if-env-changed=PJPROJECT_DIR");
        let dir = match std::env::var("PJPROJECT_DIR") {
            Ok(d) if !d.is_empty() => PathBuf::from(d),
            _ => PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("../../dev/asterisk-24-src/third-party/pjproject/source"),
        };
        let subdirs = ["pjlib", "pjlib-util", "pjnath", "pjmedia", "pjsip"];
        if dir.join("pjlib/include").is_dir() {
            for s in subdirs {
                self.build.include(dir.join(s).join("include"));
            }
        } else {
            if !dir.join("pjsip.h").exists() {
                println!("cargo:warning=pjproject headers not found in {} (set PJPROJECT_DIR)", dir.display());
            }
            self.build.include(&dir);
        }
        self.build
            .define("PJ_AUTOCONF", "1")
            .define("PJ_HAS_LINUX_EPOLL", "1")
            .define("PJ_IS_BIG_ENDIAN", "0")
            .define("PJ_IS_LITTLE_ENDIAN", "1")
            .define("PJMEDIA_HAS_SRTP", "0")
            // Asterisk's PJSIP headers have const-qualified return types.
            .flag_if_supported("-Wno-ignored-qualifiers");
        self
    }

    /// Compile the glue into a static library linked whole into the module.
    pub fn compile(self) {
        self.build.compile(&format!("dpma_glue_{}", self.name));
    }
}
