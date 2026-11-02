//! `cargo xtask ci`: the CI job of `.github/workflows/ci.yml` for one
//! pinned release, which runs the same way locally ([`ci`]), each step in
//! fresh containers of the release's test image:
//!
//! 1. `cargo build`, both clippy runs (`--all-targets`, and `-p
//!    res_dpma_rs --features devtest`) with warnings as errors, and `cargo
//!    test` for the crates whose tests run outside Asterisk ([`check`],
//!    `cargo xtask inside check`);
//! 2. every suite, as `cargo xtask test all` runs them;
//! 3. when they pass, the module for publishing ([`publish`], `cargo
//!    xtask inside publish`): `cargo build --release -p res_dpma_rs`
//!    (without devtest); a check that it needs no newer glibc than
//!    [`GLIBC_BASELINE`]; a smoke test (loaded into the container's
//!    Asterisk: `module show like res_dpma_rs` lists it, and
//!    `digium_phones show version` answers); and a copy as
//!    `target/container/<release>/res_dpma_rs-asterisk<major>-<arch>.so`,
//!    which the workflow uploads.
//!
//! Every build of the job is non-incremental (`CARGO_INCREMENTAL=0`).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use dpma_tests::harness::Instance;

use crate::container::{out_dir, Run, OUT};
use crate::pins::Pin;
use crate::{pins, run, suites};

/// The newest glibc symbol version that the module may need: the minimum
/// glibc of the published module (README.md, "Installation").
pub const GLIBC_BASELINE: [u32; 2] = [2, 34];

fn step(what: &str, version: &str) {
    println!("\n==> {what} (Asterisk {version})");
}

fn cargo_step(what: &str, version: &str, args: &[&str]) -> Result<()> {
    step(what, version);
    run(crate::cargo().args(args))
}

/// The newest `GLIBC_x.y[.z]` symbol version in `objdump -T` output.
fn newest_glibc(dynamic_symbols: &str) -> Option<Vec<u32>> {
    dynamic_symbols
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter_map(|w| w.strip_prefix("GLIBC_"))
        .filter_map(|v| {
            v.split('.')
                .map(|n| n.parse().ok())
                .collect::<Option<Vec<u32>>>()
        })
        .max()
}

/// Fails when `so` needs a newer glibc than [`GLIBC_BASELINE`].
fn check_glibc(so: &Path) -> Result<()> {
    let out = Command::new("objdump")
        .arg("-T")
        .arg(so)
        .output()
        .context("running objdump")?;
    if !out.status.success() {
        bail!("objdump -T {} failed ({})", so.display(), out.status);
    }
    let fmt = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
    let newest = newest_glibc(&String::from_utf8_lossy(&out.stdout))
        .context("no GLIBC symbol versions in the module")?;
    println!("newest glibc symbol version: GLIBC_{}", fmt(&newest));
    if newest.as_slice() > GLIBC_BASELINE.as_slice() {
        bail!(
            "the module needs GLIBC_{}, newer than the baseline GLIBC_{} (the minimum glibc \
             README.md states); find what pulls it in, or raise the baseline (tools/src/ci.rs) \
             and the README together",
            fmt(&newest),
            fmt(&GLIBC_BASELINE)
        );
    }
    Ok(())
}

/// Loads the release build into the container's Asterisk.
fn smoke_test() -> Result<()> {
    let inst = Instance::new()?;
    inst.stop()?;
    inst.reset_conf()?;
    inst.install("release")?;
    inst.start()?;
    let shown = inst.cli_run("module show like res_dpma_rs");
    let version = inst.cli_run("digium_phones show version");
    inst.stop()?;
    let (shown, version) = (shown?.to_string(), version?.to_string());
    print!("{shown}{version}");
    if !shown.contains("res_dpma_rs.so") || !shown.contains("1 modules loaded") {
        bail!("module show like res_dpma_rs does not list it");
    }
    let want = format!("dpma-rs version {}", env!("CARGO_PKG_VERSION"));
    if !version.contains(&want) {
        bail!("digium_phones show version does not answer {want:?}");
    }
    Ok(())
}

/// `cargo xtask inside check <release>`: the build, lint, and test
/// steps.
pub fn check(release: &str) -> Result<u8> {
    let v = release;
    cargo_step("cargo build", v, &["build", "--locked"])?;
    cargo_step(
        "cargo clippy --all-targets",
        v,
        &[
            "clippy",
            "--locked",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    cargo_step(
        "cargo clippy -p res_dpma_rs --features devtest",
        v,
        &[
            "clippy",
            "--locked",
            "-p",
            "res_dpma_rs",
            "--features",
            "devtest",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    // The module crate's test binary cannot link outside Asterisk (it
    // imports Asterisk's symbols), so cargo test covers the other crates.
    cargo_step(
        "cargo test",
        v,
        &[
            "test",
            "--locked",
            "--workspace",
            "--exclude",
            "res_dpma_rs",
        ],
    )?;
    Ok(0)
}

/// `cargo xtask inside publish <release>`: the module for publishing,
/// checked and smoke-tested.
pub fn publish(release: &str) -> Result<u8> {
    let pin = pins::pin(Some(release))?;
    let v = pin.version.as_str();
    cargo_step(
        "the module for publishing",
        v,
        &["build", "--locked", "--release", "-p", "res_dpma_rs"],
    )?;
    let so = Instance::module_build("release");
    check_glibc(&so)?;
    step("smoke test of the release build", v);
    smoke_test()?;
    let asset = PathBuf::from(OUT).join(format!(
        "res_dpma_rs-asterisk{}-{}.so",
        pin.major,
        std::env::consts::ARCH
    ));
    std::fs::copy(&so, &asset).with_context(|| asset.display().to_string())?;
    println!(
        "\nthe module for Asterisk {}: target/container/{v}/{}",
        pin.major,
        asset.file_name().unwrap_or_default().to_string_lossy()
    );
    Ok(0)
}

/// `cargo xtask ci`: [`check`], the suites (up to `jobs` at a time), and
/// [`publish`]; the exit status.
pub fn ci(pin: &Pin, jobs: usize) -> Result<u8> {
    let run = Run::new(pin)?.with_env("CARGO_INCREMENTAL", "0");
    let v = pin.version.as_str();
    let code = run.inside("check", &["check", v])?;
    if code != 0 {
        return Ok(code);
    }
    step("test suites", v);
    let all = suites::selection(&["all".into()]);
    let code = suites::run_suites(&run, &out_dir(pin), &all, jobs)?;
    if code != 0 {
        return Ok(code);
    }
    run.inside("publish", &["publish", v])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_versions() {
        let dump = "0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.2.5) free\n\
                    0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.34) pthread_create\n\
                    0000000000000000  w   DF *UND*\t0000000000000000 (GLIBC_2.3.4) x\n\
                    0000000000000000      DF *UND*\t0000000000000000  GLIBC_PRIVATE y\n";
        assert_eq!(newest_glibc(dump), Some(vec![2, 34]));
        assert_eq!(newest_glibc("nothing"), None);
        assert!([2, 35].as_slice() > GLIBC_BASELINE.as_slice());
        assert!([2, 34].as_slice() <= GLIBC_BASELINE.as_slice());
        assert!([2, 3, 4].as_slice() <= GLIBC_BASELINE.as_slice());
    }
}
