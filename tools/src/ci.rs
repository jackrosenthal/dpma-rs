//! `cargo xtask ci`: the CI job of `.github/workflows/ci.yml`, which
//! runs the same way locally.
//!
//! `ci setup` prepares an Ubuntu machine (a GitHub Actions runner) as
//! root.  It installs
//!
//! - Asterisk's build dependencies: the basic set of Asterisk's
//!   `contrib/scripts/install_prereq`, OpenSSL, `curl` for the downloads,
//!   and `bzip2` and `patch` for the bundled pjproject;
//! - `pkg-config` and the OpenSSL headers for the openssl crate, and
//!   libclang for bindgen;
//! - what the test suites use: `openssl`, `iproute2`, `util-linux`
//!   (`unshare` and `nsenter`), and `binutils`;
//!
//! and allows unprivileged user namespaces, which apps-discovery's network
//! namespace needs (`unshare -rn`): Ubuntu 23.10 and later restrict them
//! through AppArmor (`kernel.apparmor_restrict_unprivileged_userns`).
//! Building the xtask itself needs Rust and a C linker (`cc`), which the
//! GitHub runners have.
//!
//! `ci job <VERSION>` (with `$DPMA_SLOT`) is the whole job for one
//! release: the Asterisk build and install (skipped when done), `cargo
//! build` against the release's source tree, both clippy runs with
//! warnings as errors, `cargo test` for the crates whose tests run outside
//! Asterisk, the devtest build, the instance of `$DPMA_SLOT` created
//! afresh for the release, and every suite (`cargo xtask test all`).

use std::process::Command;

use anyhow::Result;
use dpma_tests::asterisk::{self, slot_dir, Slot};

use crate::build::{run, Build};
use crate::suites::{self, cargo};

/// The Ubuntu packages the job needs.
pub const PACKAGES: [&str; 17] = [
    "build-essential",
    "pkg-config",
    "curl",
    "ca-certificates",
    "bzip2",
    "patch",
    "libedit-dev",
    "libjansson-dev",
    "libsqlite3-dev",
    "uuid-dev",
    "libxml2-dev",
    "libssl-dev",
    "libclang-dev",
    "openssl",
    "iproute2",
    "util-linux",
    "binutils",
];

const USERNS_KNOB: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// `ci setup`: installs the packages and allows unprivileged user
/// namespaces.  Not as root, it runs itself through `sudo`.
pub fn setup() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        let exe = std::env::current_exe()?;
        println!("ci setup needs root: sudo {} ci setup", exe.display());
        return run(Command::new("sudo").arg(exe).args(["ci", "setup"]));
    }
    run(Command::new("apt-get")
        .arg("update")
        .env("DEBIAN_FRONTEND", "noninteractive"))?;
    run(Command::new("apt-get")
        .args(["install", "-y", "--no-install-recommends"])
        .args(PACKAGES)
        .env("DEBIAN_FRONTEND", "noninteractive"))?;
    if std::path::Path::new(USERNS_KNOB).exists() {
        run(Command::new("sysctl").args(["-w", "kernel.apparmor_restrict_unprivileged_userns=0"]))?;
    }
    Ok(())
}

fn step(what: &str, version: &str) {
    println!("\n==> {what} (Asterisk {version})");
}

fn cargo_step(what: &str, version: &str, args: &[&str]) -> Result<()> {
    step(what, version);
    run(cargo().args(args))
}

/// `ci job <VERSION>`; the exit status of the suites.
pub fn job(version: &str) -> Result<u8> {
    let n = asterisk::env_slot()?;
    let b = Build::new(version)?;
    let v = b.pin.version.clone();
    // For every cargo run below (no other threads run yet).
    std::env::set_var("ASTERISK_SOURCE_DIR", &b.src);
    std::env::set_var("CARGO_INCREMENTAL", "0");

    step("Asterisk", &v);
    b.run(None, true)?;
    cargo_step("cargo build", &v, &["build", "--locked"])?;
    cargo_step(
        "cargo clippy --all-targets",
        &v,
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
        &v,
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
        &v,
        &[
            "test",
            "--locked",
            "--workspace",
            "--exclude",
            "res_dpma_rs",
        ],
    )?;

    step("test suites", &v);
    run(cargo().args([
        "build",
        "--locked",
        "-p",
        "res_dpma_rs",
        "--features",
        "devtest",
    ]))?;
    let dir = slot_dir(n);
    if std::fs::symlink_metadata(&dir).is_ok() {
        if let Ok(s) = Slot::new(n) {
            let _ = s.stop();
        }
        std::fs::remove_dir_all(&dir)?;
    }
    print!(
        "{}",
        String::from_utf8_lossy(&Slot::command(n, &["init", &v])?)
    );
    suites::run(&["all".to_string()])
}
