//! A private network namespace, so that a suite's traffic never reaches a
//! real network (the apps-discovery suite's mDNS announcements).
//!
//! A suite runs itself again inside a new user and network namespace
//! (`unshare -rn`, which needs unprivileged user namespaces), where its
//! only interface is `lo`.  [`setup_loopback`] makes `lo` usable for
//! multicast: up, with multicast on (the module's responder uses an
//! interface only when it is multicast-capable), and with a route for
//! 224.0.0.0/4.  Asterisk started inside (through
//! [`crate::harness::Instance::start`]) keeps the namespace alive until it
//! stops; its CLI also works from outside (the control socket is a file),
//! but SIP and AMI on 127.0.0.1 are reachable only inside.
//!
//! ```no_run
//! use dpma_tests::netns;
//! fn main() -> std::process::ExitCode {
//!     if !netns::inside() {
//!         return netns::reexec().unwrap_or(std::process::ExitCode::FAILURE);
//!     }
//!     netns::setup_loopback().expect("loopback");
//!     // ... start Asterisk and run the checks ...
//!     std::process::ExitCode::SUCCESS
//! }
//! ```

use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};

/// Set (to `1`) in the environment of the process [`reexec`] starts.
pub const ENV: &str = "DPMA_TESTS_NETNS";

/// Whether this process is the one [`reexec`] started inside the
/// namespace.
pub fn inside() -> bool {
    std::env::var_os(ENV).is_some_and(|v| v == "1")
}

/// Runs the current executable again, with the same arguments and
/// [`ENV`] set, inside a new user and network namespace (`unshare -rn`:
/// the user is mapped to root inside), waits for it, and returns its exit
/// status.
pub fn reexec() -> Result<ExitCode> {
    let exe = std::env::current_exe().context("the test executable")?;
    let status = Command::new("unshare")
        .arg("-rn")
        .arg("--")
        .arg(&exe)
        .args(std::env::args_os().skip(1))
        .env(ENV, "1")
        .status()
        .context("running unshare -rn (it needs unprivileged user namespaces)")?;
    Ok(match status.code() {
        Some(0) => ExitCode::SUCCESS,
        Some(n) => ExitCode::from(u8::try_from(n).unwrap_or(1)),
        None => ExitCode::FAILURE,
    })
}

fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("running ip {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Brings `lo` up with multicast on and routes 224.0.0.0/4 through it
/// (inside the namespace).
pub fn setup_loopback() -> Result<()> {
    if !inside() {
        bail!("not inside the private network namespace");
    }
    ip(&["link", "set", "lo", "up"])?;
    ip(&["link", "set", "lo", "multicast", "on"])?;
    ip(&["route", "add", "224.0.0.0/4", "dev", "lo"])
}

/// Whether the current network namespace's only interface is `lo`, with
/// multicast on (`ip -o link`).
pub fn isolated() -> bool {
    let Ok(out) = Command::new("ip").args(["-o", "link"]).output() else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .collect();
    names == ["lo"] && text.contains("MULTICAST")
}
