//! `cargo xtask test`: runs test suites one after another against the
//! private instance of `$DPMA_SLOT`.
//!
//! Each suite is a test target of dpma-tests, run as `cargo test -p
//! dpma-tests --test <target> -- --ignored [OPTIONS]`; it prepares the
//! instance itself (fresh configuration, its setup, the module installed,
//! Asterisk restarted), so the suites do not see each other's
//! configuration.  Before the suites the devtest module and the suites'
//! test binaries are built; afterwards Asterisk is stopped and the
//! instance gets the simulator setup back (fresh configuration, test PKI,
//! and the simulator's test configuration).

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use dpma_tests::asterisk::{self, Slot};
use dpma_tests::harness::{fixtures, Instance};
use dpma_tests::sim::repo_root;

use crate::build::run as run_cmd;

/// The suites of a default run, in order.
pub const DEFAULT: [&str; 13] = [
    "session",
    "config-xml",
    "users-runtime",
    "methods-vm",
    "methods-vm-phone",
    "methods-calls",
    "methods-calls-phone",
    "methods-calls-http",
    "pjsip-helpers",
    "request-handlers",
    "ami",
    "apps-discovery",
    "raw-bytes",
];

/// What `all` adds to the default suites.
pub const ALL_EXTRA: [&str; 1] = ["ami-expiry"];

/// The test target of a suite and the options it runs with.  `parity`
/// runs only when named.
pub fn target(suite: &str) -> Option<(&'static str, &'static [&'static str])> {
    Some(match suite {
        "methods-vm-phone" => ("methods-vm", &["--via", "phone"]),
        "methods-calls-phone" => ("methods-calls", &["--via", "phone"]),
        "methods-calls-http" => ("methods-calls", &["--via", "http"]),
        "ami-expiry" => ("ami", &["--expiry"]),
        "parity" => ("parity", &[]),
        s => (*DEFAULT.iter().find(|&&d| d == s)?, &[]),
    })
}

/// The suites that `args` names (`[]`: the default suites; `["all"]`:
/// the default suites and ami-expiry).
pub fn selection(args: &[String]) -> Vec<String> {
    match args {
        [] => DEFAULT.iter().map(|s| s.to_string()).collect(),
        [a] if a == "all" => DEFAULT
            .iter()
            .chain(ALL_EXTRA.iter())
            .map(|s| s.to_string())
            .collect(),
        _ => args.to_vec(),
    }
}

/// Cargo, as the one that runs the xtask.
pub fn cargo() -> Command {
    let mut c = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    c.current_dir(repo_root());
    c
}

/// The test targets of dpma-tests.
fn test_targets() -> Result<Vec<String>> {
    let out = cargo()
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .stderr(Stdio::inherit())
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!("cargo metadata failed ({})", out.status);
    }
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let mut names = Vec::new();
    for p in meta["packages"].as_array().into_iter().flatten() {
        if p["name"] != "dpma-tests" {
            continue;
        }
        for t in p["targets"].as_array().into_iter().flatten() {
            let is_test = t["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|k| k == "test"));
            if let (true, Some(n)) = (is_test, t["name"].as_str()) {
                names.push(n.to_string());
            }
        }
    }
    Ok(names)
}

/// `$LOGDIR`, else a new directory `$TMPDIR/dpma-tests.XXXXXX`.
fn log_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("LOGDIR").filter(|d| !d.is_empty()) {
        let d = std::path::absolute(PathBuf::from(d))?;
        fs::create_dir_all(&d).with_context(|| d.display().to_string())?;
        return Ok(d);
    }
    let tmp = std::env::temp_dir();
    loop {
        let d = tmp.join(format!("dpma-tests.{}", dpma_tests::util::token_hex(3)));
        match fs::create_dir(&d) {
            Ok(()) => return Ok(d),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| d.display().to_string()),
        }
    }
}

/// Runs the suites `args` names; the exit status (0 when every suite
/// passed, 1 when one failed, 2 for an unknown suite).
pub fn run(args: &[String]) -> Result<u8> {
    let suites = selection(args);
    for s in &suites {
        if target(s).is_none() {
            println!("unknown suite {s}");
            return Ok(2);
        }
    }
    let n = asterisk::env_slot()?;
    let slot = Slot::new(n)?;
    if !slot.exists() {
        bail!(
            "no instance at {} (cargo xtask instance init {n} [VERSION])",
            slot.dir().display()
        );
    }
    let logdir = log_dir()?;

    // The devtest module (installed by every suite's preparation) and the
    // suites' test binaries, so that the suites' times and logs hold no
    // compiling.
    run_cmd(cargo().args(["build", "-p", "res_dpma_rs", "--features", "devtest"]))?;
    let existing = test_targets()?;
    let mut targets: Vec<&str> = Vec::new();
    for s in &suites {
        let (t, _) = target(s).expect("checked");
        if existing.iter().any(|e| e == t) && !targets.contains(&t) {
            targets.push(t);
        }
    }
    if !targets.is_empty() {
        let mut c = cargo();
        c.args(["test", "-p", "dpma-tests", "--no-run"]);
        for t in &targets {
            c.args(["--test", t]);
        }
        run_cmd(&mut c)?;
    }

    let mut failures = 0;
    for s in &suites {
        let (t, options) = target(s).expect("checked");
        print!("{s:<20} ");
        std::io::stdout().flush()?;
        let log_path = logdir.join(format!("{s}.log"));
        let mut log = File::create(&log_path).with_context(|| log_path.display().to_string())?;
        if !existing.iter().any(|e| e == t) {
            writeln!(log, "dpma-tests has no test target {t}")?;
            println!("FAIL (0 s, no test target {t})");
            failures += 1;
            continue;
        }
        let start = Instant::now();
        let status = cargo()
            .args(["test", "-p", "dpma-tests", "--test", t, "--", "--ignored"])
            .args(options)
            .env("DPMA_SLOT", n.to_string())
            .env("LOGDIR", &logdir)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .status();
        let secs = start.elapsed().as_secs();
        if status.is_ok_and(|s| s.success()) {
            println!("ok   ({secs} s)");
        } else {
            println!("FAIL ({secs} s, see {})", log_path.display());
            failures += 1;
        }
    }

    // Back to the simulator setup, with Asterisk stopped.
    let restore = Instance::for_slot(n).and_then(|inst| {
        inst.stop()?;
        inst.reset_conf()?;
        fixtures::sim_setup(&inst)
    });
    if let Err(e) = restore {
        println!("restoring the simulator setup failed: {e:#}");
    }
    println!("{failures} failure(s); logs in {}", logdir.display());
    Ok(if failures == 0 { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_names() {
        assert_eq!(target("session"), Some(("session", &[][..])));
        assert_eq!(
            target("methods-calls-http"),
            Some(("methods-calls", &["--via", "http"][..]))
        );
        assert_eq!(target("ami-expiry"), Some(("ami", &["--expiry"][..])));
        assert_eq!(target("parity"), Some(("parity", &[][..])));
        assert_eq!(target("nope"), None);
        assert_eq!(selection(&[]).len(), DEFAULT.len());
        let all = selection(&["all".into()]);
        assert_eq!(all.last().map(String::as_str), Some("ami-expiry"));
        assert!(!all.iter().any(|s| s == "parity"));
        assert_eq!(
            selection(&["ami".into(), "session".into()]),
            ["ami", "session"]
        );
    }
}
