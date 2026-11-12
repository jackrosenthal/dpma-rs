//! The suites: which ones `cargo xtask test` runs, and how.
//!
//! Each suite is a test target of dpma-tests of the same name, run as
//! `<test binary> --ignored`; it prepares the test instance itself.  A run
//! has two steps:
//!
//! 1. One container builds the devtest module and the suites' test
//!    binaries ([`build`]).
//! 2. Every suite then runs in a fresh container of its own, several at a
//!    time ([`run_suites`]): the prebuilt binary runs directly, without
//!    Cargo, so that the suites do not wait for each other on the target
//!    directory's lock.  The longest suites start first, so that the run
//!    takes little longer than the longest suite.
//!
//! The results are reported in the order of the selection, each suite's
//! output going to `target/container/<release>/logs/<suite>.log`.  A suite
//! whose test target does not exist fails without running.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{mpsc, Mutex};
use std::time::Instant;

use anyhow::{bail, Context, Result};

use crate::container::{Run, OUT, SRC};
use crate::run;

/// The suites, in order: a default run (or `all`) runs them all.
pub const SUITES: [&str; 9] = [
    "session",
    "config-xml",
    "users-runtime",
    "methods-vm",
    "methods-calls",
    "pjsip-helpers",
    "request-handlers",
    "ami",
    "apps-discovery",
];

/// The suites that take longest, longest first: they start first.
const LONGEST: [&str; 6] = [
    "apps-discovery",
    "pjsip-helpers",
    "request-handlers",
    "session",
    "ami",
    "methods-vm",
];

/// The list of test binaries that [`build`] writes (`<target> <path>`
/// lines), in `target/container/<release>/`.
const BINARIES: &str = "test-binaries";

/// The suite (and test target) named `name`, if there is one.
pub fn target(name: &str) -> Option<&'static str> {
    SUITES.iter().find(|&&s| s == name).copied()
}

/// The suites that `args` names (`[]` or `["all"]`: every suite).
pub fn selection(args: &[String]) -> Vec<String> {
    match args {
        [] => SUITES.iter().map(|s| s.to_string()).collect(),
        [a] if a == "all" => selection(&[]),
        _ => args.to_vec(),
    }
}

/// The order in which `suites` start: the longest first, the others in
/// their order.
fn start_order(suites: &[String]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..suites.len()).collect();
    order.sort_by_key(|&i| {
        LONGEST
            .iter()
            .position(|l| *l == suites[i])
            .unwrap_or(LONGEST.len())
    });
    order
}

/// The test targets of dpma-tests.
fn test_targets() -> Result<Vec<String>> {
    let out = crate::cargo()
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

/// `cargo xtask inside build SUITE...`, in the build container: the
/// devtest module, the test binaries of the suites (listed in
/// [`BINARIES`]).
pub fn build(suites: &[String]) -> Result<u8> {
    run(crate::cargo().args(["build", "-p", "res_dpma_rs", "--features", "devtest"]))?;
    let existing = test_targets()?;
    let mut targets: Vec<&str> = Vec::new();
    for s in suites {
        let t = target(s).context("an unknown suite")?;
        if existing.iter().any(|e| e == t) && !targets.contains(&t) {
            targets.push(t);
        }
    }
    let mut list = String::new();
    if !targets.is_empty() {
        let mut c = crate::cargo();
        c.args(["test", "-p", "dpma-tests", "--no-run"])
            .arg("--message-format=json-render-diagnostics");
        for t in &targets {
            c.args(["--test", t]);
        }
        let out = c
            .stderr(Stdio::inherit())
            .output()
            .context("building the test binaries")?;
        if !out.status.success() {
            bail!("building the test binaries failed ({})", out.status);
        }
        for line in out.stdout.split(|&b| b == b'\n') {
            let Ok(msg) = serde_json::from_slice::<serde_json::Value>(line) else {
                continue;
            };
            let (Some(name), Some(exe)) =
                (msg["target"]["name"].as_str(), msg["executable"].as_str())
            else {
                continue;
            };
            if targets.contains(&name) {
                list.push_str(&format!("{name} {exe}\n"));
            }
        }
    }
    let path = PathBuf::from(OUT).join(BINARIES);
    fs::write(&path, list).with_context(|| path.display().to_string())?;
    Ok(0)
}

/// How a suite went.
struct Outcome {
    ok: bool,
    secs: u64,
    why: String,
}

/// Runs suite `s` in a fresh container, its output in `log`.
fn run_one(run: &Run, s: &str, binary: Option<&String>, log: &Path) -> Outcome {
    let t = target(s).expect("checked");
    let fail = |secs: u64, why: String| Outcome {
        ok: false,
        secs,
        why,
    };
    let Some(binary) = binary else {
        let _ = fs::write(log, format!("dpma-tests has no test target {t}\n"));
        return fail(0, format!("no test target {t}"));
    };
    let see = format!("see logs/{s}.log");
    let result = (|| -> Result<Outcome> {
        let mut file = File::create(log).with_context(|| log.display().to_string())?;
        let c = match run.container(s) {
            Ok(c) => c,
            Err(e) => {
                writeln!(file, "starting the container failed: {e:#}")?;
                return Ok(fail(0, see.clone()));
            }
        };
        let args = [binary.as_str(), "--ignored"];
        // In tests/, as Cargo runs test binaries.
        let tests = format!("{SRC}/tests");
        let start = Instant::now();
        let status = c
            .work(Some(&tests), &args)
            .stdin(Stdio::null())
            .stdout(file.try_clone()?)
            .stderr(file)
            .status()?;
        let secs = start.elapsed().as_secs();
        Ok(if status.success() {
            Outcome {
                ok: true,
                secs,
                why: String::new(),
            }
        } else {
            fail(secs, see.clone())
        })
    })();
    result.unwrap_or_else(|e| fail(0, format!("{e:#}")))
}

/// Builds the suites' binaries in one container, then runs the suites,
/// each in a container of its own, up to `jobs` at a time; the exit status
/// (0 when every suite passed, 1 when one failed).
pub fn run_suites(run: &Run, out: &Path, suites: &[String], jobs: usize) -> Result<u8> {
    let logdir = out.join("logs");
    if logdir.exists() {
        fs::remove_dir_all(&logdir).with_context(|| logdir.display().to_string())?;
    }
    fs::create_dir_all(&logdir).with_context(|| logdir.display().to_string())?;
    let mut args = vec!["build"];
    args.extend(suites.iter().map(String::as_str));
    let code = run.inside("build", &args)?;
    if code != 0 {
        return Ok(code);
    }
    let list = out.join(BINARIES);
    let list = fs::read_to_string(&list).with_context(|| list.display().to_string())?;
    let binaries: BTreeMap<String, String> = list
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(t, b)| (t.to_string(), b.to_string()))
        .collect();

    let queue = Mutex::new(start_order(suites).into_iter());
    let (tx, rx) = mpsc::channel();
    let mut failures = 0;
    std::thread::scope(|scope| {
        for _ in 0..jobs.clamp(1, suites.len().max(1)) {
            let tx = tx.clone();
            let (queue, binaries, logdir) = (&queue, &binaries, &logdir);
            scope.spawn(move || loop {
                let next = queue.lock().expect("not poisoned").next();
                let Some(i) = next else { break };
                let s = &suites[i];
                let t = target(s).expect("checked");
                let log = logdir.join(format!("{s}.log"));
                let _ = tx.send((i, run_one(run, s, binaries.get(t), &log)));
            });
        }
        drop(tx);
        // Report in the selection's order, each suite once all before it
        // have finished.
        let mut done: Vec<Option<Outcome>> = suites.iter().map(|_| None).collect();
        let mut reported = 0;
        for (i, outcome) in rx {
            done[i] = Some(outcome);
            while let Some(Some(o)) = done.get(reported) {
                let s = &suites[reported];
                if o.ok {
                    println!("{s:<20} ok   ({} s)", o.secs);
                } else {
                    println!("{s:<20} FAIL ({} s, {})", o.secs, o.why);
                    failures += 1;
                }
                reported += 1;
            }
        }
    });
    println!("{failures} failure(s)");
    Ok(if failures == 0 { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_names() {
        assert_eq!(target("session"), Some("session"));
        assert_eq!(target("nope"), None);
        assert_eq!(selection(&[]), SUITES);
        assert_eq!(selection(&["all".into()]), SUITES);
        assert_eq!(
            selection(&["ami".into(), "session".into()]),
            ["ami", "session"]
        );
        assert!(LONGEST.iter().all(|s| target(s).is_some()));
    }

    #[test]
    fn longest_first() {
        let all = selection(&[]);
        let order: Vec<&str> = start_order(&all)
            .into_iter()
            .map(|i| all[i].as_str())
            .collect();
        assert_eq!(order[..LONGEST.len()], LONGEST);
        assert_eq!(order[LONGEST.len()], "config-xml");
        assert_eq!(order.len(), all.len());
    }
}
