//! `cargo xtask`: the development tasks of dpma-rs (see `tests/README.md`).
//!
//! ```text
//! cargo xtask test [--asterisk VERSION] [SUITE... | all]
//! cargo xtask ci [--asterisk VERSION]
//! cargo xtask headers [--asterisk VERSION]
//! cargo xtask majors
//! ```
//!
//! A VERSION is a major version (`22`) or a release (`22.11.0`) pinned in
//! `tools/asterisk-versions`; the default is the newest.  `test` and `ci`
//! run in a fresh container of the release's test image
//! ([`container`]), where `cargo xtask inside` (hidden) does their work.

// The doc comments below are the command-line help (clap), not rustdoc.
#![allow(rustdoc::invalid_html_tags)]

mod ci;
mod container;
mod pins;
mod suites;

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cargo xtask",
    bin_name = "cargo xtask",
    about = "Development tasks for dpma-rs: the test suites in containers, CI, and Asterisk headers."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run test suites in a fresh container of a pinned release's test
    /// image (built first if needed).
    ///
    /// Suites (default: all of these, in this order): session config-xml
    /// users-runtime methods-vm methods-vm-phone methods-calls
    /// methods-calls-phone methods-calls-http pjsip-helpers
    /// request-handlers ami apps-discovery raw-bytes.  "all" runs these
    /// and then ami-expiry (about six minutes); parity runs only when
    /// named, and needs --original.  Each suite's output goes to
    /// target/container/<release>/logs/<suite>.log.  Exit status 0 when
    /// every suite passes.
    Test {
        /// The Asterisk release: a major version or a pinned release
        /// (default: the newest).
        #[arg(long, value_name = "VERSION")]
        asterisk: Option<String>,
        /// The directory of the original binaries (res_digium_phone.so
        /// and its two PJSIP helpers 24.0_3.6.13), for parity: mounted
        /// read-only into the container.
        #[arg(long, value_name = "DIR")]
        original: Option<PathBuf>,
        /// Suites to run, or "all".
        suites: Vec<String>,
    },
    /// The CI job: in a container of the release's test image, build,
    /// lint, and test dpma-rs, run every suite, and build, check, and
    /// smoke-test the module for publishing
    /// (target/container/<release>/res_dpma_rs-asterisk<major>-<arch>.so).
    Ci {
        /// The Asterisk release: a major version or a pinned release
        /// (default: the newest).
        #[arg(long, value_name = "VERSION")]
        asterisk: Option<String>,
    },
    /// Copy the configured Asterisk headers out of a release's test image
    /// (built first if needed) and print their directory, for
    /// ASTERISK_SOURCE_DIR: export ASTERISK_SOURCE_DIR=$(cargo xtask
    /// headers).
    Headers {
        /// The Asterisk release: a major version or a pinned release
        /// (default: the newest).
        #[arg(long, value_name = "VERSION")]
        asterisk: Option<String>,
    },
    /// Print the pinned major versions as a JSON array (the CI matrix).
    Majors,
    /// The part of test and ci that runs inside the container.
    #[command(hide = true)]
    Inside {
        #[command(subcommand)]
        job: InsideJob,
    },
}

#[derive(Subcommand)]
enum InsideJob {
    /// Run these suites.
    Test { suites: Vec<String> },
    /// The CI job for this release.
    Ci { release: String },
}

/// The repository.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Cargo, as the one that runs the xtask, in the repository.
pub fn cargo() -> Command {
    let mut c = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    c.current_dir(repo_root());
    c
}

/// Runs a command; an error unless it succeeds.
pub fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("running {:?}: {e}", cmd.get_program()))?;
    if !status.success() {
        bail!("{cmd:?} failed ({status})");
    }
    Ok(())
}

fn test(asterisk: Option<String>, original: Option<PathBuf>, names: Vec<String>) -> Result<u8> {
    let suites = suites::selection(&names);
    if let Some(s) = suites.iter().find(|s| suites::target(s).is_none()) {
        println!("unknown suite {s}");
        return Ok(2);
    }
    if let Some(dir) = &original {
        if !dir.is_dir() {
            bail!("--original {}: not a directory", dir.display());
        }
    } else if suites.iter().any(|s| s == "parity") {
        bail!(
            "parity needs the original binaries (res_digium_phone.so and its two PJSIP helpers, \
             24.0_3.6.13; not distributed with dpma-rs): cargo xtask test --original DIR parity"
        );
    }
    let pin = pins::pin(asterisk.as_deref())?;
    let mut args = vec!["test".to_string()];
    args.extend(suites);
    let code = container::run_inside(&pin, &args, original.as_deref())?;
    println!(
        "Asterisk {}; logs in {}",
        pin.version,
        container::out_dir(&pin).join("logs").display()
    );
    Ok(code)
}

fn run_cli(cli: Cli) -> Result<u8> {
    match cli.cmd {
        Cmd::Test {
            asterisk,
            original,
            suites,
        } => return test(asterisk, original, suites),
        Cmd::Ci { asterisk } => {
            let pin = pins::pin(asterisk.as_deref())?;
            return container::run_inside(&pin, &["ci".into(), pin.version.clone()], None);
        }
        Cmd::Headers { asterisk } => {
            let dir = container::headers(&pins::pin(asterisk.as_deref())?)?;
            println!("{}", dir.display());
        }
        Cmd::Majors => {
            let majors: Vec<String> = pins::pins()?.into_iter().map(|p| p.major).collect();
            println!("{}", serde_json::to_string(&majors)?);
        }
        Cmd::Inside { job } => {
            return match job {
                InsideJob::Test { suites } => suites::run_suites(&suites),
                InsideJob::Ci { release } => ci::job(&release),
            }
        }
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run_cli(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("xtask: {e:#}");
            ExitCode::FAILURE
        }
    }
}
