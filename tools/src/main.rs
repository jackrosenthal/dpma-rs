//! `cargo xtask`: the development tasks of dpma-rs (see `tests/README.md`).
//!
//! ```text
//! cargo xtask test [--asterisk VERSION] [-j N] [SUITE... | all]
//! cargo xtask ci [--asterisk VERSION] [-j N]
//! cargo xtask headers [--asterisk VERSION]
//! cargo xtask majors
//! ```
//!
//! A VERSION is a major version (`22`) or a release (`22.11.0`) pinned in
//! `tools/asterisk-versions`; the default is the newest.  `test` and `ci`
//! run in fresh containers of the release's test image ([`container`]):
//! one builds, then every suite runs in one of its own ([`suites`]).
//! `cargo xtask inside` (hidden) does the work inside.

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
    /// Run test suites, each in a fresh container of a pinned release's
    /// test image (built first if needed), several at a time.
    ///
    /// Suites (default, or "all": all of these, in this order): session
    /// config-xml users-runtime methods-vm methods-calls pjsip-helpers
    /// request-handlers ami apps-discovery raw-bytes.  Each suite's output
    /// goes to target/container/<release>/logs/<suite>.log.  Exit status 0
    /// when every suite passes.
    Test {
        /// The Asterisk release: a major version or a pinned release
        /// (default: the newest).
        #[arg(long, value_name = "VERSION")]
        asterisk: Option<String>,
        /// Suites that run at the same time, each in its own container
        /// (default: the number of CPUs).
        #[arg(short, long, value_name = "N")]
        jobs: Option<usize>,
        /// Suites to run, or "all".
        suites: Vec<String>,
    },
    /// The CI job: in containers of the release's test image, build,
    /// lint, and test dpma-rs, run every suite, and build, check, and
    /// smoke-test the module for publishing
    /// (target/container/<release>/res_dpma_rs-asterisk<major>-<arch>.so).
    Ci {
        /// The Asterisk release: a major version or a pinned release
        /// (default: the newest).
        #[arg(long, value_name = "VERSION")]
        asterisk: Option<String>,
        /// Suites that run at the same time, each in its own container
        /// (default: the number of CPUs).
        #[arg(short, long, value_name = "N")]
        jobs: Option<usize>,
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
    /// Build the devtest module and these suites' test binaries.
    Build { suites: Vec<String> },
    /// CI: build, lint, and test dpma-rs.
    Check { release: String },
    /// CI: build, check, and smoke-test the module for publishing.
    Publish { release: String },
}

/// The number of suites that run at the same time: `jobs`, else the
/// number of CPUs.
fn jobs(jobs: Option<usize>) -> usize {
    jobs.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
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

fn test(asterisk: Option<String>, jobs: usize, names: Vec<String>) -> Result<u8> {
    let suites = suites::selection(&names);
    if let Some(s) = suites.iter().find(|s| suites::target(s).is_none()) {
        println!("unknown suite {s}");
        return Ok(2);
    }
    let pin = pins::pin(asterisk.as_deref())?;
    let run = container::Run::new(&pin)?;
    let code = suites::run_suites(&run, &container::out_dir(&pin), &suites, jobs)?;
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
            jobs: j,
            suites,
        } => return test(asterisk, jobs(j), suites),
        Cmd::Ci { asterisk, jobs: j } => {
            return ci::ci(&pins::pin(asterisk.as_deref())?, jobs(j));
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
                InsideJob::Build { suites } => suites::build(&suites),
                InsideJob::Check { release } => ci::check(&release),
                InsideJob::Publish { release } => ci::publish(&release),
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
