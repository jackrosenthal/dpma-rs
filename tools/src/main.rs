//! `cargo xtask`: the development tasks of dpma-rs (see `tests/README.md`).
//!
//! ```text
//! cargo xtask asterisk build [-j N] [--install] <VERSION>
//! cargo xtask asterisk info <VERSION>
//! cargo xtask asterisk majors
//! cargo xtask instance init [SLOT] [VERSION]
//! cargo xtask instance <install [debug|release] | start | stop | cli COMMAND... | reset-conf | info>
//! cargo xtask instance sim-setup [--remove]
//! cargo xtask test [SUITE... | all]
//! cargo xtask ci setup
//! cargo xtask ci job <VERSION>
//! ```
//!
//! A VERSION is a major version (`22`) or a release (`22.11.0`) pinned in
//! `tools/asterisk-versions`.  The instance commands and `test` work on
//! the private instance of `$DPMA_SLOT` (`dpma_tests::asterisk`).

// The doc comments below are the command-line help (clap), not rustdoc.
#![allow(rustdoc::invalid_html_tags)]

mod build;
mod ci;
mod suites;

use std::io::Write;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dpma_tests::asterisk::{self, Slot};
use dpma_tests::harness::{fixtures, Instance};

#[derive(Parser)]
#[command(
    name = "cargo xtask",
    bin_name = "cargo xtask",
    about = "Development tasks for dpma-rs: Asterisk builds, private instances, the test suites, and CI."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// The pinned Asterisk releases (tools/asterisk-versions).
    Asterisk {
        #[command(subcommand)]
        cmd: AsteriskCmd,
    },
    /// The private Asterisk instance of $DPMA_SLOT (dev/run/slot<N>).
    Instance {
        #[command(subcommand)]
        cmd: InstanceCmd,
    },
    /// Build the devtest module and run test suites against the instance
    /// of $DPMA_SLOT, one after another.
    ///
    /// Suites (default: all of these, in this order): session config-xml
    /// users-runtime methods-vm methods-vm-phone methods-calls
    /// methods-calls-phone methods-calls-http pjsip-helpers
    /// request-handlers ami apps-discovery raw-bytes.  "all" runs these
    /// and then ami-expiry (about six minutes); parity runs only when
    /// named.  Each suite's output goes to $LOGDIR/<suite>.log (default
    /// $LOGDIR: a new temporary directory).  Exit status 0 when every
    /// suite passes.
    Test {
        /// Suites to run, or "all".
        suites: Vec<String>,
    },
    /// The CI job of .github/workflows/ci.yml, which runs the same way
    /// locally.
    Ci {
        #[command(subcommand)]
        cmd: CiCmd,
    },
}

#[derive(Subcommand)]
enum AsteriskCmd {
    /// Download, verify, configure, and optionally build and install a
    /// pinned release into $DPMA_AST_BUILDS (default dev/asterisk-builds).
    ///
    /// Without --install the source tree is configured and its headers
    /// generated, ready for ASTERISK_SOURCE_DIR=<builds>/<release>/src.
    /// With --install it is also built and installed, with the sample
    /// configuration and tools/asterisk-conf/ on top, into
    /// <builds>/<release>/prefix.  Steps already done are skipped.
    Build {
        /// Parallel make jobs (default: the number of CPUs).
        #[arg(short = 'j', long = "jobs", value_name = "N")]
        jobs: Option<usize>,
        /// Also build and install it.
        #[arg(long)]
        install: bool,
        /// A major version or a pinned release.
        version: String,
    },
    /// Print major=, version=, sha256=, src=, and prefix= lines.
    Info {
        /// A major version or a pinned release.
        version: String,
    },
    /// Print the pinned major versions as a JSON array (the CI matrix).
    Majors,
}

#[derive(Subcommand)]
enum InstanceCmd {
    /// Create the instance of SLOT (default $DPMA_SLOT) for a release
    /// (default $DPMA_AST_VERSION, else the newest pinned release).
    Init {
        /// The slot (1 to 50).
        slot: Option<u32>,
        /// A major version or a pinned release.
        version: Option<String>,
    },
    /// Copy target/<PROFILE>/libres_dpma_rs.so into the instance as
    /// res_dpma_rs.so (restart Asterisk to use it) and remove the
    /// original modules from it.
    Install {
        /// The Cargo profile.
        #[arg(default_value = "debug", value_parser = ["debug", "release"])]
        profile: String,
    },
    /// (Re)start Asterisk and wait until it is fully booted.
    Start,
    /// Stop Asterisk.
    Stop,
    /// Run a CLI command and print its output.
    Cli {
        /// The command (its words are joined with spaces).
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Replace the configuration with a fresh copy of the scratch
    /// configuration (test setups and trust material are gone
    /// afterwards).
    ResetConf,
    /// Print the instance's directories, install, logs, and ports.
    Info,
    /// Install the simulator setup: the test PKI's trust material (made
    /// in dev/sim/pki if needed) and the simulator's test configuration
    /// (reload or restart Asterisk afterwards).
    SimSetup {
        /// Take the simulator's test configuration out instead.
        #[arg(long)]
        remove: bool,
    },
}

#[derive(Subcommand)]
enum CiCmd {
    /// Install what the job needs on Ubuntu (as root; runs itself through
    /// sudo otherwise) and allow unprivileged user namespaces.
    Setup,
    /// The CI job for one release: build and install it, build, lint,
    /// and test dpma-rs against it, create the instance of $DPMA_SLOT
    /// afresh, and run every suite.
    Job {
        /// A major version or a pinned release.
        version: String,
    },
}

fn out(bytes: &[u8]) -> Result<()> {
    let mut o = std::io::stdout().lock();
    o.write_all(bytes)?;
    o.flush()?;
    Ok(())
}

fn instance(cmd: InstanceCmd) -> Result<()> {
    let (slot, args): (u32, Vec<String>) = match cmd {
        InstanceCmd::Init { slot, version } => {
            let slot = match slot {
                Some(s) => s,
                None => asterisk::env_slot()?,
            };
            (
                slot,
                ["init".to_string()].into_iter().chain(version).collect(),
            )
        }
        InstanceCmd::Install { profile } => {
            (asterisk::env_slot()?, vec!["install".into(), profile])
        }
        InstanceCmd::Start => (asterisk::env_slot()?, vec!["start".into()]),
        InstanceCmd::Stop => (asterisk::env_slot()?, vec!["stop".into()]),
        InstanceCmd::Cli { command } => (
            asterisk::env_slot()?,
            ["cli".to_string()].into_iter().chain(command).collect(),
        ),
        InstanceCmd::ResetConf => (asterisk::env_slot()?, vec!["reset-conf".into()]),
        InstanceCmd::Info => (asterisk::env_slot()?, vec!["info".into()]),
        InstanceCmd::SimSetup { remove } => {
            let inst = Instance::from_env()?;
            if remove {
                fixtures::remove_sim_conf(&inst)?;
                println!(
                    "removed the simulator's test configuration from {}",
                    inst.dir.display()
                );
            } else {
                fixtures::sim_setup(&inst)?;
                println!("installed the simulator setup into {}", inst.dir.display());
            }
            return Ok(());
        }
    };
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    out(&Slot::command(slot, &args)?)
}

fn run(cli: Cli) -> Result<u8> {
    match cli.cmd {
        Cmd::Asterisk { cmd } => match cmd {
            AsteriskCmd::Build {
                jobs,
                install,
                version,
            } => build::Build::new(&version)?.run(jobs, install)?,
            AsteriskCmd::Info { version } => out(build::Build::new(&version)?.info().as_bytes())?,
            AsteriskCmd::Majors => {
                let majors: Vec<String> = asterisk::versions::pins()?
                    .into_iter()
                    .map(|p| p.major)
                    .collect();
                println!("{}", serde_json::to_string(&majors)?);
            }
        },
        Cmd::Instance { cmd } => instance(cmd)?,
        Cmd::Test { suites } => return suites::run(&suites),
        Cmd::Ci { cmd } => match cmd {
            CiCmd::Setup => ci::setup()?,
            CiCmd::Job { version } => return ci::job(&version),
        },
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("xtask: {e:#}");
            ExitCode::FAILURE
        }
    }
}
