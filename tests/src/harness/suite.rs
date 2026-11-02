//! The runner of a test suite: a sequence of parts that share one
//! instance, with libtest-like command-line conventions so that a suite
//! is a Cargo test target (`harness = false`):
//!
//! ```text
//! DPMA_SLOT=<n> cargo test -p dpma-tests --test <suite> -- --ignored [FILTER...]
//! ```
//!
//! Without `--ignored` (or `--include-ignored`), as in a plain `cargo
//! test`, the suite runs nothing and passes: suites need a private
//! instance and restart its Asterisk.  Other arguments:
//!
//! | Argument | Meaning |
//! |---|---|
//! | `FILTER` | Run only the parts whose name contains it (`--exact`: equals it) |
//! | `--list` | List the parts |
//! | `--no-prepare` | Do not prepare the instance (it already is) |
//! | `-v`, `--verbose` | Print details of passing checks and the simulator's diagnostics |
//!
//! A suite's own options that take a value (declared with
//! [`Suite::value_option`], read with [`option_value`]) are given as
//! `--name VALUE` or `--name=VALUE`.  Other unknown arguments
//! (`--nocapture`, `--test-threads=1`, ...) are ignored.  The parts run
//! in the order they were added; each gets its own [`Checker`]; an error
//! returned by a part ends that part and counts as a failure.  The exit
//! status is 0 when every check passed.

use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use bstr::BString;

use super::check::Checker;
use super::instance::Instance;
use super::log::Log;
use crate::ami::AmiClient;
use crate::sim::{self, Output};

/// What a test part gets: the instance, a checker, and an AMI connection.
pub struct Ctx {
    /// The instance.
    pub inst: Instance,
    /// The checks of the current part.
    pub c: Checker,
    /// Whether `-v` was given.
    pub verbose: bool,
    ami: Option<AmiClient>,
}

impl Ctx {
    /// A context for `inst` (for running parts outside a [`Suite`]).
    pub fn new(inst: Instance, verbose: bool) -> Ctx {
        Ctx {
            inst,
            c: Checker::new().verbose(verbose),
            verbose,
            ami: None,
        }
    }

    /// Runs a CLI command through the control socket; its exact output
    /// (empty when Asterisk does not answer).
    pub fn cli(&self, command: &str) -> BString {
        self.inst.cli_run(command).unwrap_or_default()
    }

    /// [`Ctx::cli`] as text (lossy).
    pub fn cli_text(&self, command: &str) -> String {
        self.inst.cli_text(command)
    }

    /// The AMI connection (connected on first use, and again when
    /// Asterisk closed it).
    pub fn ami(&mut self) -> Result<&AmiClient> {
        if self.ami.as_ref().is_none_or(AmiClient::is_closed) {
            self.ami = Some(self.inst.ami()?);
        }
        Ok(self.ami.as_ref().expect("connected"))
    }

    /// Drops the AMI connection (before restarting Asterisk).
    pub fn drop_ami(&mut self) {
        self.ami = None;
    }

    /// Phone simulator settings for the instance: quiet unless `-v`.
    pub fn sim_options(&self) -> sim::Options {
        let mut o = self.inst.sim_options();
        if self.verbose {
            o.output = Output::Stdout;
        } else {
            o = o.quiet();
        }
        o
    }

    /// The instance's `messages.log`.
    pub fn log(&self) -> Log {
        self.inst.log()
    }
}

type PartFn = Box<dyn Fn(&mut Ctx) -> Result<()>>;
type PrepareFn = Box<dyn Fn(&Instance) -> Result<()>>;

/// A test suite: an optional preparation of the instance and the parts.
pub struct Suite {
    name: String,
    prepare: Option<PrepareFn>,
    parts: Vec<(String, PartFn)>,
    value_options: Vec<String>,
}

struct Args {
    run: bool,
    list: bool,
    exact: bool,
    prepare: bool,
    verbose: bool,
    filters: Vec<String>,
}

fn parse_args(args: impl IntoIterator<Item = String>, value_options: &[String]) -> Args {
    let mut a = Args {
        run: false,
        list: false,
        exact: false,
        prepare: true,
        verbose: false,
        filters: Vec::new(),
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ignored" | "--include-ignored" => a.run = true,
            "--list" => a.list = true,
            "--exact" => a.exact = true,
            "--no-prepare" => a.prepare = false,
            "-v" | "--verbose" => a.verbose = true,
            s if value_options.iter().any(|o| o == s) => {
                args.next();
            }
            s if s.starts_with('-') => {}
            s => a.filters.push(s.to_string()),
        }
    }
    a
}

impl Suite {
    /// A suite named `name` (its Cargo test target name).
    pub fn new(name: &str) -> Suite {
        Suite {
            name: name.into(),
            prepare: None,
            parts: Vec::new(),
            value_options: Vec::new(),
        }
    }

    /// Declares an option of the suite that takes a value (`--via
    /// phone`), so that the value is not taken for a filter.  The suite
    /// reads it with [`option_value`].
    pub fn value_option(mut self, name: &str) -> Self {
        self.value_options.push(name.into());
        self
    }

    /// How to prepare the instance before the parts run (skipped with
    /// `--no-prepare`); normally [`super::fixtures::prepare`] with the
    /// suite's setup.
    pub fn prepare(mut self, f: impl Fn(&Instance) -> Result<()> + 'static) -> Self {
        self.prepare = Some(Box::new(f));
        self
    }

    /// Adds a part.
    pub fn part(mut self, name: &str, f: impl Fn(&mut Ctx) -> Result<()> + 'static) -> Self {
        self.parts.push((name.into(), Box::new(f)));
        self
    }

    /// The names of the parts.
    pub fn part_names(&self) -> Vec<&str> {
        self.parts.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Runs the suite as the `main` of a test target (see the module
    /// documentation).
    pub fn main(self) -> ExitCode {
        self.main_with_args(std::env::args().skip(1))
    }

    /// [`Suite::main`] with the arguments given (without the program
    /// name): for a suite that takes options of its own and passes the
    /// rest on.
    pub fn main_with_args(self, args: impl IntoIterator<Item = String>) -> ExitCode {
        let args = parse_args(args, &self.value_options);
        let selected: Vec<&(String, PartFn)> = self
            .parts
            .iter()
            .filter(|(n, _)| {
                args.filters.is_empty()
                    || args.filters.iter().any(|f| {
                        if args.exact {
                            n == f
                        } else {
                            n.contains(f.as_str())
                        }
                    })
            })
            .collect();
        if args.list {
            for (n, _) in &selected {
                println!("{n}: test");
            }
            return ExitCode::SUCCESS;
        }
        if !args.run {
            println!(
                "suite {}: {} parts ignored (it needs a private instance: DPMA_SLOT=<n> cargo test -p dpma-tests --test {} -- --ignored)",
                self.name,
                selected.len(),
                self.name
            );
            return ExitCode::SUCCESS;
        }
        let inst = match Instance::from_env() {
            Ok(i) => i,
            Err(e) => {
                eprintln!("suite {}: {e:#}", self.name);
                return ExitCode::FAILURE;
            }
        };
        println!(
            "suite {}: instance {} (slot {})",
            self.name,
            inst.dir.display(),
            inst.slot
        );
        if let (true, Some(prepare)) = (args.prepare, &self.prepare) {
            println!("\n== prepare");
            let t = Instant::now();
            if let Err(e) = prepare(&inst) {
                println!("FAIL prepare: {e:#}");
                return ExitCode::FAILURE;
            }
            println!("ok   prepare ({} s)", t.elapsed().as_secs());
        }
        let mut ctx = Ctx::new(inst, args.verbose);
        let mut results = Vec::new();
        for (name, f) in selected {
            println!("\n== {name}");
            ctx.c = Checker::new().verbose(args.verbose);
            let t = Instant::now();
            if let Err(e) = f(&mut ctx) {
                ctx.c.fail(format!("{name} stopped"), format!("{e:#}"));
            }
            let c = std::mem::take(&mut ctx.c);
            results.push((name.clone(), c, t.elapsed()));
        }
        println!("\n== summary of suite {}", self.name);
        let mut total = Checker::quiet();
        for (name, c, t) in results {
            let state = if c.passed() { "ok  " } else { "FAIL" };
            println!(
                "{state} {name} ({} checks, {} failed, {} s)",
                c.count(),
                c.failures().len(),
                t.as_secs()
            );
            for f in c.failures() {
                println!("       {f}");
            }
            total.absorb(c);
        }
        println!("{}", total.summary().lines().next().unwrap_or_default());
        if total.passed() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

/// The value of the option `name` (e.g., `--via`) in the command line,
/// given as `name VALUE` or `name=VALUE` (the last one counts); see
/// [`Suite::value_option`].
pub fn option_value(name: &str) -> Option<String> {
    option_value_in(std::env::args().skip(1), name)
}

fn option_value_in(args: impl IntoIterator<Item = String>, name: &str) -> Option<String> {
    let mut args = args.into_iter();
    let mut value = None;
    while let Some(arg) = args.next() {
        if arg == name {
            value = args.next();
        } else if let Some(v) = arg.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
            value = Some(v.to_string());
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn value_options() {
        let a = parse_args(
            args("--ignored --via phone get --no-prepare"),
            &["--via".into()],
        );
        assert!(a.run && !a.prepare);
        assert_eq!(a.filters, ["get"]);
        let a = parse_args(args("--via=http list"), &["--via".into()]);
        assert_eq!(a.filters, ["list"]);
        assert_eq!(
            option_value_in(args("x --via phone y"), "--via").as_deref(),
            Some("phone")
        );
        assert_eq!(
            option_value_in(args("--via=http"), "--via").as_deref(),
            Some("http")
        );
        assert_eq!(option_value_in(args("--viaduct x"), "--via"), None);
        assert_eq!(option_value_in(args("--via"), "--via"), None);
    }
}
