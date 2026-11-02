//! What the test suites share: the instance and its CLI, check
//! reporting, the log, configuration editing, the suite runner, and
//! fixtures.
//!
//! A suite is a Cargo test target (`harness = false`) whose `main` builds
//! a [`Suite`] of parts:
//!
//! ```no_run
//! use dpma_tests::harness::{fixtures, Ctx, Suite};
//!
//! fn ping(ctx: &mut Ctx) -> anyhow::Result<()> {
//!     let phone = fixtures::phone(ctx.sim_options())?;
//!     let ex = phone.ping().send()?;
//!     ctx.c.exchange("ping", &ex).ty("PingResponse").no_error();
//!     Ok(())
//! }
//!
//! fn main() -> std::process::ExitCode {
//!     Suite::new("example")
//!         .prepare(|inst| fixtures::prepare(inst, fixtures::sim_setup))
//!         .part("ping", ping)
//!         .main()
//! }
//! ```
//!
//! The suites run inside the test container (`cargo xtask test`), against
//! its Asterisk ([`Instance`]); the CLI goes through the control socket
//! ([`Cli`]).

mod check;
mod cli;
mod conf;
mod expect;
pub mod fixtures;
mod instance;
mod log;
pub mod setup;
mod suite;

pub use check::{contains_bytes, regex_capture, regex_search, Checker};
pub use cli::{filter_verbose, Cli};
pub use conf::{ConfBackup, ConfFile};
pub use expect::{AmiCheck, ExchangeCheck};
pub use instance::{Instance, AMI_PORT, DIR, ORIGINAL_MODULES, SCRATCH_CONF, SIP_PORT};
pub use log::{Log, LogMark};
pub use suite::{option_value, Ctx, Suite};
