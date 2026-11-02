//! A private Asterisk instance (`DPMA_SLOT`).
//!
//! Instance management (start, stop, installing the module, resetting the
//! configuration, and finding the instance's directories and ports) goes
//! through the instance manager, [`crate::asterisk::Slot`], which
//! `cargo xtask instance` uses too; [`AstTool`] and [`Instance`] wrap
//! it.  Everything else talks to the instance directly: the CLI through
//! its control socket ([`Cli`]), AMI ([`AmiClient`]), and its files.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use bstr::BString;

use super::cli::Cli;
use super::log::Log;
use crate::ami::AmiClient;
use crate::asterisk::Slot;
use crate::sim;

/// The instance manager of one slot, with the commands of `cargo xtask
/// instance` ([`Slot::command`]).
#[derive(Clone, Debug)]
pub struct AstTool {
    slot: Slot,
}

impl AstTool {
    /// The instance manager of `slot`.
    pub fn for_slot(slot: u32) -> Result<AstTool> {
        Ok(AstTool {
            slot: Slot::new(slot)?,
        })
    }

    /// The instance.
    pub fn slot(&self) -> &Slot {
        &self.slot
    }

    /// Runs an instance command (`start`, `stop`, `cli WORDS...`,
    /// `install [PROFILE]`, `reset-conf`, `info`, or `init [VERSION]`; see
    /// [`Slot::command`]) for the slot; returns what it prints.
    pub fn run(&self, args: &[&str]) -> Result<String> {
        let out = Slot::command(self.slot.number(), args)?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// The `key: value` pairs of `info`.
    pub fn info(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .slot
            .info()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect())
    }
}

/// A private Asterisk instance.
#[derive(Clone, Debug)]
pub struct Instance {
    /// The slot number.
    pub slot: u32,
    /// The instance directory (`dev/run/slot<N>`).
    pub dir: PathBuf,
    /// Its configuration directory (`<dir>/etc/asterisk`).
    pub etc: PathBuf,
    /// Its `messages.log`.
    pub messages_log: PathBuf,
    /// Its SIP port.
    pub sip_port: u16,
    /// Its AMI port (user `test`, secret `test`).
    pub ami_port: u16,
    tool: AstTool,
}

impl Instance {
    /// The instance of `$DPMA_SLOT` (an error when it is not set: the
    /// shared install is never used).
    pub fn from_env() -> Result<Instance> {
        Instance::for_slot(crate::asterisk::env_slot()?)
    }

    /// The instance of `slot`.
    pub fn for_slot(slot: u32) -> Result<Instance> {
        let tool = AstTool::for_slot(slot)?;
        let s = tool.slot();
        let etc = s.etc();
        if !etc.is_dir() {
            bail!(
                "no instance configuration in {} (create the instance: cargo xtask instance init {slot} [VERSION])",
                etc.display()
            );
        }
        Ok(Instance {
            slot,
            dir: s.dir().to_path_buf(),
            etc,
            messages_log: s.messages_log(),
            sip_port: s.sip_port(),
            ami_port: s.ami_port(),
            tool,
        })
    }

    /// The instance manager.
    pub fn tool(&self) -> &AstTool {
        &self.tool
    }

    /// A file in the configuration directory.
    pub fn conf(&self, name: &str) -> PathBuf {
        self.etc.join(name)
    }

    /// `<dir>/var/lib/asterisk`.
    pub fn var_lib(&self) -> PathBuf {
        self.dir.join("var").join("lib").join("asterisk")
    }

    /// `<dir>/var/spool/asterisk`.
    pub fn spool(&self) -> PathBuf {
        self.dir.join("var").join("spool").join("asterisk")
    }

    /// The instance's `messages.log`.
    pub fn log(&self) -> Log {
        Log::new(&self.messages_log)
    }

    /// The CLI through the instance's control socket.
    pub fn cli(&self) -> Result<Cli> {
        Cli::from_asterisk_conf(&self.etc.join("asterisk.conf"))
    }

    /// Runs a CLI command (see [`Cli::run`]).
    pub fn cli_run(&self, command: &str) -> Result<BString> {
        self.cli()?.run(command)
    }

    /// Runs a CLI command and returns its output as text (lossy; empty on
    /// errors).
    pub fn cli_text(&self, command: &str) -> String {
        self.cli().map(|c| c.text(command)).unwrap_or_default()
    }

    /// A new AMI connection (logged in as test/test, events on).
    pub fn ami(&self) -> Result<AmiClient> {
        AmiClient::connect(
            "127.0.0.1",
            self.ami_port,
            "test",
            "test",
            true,
            Duration::from_secs(10),
        )
    }

    /// Phone simulator settings for this instance (slot and SIP port).
    pub fn sim_options(&self) -> sim::Options {
        let mut o = sim::Options::for_slot(self.slot);
        o.sip_port = self.sip_port;
        o
    }

    /// Whether Asterisk answers on the control socket.
    pub fn running(&self) -> bool {
        self.cli().is_ok_and(|c| c.alive())
    }

    /// (Re)starts Asterisk and waits until it is fully booted.
    pub fn start(&self) -> Result<()> {
        self.tool.slot().start()?;
        if !crate::util::wait_until(Duration::from_secs(10), Duration::from_millis(200), || {
            self.running()
        }) {
            bail!(
                "Asterisk did not start (see {})",
                self.tool.slot().console_log().display()
            );
        }
        Ok(())
    }

    /// Stops Asterisk (no error when it is not running).
    pub fn stop(&self) -> Result<()> {
        let _ = self.tool.slot().stop();
        Ok(())
    }

    /// Installs the module built in the `debug` or `release` profile
    /// (restart Asterisk to use it).
    pub fn install(&self, profile: &str) -> Result<()> {
        self.tool.slot().install(profile).map(|_| ())
    }

    /// Replaces the instance's configuration with a fresh copy of the
    /// scratch configuration.
    pub fn reset_conf(&self) -> Result<()> {
        self.tool.slot().reset_conf()
    }
}
