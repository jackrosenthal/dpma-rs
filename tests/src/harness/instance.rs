//! A private Asterisk instance (`DPMA_SLOT`).
//!
//! Instance management (start, stop, installing the module, resetting the
//! configuration, and finding the instance's directories and ports) goes
//! through the instance manager script, `dev/tools/ast.sh` (or
//! `tools/ast.sh`), and only through [`AstTool`] in this module, so that
//! replacing the script touches nothing else.  Everything else talks to
//! the instance directly: the CLI through its control socket
//! ([`Cli`]), AMI ([`AmiClient`]), and its files.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bstr::BString;

use super::cli::Cli;
use super::log::Log;
use crate::ami::AmiClient;
use crate::sim::{self, repo_root};

/// The instance manager script: the one place that runs it.
#[derive(Clone, Debug)]
pub struct AstTool {
    script: PathBuf,
    slot: u32,
}

impl AstTool {
    /// The script for `slot`: `$DPMA_AST` if set, else `tools/ast.sh` or
    /// `dev/tools/ast.sh` in the repository.
    pub fn for_slot(slot: u32) -> Result<AstTool> {
        let script = match std::env::var_os("DPMA_AST") {
            Some(p) => PathBuf::from(p),
            None => {
                let root = repo_root();
                [
                    root.join("tools").join("ast.sh"),
                    root.join("dev").join("tools").join("ast.sh"),
                ]
                .into_iter()
                .find(|p| p.exists())
                .ok_or_else(|| {
                    anyhow!(
                        "no ast.sh in {}/tools or {}/dev/tools",
                        root.display(),
                        root.display()
                    )
                })?
            }
        };
        Ok(AstTool { script, slot })
    }

    /// Runs `ast.sh ARGS...` for the slot; returns its standard output.
    pub fn run(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.script)
            .args(args)
            .env("DPMA_SLOT", self.slot.to_string())
            .output()
            .with_context(|| format!("running {}", self.script.display()))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() {
            bail!(
                "{} {} failed ({}): {}{}",
                self.script.display(),
                args.join(" "),
                out.status,
                stdout,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(stdout)
    }

    /// The `key: value` lines of `ast.sh info`.
    pub fn info(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .run(&["info"])?
            .lines()
            .filter_map(|l| {
                l.split_once(':')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
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

fn port_of(addr: &str) -> Option<u16> {
    addr.split_whitespace()
        .next()?
        .rsplit(':')
        .next()?
        .parse()
        .ok()
}

impl Instance {
    /// The instance of `$DPMA_SLOT` (an error when it is not set: the
    /// shared install is never used).
    pub fn from_env() -> Result<Instance> {
        let slot = std::env::var("DPMA_SLOT")
            .map_err(|_| anyhow!("DPMA_SLOT is not set (never use the shared install)"))?;
        Instance::for_slot(
            slot.trim()
                .parse()
                .with_context(|| format!("DPMA_SLOT={slot}"))?,
        )
    }

    /// The instance of `slot`, as `ast.sh info` describes it.
    pub fn for_slot(slot: u32) -> Result<Instance> {
        let tool = AstTool::for_slot(slot)?;
        let info = tool.info()?;
        let get = |k: &str| {
            info.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        let dir =
            PathBuf::from(get("instance").ok_or_else(|| anyhow!("ast.sh info: no instance"))?);
        let conf = get("config")
            .map(PathBuf::from)
            .unwrap_or_else(|| dir.join("etc/asterisk/asterisk.conf"));
        let etc = conf
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| dir.join("etc/asterisk"));
        let messages_log = get("messages")
            .map(PathBuf::from)
            .unwrap_or_else(|| dir.join("var/log/asterisk/messages.log"));
        let sip_port = get("SIP")
            .and_then(|v| port_of(&v))
            .unwrap_or_else(|| sim::sip_port_for(Some(slot)));
        let ami_port = get("AMI")
            .and_then(|v| port_of(&v))
            .unwrap_or_else(|| sim::ami_port_for(Some(slot)));
        if !etc.is_dir() {
            bail!(
                "no instance configuration in {} (create the instance: ast.sh init {slot})",
                etc.display()
            );
        }
        Ok(Instance {
            slot,
            dir,
            etc,
            messages_log,
            sip_port,
            ami_port,
            tool,
        })
    }

    /// The instance manager script.
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
        self.tool.run(&["start"])?;
        if !crate::util::wait_until(Duration::from_secs(10), Duration::from_millis(200), || {
            self.running()
        }) {
            bail!(
                "Asterisk did not start (see {})",
                self.dir.join("ast-console.log").display()
            );
        }
        Ok(())
    }

    /// Stops Asterisk (no error when it is not running).
    pub fn stop(&self) -> Result<()> {
        let _ = self.tool.run(&["stop"]);
        Ok(())
    }

    /// Installs the module built in the `debug` or `release` profile
    /// (restart Asterisk to use it).
    pub fn install(&self, profile: &str) -> Result<()> {
        self.tool.run(&["install", profile]).map(|_| ())
    }

    /// Replaces the instance's configuration with a fresh copy of the
    /// scratch configuration.
    pub fn reset_conf(&self) -> Result<()> {
        self.tool.run(&["reset-conf"]).map(|_| ())
    }
}
