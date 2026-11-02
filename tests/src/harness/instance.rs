//! The test instance: the Asterisk of the test container (see
//! [`Instance`]).

use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bstr::{BString, ByteSlice};

use super::cli::Cli;
use super::log::Log;
use crate::ami::AmiClient;
use crate::sim;

/// The instance: Asterisk's install in the test container.
pub const DIR: &str = "/opt/asterisk";

/// The scratch configuration, which [`Instance::reset_conf`] copies into
/// the instance.
pub const SCRATCH_CONF: &str = "/opt/asterisk-conf";

/// The instance's SIP port (UDP and, with the simulator setup, TCP).
pub const SIP_PORT: u16 = 15060;

/// The instance's AMI port (user `test`, secret `test`).
pub const AMI_PORT: u16 = 15038;

/// How long [`Instance::start`] waits for Asterisk to boot, and
/// [`Instance::stop`] for it to exit.
const START_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// The test instance: the Asterisk of the test container.
///
/// The suites run inside a container of the test image
/// (`tools/Containerfile`, which `cargo xtask test` builds and starts).
/// The image holds one pinned Asterisk release installed with
/// `--prefix=/opt/asterisk` ([`DIR`]), and that install is the instance:
/// its configuration, AstDB, spool, logs, and module directory are
/// writable by every user, since the tests run as the host user's user ID.
/// [`Instance::reset_conf`] copies the scratch configuration
/// ([`SCRATCH_CONF`]: the samples with `tools/asterisk-conf/` and a few
/// edits on top) into `etc/asterisk`.
///
/// The container has a network namespace of its own whose only interface
/// is `lo`, so the ports are fixed: SIP on 127.0.0.1:15060 ([`SIP_PORT`])
/// and AMI on 127.0.0.1:15038 ([`AMI_PORT`], user `test`, secret `test`).
/// The CLI goes through the control socket ([`Cli`]); Asterisk's console
/// output goes to `/opt/asterisk/ast-console.log` while it runs.
#[derive(Clone, Debug)]
pub struct Instance {
    /// The instance directory, [`DIR`].
    pub dir: PathBuf,
    /// Its configuration directory (`<dir>/etc/asterisk`).
    pub etc: PathBuf,
    /// Its `messages.log`.
    pub messages_log: PathBuf,
    /// Its SIP port, [`SIP_PORT`].
    pub sip_port: u16,
    /// Its AMI port, [`AMI_PORT`] (user `test`, secret `test`).
    pub ami_port: u16,
}

/// Whether `pid` is a live process (not a zombie).
fn pid_alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => false,
        Ok(stat) => stat
            .rfind(')')
            .and_then(|i| stat[i + 1..].split_whitespace().next())
            .is_some_and(|state| state != "Z" && state != "X"),
    }
}

/// The value of `key => value` (or `key = value`) in `asterisk.conf`.
fn conf_value(conf: &Path, key: &str) -> Option<String> {
    let text = fs::read(conf).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim_ascii();
        if line.starts_with(b";") {
            return None;
        }
        let i = line.find_byte(b'=')?;
        if !line[..i].trim_ascii().eq_ignore_ascii_case(key.as_bytes()) {
            return None;
        }
        let mut v = &line[i + 1..];
        if v.first() == Some(&b'>') {
            v = &v[1..];
        }
        Some(v.trim_ascii().to_str_lossy().into_owned())
    })
}

/// Copies `src` to `dst` recursively, as `cp -a` does for regular files,
/// directories, and symbolic links (permissions kept; other file types
/// are skipped).  Existing directories are merged into.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src).with_context(|| src.display().to_string())?;
    let t = meta.file_type();
    if t.is_symlink() {
        let target = fs::read_link(src)?;
        std::os::unix::fs::symlink(&target, dst).with_context(|| dst.display().to_string())?;
    } else if t.is_dir() {
        fs::create_dir_all(dst).with_context(|| dst.display().to_string())?;
        for e in fs::read_dir(src).with_context(|| src.display().to_string())? {
            let e = e?;
            copy_tree(&e.path(), &dst.join(e.file_name()))?;
        }
        fs::set_permissions(dst, meta.permissions())?;
    } else if t.is_file() {
        fs::copy(src, dst).with_context(|| format!("copying {}", src.display()))?;
    }
    Ok(())
}

impl Instance {
    /// The test instance; an error outside the test container.
    pub fn new() -> Result<Instance> {
        let dir = PathBuf::from(DIR);
        if !dir.join("sbin").join("asterisk").is_file() {
            bail!(
                "no Asterisk in {DIR}: the suites run inside the test container (cargo xtask test [SUITE...])"
            );
        }
        Ok(Instance {
            etc: dir.join("etc").join("asterisk"),
            messages_log: dir.join("var/log/asterisk/messages.log"),
            sip_port: SIP_PORT,
            ami_port: AMI_PORT,
            dir,
        })
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

    /// The module directory: `astmoddir` of the instance's
    /// `asterisk.conf` (default `<dir>/lib/asterisk/modules`).
    pub fn modules_dir(&self) -> PathBuf {
        conf_value(&self.conf("asterisk.conf"), "astmoddir")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.dir.join("lib").join("asterisk").join("modules"))
    }

    /// Asterisk's console output while it runs (`<dir>/ast-console.log`).
    pub fn console_log(&self) -> PathBuf {
        self.dir.join("ast-console.log")
    }

    /// The instance's `messages.log`.
    pub fn log(&self) -> Log {
        Log::new(&self.messages_log)
    }

    /// The CLI through the instance's control socket.
    pub fn cli(&self) -> Result<Cli> {
        Cli::from_asterisk_conf(&self.conf("asterisk.conf"))
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

    /// Phone simulator settings for this instance (its SIP port).
    pub fn sim_options(&self) -> sim::Options {
        sim::Options {
            sip_port: self.sip_port,
            ..sim::Options::default()
        }
    }

    /// Whether Asterisk answers on the control socket.
    pub fn running(&self) -> bool {
        self.cli().is_ok_and(|c| c.alive())
    }

    fn pid(&self) -> Option<u32> {
        let run = conf_value(&self.conf("asterisk.conf"), "astrundir")?;
        let text = fs::read_to_string(Path::new(&run).join("asterisk.pid")).ok()?;
        text.trim().parse().ok()
    }

    /// The instance's `asterisk` binary.
    fn binary(&self) -> PathBuf {
        self.dir.join("sbin").join("asterisk")
    }

    /// A command running the instance's `asterisk`, with `<dir>/lib` first
    /// in `LD_LIBRARY_PATH`.
    fn command(&self) -> Command {
        let mut ld = self.dir.join("lib").into_os_string();
        if let Some(old) = std::env::var_os("LD_LIBRARY_PATH").filter(|v| !v.is_empty()) {
            ld.push(":");
            ld.push(old);
        }
        let mut c = Command::new(self.binary());
        c.env("LD_LIBRARY_PATH", ld);
        c
    }

    /// The Asterisk release, e.g., `22.11.0` (`asterisk -V`, which needs no
    /// running Asterisk).
    pub fn release(&self) -> Result<String> {
        let out = self
            .command()
            .arg("-V")
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("running {} -V", self.binary().display()))?;
        let text = out.stdout.to_str_lossy();
        text.trim()
            .strip_prefix("Asterisk ")
            .filter(|v| !v.is_empty() && !v.contains(char::is_whitespace))
            .map(str::to_string)
            .with_context(|| format!("unexpected `asterisk -V` output: {:?}", text))
    }

    /// (Re)starts Asterisk in the background (`asterisk -g -f -n`, its
    /// console output in [`Instance::console_log`], in a process group of
    /// its own) and waits until it is fully booted.
    pub fn start(&self) -> Result<()> {
        let conf = self.conf("asterisk.conf");
        if !conf.is_file() {
            bail!("no configuration in {}", self.etc.display());
        }
        self.shutdown()?;
        let _ = fs::remove_file(&self.messages_log);
        if let Some(run) = conf_value(&conf, "astrundir") {
            let _ = fs::create_dir_all(run);
        }
        let log_path = self.console_log();
        let log = File::create(&log_path).with_context(|| log_path.display().to_string())?;
        let binary = self.binary();
        let mut child = self
            .command()
            .arg("-C")
            .arg(&conf)
            .args(["-g", "-f", "-n"])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .process_group(0)
            .spawn()
            .with_context(|| format!("starting {}", binary.display()))?;
        // Reap it when it exits, so that it never lingers as a zombie of
        // a long-running caller (a suite restarts Asterisk many times).
        let exited = Arc::new(AtomicBool::new(false));
        {
            let exited = exited.clone();
            std::thread::spawn(move || {
                let _ = child.wait();
                exited.store(true, Ordering::SeqCst);
            });
        }
        let cli = self.cli()?.timeout(START_TIMEOUT);
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if exited.load(Ordering::SeqCst) {
                bail!(
                    "Asterisk exited while starting (see {})",
                    log_path.display()
                );
            }
            if cli
                .run("core waitfullybooted")
                .is_ok_and(|o| o.contains_str("fully booted"))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "Asterisk did not boot in {} s (see {})",
                    START_TIMEOUT.as_secs(),
                    log_path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stops Asterisk (`core stop now`) and waits until its process has
    /// exited (no error when it is not running, or does not stop).
    pub fn stop(&self) -> Result<()> {
        let _ = self.shutdown();
        Ok(())
    }

    /// [`Instance::stop`], but an error when Asterisk does not stop in
    /// time.
    fn shutdown(&self) -> Result<()> {
        let Ok(cli) = self.cli() else {
            return Ok(());
        };
        let cli = cli.timeout(STOP_TIMEOUT);
        let pid = self.pid();
        if cli.run("core stop now").is_err() {
            return Ok(());
        }
        let stopped =
            crate::util::wait_until(STOP_TIMEOUT, Duration::from_millis(20), || match pid {
                Some(p) => !pid_alive(p),
                None => !cli.alive(),
            });
        if !stopped {
            bail!(
                "Asterisk{} did not stop in {} s",
                pid.map(|p| format!(" (pid {p})")).unwrap_or_default(),
                STOP_TIMEOUT.as_secs()
            );
        }
        Ok(())
    }

    /// The module build of a Cargo profile:
    /// `<target>/<profile>/libres_dpma_rs.so`, where `<target>` is
    /// `$CARGO_TARGET_DIR` (as Cargo uses it), else `target` in the
    /// repository.
    pub fn module_build(profile: &str) -> PathBuf {
        std::env::var_os("CARGO_TARGET_DIR")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| sim::repo_root().join("target"))
            .join(profile)
            .join("libres_dpma_rs.so")
    }

    /// Installs the module built in `profile` (`debug` or `release`) as
    /// `res_dpma_rs.so` in the module directory, by copying it to a
    /// temporary file and renaming that into place (so that a running
    /// Asterisk is not hurt; restart it to use the new build).
    pub fn install(&self, profile: &str) -> Result<()> {
        let src = Instance::module_build(profile);
        if !src.is_file() {
            bail!(
                "no module build {} (cargo build{} -p res_dpma_rs --features devtest)",
                src.display(),
                if profile == "release" {
                    " --release"
                } else {
                    ""
                }
            );
        }
        let m = self.modules_dir();
        let dest = m.join("res_dpma_rs.so");
        let tmp = m.join(format!("res_dpma_rs.so.new.{}", std::process::id()));
        fs::copy(&src, &tmp).with_context(|| format!("copying {}", src.display()))?;
        fs::rename(&tmp, &dest).with_context(|| dest.display().to_string())?;
        Ok(())
    }

    /// Replaces the instance's configuration with a fresh copy of the
    /// scratch configuration ([`SCRATCH_CONF`]; test setups and trust
    /// material are gone afterwards).
    pub fn reset_conf(&self) -> Result<()> {
        if self.etc.exists() {
            fs::remove_dir_all(&self.etc).with_context(|| self.etc.display().to_string())?;
        }
        copy_tree(Path::new(SCRATCH_CONF), &self.etc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::fixtures::TempDir;

    #[test]
    fn processes() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(u32::MAX));
    }

    #[test]
    fn asterisk_conf_values() {
        let dir = TempDir::new("dpma-instance-test").unwrap();
        let conf = dir.path().join("asterisk.conf");
        fs::write(
            &conf,
            "[directories]\n;astrundir => /no\nastetcdir => /etc/x\nastrundir => /tmp/r \n",
        )
        .unwrap();
        assert_eq!(conf_value(&conf, "astrundir").as_deref(), Some("/tmp/r"));
        assert_eq!(conf_value(&conf, "astetcdir").as_deref(), Some("/etc/x"));
        assert_eq!(conf_value(&conf, "astlogdir"), None);
    }

    #[test]
    fn tree_copies() {
        let dir = TempDir::new("dpma-copy-tree").unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("d")).unwrap();
        fs::write(src.join("d/f"), b"x").unwrap();
        std::os::unix::fs::symlink("d/f", src.join("l")).unwrap();
        copy_tree(&src, &dir.path().join("dst")).unwrap();
        assert_eq!(fs::read(dir.path().join("dst/d/f")).unwrap(), b"x");
        assert_eq!(
            fs::read_link(dir.path().join("dst/l")).unwrap(),
            Path::new("d/f")
        );
    }
}
