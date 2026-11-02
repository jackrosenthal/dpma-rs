//! The instance manager: creating, configuring, starting, and stopping a
//! private Asterisk instance (see the [module documentation](super)).

use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bstr::ByteSlice;

use super::versions::{self, builds_dir};
use super::{copy_tree, edit_lines};
use crate::harness::Cli;
use crate::sim::{ami_port_for, repo_root, sip_port_for};

/// The highest slot number.
pub const MAX_SLOT: u32 = 50;

/// The modules of the original distribution, which `install` removes
/// from the instance: Asterisk would load them next to `res_dpma_rs.so`.
pub const ORIGINAL_MODULES: [&str; 3] = [
    "res_digium_phone.so",
    "res_pjsip_endpoint_identifier_dpma.so",
    "res_pjsip_dialog_info_digium_body_supplement.so",
];

/// How long `start` waits for Asterisk to boot, and `stop` for it to
/// exit.
const START_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// A private Asterisk instance, `dev/run/slot<N>` (which need not exist
/// yet): its directories, ports, and Asterisk release.
#[derive(Clone, Debug)]
pub struct Slot {
    number: u32,
    dir: PathBuf,
    version: Option<String>,
    home: Option<PathBuf>,
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// `dev/run/slot<n>` in the repository.
pub fn slot_dir(n: u32) -> PathBuf {
    repo_root().join("dev").join("run").join(format!("slot{n}"))
}

fn check_number(n: u32) -> Result<()> {
    if !(1..=MAX_SLOT).contains(&n) {
        bail!("instance slot {n} is out of range (1 to {MAX_SLOT})");
    }
    Ok(())
}

/// The slot of `$DPMA_SLOT`.
pub fn env_slot() -> Result<u32> {
    let v = std::env::var("DPMA_SLOT")
        .map_err(|_| anyhow!("DPMA_SLOT is not set (never use the shared install)"))?;
    v.trim()
        .parse()
        .with_context(|| format!("DPMA_SLOT={v} is not a slot number"))
}

/// The install of a release: `$DPMA_AST_HOME`, else
/// `<builds>/<release>/prefix`.
fn home_of(version: Option<&str>) -> Option<PathBuf> {
    match nonempty_env("DPMA_AST_HOME") {
        Some(h) => Some(std::path::absolute(&h).unwrap_or_else(|_| h.into())),
        None => version.map(|v| builds_dir().join(v).join("prefix")),
    }
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

impl Slot {
    /// The instance of slot `n`.  Its release is the one it recorded in
    /// `asterisk-version`; `$DPMA_AST_VERSION`, when set, must name the
    /// same.  For an instance that does not exist yet, the release is
    /// `$DPMA_AST_VERSION`, else the newest pinned one.
    pub fn new(n: u32) -> Result<Slot> {
        check_number(n)?;
        let dir = slot_dir(n);
        let wanted = match nonempty_env("DPMA_AST_VERSION") {
            Some(v) => Some(versions::pin(v.trim())?.version),
            None => None,
        };
        let version = if dir.join("etc").join("asterisk").is_dir() {
            let recorded = fs::read_to_string(dir.join("asterisk-version"))
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            if let Some(want) = wanted {
                if recorded.as_deref() != Some(want.as_str()) {
                    bail!(
                        "{} is an instance of {}, not of Asterisk {want} (DPMA_AST_VERSION)",
                        dir.display(),
                        recorded.map_or("no recorded release".into(), |r| format!("Asterisk {r}"))
                    );
                }
            }
            recorded
        } else {
            Some(match wanted {
                Some(v) => v,
                None => versions::newest()?.version,
            })
        };
        let home = home_of(version.as_deref());
        Ok(Slot {
            number: n,
            dir,
            version,
            home,
        })
    }

    /// The instance of `$DPMA_SLOT`.
    pub fn from_env() -> Result<Slot> {
        Slot::new(env_slot()?)
    }

    /// Creates the instance of slot `n` for `version` (a major version or
    /// a release; default `$DPMA_AST_VERSION`, else the newest pinned
    /// release): a copy of the release's install (`var` and the module
    /// directory), the scratch configuration rewritten for the instance
    /// ([`Slot::reset_conf`]), and the release recorded in
    /// `asterisk-version`.  The directory must not exist.
    pub fn init(n: u32, version: Option<&str>) -> Result<Slot> {
        check_number(n)?;
        let pin = match version
            .map(str::to_string)
            .or_else(|| nonempty_env("DPMA_AST_VERSION"))
        {
            Some(v) => versions::pin(v.trim())?,
            None => versions::newest()?,
        };
        let dir = slot_dir(n);
        if fs::symlink_metadata(&dir).is_ok() {
            bail!("{} already exists", dir.display());
        }
        let slot = Slot {
            number: n,
            dir,
            home: home_of(Some(&pin.version)),
            version: Some(pin.version),
        };
        let home = slot.home()?.to_path_buf();
        let a = &slot.dir;
        for d in ["lib/asterisk", "var", "etc"] {
            fs::create_dir_all(a.join(d)).with_context(|| a.join(d).display().to_string())?;
        }
        copy_tree(&home.join("var"), &a.join("var"))?;
        copy_tree(
            &home.join("lib/asterisk/modules"),
            &a.join("lib/asterisk/modules"),
        )?;
        // No state of the install's own runs: its run files and log.
        if let Ok(entries) = fs::read_dir(a.join("var/run/asterisk")) {
            for e in entries.flatten() {
                if !e.file_type().is_ok_and(|t| t.is_dir()) {
                    fs::remove_file(e.path())?;
                }
            }
        }
        if let Ok(entries) = fs::read_dir(a.join("var/log/asterisk")) {
            for e in entries.flatten() {
                if e.file_name()
                    .as_encoded_bytes()
                    .starts_with(b"messages.log")
                    && !e.file_type().is_ok_and(|t| t.is_dir())
                {
                    fs::remove_file(e.path())?;
                }
            }
        }
        slot.copy_conf()?;
        let version = slot.version.as_deref().unwrap_or_default();
        fs::write(a.join("asterisk-version"), format!("{version}\n"))?;
        Ok(slot)
    }

    /// The slot number.
    pub fn number(&self) -> u32 {
        self.number
    }

    /// The instance directory, `dev/run/slot<N>`.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the instance exists (has a configuration directory).
    pub fn exists(&self) -> bool {
        self.etc().is_dir()
    }

    /// The instance's Asterisk release (none for an instance that
    /// recorded none).
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// The Asterisk install the instance runs: its binaries, libraries,
    /// and the master copy of the scratch configuration.  An error when
    /// it is not installed.
    pub fn home(&self) -> Result<&Path> {
        let Some(home) = self.home.as_deref() else {
            bail!(
                "{} records no Asterisk release (it has no asterisk-version file); \
                 delete it and create it again (cargo xtask instance init {} [VERSION]), \
                 or name an install with DPMA_AST_HOME",
                self.dir.display(),
                self.number
            );
        };
        if !home.join("sbin").join("asterisk").is_file() {
            match &self.version {
                Some(v) if std::env::var_os("DPMA_AST_HOME").is_none() => bail!(
                    "Asterisk {v} is not installed in {} (cargo xtask asterisk build --install {v})",
                    home.display()
                ),
                _ => bail!("no Asterisk is installed in {}", home.display()),
            }
        }
        Ok(home)
    }

    /// The configuration directory, `<dir>/etc/asterisk`.
    pub fn etc(&self) -> PathBuf {
        self.dir.join("etc").join("asterisk")
    }

    /// The instance's `asterisk.conf`.
    pub fn asterisk_conf(&self) -> PathBuf {
        self.etc().join("asterisk.conf")
    }

    /// The module directory, `<dir>/lib/asterisk/modules`.
    pub fn modules_dir(&self) -> PathBuf {
        self.dir.join("lib").join("asterisk").join("modules")
    }

    /// Asterisk's console output while it runs (`<dir>/ast-console.log`).
    pub fn console_log(&self) -> PathBuf {
        self.dir.join("ast-console.log")
    }

    /// The instance's `messages.log`.
    pub fn messages_log(&self) -> PathBuf {
        self.dir.join("var/log/asterisk/messages.log")
    }

    /// The SIP port, 15060+100·N.
    pub fn sip_port(&self) -> u16 {
        sip_port_for(Some(self.number))
    }

    /// The AMI port, 15038+100·N (user `test`, secret `test`).
    pub fn ami_port(&self) -> u16 {
        ami_port_for(Some(self.number))
    }

    /// The run directory (`astrundir`), which holds the control socket.
    pub fn run_dir(&self) -> Option<PathBuf> {
        conf_value(&self.asterisk_conf(), "astrundir").map(PathBuf::from)
    }

    /// The CLI through the instance's control socket.
    pub fn cli(&self) -> Result<Cli> {
        Cli::from_asterisk_conf(&self.asterisk_conf())
    }

    /// Whether Asterisk answers on the control socket.
    pub fn running(&self) -> bool {
        self.cli().is_ok_and(|c| c.alive())
    }

    fn pid(&self) -> Option<u32> {
        let file = self.run_dir()?.join("asterisk.pid");
        fs::read_to_string(file).ok()?.trim().parse().ok()
    }

    /// (Re)starts Asterisk in the background (`asterisk -g -f -n`, its
    /// console output in [`Slot::console_log`], in a process group of its
    /// own) and waits until it is fully booted.
    pub fn start(&self) -> Result<()> {
        let home = self.home()?.to_path_buf();
        let conf = self.asterisk_conf();
        if !conf.is_file() {
            bail!(
                "no instance at {} (cargo xtask instance init {} [VERSION])",
                self.dir.display(),
                self.number
            );
        }
        self.stop()?;
        let _ = fs::remove_file(self.messages_log());
        if let Some(run) = self.run_dir() {
            let _ = fs::create_dir_all(run);
        }
        let log_path = self.console_log();
        let log = File::create(&log_path).with_context(|| log_path.display().to_string())?;
        let mut ld = home.join("lib").into_os_string();
        if let Some(old) = std::env::var_os("LD_LIBRARY_PATH").filter(|v| !v.is_empty()) {
            ld.push(":");
            ld.push(old);
        }
        let binary = home.join("sbin").join("asterisk");
        let mut child = Command::new(&binary)
            .arg("-C")
            .arg(&conf)
            .args(["-g", "-f", "-n"])
            .env("LD_LIBRARY_PATH", ld)
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
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Stops Asterisk (`core stop now`) and waits until its process has
    /// exited; whether it was running.
    pub fn stop(&self) -> Result<bool> {
        if !self.asterisk_conf().is_file() {
            return Ok(false);
        }
        let cli = self.cli()?.timeout(STOP_TIMEOUT);
        let pid = self.pid();
        if cli.run("core stop now").is_err() {
            return Ok(false);
        }
        let stopped =
            crate::util::wait_until(STOP_TIMEOUT, Duration::from_millis(100), || match pid {
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
        Ok(true)
    }

    /// Runs a CLI command through the control socket; its output exactly
    /// as `asterisk -rx` prints it.
    pub fn cli_run(&self, command: &str) -> Result<bstr::BString> {
        self.cli()?.run(command).with_context(|| {
            format!(
                "Asterisk is not running in {} (cargo xtask instance start)",
                self.dir.display()
            )
        })
    }

    /// The module build of a Cargo profile: `target/<profile>/libres_dpma_rs.so`.
    pub fn module_build(profile: &str) -> PathBuf {
        repo_root()
            .join("target")
            .join(profile)
            .join("libres_dpma_rs.so")
    }

    /// Installs the module built in `profile` (`debug` or `release`) as
    /// `res_dpma_rs.so` in the instance's module directory, by copying it
    /// to a temporary file and renaming that into place (so that a
    /// running Asterisk is not hurt; restart it to use the new build),
    /// and removes the [`ORIGINAL_MODULES`] from it.  Returns the
    /// installed file.
    pub fn install(&self, profile: &str) -> Result<PathBuf> {
        let src = Slot::module_build(profile);
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
        if !m.is_dir() {
            bail!("no instance at {}", self.dir.display());
        }
        let dest = m.join("res_dpma_rs.so");
        let tmp = m.join(format!("res_dpma_rs.so.new.{}", std::process::id()));
        fs::copy(&src, &tmp).with_context(|| format!("copying {}", src.display()))?;
        fs::rename(&tmp, &dest).with_context(|| dest.display().to_string())?;
        for name in ORIGINAL_MODULES {
            match fs::remove_file(m.join(name)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| m.join(name).display().to_string())
                }
                _ => {}
            }
        }
        Ok(dest)
    }

    /// Replaces the instance's configuration with a fresh copy of the
    /// scratch configuration (as `init` makes it: test setups and trust
    /// material are gone afterwards).
    pub fn reset_conf(&self) -> Result<()> {
        if !self.exists() {
            bail!("no instance at {}", self.dir.display());
        }
        self.copy_conf()
    }

    /// Copies the install's configuration into the instance and points
    /// it at the instance's directories and ports.  An existing instance
    /// keeps its run directory.
    fn copy_conf(&self) -> Result<()> {
        let h = self.home()?.to_path_buf();
        let a = &self.dir;
        let etc = self.etc();
        let conf = self.asterisk_conf();
        let rundir = conf_value(&conf, "astrundir");
        if etc.exists() {
            fs::remove_dir_all(&etc).with_context(|| etc.display().to_string())?;
        }
        fs::create_dir_all(a.join("etc"))?;
        copy_tree(&h.join("etc").join("asterisk"), &etc)?;

        // asterisk.conf holds real paths; the install may be reached
        // through a symbolic link.
        let hr = fs::canonicalize(&h).unwrap_or_else(|_| h.clone());
        let m = self.modules_dir();
        let mut pairs = Vec::new();
        for base in [&h, &hr] {
            pairs.push((base.join("etc"), a.join("etc")));
            pairs.push((base.join("var"), a.join("var")));
            pairs.push((base.join("lib/asterisk/modules"), m.clone()));
        }
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = pairs
            .into_iter()
            .map(|(f, t)| {
                (
                    f.into_os_string().into_encoded_bytes(),
                    t.into_os_string().into_encoded_bytes(),
                )
            })
            .collect();
        edit_lines(&conf, |line| {
            let mut line = line.to_vec();
            for (from, to) in &pairs {
                line = line.replacen(from, to, 1);
            }
            line
        })?;

        // Unix socket paths are limited to 108 bytes; deep trees need a
        // short run directory for asterisk.ctl.
        let rundir = match rundir {
            Some(r) => Some(r),
            None if a.as_os_str().len() > 70 => {
                let uid = unsafe { libc::getuid() };
                let tmp = nonempty_env("TMPDIR").unwrap_or_else(|| "/tmp".into());
                let mut r = format!("{tmp}/dpma-slot{}-{uid}", self.number);
                if r.len() + 22 > 107 {
                    r = format!("/tmp/dpma-slot{}-{uid}", self.number);
                }
                fs::create_dir_all(&r).with_context(|| r.clone())?;
                Some(r)
            }
            None => None,
        };
        if let Some(r) = rundir {
            edit_lines(&conf, |line| {
                if line.starts_with(b"astrundir => ") {
                    format!("astrundir => {r}").into_bytes()
                } else {
                    line.to_vec()
                }
            })?;
        }

        let sip = format!("bind=127.0.0.1:{}", self.sip_port());
        edit_lines(&etc.join("pjsip.conf"), |line| {
            match line.strip_prefix(b"bind=127.0.0.1:15060") {
                Some(rest) => [sip.as_bytes(), rest].concat(),
                None => line.to_vec(),
            }
        })?;
        let ami = format!("port = {}", self.ami_port());
        edit_lines(&etc.join("manager.conf"), |line| {
            match line.strip_prefix(b"port = 15038") {
                Some(rest) => [ami.as_bytes(), rest].concat(),
                None => line.to_vec(),
            }
        })?;
        let modules = etc.join("modules.conf");
        let mut text = fs::read(&modules).with_context(|| modules.display().to_string())?;
        if !text
            .lines()
            .any(|l| l.starts_with(b"noload => pbx_dundi.so"))
        {
            if !text.is_empty() && !text.ends_with(b"\n") {
                text.push(b'\n');
            }
            text.extend_from_slice(b"noload => pbx_dundi.so\n");
            fs::write(&modules, text)?;
        }
        Ok(())
    }

    /// What `cargo xtask instance info` prints: the instance, its
    /// install and release, configuration, logs, and ports.
    pub fn info(&self) -> Vec<(&'static str, String)> {
        let home = match (&self.home, &self.version) {
            (Some(h), Some(v)) => format!("{} (Asterisk {v})", h.display()),
            (Some(h), None) => h.display().to_string(),
            (None, _) => "(none: no asterisk-version)".into(),
        };
        vec![
            ("instance", self.dir.display().to_string()),
            ("asterisk", home),
            ("config", self.asterisk_conf().display().to_string()),
            ("console", self.console_log().display().to_string()),
            ("messages", self.messages_log().display().to_string()),
            ("SIP", format!("127.0.0.1:{}", self.sip_port())),
            (
                "AMI",
                format!("127.0.0.1:{} (user test, secret test)", self.ami_port()),
            ),
        ]
    }

    /// [`Slot::info`] as text, one `key: value` line each.
    pub fn info_text(&self) -> String {
        self.info()
            .into_iter()
            .map(|(k, v)| format!("{:<10}{v}\n", format!("{k}:")))
            .collect()
    }

    /// Runs an instance command as `cargo xtask instance` does, and
    /// returns what it prints:
    ///
    /// | Command | Does |
    /// |---|---|
    /// | `init [VERSION]` | [`Slot::init`] |
    /// | `start` | [`Slot::start`] |
    /// | `stop` | [`Slot::stop`] |
    /// | `cli WORDS...` | [`Slot::cli_run`] (the words joined with spaces) |
    /// | `install [debug\|release]` | [`Slot::install`] (default `debug`) |
    /// | `reset-conf` | [`Slot::reset_conf`] |
    /// | `info` | [`Slot::info_text`] |
    pub fn command(n: u32, args: &[&str]) -> Result<Vec<u8>> {
        let Some((&cmd, rest)) = args.split_first() else {
            bail!("no instance command");
        };
        if cmd == "init" {
            if rest.len() > 1 {
                bail!("usage: init [VERSION]");
            }
            let s = Slot::init(n, rest.first().copied())?;
            return Ok(format!(
                "created {} (Asterisk {}, SIP 127.0.0.1:{}, AMI 127.0.0.1:{})\n",
                s.dir.display(),
                s.version().unwrap_or_default(),
                s.sip_port(),
                s.ami_port()
            )
            .into_bytes());
        }
        let s = Slot::new(n)?;
        let usage = |u: &str| -> Result<Vec<u8>> { bail!("usage: {u}") };
        match (cmd, rest) {
            ("start", []) => {
                s.start()?;
                Ok(b"started\n".to_vec())
            }
            ("stop", []) => Ok(if s.stop()? {
                b"stopped\n".to_vec()
            } else {
                b"not running\n".to_vec()
            }),
            ("cli", words) if !words.is_empty() => Ok(s.cli_run(&words.join(" "))?.into()),
            ("cli", _) => usage("cli COMMAND..."),
            ("install", [] | ["debug" | "release"]) => {
                let dest = s.install(rest.first().copied().unwrap_or("debug"))?;
                Ok(format!("installed {}\n", dest.display()).into_bytes())
            }
            ("install", _) => usage("install [debug|release]"),
            ("reset-conf", []) => {
                s.reset_conf()?;
                Ok(format!("reset the configuration of {}\n", s.dir.display()).into_bytes())
            }
            ("info", []) => Ok(s.info_text().into_bytes()),
            ("start" | "stop" | "reset-conf" | "info", _) => usage(cmd),
            _ => bail!("unknown instance command {cmd}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_numbers() {
        assert!(check_number(0).is_err());
        assert!(check_number(1).is_ok());
        assert!(check_number(MAX_SLOT).is_ok());
        assert!(check_number(MAX_SLOT + 1).is_err());
        assert!(slot_dir(7).ends_with("dev/run/slot7"));
    }

    #[test]
    fn processes() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(u32::MAX));
    }

    #[test]
    fn asterisk_conf_values() {
        let dir = crate::harness::fixtures::TempDir::new("dpma-slot-test").unwrap();
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
}
