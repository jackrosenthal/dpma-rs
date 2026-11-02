//! The test container: the container engine, the test image of a pinned
//! release, and a container that runs `cargo xtask inside ...`.
//!
//! # The engine
//!
//! `$DPMA_ENGINE` (a command name or path) when set, else `podman` when it
//! is on the `PATH`, else `docker`.  The engine is used as its user has
//! configured it (storage, registries, rootless or not); only commands
//! and options that podman and docker share are used.
//!
//! # The image
//!
//! One image per pinned release, built from `tools/Containerfile` with the
//! release and its checksum as build arguments and `tools/` as the
//! context.  Its tag, `dpma-rs-asterisk:<release>-<hash>`, carries a hash
//! of what goes into it (the Containerfile, the pin, and
//! `tools/asterisk-conf/`), so that a change to any of them builds a new
//! image and anything else reuses the existing one ([`image_tag`]).
//!
//! # The container
//!
//! A fresh container per run ([`Container`]), removed afterwards:
//!
//! - `--network none`: a network namespace of its own whose only interface
//!   is `lo`, so that SIP, AMI, and mDNS stay inside and runs for
//!   different releases never clash.  Root in the container (an `exec` as
//!   user 0, with `--cap-add NET_ADMIN`) turns multicast on for `lo` and
//!   routes 224.0.0.0/4 through it, for the apps-discovery suite's mDNS.
//! - Mounts (the [`SRC`], [`OUT`], [`CARGO_HOME`], and [`ORIGINAL`]
//!   paths): the repository; `target/container/<release>/` for the Cargo
//!   target directory, the logs, the test PKI, and the published module;
//!   `target/container/cargo/` as `CARGO_HOME`, the registry cache that
//!   the releases share; and, for parity, the original binaries
//!   (read-only).  The container has no network, so the host fetches the
//!   crates into that cache first (`cargo fetch --locked`).
//! - `--security-opt label=disable`, so that SELinux hosts let the
//!   container read and write the mounts without relabeling them.
//! - The work runs as the container user that the engine maps to the host
//!   user ([`container_id`], from `/proc/self/uid_map` in the container):
//!   root for a rootless engine, the host user's own IDs for a rootful
//!   one.  So the files it writes into the mounts belong to the host user.
//!   `--cap-drop DAC_OVERRIDE` makes root, too, respect file permissions
//!   as the host user would (methods-calls checks that a read-only
//!   phonebook file cannot be written).
//! - The container's main process is `cat`, which reads a pipe from the
//!   xtask: when the xtask exits, however it exits, the pipe closes, `cat`
//!   ends, and the engine stops and removes (`--rm`) the container.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::pins::Pin;
use crate::{repo_root, run};

/// The repository, in the container.
pub const SRC: &str = "/src";
/// `target/container/<release>/`, in the container.
pub const OUT: &str = "/out";
/// `target/container/cargo/` (`CARGO_HOME`), in the container.
pub const CARGO_HOME: &str = "/cargo";
/// The original binaries, in the container (read-only; `test --original`).
pub const ORIGINAL: &str = "/original";
/// The configured headers in the image (`ASTERISK_SOURCE_DIR`).
const HEADERS: &str = "/opt/asterisk-headers";
/// The image's name; the tag is [`image_tag`].
const IMAGE: &str = "dpma-rs-asterisk";

/// `target/container` in the repository.
pub fn container_dir() -> PathBuf {
    repo_root().join("target").join("container")
}

/// `target/container/<release>`: the run's directory ([`OUT`]).
pub fn out_dir(pin: &Pin) -> PathBuf {
    container_dir().join(&pin.version)
}

/// The container engine.
pub struct Engine(OsString);

/// Whether `name` is an executable file in a `PATH` directory.
fn on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(d.join(name))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

impl Engine {
    /// `$DPMA_ENGINE`, else podman when it is on the `PATH`, else docker.
    pub fn detect() -> Result<Engine> {
        if let Some(e) = std::env::var_os("DPMA_ENGINE").filter(|e| !e.is_empty()) {
            return Ok(Engine(e));
        }
        for name in ["podman", "docker"] {
            if on_path(name) {
                return Ok(Engine(name.into()));
            }
        }
        bail!("no container engine: install podman or docker (or name one in DPMA_ENGINE)")
    }

    /// A command of the engine.
    pub fn cmd(&self) -> Command {
        Command::new(&self.0)
    }

    /// The image of `pin`: built unless the engine has it.  Its tag.
    pub fn image(&self, pin: &Pin) -> Result<String> {
        let tag = image_tag(pin)?;
        let have = self
            .cmd()
            .args(["image", "inspect", &tag])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("running {}", self.0.to_string_lossy()))?;
        if have.success() {
            return Ok(tag);
        }
        let tools = repo_root().join("tools");
        eprintln!("building the image {tag}");
        // Its output goes to stderr: `headers` prints a path on stdout.
        run(self
            .cmd()
            .arg("build")
            .arg("-f")
            .arg(tools.join("Containerfile"))
            .arg("--build-arg")
            .arg(format!("ASTERISK_VERSION={}", pin.version))
            .arg("--build-arg")
            .arg(format!("ASTERISK_SHA256={}", pin.sha256))
            .args(["-t", &tag])
            .arg(&tools)
            .stdout(std::io::stderr()))?;
        Ok(tag)
    }
}

/// The tag of `pin`'s image: `dpma-rs-asterisk:<release>-<hash>`, where
/// the hash (12 hex digits of SHA-256) covers the Containerfile, the pin,
/// and the files of `tools/asterisk-conf/`.
pub fn image_tag(pin: &Pin) -> Result<String> {
    let tools = repo_root().join("tools");
    let mut h = Sha256::new();
    let mut add = |name: &str, data: &[u8]| {
        h.update(name.as_bytes());
        h.update([0]);
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
    };
    let file = tools.join("Containerfile");
    add(
        "Containerfile",
        &fs::read(&file).with_context(|| file.display().to_string())?,
    );
    add("pin", format!("{} {}", pin.version, pin.sha256).as_bytes());
    let conf = tools.join("asterisk-conf");
    let mut names: Vec<_> = fs::read_dir(&conf)
        .with_context(|| conf.display().to_string())?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()?;
    names.sort();
    for n in names {
        let data = fs::read(conf.join(&n)).with_context(|| n.to_string_lossy().into_owned())?;
        add(&format!("asterisk-conf/{}", n.to_string_lossy()), &data);
    }
    let hash: String = h.finalize()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!("{IMAGE}:{}-{hash}", pin.version))
}

/// The ID inside a user namespace that maps to `host` outside, from an ID
/// map (`/proc/<pid>/uid_map` or `gid_map`: lines of "inside outside
/// count").
pub fn container_id(map: &str, host: u32) -> Option<u32> {
    let host = u64::from(host);
    map.lines().find_map(|l| {
        let mut f = l.split_whitespace().map(|x| x.parse::<u64>().ok());
        let (inside, outside, count) = (f.next()??, f.next()??, f.next()??);
        (outside..outside + count)
            .contains(&host)
            .then(|| u32::try_from(inside + host - outside).ok())?
    })
}

/// A running test container (see the module documentation), removed when
/// dropped.
pub struct Container {
    engine: Engine,
    name: String,
    main: Child,
    stdin: Option<ChildStdin>,
}

/// A bind mount: host path, container path, read-only.
pub type Mount = (PathBuf, &'static str, bool);

impl Container {
    /// Starts a container of `image` with `mounts` and `env`, and waits
    /// until it runs.
    pub fn start(
        engine: Engine,
        image: &str,
        name: &str,
        mounts: &[Mount],
        env: &[(&str, &str)],
    ) -> Result<Container> {
        let mut c = engine.cmd();
        c.args(["run", "--rm", "-i", "--name", name])
            .args(["--network", "none", "--cap-add", "NET_ADMIN"])
            .args(["--cap-drop", "DAC_OVERRIDE"])
            .args(["--security-opt", "label=disable"]);
        for (host, inside, ro) in mounts {
            let host = fs::canonicalize(host).with_context(|| host.display().to_string())?;
            let mut v = host.into_os_string();
            v.push(format!(":{inside}{}", if *ro { ":ro" } else { "" }));
            c.arg("-v").arg(v);
        }
        for (k, v) in env {
            c.arg("-e").arg(format!("{k}={v}"));
        }
        // Its own process group: a Ctrl-C reaches the xtask, whose exit
        // ends the container, not the engine's client.
        use std::os::unix::process::CommandExt;
        let mut main = c
            .args(["-w", SRC, image, "cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .process_group(0)
            .spawn()
            .context("starting the container")?;
        let stdin = main.stdin.take();
        let mut container = Container {
            engine,
            name: name.to_string(),
            main,
            stdin,
        };
        container.wait_running()?;
        Ok(container)
    }

    /// Waits until `exec` works (or the engine's client has exited).
    fn wait_running(&mut self) -> Result<()> {
        loop {
            let ok = self
                .exec(None, &["true"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if ok {
                return Ok(());
            }
            if let Some(status) = self.main.try_wait()? {
                bail!("the container did not start ({status})");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// `<engine> exec [-u USER] <container> ARGS...`.
    pub fn exec(&self, user: Option<&str>, args: &[&str]) -> Command {
        let mut c = self.engine.cmd();
        c.arg("exec");
        if let Some(u) = user {
            c.args(["-u", u]);
        }
        c.arg(&self.name).args(args);
        c
    }

    /// Runs `args` as root in the container.
    pub fn root(&self, args: &[&str]) -> Result<()> {
        run(&mut self.exec(Some("0"), args))
    }

    /// The `UID:GID` of the container user that is the host user.
    pub fn host_user(&self) -> Result<String> {
        let map = |file: &str| -> Result<String> {
            let out = self.exec(None, &["cat", file]).output()?;
            if !out.status.success() {
                bail!("reading {file} in the container failed ({})", out.status);
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        };
        // SAFETY: getuid and getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        match (
            container_id(&map("/proc/self/uid_map")?, uid),
            container_id(&map("/proc/self/gid_map")?, gid),
        ) {
            (Some(u), Some(g)) => Ok(format!("{u}:{g}")),
            _ => bail!(
                "no user of the container maps to your user and group IDs ({uid}:{gid}), so the \
                 files it writes into the repository would not be yours (does the engine remap \
                 user namespaces?)"
            ),
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // End of input: `cat` exits, and the engine stops and removes the
        // container.
        drop(self.stdin.take());
        let _ = self.main.wait();
    }
}

/// Runs `cargo xtask inside ARGS...` in a fresh container of `pin`'s image
/// (built if needed), as the host user, with `original` (the original
/// binaries) mounted at [`ORIGINAL`]; its exit status.
pub fn run_inside(pin: &Pin, args: &[String], original: Option<&Path>) -> Result<u8> {
    let engine = Engine::detect()?;
    let image = engine.image(pin)?;
    let root = repo_root();
    let out = out_dir(pin);
    let cargo_home = container_dir().join("cargo");
    for d in [&out, &cargo_home] {
        fs::create_dir_all(d).with_context(|| d.display().to_string())?;
    }

    // The container has no network: the crates come from the cache.
    eprintln!("fetching the crates into {}", cargo_home.display());
    run(crate::cargo()
        .args(["fetch", "--locked"])
        .env("CARGO_HOME", &cargo_home))?;

    let mut mounts: Vec<Mount> = vec![
        (root.clone(), SRC, false),
        (out, OUT, false),
        (cargo_home, CARGO_HOME, false),
    ];
    if let Some(dir) = original {
        mounts.push((dir.to_path_buf(), ORIGINAL, true));
    }
    let target = format!("{OUT}/target");
    let pki = format!("{OUT}/pki");
    let env = [
        ("CARGO_HOME", CARGO_HOME),
        ("CARGO_TARGET_DIR", target.as_str()),
        ("CARGO_NET_OFFLINE", "true"),
        ("DPMA_PKI", pki.as_str()),
    ];
    let name = format!("dpma-rs-{}-{}", pin.version, std::process::id());
    let c = Container::start(engine, &image, &name, &mounts, &env)?;
    c.root(&["ip", "link", "set", "lo", "multicast", "on"])?;
    c.root(&["ip", "route", "add", "224.0.0.0/4", "dev", "lo"])?;
    let user = c.host_user()?;
    let mut inner = vec!["cargo", "xtask", "inside"];
    inner.extend(args.iter().map(String::as_str));
    let status = c
        .exec(Some(&user), &inner)
        .stdin(Stdio::null())
        .status()
        .context("running the xtask in the container")?;
    drop(c);
    Ok(match status.code() {
        Some(0) => 0,
        Some(n) => u8::try_from(n).unwrap_or(1),
        None => 1,
    })
}

/// `cargo xtask headers`: copies the configured headers of `pin`'s image
/// into `target/container/<release>/asterisk-headers` (unless they are
/// there already, from the same image) and returns that directory.
pub fn headers(pin: &Pin) -> Result<PathBuf> {
    let dest = out_dir(pin).join("asterisk-headers");
    let stamp = dest.join(".image");
    let tag = image_tag(pin)?;
    if fs::read_to_string(&stamp).is_ok_and(|s| s.trim() == tag) {
        return Ok(dest);
    }
    let engine = Engine::detect()?;
    engine.image(pin)?;
    if dest.exists() {
        fs::remove_dir_all(&dest).with_context(|| dest.display().to_string())?;
    }
    fs::create_dir_all(dest.parent().expect("a parent"))?;
    let name = format!("dpma-rs-headers-{}-{}", pin.version, std::process::id());
    let quiet = |c: &mut Command| -> Result<()> { run(c.stdout(Stdio::null())) };
    quiet(engine.cmd().args(["create", "--name", &name, &tag]))?;
    let copied = run(engine
        .cmd()
        .arg("cp")
        .arg(format!("{name}:{HEADERS}"))
        .arg(&dest)
        .stdout(Stdio::null()));
    let removed = quiet(engine.cmd().args(["rm", &name]));
    copied.and(removed)?;
    let mut f = fs::File::create(&stamp)?;
    writeln!(f, "{tag}")?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_maps() {
        // Rootless: the container's root is the host user.
        let rootless = "         0       1000          1\n         1     165536      65536\n";
        assert_eq!(container_id(rootless, 1000), Some(0));
        assert_eq!(container_id(rootless, 165537), Some(2));
        assert_eq!(container_id(rootless, 5), None);
        // Rootful: the identity.
        let rootful = "         0          0 4294967295\n";
        assert_eq!(container_id(rootful, 1001), Some(1001));
        assert_eq!(container_id("", 1000), None);
    }

    #[test]
    fn tags() {
        let pin = crate::pins::pin(None).unwrap();
        let tag = image_tag(&pin).unwrap();
        assert!(tag.starts_with(&format!("dpma-rs-asterisk:{}-", pin.version)));
        assert_eq!(
            tag.len(),
            "dpma-rs-asterisk:".len() + pin.version.len() + 13
        );
        let other = Pin {
            sha256: "0".repeat(64),
            ..pin.clone()
        };
        assert_ne!(image_tag(&other).unwrap(), tag);
    }
}
