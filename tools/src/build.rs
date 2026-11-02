//! `cargo xtask asterisk build`: fetch, verify, configure, and optionally
//! build and install a pinned Asterisk release.
//!
//! Everything goes under the builds directory (`$DPMA_AST_BUILDS`,
//! default `dev/asterisk-builds`, resolved to its physical path because
//! configure records the prefix):
//!
//! | Path | What it is |
//! |---|---|
//! | `downloads/` | The tarballs; `downloads/externals` holds the bundled pjproject and `downloads/sounds` the sounds packages, which Asterisk's own build downloads and checks |
//! | `<release>/src` | The configured source tree, for the module build (`ASTERISK_SOURCE_DIR`) |
//! | `<release>/prefix` | The installation (`--install`) |
//!
//! Each step leaves a stamp, so a step already done is skipped:
//! `src/.dpma-extracted` (`"<release> <sha256>"`), `src/.dpma-configured`
//! (the configuration, [`Build::config`]), and `prefix/.dpma-installed`
//! (both).  When either source stamp differs, the tree is extracted
//! afresh from the verified tarball.
//!
//! The configure options are those of the old `dev/asterisk-24`
//! (`--with-pjproject-bundled --with-jansson-bundled=no --without-pwlib
//! --disable-xmldoc`) plus the prefix and the download caches, and the
//! menuselect option BUILD_NATIVE (`-march=native`) is off, so that a
//! build cached on one CI runner also runs on another runner's CPU.  The
//! build needs Asterisk's build dependencies (`cargo xtask ci setup`
//! installs them on Ubuntu), `curl`, and `tar`.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use dpma_tests::asterisk::{edit_lines, versions, Pin};
use dpma_tests::sim::repo_root;
use sha2::{Digest, Sha256};

/// A pinned release and where its build goes.
pub struct Build {
    /// The release.
    pub pin: Pin,
    /// The source tree.
    pub src: PathBuf,
    /// The installation.
    pub prefix: PathBuf,
    builds: PathBuf,
    downloads: PathBuf,
    tarball: PathBuf,
}

/// Runs a command; an error unless it succeeds.
pub fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("running {:?}", cmd.get_program()))?;
    if !status.success() {
        bail!("{cmd:?} failed ({status})");
    }
    Ok(())
}

/// The SHA-256 checksum of a file, lowercase hex.
fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).with_context(|| path.display().to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// A stamp's contents (without trailing line breaks, as the shell's
/// `$(cat FILE)` read them).
fn stamp(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end_matches('\n').to_string())
}

fn write_stamp(path: &Path, text: &str) -> Result<()> {
    fs::write(path, format!("{text}\n")).with_context(|| path.display().to_string())
}

fn remove_dir(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

fn remove_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

fn make(src: &Path) -> Command {
    let mut c = Command::new("make");
    c.arg("-C").arg(src);
    c
}

impl Build {
    /// The build of the release `name` (a major version or a release).
    pub fn new(name: &str) -> Result<Build> {
        let pin = versions::pin(name)?;
        let builds = versions::builds_dir();
        fs::create_dir_all(&builds).with_context(|| builds.display().to_string())?;
        let builds = fs::canonicalize(&builds)?;
        let downloads = builds.join("downloads");
        Ok(Build {
            src: pin.src(&builds),
            prefix: pin.prefix(&builds),
            tarball: downloads.join(pin.tarball()),
            downloads,
            builds,
            pin,
        })
    }

    /// The configuration, as the stamps record it: a change starts over
    /// from a fresh source tree.
    pub fn config(&self) -> String {
        format!(
            "--prefix={} --with-pjproject-bundled --with-jansson-bundled=no --without-pwlib --disable-xmldoc --disable BUILD_NATIVE",
            self.prefix.display()
        )
    }

    /// What `cargo xtask asterisk info` prints (for `$GITHUB_OUTPUT`).
    pub fn info(&self) -> String {
        format!(
            "major={}\nversion={}\nsha256={}\nsrc={}\nprefix={}\n",
            self.pin.major,
            self.pin.version,
            self.pin.sha256,
            self.src.display(),
            self.prefix.display()
        )
    }

    fn extracted_stamp(&self) -> String {
        format!("{} {}", self.pin.version, self.pin.sha256)
    }

    /// Prepares the source tree, and with `install` builds and installs
    /// it (`make -jN`, N = `jobs` or the number of CPUs).
    pub fn run(&self, jobs: Option<usize>, install: bool) -> Result<()> {
        // A source tree extracted from the pinned tarball and configured
        // as now needs no download (a restored CI cache has no
        // downloads/).
        if stamp(&self.src.join(".dpma-extracted")).as_deref() != Some(&self.extracted_stamp())
            || stamp(&self.src.join(".dpma-configured")) != Some(self.config())
        {
            self.fetch()?;
            self.extract()?;
        }
        self.configure()?;
        if install {
            let jobs = match jobs {
                Some(j) => j,
                None => std::thread::available_parallelism().map_or(1, usize::from),
            };
            self.install(jobs)?;
        }
        println!(
            "Asterisk {}: source {}{}",
            self.pin.version,
            self.src.display(),
            if install {
                format!(", installed in {}", self.prefix.display())
            } else {
                String::new()
            }
        );
        Ok(())
    }

    fn fetch(&self) -> Result<()> {
        fs::create_dir_all(&self.downloads)?;
        if self.tarball.is_file() && sha256_file(&self.tarball)? == self.pin.sha256 {
            println!("verified {}", self.tarball.display());
            return Ok(());
        }
        let part = self.tarball.with_extension("gz.part");
        remove_file(&self.tarball)?;
        remove_file(&part)?;
        let url = self.pin.url();
        println!("downloading {url}");
        run(Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&part)
            .arg(&url))?;
        let got = sha256_file(&part)?;
        if got != self.pin.sha256 {
            remove_file(&part)?;
            bail!(
                "checksum mismatch for {}: got {got}, pinned {}",
                self.pin.tarball(),
                self.pin.sha256
            );
        }
        fs::rename(&part, &self.tarball)?;
        println!("verified {}", self.tarball.display());
        Ok(())
    }

    fn extract(&self) -> Result<()> {
        let dir = self.pin.dir(&self.builds);
        let unpacked = dir.join(format!("asterisk-{}", self.pin.version));
        remove_dir(&self.src)?;
        remove_dir(&unpacked)?;
        fs::create_dir_all(&dir)?;
        run(Command::new("tar")
            .arg("-xzf")
            .arg(&self.tarball)
            .arg("-C")
            .arg(&dir))?;
        fs::rename(&unpacked, &self.src)
            .with_context(|| format!("renaming {}", unpacked.display()))?;
        write_stamp(&self.src.join(".dpma-extracted"), &self.extracted_stamp())?;
        println!("extracted {}", self.src.display());
        Ok(())
    }

    fn configure(&self) -> Result<()> {
        let config = self.config();
        if stamp(&self.src.join(".dpma-configured")) != Some(config.clone()) {
            let t = Instant::now();
            let externals = self.downloads.join("externals");
            let sounds = self.downloads.join("sounds");
            fs::create_dir_all(&externals)?;
            fs::create_dir_all(&sounds)?;
            run(Command::new(self.src.join("configure"))
                .current_dir(&self.src)
                .arg(format!("--prefix={}", self.prefix.display()))
                .args([
                    "--with-pjproject-bundled",
                    "--with-jansson-bundled=no",
                    "--without-pwlib",
                    "--disable-xmldoc",
                ])
                .arg(format!("--with-externals-cache={}", externals.display()))
                .arg(format!("--with-sounds-cache={}", sounds.display())))?;
            run(make(&self.src)
                .arg("menuselect.makeopts")
                .stdout(Stdio::null()))?;
            run(Command::new(self.src.join("menuselect/menuselect"))
                .current_dir(&self.src)
                .args(["--disable", "BUILD_NATIVE", "menuselect.makeopts"]))?;
            write_stamp(&self.src.join(".dpma-configured"), &config)?;
            println!(
                "configured {} in {} s",
                self.src.display(),
                t.elapsed().as_secs()
            );
        }
        // buildopts.h (from menuselect.makeopts) completes the headers a
        // module build needs; its options checksum must match the
        // installed Asterisk's.
        run(make(&self.src)
            .arg("include/asterisk/buildopts.h")
            .stdout(Stdio::null()))?;
        if !self
            .src
            .join("third-party/pjproject/source/pjlib/include/pj/config_site.h")
            .is_file()
        {
            bail!(
                "the bundled pjproject is not configured in {}",
                self.src.display()
            );
        }
        Ok(())
    }

    fn install(&self, jobs: usize) -> Result<()> {
        let want = format!("{} {}", self.extracted_stamp(), self.config());
        let stamp_file = self.prefix.join(".dpma-installed");
        if stamp(&stamp_file).as_deref() == Some(want.as_str()) {
            println!("installed in {}", self.prefix.display());
            return Ok(());
        }
        remove_dir(&self.prefix)?;
        let t = Instant::now();
        run(make(&self.src).arg(format!("-j{jobs}")))?;
        println!(
            "built {} in {} s (-j{jobs})",
            self.src.display(),
            t.elapsed().as_secs()
        );
        let t = Instant::now();
        // ASTDATADIR is given explicitly: with a --prefix of its own,
        // makeopts defines it through ${prefix}, which the bundled
        // pjproject's install step (third-party/pjproject) sees as
        // pjproject's /opt/pjproject (an Asterisk bug).
        run(make(&self.src).arg("install").arg(format!(
            "ASTDATADIR={}",
            self.prefix.join("var/lib/asterisk").display()
        )))?;
        run(make(&self.src).arg("samples"))?;
        self.scratch_conf()?;
        write_stamp(&stamp_file, &want)?;
        println!(
            "installed in {} in {} s",
            self.prefix.display(),
            t.elapsed().as_secs()
        );
        Ok(())
    }

    /// The scratch configuration: the samples, with the files of
    /// `tools/asterisk-conf/` and a few edits on top.  asterisk.conf's
    /// `[directories]` section is made active, so that instances can
    /// point it at their own directories.
    fn scratch_conf(&self) -> Result<()> {
        let e = self.prefix.join("etc/asterisk");
        let conf_dir = repo_root().join("tools/asterisk-conf");
        let mut names: Vec<_> = fs::read_dir(&conf_dir)
            .with_context(|| conf_dir.display().to_string())?
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|n| n.as_encoded_bytes().ends_with(b".conf"))
            .collect();
        names.sort();
        for n in names {
            fs::copy(conf_dir.join(&n), e.join(&n))
                .with_context(|| format!("copying {}", n.to_string_lossy()))?;
        }
        edit_lines(&e.join("rtp.conf"), |l| {
            if l.starts_with(b"rtpstart=") {
                b"rtpstart=21000".to_vec()
            } else if l.starts_with(b"rtpend=") {
                b"rtpend=21100".to_vec()
            } else {
                l.to_vec()
            }
        })?;
        edit_lines(&e.join("voicemail.conf"), |l| {
            if l == b"[default]" {
                b"[default]\nbob101 => -9876,Bob Example".to_vec()
            } else {
                l.to_vec()
            }
        })?;
        edit_lines(&e.join("asterisk.conf"), |l| {
            if l == b"[directories](!)" {
                b"[directories]".to_vec()
            } else {
                l.to_vec()
            }
        })?;
        let has = |file: &str, f: &dyn Fn(&[u8]) -> bool| -> Result<bool> {
            Ok(fs::read(e.join(file))?.split(|&b| b == b'\n').any(f))
        };
        let moddir = format!(
            "astmoddir => {}",
            self.prefix.join("lib/asterisk/modules").display()
        );
        if !(has("rtp.conf", &|l| l == b"rtpstart=21000")?
            && has("rtp.conf", &|l| l == b"rtpend=21100")?
            && has("voicemail.conf", &|l| l.starts_with(b"bob101 => "))?
            && has("asterisk.conf", &|l| l == b"[directories]")?
            && has("asterisk.conf", &|l| l == moddir.as_bytes())?)
        {
            bail!(
                "the sample configuration of {} has changed; check scratch_conf",
                self.pin.version
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums() {
        let dir = dpma_tests::harness::fixtures::TempDir::new("xtask-sha").unwrap();
        let f = dir.path().join("x");
        fs::write(&f, b"abc").unwrap();
        assert_eq!(
            sha256_file(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        write_stamp(&dir.path().join("s"), "a b").unwrap();
        assert_eq!(stamp(&dir.path().join("s")).as_deref(), Some("a b"));
    }
}
