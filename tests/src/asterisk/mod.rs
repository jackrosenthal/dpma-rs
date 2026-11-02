//! Asterisk for the tests: the pinned releases and the private
//! instances the suites run against.  `cargo xtask instance` and
//! [`crate::harness::Instance`] both manage instances through this
//! module.
//!
//! # Releases
//!
//! `tools/asterisk-versions` pins one Asterisk release per supported
//! major version ([`versions`]).  `cargo xtask asterisk build --install
//! <version>` downloads, verifies, configures, builds, and installs one
//! into `<builds>/<release>/prefix`, where `<builds>` is
//! `$DPMA_AST_BUILDS`, default `dev/asterisk-builds`
//! ([`versions::builds_dir`]).  The install carries the sample
//! configuration with the scratch configuration of
//! `tools/asterisk-conf/` on top.
//!
//! # Instances
//!
//! A private instance ([`Slot`]) lives in `dev/run/slot<N>` (N from 1 to
//! 50, normally `$DPMA_SLOT`) and has its own configuration, AstDB,
//! spool, logs, and module directory; the Asterisk binaries and libraries
//! are those of its release's install.  SIP listens on
//! 127.0.0.1:15060+100·N and AMI on 127.0.0.1:15038+100·N (user `test`,
//! secret `test`).
//!
//! | Command | What it does |
//! |---|---|
//! | `cargo xtask instance init <N> [VERSION]` | Creates the instance for a release (a major version or a release of the pin file; default `$DPMA_AST_VERSION`, else the newest pinned release): copies the install's `var` and module directory, copies its configuration and rewrites it for the instance (below), and records the release in `dev/run/slot<N>/asterisk-version`. |
//! | `cargo xtask instance install [debug\|release]` | Copies `target/<profile>/libres_dpma_rs.so` (default `debug`) into the module directory as `res_dpma_rs.so`, through a temporary file renamed into place (so a running Asterisk is not hurt; restart it to use the build), and removes the original `res_digium_phone.so` and its two PJSIP helpers. |
//! | `cargo xtask instance start` | Stops Asterisk if it runs, then starts it in the background (`asterisk -g -f -n`, console output in `ast-console.log`) and waits until it is fully booted. |
//! | `cargo xtask instance stop` | `core stop now`, and waits for the process to exit. |
//! | `cargo xtask instance cli <COMMAND...>` | Runs a CLI command through the control socket and prints its output as `asterisk -rx` does. |
//! | `cargo xtask instance reset-conf` | Replaces the configuration with a fresh copy (test setups and trust material are gone afterwards). |
//! | `cargo xtask instance info` | Prints the instance's directories, install, release, logs, and ports. |
//!
//! Every command but `init` works on the instance of `$DPMA_SLOT`.  The
//! configuration is the install's `etc/asterisk`, rewritten for the
//! instance: the directories of `asterisk.conf` point into the instance,
//! except `astsbindir`; SIP's `bind` and AMI's `port` move to the
//! instance's ports; `pbx_dundi.so` is not loaded.  Unix socket paths are
//! limited to 108 bytes, so when the instance directory is longer than 70
//! bytes, `init` gives it a short run directory for the control socket,
//! `$TMPDIR/dpma-slot<N>-<uid>` (or `/tmp/dpma-slot<N>-<uid>`), which
//! `reset-conf` keeps.
//!
//! # Versions
//!
//! An instance always runs the release it was created for (its module
//! directory is a copy of that release's).  `$DPMA_AST_VERSION`, when
//! set, names the release of a new instance and must agree with that of
//! an existing one.  To switch releases, delete the instance and create
//! it again:
//!
//! ```text
//! cargo xtask instance stop
//! rm -rf dev/run/slot<N>
//! cargo xtask instance init <N> 22
//! ```
//!
//! `$DPMA_AST_HOME` names an install directory directly (binaries,
//! libraries, and the master configuration) and wins over the recorded
//! release, for testing against an Asterisk that is not pinned.
//!
//! Build the module against the instance's release
//! (`ASTERISK_SOURCE_DIR=<builds>/<release>/src`): `install` copies
//! whatever `target/debug` holds, and Asterisk declines a module built
//! with other build options.

mod slot;
pub mod versions;

use std::path::Path;

use anyhow::{Context, Result};
use bstr::ByteSlice;

pub use slot::{env_slot, slot_dir, Slot, MAX_SLOT, ORIGINAL_MODULES};
pub use versions::{builds_dir, Pin};

/// Copies `src` to `dst` recursively, as `cp -a` does for regular files,
/// directories, and symbolic links (permissions kept; other file types
/// are skipped).  Existing directories are merged into.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(src).with_context(|| src.display().to_string())?;
    let t = meta.file_type();
    if t.is_symlink() {
        let target = std::fs::read_link(src)?;
        std::os::unix::fs::symlink(&target, dst).with_context(|| dst.display().to_string())?;
    } else if t.is_dir() {
        std::fs::create_dir_all(dst).with_context(|| dst.display().to_string())?;
        for e in std::fs::read_dir(src).with_context(|| src.display().to_string())? {
            let e = e?;
            copy_tree(&e.path(), &dst.join(e.file_name()))?;
        }
        std::fs::set_permissions(dst, meta.permissions())?;
    } else if t.is_file() {
        std::fs::copy(src, dst).with_context(|| format!("copying {}", src.display()))?;
    }
    Ok(())
}

/// Rewrites a text file line by line, as bytes: `f` gets each line
/// without its line break and returns its replacement (which may hold
/// line breaks of its own).  Line breaks, including a missing last one,
/// are kept.
pub fn edit_lines(path: &Path, mut f: impl FnMut(&[u8]) -> Vec<u8>) -> Result<()> {
    let text = std::fs::read(path).with_context(|| path.display().to_string())?;
    let mut out = Vec::with_capacity(text.len());
    for line in text.lines_with_terminator() {
        let body = line.trim_end_with(|c| c == '\n');
        out.extend_from_slice(&f(body));
        out.extend_from_slice(&line[body.len()..]);
    }
    if out != text {
        std::fs::write(path, out).with_context(|| path.display().to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::fixtures::TempDir;

    #[test]
    fn line_edits() {
        let dir = TempDir::new("dpma-edit-lines").unwrap();
        let p = dir.path().join("x.conf");
        std::fs::write(&p, b"a=1\r\n[default]\nb=\xe9\nlast").unwrap();
        edit_lines(&p, |l| {
            if l == b"[default]" {
                b"[default]\nnew".to_vec()
            } else {
                l.replace("1", "2")
            }
        })
        .unwrap();
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"a=2\r\n[default]\nnew\nb=\xe9\nlast"
        );
    }

    #[test]
    fn tree_copies() {
        let dir = TempDir::new("dpma-copy-tree").unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("d")).unwrap();
        std::fs::write(src.join("d/f"), b"x").unwrap();
        std::os::unix::fs::symlink("d/f", src.join("l")).unwrap();
        copy_tree(&src, &dir.path().join("dst")).unwrap();
        assert_eq!(std::fs::read(dir.path().join("dst/d/f")).unwrap(), b"x");
        assert_eq!(
            std::fs::read_link(dir.path().join("dst/l")).unwrap(),
            Path::new("d/f")
        );
    }
}
