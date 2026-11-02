//! The pinned Asterisk releases (`tools/asterisk-versions`) and where
//! their builds live.
//!
//! The pin file has one line per supported major version: the major
//! version, the exact release (a tarball in [`RELEASES_URL`]), and the
//! SHA-256 checksum of `asterisk-<release>.tar.gz`.  Lines starting with
//! `#` are comments.  A version is named by its major version (`22`) or
//! its release (`22.11.0`).
//!
//! Builds go under [`builds_dir`]: `<release>/src` (the configured
//! source tree, for `ASTERISK_SOURCE_DIR`) and `<release>/prefix` (the
//! installation), made by `cargo xtask asterisk build`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::sim::repo_root;

/// Where the release tarballs are downloaded from.
pub const RELEASES_URL: &str = "https://downloads.asterisk.org/pub/telephony/asterisk/releases";

/// One pinned release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The major version (`22`).
    pub major: String,
    /// The release (`22.11.0`).
    pub version: String,
    /// The SHA-256 checksum of the tarball (lowercase hex).
    pub sha256: String,
}

impl Pin {
    /// The tarball's file name.
    pub fn tarball(&self) -> String {
        format!("asterisk-{}.tar.gz", self.version)
    }

    /// The tarball's download URL.
    pub fn url(&self) -> String {
        format!("{RELEASES_URL}/{}", self.tarball())
    }

    /// The release's directory in `builds` (`<builds>/<release>`).
    pub fn dir(&self, builds: &Path) -> PathBuf {
        builds.join(&self.version)
    }

    /// Its configured source tree (`<builds>/<release>/src`).
    pub fn src(&self, builds: &Path) -> PathBuf {
        self.dir(builds).join("src")
    }

    /// Its installation (`<builds>/<release>/prefix`).
    pub fn prefix(&self, builds: &Path) -> PathBuf {
        self.dir(builds).join("prefix")
    }
}

/// The pin file, `tools/asterisk-versions`.
pub fn pins_file() -> PathBuf {
    repo_root().join("tools").join("asterisk-versions")
}

/// The pins in the text of a pin file, in file order.
pub fn parse_pins(text: &str) -> Vec<Pin> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (major, version, sha256) = (f.next()?, f.next()?, f.next()?);
            Some(Pin {
                major: major.into(),
                version: version.into(),
                sha256: sha256.into(),
            })
        })
        .collect()
}

/// The pins of [`pins_file`], in file order.
pub fn pins() -> Result<Vec<Pin>> {
    let path = pins_file();
    let text = std::fs::read_to_string(&path).with_context(|| path.display().to_string())?;
    Ok(parse_pins(&text))
}

/// The pin named by `name`: a major version or a release.
pub fn pin(name: &str) -> Result<Pin> {
    pins()?
        .into_iter()
        .find(|p| p.major == name || p.version == name)
        .ok_or_else(|| anyhow!("Asterisk {name} is not pinned in {}", pins_file().display()))
}

/// The newest pinned release (the highest major version): the default
/// release of a new instance.
pub fn newest() -> Result<Pin> {
    pins()?
        .into_iter()
        .max_by_key(|p| p.major.parse::<u32>().unwrap_or(0))
        .ok_or_else(|| anyhow!("no releases are pinned in {}", pins_file().display()))
}

/// Where the builds go: `$DPMA_AST_BUILDS` (made absolute), else
/// `dev/asterisk-builds` in the repository.  Not resolved to its physical
/// path; `cargo xtask asterisk build` does that (configure records the
/// prefix).
pub fn builds_dir() -> PathBuf {
    match std::env::var_os("DPMA_AST_BUILDS") {
        Some(p) if !p.is_empty() => {
            let p = PathBuf::from(p);
            std::path::absolute(&p).unwrap_or(p)
        }
        _ => repo_root().join("dev").join("asterisk-builds"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_file() {
        let pins = parse_pins(
            "# comment\n22  22.11.0  abc\n\n23 23.5.0 def extra\n24  24.0.0-rc4\n# 25 x y\n",
        );
        assert_eq!(pins.len(), 2);
        assert_eq!(
            pins[1],
            Pin {
                major: "23".into(),
                version: "23.5.0".into(),
                sha256: "def".into()
            }
        );
        assert_eq!(
            pins[0].url(),
            "https://downloads.asterisk.org/pub/telephony/asterisk/releases/asterisk-22.11.0.tar.gz"
        );
        assert_eq!(
            pins[0].prefix(Path::new("/b")),
            Path::new("/b/22.11.0/prefix")
        );
    }

    #[test]
    fn the_pins_resolve() {
        let all = pins().unwrap();
        assert!(!all.is_empty());
        for p in &all {
            assert_eq!(pin(&p.major).unwrap(), *p);
            assert_eq!(pin(&p.version).unwrap(), *p);
            assert_eq!(p.sha256.len(), 64);
        }
        assert!(pin("not-a-version").is_err());
        let n = newest().unwrap();
        assert!(all
            .iter()
            .all(|p| p.major.parse::<u32>().unwrap() <= n.major.parse::<u32>().unwrap()));
    }
}
