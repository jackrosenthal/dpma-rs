//! The pinned Asterisk releases (`tools/asterisk-versions`).
//!
//! The pin file has one line per supported major version: the major
//! version, the exact release, and the SHA-256 checksum of its tarball,
//! which `tools/Containerfile` downloads and verifies.  Lines starting
//! with `#` are comments.  A version is named by its major version (`22`)
//! or its release (`22.11.0`).

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use crate::repo_root;

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

/// The pin named by `name` (a major version or a release), or the newest
/// pinned release (the highest major version) for `None`.
pub fn pin(name: Option<&str>) -> Result<Pin> {
    let all = pins()?;
    match name {
        Some(name) => all
            .into_iter()
            .find(|p| p.major == name || p.version == name)
            .ok_or_else(|| anyhow!("Asterisk {name} is not pinned in {}", pins_file().display())),
        None => all
            .into_iter()
            .max_by_key(|p| p.major.parse::<u32>().unwrap_or(0))
            .ok_or_else(|| anyhow!("no releases are pinned in {}", pins_file().display())),
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
        assert_eq!(pins[0].version, "22.11.0");
    }

    #[test]
    fn the_pins_resolve() {
        let all = pins().unwrap();
        assert!(!all.is_empty());
        for p in &all {
            assert_eq!(pin(Some(&p.major)).unwrap(), *p);
            assert_eq!(pin(Some(&p.version)).unwrap(), *p);
            assert_eq!(p.sha256.len(), 64);
        }
        assert!(pin(Some("not-a-version")).is_err());
        let n = pin(None).unwrap();
        assert!(all
            .iter()
            .all(|p| p.major.parse::<u32>().unwrap() <= n.major.parse::<u32>().unwrap()));
    }
}
