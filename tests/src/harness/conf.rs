//! Editing Asterisk configuration files as bytes (Latin-1 values stay
//! as they are).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bstr::ByteSlice;

/// An Asterisk configuration file.
#[derive(Clone, Debug)]
pub struct ConfFile {
    path: PathBuf,
}

/// Restores a file's earlier contents when dropped (or on
/// [`ConfBackup::restore`]).
pub struct ConfBackup {
    path: PathBuf,
    data: Option<Vec<u8>>,
}

impl ConfBackup {
    /// Puts the saved contents back now.
    pub fn restore(mut self) -> Result<()> {
        self.put_back()
    }

    fn put_back(&mut self) -> Result<()> {
        match self.data.take() {
            Some(d) => {
                std::fs::write(&self.path, d).with_context(|| self.path.display().to_string())
            }
            None => Ok(()),
        }
    }
}

impl Drop for ConfBackup {
    fn drop(&mut self) {
        let _ = self.put_back();
    }
}

fn section_name(line: &[u8]) -> Option<&[u8]> {
    let t = line.trim_ascii();
    if !t.starts_with(b"[") {
        return None;
    }
    let end = t.find_byte(b']')?;
    Some(&t[1..end])
}

impl ConfFile {
    /// The file at `path`.
    pub fn new(path: &Path) -> ConfFile {
        ConfFile {
            path: path.to_path_buf(),
        }
    }

    /// The path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The contents.
    pub fn read(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.path).with_context(|| self.path.display().to_string())
    }

    /// Replaces the contents.
    pub fn write(&self, data: impl AsRef<[u8]>) -> Result<()> {
        std::fs::write(&self.path, data).with_context(|| self.path.display().to_string())
    }

    /// Saves the contents, to be restored when the guard is dropped.
    pub fn backup(&self) -> Result<ConfBackup> {
        Ok(ConfBackup {
            path: self.path.clone(),
            data: Some(self.read()?),
        })
    }

    /// Sets options of `[section]` (case insensitive): every existing line
    /// of a key in `options` is removed from the section, and the options
    /// whose value is `Some` are written right after the section header
    /// (as `key=value`).
    pub fn set_options(&self, section: &str, options: &[(&str, Option<&[u8]>)]) -> Result<()> {
        let data = self.read()?;
        let mut out: Vec<u8> = Vec::with_capacity(data.len() + 64);
        let mut inside = false;
        for line in data.split_inclusive(|&b| b == b'\n') {
            if let Some(name) = section_name(line) {
                inside = name.eq_ignore_ascii_case(section.as_bytes());
                out.extend_from_slice(line);
                if inside {
                    if !line.ends_with(b"\n") {
                        out.push(b'\n');
                    }
                    for (k, v) in options {
                        if let Some(v) = v {
                            out.extend_from_slice(k.as_bytes());
                            out.push(b'=');
                            out.extend_from_slice(v);
                            out.push(b'\n');
                        }
                    }
                }
                continue;
            }
            if inside {
                let t = line.trim_ascii();
                if let Some(eq) = t.find_byte(b'=') {
                    let key = t[..eq].trim_ascii();
                    if options
                        .iter()
                        .any(|(k, _)| key.eq_ignore_ascii_case(k.as_bytes()))
                    {
                        continue;
                    }
                }
            }
            out.extend_from_slice(line);
        }
        self.write(out)
    }

    /// Replaces the body of `[section]` (up to the next section header)
    /// with `lines`.
    pub fn replace_section(&self, section: &str, lines: &[&[u8]]) -> Result<()> {
        let data = self.read()?;
        let mut out: Vec<u8> = Vec::with_capacity(data.len());
        let mut inside = false;
        let mut done = false;
        for line in data.split_inclusive(|&b| b == b'\n') {
            if let Some(name) = section_name(line) {
                inside = !done && name.eq_ignore_ascii_case(section.as_bytes());
                out.extend_from_slice(line);
                if inside {
                    done = true;
                    for l in lines {
                        out.extend_from_slice(l);
                        out.push(b'\n');
                    }
                    out.push(b'\n');
                }
                continue;
            }
            if !inside {
                out.extend_from_slice(line);
            }
        }
        self.write(out)
    }

    /// Adds `#include "<name>"` at the end unless the file has that line.
    pub fn add_include(&self, name: &str) -> Result<()> {
        let mut data = self.read()?;
        let line = format!("#include \"{name}\"");
        if data.lines().any(|l| l == line.as_bytes()) {
            return Ok(());
        }
        data.extend_from_slice(format!("\n{line}\n").as_bytes());
        self.write(data)
    }

    /// Removes the line `#include "<name>"`.
    pub fn remove_include(&self, name: &str) -> Result<()> {
        let data = self.read()?;
        let line = format!("#include \"{name}\"");
        let out: Vec<u8> = data
            .split_inclusive(|&b| b == b'\n')
            .filter(|l| l.trim_end_with(|c| c == '\n' || c == '\r') != line.as_bytes())
            .flatten()
            .copied()
            .collect();
        self.write(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_and_sections() {
        let dir = std::env::temp_dir().join(format!("dpma-tests-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = ConfFile::new(&dir.join("x.conf"));
        f.write(b"; c\n[general]\na=1\nb=2\n\n[p]\na=3\n").unwrap();
        f.set_options(
            "general",
            &[("a", Some(b"9")), ("b", None), ("c", Some(b"\xe9"))],
        )
        .unwrap();
        assert_eq!(
            f.read().unwrap(),
            b"; c\n[general]\na=9\nc=\xe9\n\n[p]\na=3\n"
        );
        f.replace_section("general", &[b"x=1"]).unwrap();
        assert_eq!(f.read().unwrap(), b"; c\n[general]\nx=1\n\n[p]\na=3\n");
        {
            let _b = f.backup().unwrap();
            f.add_include("s.conf").unwrap();
            f.add_include("s.conf").unwrap();
            assert_eq!(
                f.read().unwrap(),
                b"; c\n[general]\nx=1\n\n[p]\na=3\n\n#include \"s.conf\"\n"
            );
            f.remove_include("s.conf").unwrap();
            assert_eq!(f.read().unwrap(), b"; c\n[general]\nx=1\n\n[p]\na=3\n\n");
        }
        assert_eq!(f.read().unwrap(), b"; c\n[general]\nx=1\n\n[p]\na=3\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
