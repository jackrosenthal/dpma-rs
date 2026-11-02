//! The Asterisk CLI through the control socket, as `asterisk -rx` runs
//! it (`ast_remotecontrol` in Asterisk's `main/asterisk.c`).
//!
//! The client connects to `<astrundir>/<astctl>`, reads the banner
//! (`host/pid/version`), sends `cli quit after <command>` and a NUL, and
//! reads the output until Asterisk closes the connection.  Like `asterisk
//! -rx`, it drops the verbose and log lines Asterisk interleaves (lines
//! whose first byte has the high bit set, the verbose "magic"), so the
//! result is exactly what `asterisk -rx` prints, bytes included.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bstr::{BString, ByteSlice};

/// A CLI client for one instance's control socket.
#[derive(Clone, Debug)]
pub struct Cli {
    socket: PathBuf,
    timeout: Duration,
}

impl Cli {
    /// A client for the control socket at `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Cli {
        Cli {
            socket: socket.into(),
            timeout: Duration::from_secs(60),
        }
    }

    /// The client of the instance whose `asterisk.conf` is `conf`: the
    /// socket is `astctl` (default `asterisk.ctl`) in `astrundir`.
    pub fn from_asterisk_conf(conf: &Path) -> Result<Cli> {
        let text = std::fs::read(conf).with_context(|| conf.display().to_string())?;
        let mut rundir = None;
        let mut ctl = "asterisk.ctl".to_string();
        for line in text.lines() {
            let line = line.trim_ascii();
            if line.starts_with(b";") {
                continue;
            }
            let Some(i) = line.find_byte(b'=') else {
                continue;
            };
            let key = line[..i].trim_ascii();
            let mut value = &line[i + 1..];
            if value.first() == Some(&b'>') {
                value = &value[1..];
            }
            let value = value.trim_ascii().to_str_lossy().into_owned();
            if key.eq_ignore_ascii_case(b"astrundir") {
                rundir = Some(value);
            } else if key.eq_ignore_ascii_case(b"astctl") {
                ctl = value;
            }
        }
        let rundir = rundir.ok_or_else(|| anyhow!("no astrundir in {}", conf.display()))?;
        Ok(Cli::new(Path::new(&rundir).join(ctl)))
    }

    /// The socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Sets how long to wait for output (default 60 s, as `asterisk
    /// -rx`).
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Runs `command` and returns its output exactly as `asterisk -rx`
    /// prints it.  Fails when Asterisk is not running.
    pub fn run(&self, command: &str) -> Result<BString> {
        self.run_bytes(command.as_bytes())
    }

    /// [`Cli::run`] with a command given as bytes.
    pub fn run_bytes(&self, command: &[u8]) -> Result<BString> {
        let mut s = UnixStream::connect(&self.socket)
            .with_context(|| format!("connecting to {}", self.socket.display()))?;
        let deadline = Instant::now() + self.timeout;
        s.set_read_timeout(Some(self.timeout))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        // The banner: "<host>/<pid>/<version>\n".
        let banner_end = loop {
            if let Some(i) = buf.find_byte(b'\n') {
                break i + 1;
            }
            let n = s.read(&mut chunk)?;
            if n == 0 {
                return Err(anyhow!("the control socket closed before the banner"));
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        buf.drain(..banner_end);
        let mut msg = b"cli quit after ".to_vec();
        msg.extend_from_slice(command);
        msg.push(0);
        s.write_all(&msg)?;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            s.set_read_timeout(Some(left))?;
            match s.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::Interrupted) => continue,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(filter_verbose(&buf))
    }

    /// [`Cli::run`] as text (lossy; empty when Asterisk is not running).
    pub fn text(&self, command: &str) -> String {
        self.run(command)
            .map(|b| b.to_str_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Whether Asterisk answers on the control socket.
    pub fn alive(&self) -> bool {
        self.run("core show uptime")
            .is_ok_and(|o| o.contains_str("uptime"))
    }
}

/// Drops the lines `asterisk -rx` does not print: those whose first byte
/// is a verbose marker (high bit set) and the continuations of such lines.
pub fn filter_verbose(data: &[u8]) -> BString {
    let mut out = Vec::with_capacity(data.len());
    for line in data.split_inclusive(|&b| b == b'\n') {
        if line.first().is_some_and(|&b| b < 0x80) {
            out.extend_from_slice(line);
        }
    }
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbose_lines_are_dropped() {
        let data = b"line one\n\x8c-- verbose\nline \xe9 two\n\xffmore verbose\n\nlast";
        assert_eq!(
            filter_verbose(data),
            &b"line one\nline \xe9 two\n\nlast"[..]
        );
    }
}
