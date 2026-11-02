//! Reading what Asterisk logged since a mark.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bstr::BString;

use super::check::contains_bytes;

/// A position in a log file (its size when the mark was taken).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogMark(pub u64);

/// A log file (normally an instance's `messages.log`).
#[derive(Clone, Debug)]
pub struct Log {
    path: PathBuf,
}

impl Log {
    /// The log at `path`.
    pub fn new(path: &Path) -> Log {
        Log {
            path: path.to_path_buf(),
        }
    }

    /// The path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current end of the log.
    pub fn mark(&self) -> LogMark {
        LogMark(std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0))
    }

    /// What was written since `mark`; all of the log when it is shorter
    /// than the mark (Asterisk was restarted, which starts a new log).
    pub fn since(&self, mark: LogMark) -> BString {
        let Ok(mut f) = std::fs::File::open(&self.path) else {
            return BString::default();
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len >= mark.0 {
            let _ = f.seek(SeekFrom::Start(mark.0));
        }
        let mut out = Vec::new();
        let _ = f.read_to_end(&mut out);
        out.into()
    }

    /// The whole log.
    pub fn all(&self) -> BString {
        self.since(LogMark(0))
    }

    /// Whether `text` was logged since `mark`, waiting up to `timeout` for
    /// it (Asterisk's logger writes from its own thread).
    pub fn wait_for(&self, mark: LogMark, text: impl AsRef<[u8]>, timeout: Duration) -> bool {
        crate::util::wait_until(timeout, Duration::from_millis(20), || {
            contains_bytes(&self.since(mark), text.as_ref())
        })
    }
}
