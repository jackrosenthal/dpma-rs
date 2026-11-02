//! The Digium phone application-server protocol, independent of Asterisk.
//!
//! Everything here is pure Rust so it can be unit tested with `cargo test
//! -p dpma-proto`.  The Asterisk side (ast_msg handling, sessions, dialplan
//! routing) lives in `res_digium_phone`.
//!
//! Cryptography uses the RustCrypto crates, and certificates are decoded
//! with `x509-cert` ([`cert`] documents what phone certificate
//! verification checks).  Where the official DPMA's message encryption and
//! common password depend on the behavior of the OpenSSL 1.1.1t it links
//! statically (key checks, the error texts it logs), that behavior is
//! reproduced here from 1.1.1t's source ([`crypto`], [`errstack`]).
//!
//! The official DPMA logs from inside several of the functions ported here
//! (phone_crypto.c, reqresp_parser.c, `session_verify_cert`).  Those
//! messages are passed, with the official DPMA's file, line, and function
//! names, to a hook that the module installs with [`set_log_hook`]; without
//! a hook (for example, in unit tests) they are dropped.

pub mod cert;
pub mod crypto;
pub mod errors;
pub mod errstack;
pub mod framing;
pub mod headers;
pub mod json;
pub mod types;
pub mod uri;
pub mod xml;

mod cbuf;
mod rsakey;

use std::sync::RwLock;

/// Errors from this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Invalid input (bad hex, bad base64, wrong length, ...).
    Invalid(String),
    /// A cryptographic operation failed; the text is what the official DPMA
    /// logs (format string filled in, no trailing newline).
    Crypto(String),
}

impl ProtoError {
    /// The bare message, without the variant prefix of `Display`.
    pub fn message(&self) -> &str {
        match self {
            ProtoError::Invalid(s) | ProtoError::Crypto(s) => s,
        }
    }
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Invalid(s) => write!(f, "invalid: {}", s),
            ProtoError::Crypto(s) => write!(f, "crypto: {}", s),
        }
    }
}

impl std::error::Error for ProtoError {}

pub type Result<T> = std::result::Result<T, ProtoError>;

/// Where a log message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// The module's custom `DPMA` logger level (`DAT_005e7e38`).
    Dpma,
    /// `ast_debug(n, ...)`: the hook must check the debug level itself.
    Debug(i32),
}

/// Receives log messages: level, the official DPMA's source file, line, and
/// function, and the message exactly as the official DPMA formats it
/// (including its trailing newline, or the lack of one; bytes, as the
/// message carries text from phones as it came).
pub type LogHook = fn(level: LogLevel, file: &str, line: u32, func: &str, msg: &[u8]);

static LOG_HOOK: RwLock<Option<LogHook>> = RwLock::new(None);

/// Install (or, with `None`, remove) the log hook.
pub fn set_log_hook(hook: Option<LogHook>) {
    if let Ok(mut h) = LOG_HOOK.write() {
        *h = hook;
    }
}

pub(crate) fn log(level: LogLevel, file: &str, line: u32, func: &str, msg: &[u8]) {
    let hook = LOG_HOOK.read().ok().and_then(|h| *h);
    if let Some(hook) = hook {
        hook(level, file, line, func, msg);
    }
}

#[cfg(test)]
pub(crate) mod testlog {
    //! Captures log messages in unit tests (per thread).
    use std::cell::RefCell;

    thread_local! {
        static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn hook(_level: super::LogLevel, _file: &str, _line: u32, _func: &str, msg: &[u8]) {
        LINES.with(|l| l.borrow_mut().push(String::from_utf8_lossy(msg).into_owned()));
    }

    /// Run `f` and return what it logged on this thread.
    pub fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
        super::set_log_hook(Some(hook));
        LINES.with(|l| l.borrow_mut().clear());
        let r = f();
        let lines = LINES.with(|l| std::mem::take(&mut *l.borrow_mut()));
        (r, lines)
    }
}
