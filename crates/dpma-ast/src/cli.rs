//! CLI command registration.
//!
//! Each command is an `ast_cli_entry` owned here, with the Rust handler
//! next to it; Asterisk calls the one `handler` below for all of them,
//! which finds the Rust handler from the entry it is given.

use crate::sys;
use crate::util::{ast_strdup, cstr, from_ptr};
use dpma_bytes::starts_with_ic;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

/// Arguments passed to a CLI command handler.
pub struct CliArgs {
    pub fd: i32,
    pub argv: Vec<Vec<u8>>,
}

impl CliArgs {
    pub fn argc(&self) -> usize {
        self.argv.len()
    }

    /// Write text to the CLI (`ast_cli(fd, "%s", text)`: up to a NUL).
    pub fn out(&self, text: impl AsRef<[u8]>) {
        let c = cstr(text);
        // SAFETY: valid C strings; the text is passed as a "%s" argument.
        unsafe { sys::ast_cli(self.fd, c"%s".as_ptr(), c.as_ptr()) };
    }
}

/// Arguments passed to a completion handler.
pub struct CompleteArgs {
    pub line: Vec<u8>,
    pub word: Vec<u8>,
    pub pos: i32,
    pub n: i32,
}

pub enum CliResult {
    Success,
    ShowUsage,
    Failure,
}

pub type ExecFn = fn(&CliArgs) -> CliResult;
pub type CompleteFn = fn(&CompleteArgs) -> Option<Vec<u8>>;

/// Definition of one CLI command.
pub struct CliCommand {
    pub command: &'static str,
    pub summary: &'static str,
    pub usage: &'static str,
    pub exec: ExecFn,
    pub complete: Option<CompleteFn>,
}

/// `CLI_SUCCESS`, `CLI_SHOWUSAGE`, and `CLI_FAILURE` (`(char *)
/// RESULT_*`).
const CLI_SUCCESS: *mut c_char = std::ptr::null_mut();
const CLI_SHOWUSAGE: *mut c_char = std::ptr::without_provenance_mut(1);
const CLI_FAILURE: *mut c_char = std::ptr::without_provenance_mut(2);

/// A registered command: the `ast_cli_entry` Asterisk holds (first, so a
/// pointer to it is a pointer to the whole) and what it refers to.
#[repr(C)]
struct Entry {
    raw: sys::ast_cli_entry,
    command: CString,
    summary: CString,
    usage: CString,
    exec: ExecFn,
    complete: Option<CompleteFn>,
}

/// The handler of every entry (`char *(*handler)(struct ast_cli_entry *e,
/// int cmd, struct ast_cli_args *a)`).
unsafe extern "C" fn handler(e: *mut sys::ast_cli_entry, cmd: c_int, a: *mut sys::ast_cli_args) -> *mut c_char {
    // SAFETY: every entry registered with this handler is the first field
    // of an `Entry` that lives until it is unregistered.
    let entry = &*(e as *const Entry);
    if cmd == sys::CLI_INIT {
        // The command words and usage (Asterisk copies the command).
        (*e).command = entry.command.as_ptr() as *mut c_char;
        (*e).usage = entry.usage.as_ptr();
        return std::ptr::null_mut();
    }
    if a.is_null() {
        return CLI_FAILURE;
    }
    // SAFETY: Asterisk's arguments for this call.
    let a = &*a;
    if cmd == sys::CLI_GENERATE {
        let Some(complete) = entry.complete else {
            return std::ptr::null_mut();
        };
        return crate::guard(std::ptr::null_mut(), || {
            let args = CompleteArgs {
                line: from_ptr(a.line).unwrap_or_default(),
                word: from_ptr(a.word).unwrap_or_default(),
                pos: a.pos,
                n: a.n,
            };
            // The caller frees the result with ast_free.
            complete(&args).map_or(std::ptr::null_mut(), ast_strdup)
        });
    }
    let exec = entry.exec;
    crate::guard(CLI_FAILURE, || {
        let argv = (0..a.argc.max(0) as usize).map(|i| from_ptr(*a.argv.add(i)).unwrap_or_default()).collect();
        match exec(&CliArgs { fd: a.fd, argv }) {
            CliResult::Success => CLI_SUCCESS,
            CliResult::ShowUsage => CLI_SHOWUSAGE,
            CliResult::Failure => CLI_FAILURE,
        }
    })
}

/// A registered group of commands; unregistered on drop.
pub struct CliGroup {
    /// Registered entries; Asterisk holds pointers into the slice, which
    /// never moves or grows.
    entries: Box<[Entry]>,
}

// SAFETY: the entries are only touched by Asterisk (under its CLI lock)
// and by `drop`, after they are unregistered.
unsafe impl Send for CliGroup {}
unsafe impl Sync for CliGroup {}

impl CliGroup {
    /// `ast_cli_register_multiple`: register `cmds` for this module.
    pub fn register(cmds: &[CliCommand]) -> CliGroup {
        let mut entries: Box<[Entry]> = cmds
            .iter()
            .map(|c| {
                Entry {
                    // SAFETY: an all-zero ast_cli_entry is the C empty
                    // initializer (NULL pointers, no handler).
                    raw: unsafe { std::mem::zeroed() },
                    command: cstr(c.command),
                    summary: cstr(c.summary),
                    usage: cstr(c.usage),
                    exec: c.exec,
                    complete: c.complete,
                }
            })
            .collect();
        let mut failed = false;
        for e in entries.iter_mut() {
            e.raw.summary = e.summary.as_ptr();
            e.raw.handler = Some(handler);
            // SAFETY: the entry stays at this address (the slice is never
            // moved or resized) until `drop` unregisters it.
            failed |= unsafe { sys::__ast_cli_register(&mut e.raw, crate::module::self_ptr()) } != 0;
        }
        if failed {
            crate::ast_log!(crate::log::LOG_ERROR, "Unable to register CLI commands");
        }
        CliGroup { entries }
    }
}

impl Drop for CliGroup {
    fn drop(&mut self) {
        for e in self.entries.iter_mut() {
            // SAFETY: registered by `register`.
            unsafe { sys::ast_cli_unregister(&mut e.raw) };
        }
    }
}

/// Standard completion over a list of candidate names: returns the n-th name
/// that starts with `word` (`strncasecmp`).
pub fn complete_from<I: IntoIterator<Item = Vec<u8>>>(args: &CompleteArgs, names: I) -> Option<Vec<u8>> {
    names
        .into_iter()
        .filter(|n| starts_with_ic(n, &args.word))
        .nth(args.n.max(0) as usize)
}
