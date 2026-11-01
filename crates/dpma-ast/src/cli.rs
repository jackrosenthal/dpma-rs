//! CLI command registration.
//!
//! Commands are registered as a group; the C glue owns the `ast_cli_entry`
//! structures and dispatches back into Rust by numeric id.

use crate::ffi;
use crate::util::{ast_strdup, cstr, from_ptr};
use std::collections::HashMap;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

/// Arguments passed to a CLI command handler.
pub struct CliArgs {
    pub fd: i32,
    pub argv: Vec<String>,
}

impl CliArgs {
    pub fn argc(&self) -> usize {
        self.argv.len()
    }

    /// Write text to the CLI.
    pub fn out(&self, text: &str) {
        let c = cstr(text);
        unsafe { ffi::dpma_glue_cli_out(self.fd, c.as_ptr()) };
    }
}

/// Arguments passed to a completion handler.
pub struct CompleteArgs {
    pub line: String,
    pub word: String,
    pub pos: i32,
    pub n: i32,
}

pub enum CliResult {
    Success,
    ShowUsage,
    Failure,
}

pub type ExecFn = fn(&CliArgs) -> CliResult;
pub type CompleteFn = fn(&CompleteArgs) -> Option<String>;

/// Definition of one CLI command.
pub struct CliCommand {
    pub command: &'static str,
    pub summary: &'static str,
    pub usage: &'static str,
    pub exec: ExecFn,
    pub complete: Option<CompleteFn>,
}

struct Handler {
    exec: ExecFn,
    complete: Option<CompleteFn>,
}

fn handlers() -> &'static Mutex<HashMap<i32, Handler>> {
    static H: OnceLock<Mutex<HashMap<i32, Handler>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: Mutex<i32> = Mutex::new(1);

/// A registered group of commands; unregistered on drop.
pub struct CliGroup {
    handle: *mut c_void,
    ids: Vec<i32>,
}

unsafe impl Send for CliGroup {}
unsafe impl Sync for CliGroup {}

impl CliGroup {
    pub fn register(cmds: &[CliCommand]) -> CliGroup {
        let mut ids = Vec::new();
        {
            let mut next = NEXT_ID.lock().unwrap();
            let mut h = handlers().lock().unwrap();
            for c in cmds {
                let id = *next;
                *next += 1;
                h.insert(id, Handler { exec: c.exec, complete: c.complete });
                ids.push(id);
            }
        }
        let commands: Vec<_> = cmds.iter().map(|c| cstr(c.command)).collect();
        let summaries: Vec<_> = cmds.iter().map(|c| cstr(c.summary)).collect();
        let usages: Vec<_> = cmds.iter().map(|c| cstr(c.usage)).collect();
        let cp: Vec<*const c_char> = commands.iter().map(|c| c.as_ptr()).collect();
        let sp: Vec<*const c_char> = summaries.iter().map(|c| c.as_ptr()).collect();
        let up: Vec<*const c_char> = usages.iter().map(|c| c.as_ptr()).collect();
        let handle = unsafe {
            ffi::dpma_glue_cli_register(cp.as_ptr(), sp.as_ptr(), up.as_ptr(), ids.as_ptr(), ids.len() as c_int)
        };
        CliGroup { handle, ids }
    }
}

impl Drop for CliGroup {
    fn drop(&mut self) {
        unsafe { ffi::dpma_glue_cli_unregister(self.handle) };
        let mut h = handlers().lock().unwrap();
        for id in &self.ids {
            h.remove(id);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpma_rust_cli_exec(id: c_int, fd: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    crate::guard(2, || {
        let exec = match handlers().lock().unwrap().get(&id) {
            Some(h) => h.exec,
            None => return 2,
        };
        let mut args = Vec::with_capacity(argc as usize);
        for i in 0..argc as usize {
            args.push(from_ptr(*argv.add(i)).unwrap_or_default());
        }
        match exec(&CliArgs { fd, argv: args }) {
            CliResult::Success => 0,
            CliResult::ShowUsage => 1,
            CliResult::Failure => 2,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dpma_rust_cli_complete(
    id: c_int,
    line: *const c_char,
    word: *const c_char,
    pos: c_int,
    n: c_int,
) -> *mut c_char {
    crate::guard(std::ptr::null_mut(), || {
        let complete = match handlers().lock().unwrap().get(&id) {
            Some(Handler { complete: Some(c), .. }) => *c,
            _ => return std::ptr::null_mut(),
        };
        let args = CompleteArgs {
            line: from_ptr(line).unwrap_or_default(),
            word: from_ptr(word).unwrap_or_default(),
            pos,
            n,
        };
        match complete(&args) {
            Some(s) => ast_strdup(&s),
            None => std::ptr::null_mut(),
        }
    })
}

/// Standard completion over a list of candidate names: returns the n-th name
/// that starts with `word` (case insensitive).
pub fn complete_from<I: IntoIterator<Item = String>>(args: &CompleteArgs, names: I) -> Option<String> {
    let word = args.word.to_ascii_lowercase();
    names
        .into_iter()
        .filter(|n| n.to_ascii_lowercase().starts_with(&word))
        .nth(args.n.max(0) as usize)
}
