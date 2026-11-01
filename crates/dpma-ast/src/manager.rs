//! Asterisk Manager Interface helpers.

use crate::ffi;
use crate::types::{Mansession, Message};
use crate::util::{cstr, from_ptr, take_ast_string};
use std::collections::HashMap;
use std::os::raw::c_int;
use std::sync::{Mutex, OnceLock};

/// A manager session plus the request message being handled.
pub struct Request {
    s: *mut Mansession,
    m: *const Message,
}

impl Request {
    /// `astman_get_header(m, name)`: the header's bytes ("" when absent).
    pub fn header(&self, name: &str) -> Vec<u8> {
        let c = cstr(name);
        unsafe { from_ptr(ffi::astman_get_header(self.m, c.as_ptr())).unwrap_or_default() }
    }

    /// `astman_append(s, "%s", text)` (up to a NUL).
    pub fn append(&self, text: impl AsRef<[u8]>) {
        let c = cstr(text);
        unsafe { ffi::dpma_glue_astman_append(self.s, c.as_ptr()) };
    }

    pub fn send_ack(&self, msg: Option<&[u8]>) {
        let c = msg.map(cstr);
        unsafe {
            ffi::astman_send_ack(self.s, self.m, c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()))
        };
    }

    pub fn send_error(&self, msg: impl AsRef<[u8]>) {
        let c = cstr(msg);
        unsafe { ffi::astman_send_error(self.s, self.m, c.as_ptr()) };
    }

    pub fn send_listack(&self, msg: impl AsRef<[u8]>, listflag: &str) {
        let c = cstr(msg);
        let l = cstr(listflag);
        unsafe { ffi::astman_send_listack(self.s, self.m, c.as_ptr(), l.as_ptr()) };
    }
}

pub type ActionFn = fn(&Request) -> i32;

/// Registered actions by lower-cased name.
fn actions() -> &'static Mutex<HashMap<Vec<u8>, ActionFn>> {
    static A: OnceLock<Mutex<HashMap<Vec<u8>, ActionFn>>> = OnceLock::new();
    A.get_or_init(|| Mutex::new(HashMap::new()))
}

pub const AUTH_SYSTEM: i32 = 1 << 0;
pub const AUTH_CALL: i32 = 1 << 1;
pub const AUTH_LOG: i32 = 1 << 2;
pub const AUTH_VERBOSE: i32 = 1 << 3;
pub const AUTH_COMMAND: i32 = 1 << 4;
pub const AUTH_AGENT: i32 = 1 << 5;
pub const AUTH_USER: i32 = 1 << 6;
pub const AUTH_CONFIG: i32 = 1 << 7;
pub const AUTH_REPORTING: i32 = 1 << 9;
pub const AUTH_MESSAGE: i32 = 1 << 30;

/// Register a manager action.
pub fn register(action: &str, authority: i32, synopsis: &str, description: &str, f: ActionFn) -> bool {
    actions().lock().unwrap().insert(action.as_bytes().to_ascii_lowercase(), f);
    let a = cstr(action);
    let s = cstr(synopsis);
    let d = cstr(description);
    unsafe { ffi::dpma_glue_manager_register(a.as_ptr(), authority, s.as_ptr(), d.as_ptr()) == 0 }
}

pub fn unregister(action: &str) {
    let a = cstr(action);
    unsafe { ffi::dpma_glue_manager_unregister(a.as_ptr()) };
    actions().lock().unwrap().remove(&action.as_bytes().to_ascii_lowercase());
}

#[no_mangle]
pub unsafe extern "C" fn dpma_rust_manager_action(s: *mut Mansession, m: *const Message) -> c_int {
    crate::guard(0, || {
        let req = Request { s, m };
        let action = req.header("Action").to_ascii_lowercase();
        let f = actions().lock().unwrap().get(&action).copied();
        match f {
            Some(f) => f(&req),
            None => {
                req.send_error("Unknown action");
                0
            }
        }
    })
}

/// Raise a manager event (`manager_event(category, event, "%s", body)`).
pub fn event(category: i32, event: &str, body: impl AsRef<[u8]>) {
    let e = cstr(event);
    let b = cstr(body);
    unsafe { ffi::dpma_glue_manager_event(category, e.as_ptr(), b.as_ptr()) };
}

/// Raise a manager event that names `file`, `line`, and `func` as its
/// origin (the `File`, `Line`, and `Func` headers shown with `manager set
/// debug on`), as the original's `manager_event` calls do.
pub fn event_at(category: i32, event: &str, file: &str, line: u32, func: &str, body: impl AsRef<[u8]>) {
    let e = cstr(event);
    let f = cstr(file);
    let fu = cstr(func);
    let b = cstr(body);
    unsafe { ffi::dpma_glue_manager_event_at(category, e.as_ptr(), f.as_ptr(), line as c_int, fu.as_ptr(), b.as_ptr()) };
}

/// Run a manager action in-process (through a custom hook) and return the
/// raw response text.  `action` is the full action text, e.g.
/// "Action: QueueStatus\r\nQueue: sales\r\n".
pub fn hook_action(action: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let c = cstr(action);
    unsafe { take_ast_string(ffi::dpma_glue_manager_hook_action(c.as_ptr())) }
}
