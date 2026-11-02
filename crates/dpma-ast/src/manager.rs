//! Asterisk Manager Interface helpers.

use crate::sys;
use crate::types::{Mansession, Message};
use crate::util::{cstr, from_ptr};
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::raw::{c_char, c_int};
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
        // SAFETY: the request is valid while its action runs.
        unsafe { from_ptr(sys::astman_get_header(self.m, c.as_ptr() as *mut c_char)).unwrap_or_default() }
    }

    /// `astman_append(s, "%s", text)` (up to a NUL).
    pub fn append(&self, text: impl AsRef<[u8]>) {
        let c = cstr(text);
        // SAFETY: as above; the text is passed as a "%s" argument.
        unsafe { sys::astman_append(self.s, c"%s".as_ptr(), c.as_ptr()) };
    }

    pub fn send_ack(&self, msg: Option<&[u8]>) {
        let c = msg.map(cstr);
        // SAFETY: as above.
        unsafe { sys::astman_send_ack(self.s, self.m, c.as_ref().map_or(std::ptr::null_mut(), |c| c.as_ptr() as *mut c_char)) };
    }

    pub fn send_error(&self, msg: impl AsRef<[u8]>) {
        let c = cstr(msg);
        // SAFETY: as above.
        unsafe { sys::astman_send_error(self.s, self.m, c.as_ptr() as *mut c_char) };
    }

    pub fn send_listack(&self, msg: impl AsRef<[u8]>, listflag: &str) {
        let c = cstr(msg);
        let l = cstr(listflag);
        // SAFETY: as above.
        unsafe { sys::astman_send_listack(self.s, self.m, c.as_ptr() as *mut c_char, l.as_ptr() as *mut c_char) };
    }
}

pub type ActionFn = fn(&Request) -> i32;

/// Registered actions by lower-cased name.
fn actions() -> &'static Mutex<HashMap<Vec<u8>, ActionFn>> {
    static A: OnceLock<Mutex<HashMap<Vec<u8>, ActionFn>>> = OnceLock::new();
    A.get_or_init(|| Mutex::new(HashMap::new()))
}

pub const AUTH_SYSTEM: i32 = sys::EVENT_FLAG_SYSTEM as i32;
pub const AUTH_CALL: i32 = sys::EVENT_FLAG_CALL as i32;
pub const AUTH_LOG: i32 = sys::EVENT_FLAG_LOG as i32;
pub const AUTH_VERBOSE: i32 = sys::EVENT_FLAG_VERBOSE as i32;
pub const AUTH_COMMAND: i32 = sys::EVENT_FLAG_COMMAND as i32;
pub const AUTH_AGENT: i32 = sys::EVENT_FLAG_AGENT as i32;
pub const AUTH_USER: i32 = sys::EVENT_FLAG_USER as i32;
pub const AUTH_CONFIG: i32 = sys::EVENT_FLAG_CONFIG as i32;
pub const AUTH_REPORTING: i32 = sys::EVENT_FLAG_REPORTING as i32;
pub const AUTH_MESSAGE: i32 = sys::EVENT_FLAG_MESSAGE as i32;

/// Register a manager action (`ast_manager_register2`, for this module).
pub fn register(action: &str, authority: i32, synopsis: &str, description: &str, f: ActionFn) -> bool {
    actions().lock().unwrap().insert(action.as_bytes().to_ascii_lowercase(), f);
    // ast_manager_register2() keeps the action name pointer.
    let a = crate::util::intern(action);
    let s = cstr(synopsis);
    let d = cstr(description);
    // SAFETY: the name lives as long as the module; the synopsis and
    // description are copied.
    unsafe {
        sys::ast_manager_register2(a.as_ptr(), authority, Some(action_handler), crate::module::self_ptr(), s.as_ptr(), d.as_ptr())
            == 0
    }
}

pub fn unregister(action: &str) {
    let a = cstr(action);
    // SAFETY: a valid C string.
    unsafe { sys::ast_manager_unregister(a.as_ptr()) };
    actions().lock().unwrap().remove(&action.as_bytes().to_ascii_lowercase());
}

/// The handler of every action this module registers; it dispatches on
/// the request's `Action` header.
unsafe extern "C" fn action_handler(s: *mut Mansession, m: *const Message) -> c_int {
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

/// Raise a manager event that names `file`, `line`, and `func` as its
/// origin (the `File`, `Line`, and `Func` headers shown with `manager set
/// debug on`), as the official DPMA's `manager_event` calls do.
pub fn event_at(category: i32, event: &str, file: &str, line: u32, func: &str, body: impl AsRef<[u8]>) {
    let e = cstr(event);
    let f = cstr(file);
    let fu = cstr(func);
    let b = cstr(body);
    // SAFETY: valid C strings; the body is passed as a "%s" argument.
    unsafe {
        sys::__ast_manager_event_multichan(
            category,
            e.as_ptr(),
            0,
            std::ptr::null_mut(),
            f.as_ptr(),
            line as c_int,
            fu.as_ptr(),
            c"%s".as_ptr(),
            b.as_ptr(),
        )
    };
}

thread_local! {
    /// The response text `hook_action` is collecting on this thread.
    static HOOK_RESPONSE: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// The custom hook's helper: collect the response text.
unsafe extern "C" fn hook_collect(_category: c_int, _event: *const c_char, content: *mut c_char) -> c_int {
    crate::guard(0, || {
        // SAFETY: Asterisk passes the response text as a C string.
        let text = crate::util::bytes_or_empty(content);
        HOOK_RESPONSE.with(|r| {
            if let Some(buf) = r.borrow_mut().as_mut() {
                buf.extend_from_slice(text);
            }
        });
        0
    })
}

/// Run a manager action in-process (through a custom hook) and return the
/// raw response text.  `action` is the full action text, e.g.
/// "Action: QueueStatus\r\nQueue: sales\r\n".
pub fn hook_action(action: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let c = cstr(action);
    // SAFETY: an all-zero hook is unlinked; the action runs on this thread
    // and calls the helper before ast_hook_send_action returns.
    let mut hook: sys::manager_custom_hook = unsafe { std::mem::zeroed() };
    hook.file = c"dpma".as_ptr() as *mut c_char;
    hook.helper = Some(hook_collect);
    HOOK_RESPONSE.with(|r| *r.borrow_mut() = Some(Vec::new()));
    // SAFETY: as above.
    unsafe { sys::ast_hook_send_action(&mut hook, c.as_ptr()) };
    HOOK_RESPONSE.with(|r| r.borrow_mut().take())
}
