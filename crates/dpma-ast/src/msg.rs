//! Out of call message (`ast_msg`) wrapper and the message technology.

use crate::ffi;
use crate::types::AstMsg;
use crate::util::{cstr, from_ptr};
use std::os::raw::{c_char, c_int};
use std::sync::RwLock;

/// Opaque `struct ast_msg_var_iterator`.
#[repr(C)]
struct AstMsgVarIterator {
    _private: [u8; 0],
}

extern "C" {
    fn ast_msg_get_to(msg: *const AstMsg) -> *const c_char;
    fn ast_msg_get_from(msg: *const AstMsg) -> *const c_char;
    fn ast_msg_get_tech(msg: *const AstMsg) -> *const c_char;
    fn ast_msg_get_endpoint(msg: *const AstMsg) -> *const c_char;
    fn ast_msg_var_iterator_init(msg: *const AstMsg) -> *mut AstMsgVarIterator;
    fn ast_msg_var_iterator_next(
        msg: *const AstMsg,
        iter: *mut AstMsgVarIterator,
        name: *mut *const c_char,
        value: *mut *const c_char,
    ) -> c_int;
    fn ast_msg_var_iterator_next_received(
        msg: *const AstMsg,
        iter: *mut AstMsgVarIterator,
        name: *mut *const c_char,
        value: *mut *const c_char,
    ) -> c_int;
    fn ast_msg_var_unref_current(iter: *mut AstMsgVarIterator);
    fn ast_msg_var_iterator_destroy(iter: *mut AstMsgVarIterator);
    fn __ao2_ref(o: *mut AstMsg, delta: c_int, tag: *const c_char, file: *const c_char, line: c_int, func: *const c_char)
        -> c_int;
}

/// One message variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgVar {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    /// Marked for sending out (outbound messages turn these into headers).
    pub outbound: bool,
}

/// An owned reference to an `ast_msg`.
pub struct Msg {
    ptr: *mut AstMsg,
}

// SAFETY: an ast_msg is a reference-counted ao2 object.  Through a shared
// reference only the getters run, which read the string fields and look up
// the (locked) variable container; everything that changes the message
// takes `&mut self`.
unsafe impl Send for Msg {}
unsafe impl Sync for Msg {}


impl Msg {
    /// Allocate a new, empty message.
    pub fn alloc() -> Option<Msg> {
        let p = unsafe { ffi::ast_msg_alloc() };
        if p.is_null() {
            None
        } else {
            Some(Msg { ptr: p })
        }
    }

    /// Take a new reference to a message owned by somebody else.
    ///
    /// # Safety
    /// `p` must be a valid message.
    pub unsafe fn from_borrowed(p: *const AstMsg) -> Option<Msg> {
        let r = ffi::dpma_glue_msg_ref(p);
        if r.is_null() {
            None
        } else {
            Some(Msg { ptr: r })
        }
    }

    pub fn as_ptr(&self) -> *mut AstMsg {
        self.ptr
    }

    /// The message's current reference count (for diagnostics).
    pub fn refcount(&self) -> i32 {
        let file = c"msg.rs";
        let func = c"refcount";
        unsafe { __ao2_ref(self.ptr, 0, std::ptr::null(), file.as_ptr(), line!() as c_int, func.as_ptr()) }
    }

    /// `ast_msg_get_var`: the variable's bytes.
    pub fn get_var(&self, name: &str) -> Option<Vec<u8>> {
        let n = cstr(name);
        unsafe { from_ptr(ffi::ast_msg_get_var(self.ptr, n.as_ptr())) }
    }

    /// Like `get_var`, but empty values are treated as absent.
    pub fn var(&self, name: &str) -> Option<Vec<u8>> {
        self.get_var(name).filter(|s| !s.is_empty())
    }

    /// The body's bytes (up to its NUL).
    pub fn body(&self) -> Option<Vec<u8>> {
        unsafe { from_ptr(ffi::ast_msg_get_body(self.ptr)) }
    }

    /// The message's "to" (for received PJSIP messages, the Request-URI
    /// with a `pjsip:` prefix).
    pub fn to(&self) -> Option<Vec<u8>> {
        unsafe { from_ptr(ast_msg_get_to(self.ptr)) }
    }

    /// The message's "from".
    pub fn from(&self) -> Option<Vec<u8>> {
        unsafe { from_ptr(ast_msg_get_from(self.ptr)) }
    }

    /// The technology that received the message (e.g., "PJSIP").
    pub fn tech(&self) -> Option<Vec<u8>> {
        unsafe { from_ptr(ast_msg_get_tech(self.ptr)) }
    }

    /// The endpoint that sent the message.
    pub fn endpoint(&self) -> Option<Vec<u8>> {
        unsafe { from_ptr(ast_msg_get_endpoint(self.ptr)) }
    }

    /// Every variable of the message: first those marked outbound, then
    /// the received (not outbound) ones, each in the message container's
    /// order.
    pub fn vars(&self) -> Vec<MsgVar> {
        let mut out = Vec::new();
        for outbound in [true, false] {
            unsafe {
                let iter = ast_msg_var_iterator_init(self.ptr);
                if iter.is_null() {
                    continue;
                }
                loop {
                    let mut name: *const c_char = std::ptr::null();
                    let mut value: *const c_char = std::ptr::null();
                    let more = if outbound {
                        ast_msg_var_iterator_next(self.ptr, iter, &mut name, &mut value)
                    } else {
                        ast_msg_var_iterator_next_received(self.ptr, iter, &mut name, &mut value)
                    };
                    if more == 0 {
                        break;
                    }
                    out.push(MsgVar {
                        name: from_ptr(name).unwrap_or_default(),
                        value: from_ptr(value).unwrap_or_default(),
                        outbound,
                    });
                    ast_msg_var_unref_current(iter);
                }
                ast_msg_var_iterator_destroy(iter);
            }
        }
        out
    }

    pub fn set_var(&mut self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> bool {
        let n = cstr(name);
        let v = cstr(value);
        unsafe { ffi::ast_msg_set_var(self.ptr, n.as_ptr(), v.as_ptr()) == 0 }
    }

    pub fn set_var_outbound(&mut self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> bool {
        let n = cstr(name);
        let v = cstr(value);
        unsafe { ffi::ast_msg_set_var_outbound(self.ptr, n.as_ptr(), v.as_ptr()) == 0 }
    }

    pub fn set_context(&mut self, v: impl AsRef<[u8]>) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_context(self.ptr, c.as_ptr()) == 0 }
    }

    pub fn set_exten(&mut self, v: impl AsRef<[u8]>) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_exten(self.ptr, c.as_ptr()) == 0 }
    }

    /// `ast_msg_set_body(msg, "%s", v)`: the body ends at the first NUL,
    /// as it would in C.
    pub fn set_body(&mut self, v: impl AsRef<[u8]>) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_body(self.ptr, c.as_ptr()) == 0 }
    }

    /// Queue the message for dialplan processing (`ast_msg_queue`).  The
    /// message core takes over this reference either way (it releases it
    /// itself when queueing fails).
    pub fn queue(self) -> bool {
        let p = self.ptr;
        std::mem::forget(self);
        unsafe { ffi::ast_msg_queue(p) == 0 }
    }

    /// Send the message straight to a message technology (`ast_msg_send`),
    /// e.g., to "pjsip:<endpoint>".  The message core takes over this
    /// reference.  Returns `ast_msg_send`'s result (0 on success).
    pub fn send(self, to: impl AsRef<[u8]>, from: Option<&[u8]>) -> i32 {
        let p = self.ptr;
        std::mem::forget(self);
        let t = cstr(to);
        let f = from.map(cstr);
        unsafe { ffi::ast_msg_send(p, t.as_ptr(), f.as_ref().map_or(std::ptr::null(), |f| f.as_ptr())) }
    }
}

impl Drop for Msg {
    fn drop(&mut self) {
        unsafe { ffi::ast_msg_destroy(self.ptr) };
    }
}

/// Receives the messages handed to the `digium_phone` technology
/// (`MessageSend(digium_phone:...)`): the message (a new reference), the
/// destination, and the sender.  Returns 0 on success, or -1.
pub type ReceiveFn = fn(msg: Msg, to: &[u8], from: &[u8]) -> i32;

static RECEIVER: RwLock<Option<ReceiveFn>> = RwLock::new(None);

/// Register the `digium_phone` message technology; its messages go to
/// `receiver`.
pub fn tech_register(receiver: ReceiveFn) -> bool {
    *RECEIVER.write().unwrap() = Some(receiver);
    let ok = unsafe { ffi::dpma_glue_msg_tech_register() == 0 };
    if !ok {
        *RECEIVER.write().unwrap() = None;
    }
    ok
}

/// Unregister the `digium_phone` message technology.  Once this returns,
/// no message is being delivered to the receiver (Asterisk holds its
/// technology lock while calling `msg_send`).
pub fn tech_unregister() {
    unsafe { ffi::dpma_glue_msg_tech_unregister() };
    *RECEIVER.write().unwrap() = None;
}

/// `msg_send` of the `digium_phone` technology (called through
/// `msg_send_trampoline` in common.c).
#[no_mangle]
pub unsafe extern "C" fn dpma_rust_msg_received(msg: *const AstMsg, to: *const c_char, from: *const c_char) -> c_int {
    crate::guard(-1, || {
        let Some(receiver) = *RECEIVER.read().unwrap() else {
            return -1;
        };
        if msg.is_null() {
            return -1;
        }
        let Some(m) = Msg::from_borrowed(msg) else {
            return -1;
        };
        let to = from_ptr(to).unwrap_or_default();
        let from = from_ptr(from).unwrap_or_default();
        receiver(m, &to, &from)
    })
}
