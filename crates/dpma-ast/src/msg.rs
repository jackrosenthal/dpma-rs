//! Out of call message (`ast_msg`) wrapper.

use crate::ffi;
use crate::types::AstMsg;
use crate::util::{cstr, from_ptr};

/// An owned reference to an `ast_msg`.
pub struct Msg {
    ptr: *mut AstMsg,
}

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

    pub fn get_var(&self, name: &str) -> Option<String> {
        let n = cstr(name);
        unsafe { from_ptr(ffi::ast_msg_get_var(self.ptr, n.as_ptr())) }
    }

    /// Like `get_var`, but empty values are treated as absent.
    pub fn var(&self, name: &str) -> Option<String> {
        self.get_var(name).filter(|s| !s.is_empty())
    }

    pub fn body(&self) -> Option<String> {
        unsafe { from_ptr(ffi::ast_msg_get_body(self.ptr)) }
    }

    pub fn set_var(&self, name: &str, value: &str) -> bool {
        let n = cstr(name);
        let v = cstr(value);
        unsafe { ffi::ast_msg_set_var(self.ptr, n.as_ptr(), v.as_ptr()) == 0 }
    }

    pub fn set_var_outbound(&self, name: &str, value: &str) -> bool {
        let n = cstr(name);
        let v = cstr(value);
        unsafe { ffi::ast_msg_set_var_outbound(self.ptr, n.as_ptr(), v.as_ptr()) == 0 }
    }

    pub fn set_context(&self, v: &str) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_context(self.ptr, c.as_ptr()) == 0 }
    }

    pub fn set_exten(&self, v: &str) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_exten(self.ptr, c.as_ptr()) == 0 }
    }

    pub fn set_body(&self, v: &str) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_body(self.ptr, c.as_ptr()) == 0 }
    }

    pub fn set_from(&self, v: &str) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_from(self.ptr, c.as_ptr()) == 0 }
    }

    pub fn set_to(&self, v: &str) -> bool {
        let c = cstr(v);
        unsafe { ffi::dpma_glue_msg_set_to(self.ptr, c.as_ptr()) == 0 }
    }

    /// Queue the message for dialplan processing.  Ownership passes to the
    /// message core on success.
    pub fn queue(self) -> bool {
        let p = self.ptr;
        std::mem::forget(self);
        let res = unsafe { ffi::ast_msg_queue(p) };
        if res != 0 {
            unsafe { ffi::ast_msg_destroy(p) };
            false
        } else {
            true
        }
    }
}

impl Drop for Msg {
    fn drop(&mut self) {
        unsafe { ffi::ast_msg_destroy(self.ptr) };
    }
}

pub fn tech_register() -> bool {
    unsafe { ffi::dpma_glue_msg_tech_register() == 0 }
}

pub fn tech_unregister() {
    unsafe { ffi::dpma_glue_msg_tech_unregister() };
}
