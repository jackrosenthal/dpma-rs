//! Scheduler contexts (`ast_sched_*`).
//!
//! A [`Context`] owns an `ast_sched_context`; dropping it destroys the
//! context (`ast_sched_context_destroy`), which stops its thread, if one was
//! started, and frees every pending entry without running it.  Scheduled
//! entries run only while something services the context: a thread from
//! [`Context::start_thread`], or explicit [`Context::runq`] calls.

use std::os::raw::{c_int, c_void};

#[repr(C)]
pub struct AstSchedContext {
    _private: [u8; 0],
}

/// `ast_sched_cb`: return non-zero to reschedule with the same delay, 0 to
/// drop the entry.  `data` is what was passed to [`Context::add`].
pub type SchedCb = unsafe extern "C" fn(data: *const c_void) -> c_int;

extern "C" {
    fn ast_sched_context_create() -> *mut AstSchedContext;
    fn ast_sched_context_destroy(con: *mut AstSchedContext);
    fn ast_sched_start_thread(con: *mut AstSchedContext) -> c_int;
    fn ast_sched_add(con: *mut AstSchedContext, when: c_int, callback: SchedCb, data: *const c_void) -> c_int;
    fn ast_sched_del(con: *mut AstSchedContext, id: c_int) -> c_int;
    fn ast_sched_runq(con: *mut AstSchedContext) -> c_int;
}

/// An `ast_sched_context`.
pub struct Context(*mut AstSchedContext);

// The scheduler API locks the context internally.
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    /// `ast_sched_context_create`; None on allocation failure.
    pub fn create() -> Option<Context> {
        let p = unsafe { ast_sched_context_create() };
        (!p.is_null()).then_some(Context(p))
    }

    /// `ast_sched_start_thread`: service the context from its own thread.
    /// True on success.
    pub fn start_thread(&self) -> bool {
        unsafe { ast_sched_start_thread(self.0) == 0 }
    }

    /// `ast_sched_add`: run `callback(data)` after `when_ms` milliseconds.
    /// Returns the entry id, or -1 on failure.
    pub fn add(&self, when_ms: i32, callback: SchedCb, data: usize) -> i32 {
        unsafe { ast_sched_add(self.0, when_ms, callback, data as *const c_void) }
    }

    /// `ast_sched_del`: cancel entry `id`.  0 when it was found and
    /// removed, -1 otherwise.
    pub fn del(&self, id: i32) -> i32 {
        unsafe { ast_sched_del(self.0, id) }
    }

    /// `ast_sched_runq`: run every entry that is due now; returns how many
    /// ran.
    pub fn runq(&self) -> i32 {
        unsafe { ast_sched_runq(self.0) }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ast_sched_context_destroy(self.0) };
    }
}
