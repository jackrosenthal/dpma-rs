//! Asterisk thread pools (`ast_threadpool_*`) and thread registration
//! (`ast_register_thread`).
//!
//! Filled in by P3 "request" (wave 1).
//!
//! A task pushed onto a pool is a boxed Rust closure.  The closure is kept
//! in a table here and only its id travels through Asterisk, so tasks still
//! queued when a pool is shut down (Asterisk frees those without running
//! them) are dropped properly instead of leaking.

use crate::util::{ast_strdup, cstr};
use std::collections::HashMap;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

#[repr(C)]
struct AstThreadpool {
    _private: [u8; 0],
}

/// `struct ast_threadpool_options` (AST_THREADPOOL_OPTIONS_VERSION 1).
#[repr(C)]
struct AstThreadpoolOptions {
    version: c_int,
    idle_timeout: c_int,
    auto_increment: c_int,
    initial_size: c_int,
    max_size: c_int,
    thread_start: Option<extern "C" fn()>,
    thread_end: Option<extern "C" fn()>,
}

extern "C" {
    fn ast_threadpool_create(
        name: *const c_char,
        listener: *mut c_void,
        options: *const AstThreadpoolOptions,
    ) -> *mut AstThreadpool;
    fn __ast_threadpool_push(
        pool: *mut AstThreadpool,
        task: extern "C" fn(*mut c_void) -> c_int,
        data: *mut c_void,
        file: *const c_char,
        line: c_int,
        function: *const c_char,
    ) -> c_int;
    fn ast_threadpool_shutdown(pool: *mut AstThreadpool);
    fn ast_register_thread(name: *mut c_char);
    fn ast_unregister_thread(id: *mut c_void);
}

/// Pool sizing (the fields of `struct ast_threadpool_options`).
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Seconds before an idle thread exits (0 or less: never).
    pub idle_timeout: i32,
    /// Threads added when a task finds no idle thread.
    pub auto_increment: i32,
    pub initial_size: i32,
    /// 0 means unlimited.
    pub max_size: i32,
}

/// A task run on a pool thread.
pub type Task = Box<dyn FnOnce() + Send + 'static>;

/// Where a push came from, for Asterisk's taskprocessor bookkeeping (the
/// `__FILE__`, `__LINE__`, and `__PRETTY_FUNCTION__` of the C macro).
#[derive(Debug, Clone, Copy)]
pub struct Origin {
    pub file: &'static str,
    pub line: i32,
    pub function: &'static str,
}

struct Pending {
    pool: usize,
    task: Task,
}

struct Tasks {
    next: usize,
    pending: HashMap<usize, Pending>,
}

fn tasks() -> &'static Mutex<Tasks> {
    static T: OnceLock<Mutex<Tasks>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(Tasks { next: 1, pending: HashMap::new() }))
}

extern "C" fn run_task(data: *mut c_void) -> c_int {
    let id = data as usize;
    let task = tasks().lock().unwrap().pending.remove(&id);
    if let Some(p) = task {
        crate::guard((), p.task);
    }
    0
}

/// An Asterisk thread pool; shut down (waiting for running tasks) on drop.
pub struct ThreadPool {
    ptr: *mut AstThreadpool,
    name: String,
}

// The ast_threadpool API is thread safe.
unsafe impl Send for ThreadPool {}
unsafe impl Sync for ThreadPool {}

impl ThreadPool {
    /// `ast_threadpool_create(name, NULL, &options)`.  The pool's
    /// taskprocessors are named "<name>/pool" and "<name>/pool-control".
    pub fn create(name: &str, opts: &Options) -> Option<ThreadPool> {
        let o = AstThreadpoolOptions {
            version: 1,
            idle_timeout: opts.idle_timeout,
            auto_increment: opts.auto_increment,
            initial_size: opts.initial_size,
            max_size: opts.max_size,
            thread_start: None,
            thread_end: None,
        };
        let n = cstr(name);
        let ptr = unsafe { ast_threadpool_create(n.as_ptr(), std::ptr::null_mut(), &o) };
        if ptr.is_null() {
            None
        } else {
            Some(ThreadPool { ptr, name: name.to_string() })
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Queue `task`.  On failure (the pool is shutting down or out of
    /// memory) the task is handed back unrun.
    pub fn push(&self, task: Task, origin: Origin) -> Result<(), Task> {
        let id = {
            let mut t = tasks().lock().unwrap();
            let id = t.next;
            t.next = t.next.wrapping_add(1).max(1);
            t.pending.insert(id, Pending { pool: self.ptr as usize, task });
            id
        };
        let file = cstr(origin.file);
        let function = cstr(origin.function);
        let res = unsafe {
            __ast_threadpool_push(
                self.ptr,
                run_task,
                id as *mut c_void,
                file.as_ptr(),
                origin.line,
                function.as_ptr(),
            )
        };
        if res == 0 {
            return Ok(());
        }
        match tasks().lock().unwrap().pending.remove(&id) {
            Some(p) => Err(p.task),
            // Cannot happen: a task that was not queued cannot have run.
            None => Ok(()),
        }
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        // Stops the workers and waits for the running tasks; queued tasks
        // are discarded by Asterisk without running.
        unsafe { ast_threadpool_shutdown(self.ptr) };
        let pool = self.ptr as usize;
        let dropped: Vec<Pending> = {
            let mut t = tasks().lock().unwrap();
            let ids: Vec<usize> = t.pending.iter().filter(|(_, p)| p.pool == pool).map(|(id, _)| *id).collect();
            ids.into_iter().filter_map(|id| t.pending.remove(&id)).collect()
        };
        // Drop the tasks outside the table lock (their captures may run
        // arbitrary destructors).
        drop(dropped);
    }
}

/// The name `ast_pthread_create_stack` gives a thread in `core show
/// threads`: "<start_fn padded to 20> started at [<line>] <file> <caller>()".
pub fn thread_name(start_fn: &str, line: i32, file: &str, caller: &str) -> String {
    format!("{:<20} started at [{:5}] {} {}()", start_fn, line, file, caller)
}

/// Register the calling thread with Asterisk (`ast_register_thread`) so it
/// is listed by `core show threads`.  Pair with [`unregister_thread`] on
/// the same thread before it exits.
pub fn register_thread(name: &str) {
    // Asterisk takes ownership of the name and frees it with ast_free.
    let n = ast_strdup(name);
    if !n.is_null() {
        unsafe { ast_register_thread(n) };
    }
}

/// `ast_unregister_thread(pthread_self())`.
pub fn unregister_thread() {
    unsafe { ast_unregister_thread(libc::pthread_self() as *mut c_void) };
}
