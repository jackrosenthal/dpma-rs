//! astobj2 objects and containers, for objects handed to C callers of the
//! exported API (`ao2_alloc`, hash containers of named objects, link,
//! unlink, find, iterators, and locking).  The C side is in `glue/ao2.c`.
//!
//! Objects are raw pointers: their lifetime is governed by the ao2
//! reference count, which C code manipulates too.

use std::os::raw::{c_char, c_int, c_void};

/// An ao2 destructor (called with the object's user data).
pub type Destructor = unsafe extern "C" fn(obj: *mut c_void);

/// Opaque `struct ao2_container`.
#[repr(C)]
pub struct Container {
    _private: [u8; 0],
}

/// Opaque `struct ao2_iterator` (allocated by the glue).
#[repr(C)]
struct Iter {
    _private: [u8; 0],
}

extern "C" {
    fn dpma_glue_ao2_alloc(size: usize, destructor: Option<Destructor>, nolock: c_int) -> *mut c_void;
    fn dpma_glue_ao2_ref(obj: *mut c_void, delta: c_int) -> c_int;
    fn dpma_glue_ao2_lock(obj: *mut c_void) -> c_int;
    fn dpma_glue_ao2_unlock(obj: *mut c_void) -> c_int;
    fn dpma_glue_ao2_named_container(buckets: c_int) -> *mut Container;
    fn dpma_glue_ao2_link(c: *mut Container, obj: *mut c_void) -> c_int;
    fn dpma_glue_ao2_unlink(c: *mut Container, obj: *mut c_void);
    fn dpma_glue_ao2_find_key(c: *mut Container, key: *const c_char) -> *mut c_void;
    fn dpma_glue_ao2_iterator_new(c: *mut Container) -> *mut Iter;
    fn dpma_glue_ao2_iterator_next(it: *mut Iter) -> *mut c_void;
    fn dpma_glue_ao2_iterator_free(it: *mut Iter);
}

/// Allocate an object of `size` bytes (zeroed) with a recursive mutex and
/// one reference.
pub fn alloc(size: usize, destructor: Option<Destructor>) -> *mut c_void {
    unsafe { dpma_glue_ao2_alloc(size, destructor, 0) }
}

/// `ao2_ref(obj, delta)`; returns the previous count.  NULL is ignored.
///
/// # Safety
/// `obj` must be NULL or a live ao2 object.
pub unsafe fn ao2_ref(obj: *mut c_void, delta: i32) -> i32 {
    if obj.is_null() {
        return 0;
    }
    dpma_glue_ao2_ref(obj, delta)
}

/// `ao2_cleanup`: drop a reference unless NULL.
///
/// # Safety
/// `obj` must be NULL or a live ao2 object the caller holds a reference on.
pub unsafe fn cleanup(obj: *mut c_void) {
    ao2_ref(obj, -1);
}

/// # Safety
/// `obj` must be a live ao2 object.
pub unsafe fn lock(obj: *mut c_void) {
    dpma_glue_ao2_lock(obj);
}

/// # Safety
/// `obj` must be a live ao2 object locked by this thread.
pub unsafe fn unlock(obj: *mut c_void) {
    dpma_glue_ao2_unlock(obj);
}

/// A hash container (mutex locked) of objects whose first bytes are a
/// NUL-terminated name, hashed and compared case-insensitively.
pub fn named_container(buckets: i32) -> *mut Container {
    unsafe { dpma_glue_ao2_named_container(buckets) }
}

/// # Safety
/// `c` and `obj` must be live ao2 objects.
pub unsafe fn link(c: *mut Container, obj: *mut c_void) -> bool {
    dpma_glue_ao2_link(c, obj) != 0
}

/// # Safety
/// `c` and `obj` must be live ao2 objects.
pub unsafe fn unlink(c: *mut Container, obj: *mut c_void) {
    dpma_glue_ao2_unlink(c, obj)
}

/// `ao2_find(c, key, OBJ_SEARCH_KEY)`: the object with a reference, or NULL.
///
/// # Safety
/// `c` must be a live container of named objects.
pub unsafe fn find_key(c: *mut Container, key: *const c_char) -> *mut c_void {
    if c.is_null() || key.is_null() {
        return std::ptr::null_mut();
    }
    dpma_glue_ao2_find_key(c, key)
}

/// Every object of `c` in container order, each with a reference the
/// caller must drop.
///
/// # Safety
/// `c` must be NULL or a live container.
pub unsafe fn collect(c: *mut Container) -> Vec<*mut c_void> {
    let mut out = Vec::new();
    if c.is_null() {
        return out;
    }
    let it = dpma_glue_ao2_iterator_new(c);
    if it.is_null() {
        return out;
    }
    loop {
        let o = dpma_glue_ao2_iterator_next(it);
        if o.is_null() {
            break;
        }
        out.push(o);
    }
    dpma_glue_ao2_iterator_free(it);
    out
}
