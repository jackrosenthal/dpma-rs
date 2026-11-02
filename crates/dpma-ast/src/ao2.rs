//! astobj2: the `ao2_*` macros of astobj2.h as functions (objects,
//! references, locks, hash containers of named objects, iterators, and
//! callbacks).
//!
//! Objects are raw pointers: their lifetime is governed by the ao2
//! reference count.

use crate::here;
use crate::sys;
use std::os::raw::{c_char, c_int, c_void};

/// An ao2 destructor (called with the object's user data).
pub type Destructor = unsafe extern "C" fn(obj: *mut c_void);

/// `struct ao2_container`.
pub type Container = sys::ao2_container;

/// The callback of [`callback`] (`ao2_callback_fn`).
pub type CallbackFn = unsafe extern "C" fn(obj: *mut c_void, arg: *mut c_void, flags: c_int) -> c_int;

/// `ao2_alloc(size, destructor)`: an object of `size` bytes (zeroed) with
/// a recursive mutex and one reference.
pub fn alloc(size: usize, destructor: Option<Destructor>) -> *mut c_void {
    let (file, line, func) = here!("ao2::alloc");
    // SAFETY: plain allocation; the destructor runs on this object only.
    unsafe {
        sys::__ao2_alloc(size, destructor, sys::AO2_ALLOC_OPT_LOCK_MUTEX, std::ptr::null(), file, line, func)
    }
}

/// `ao2_ref(obj, delta)`; returns the previous count.  NULL is ignored.
///
/// # Safety
/// `obj` must be NULL or a live ao2 object.
pub unsafe fn ao2_ref(obj: *mut c_void, delta: i32) -> i32 {
    if obj.is_null() {
        return 0;
    }
    let (file, line, func) = here!("ao2::ao2_ref");
    sys::__ao2_ref(obj, delta, std::ptr::null(), file, line, func)
}

/// `ao2_cleanup`: drop a reference unless NULL.
///
/// # Safety
/// `obj` must be NULL or a live ao2 object the caller holds a reference on.
pub unsafe fn cleanup<T>(obj: *mut T) {
    ao2_ref(obj.cast(), -1);
}

/// `ao2_lock(obj)`.
///
/// # Safety
/// `obj` must be a live ao2 object.
pub unsafe fn lock<T>(obj: *mut T) {
    let (file, line, func) = here!("ao2::lock");
    sys::__ao2_lock(obj.cast(), sys::AO2_LOCK_REQ_MUTEX, file, func, line, c"obj".as_ptr());
}

/// `ao2_unlock(obj)`.
///
/// # Safety
/// `obj` must be a live ao2 object locked by this thread.
pub unsafe fn unlock<T>(obj: *mut T) {
    let (file, line, func) = here!("ao2::unlock");
    sys::__ao2_unlock(obj.cast(), file, func, line, c"obj".as_ptr());
}

/// The hash function of the original module's phone, line, and other
/// containers: the key is the NUL-terminated name at the start of the
/// object, hashed with a case-insensitive djb2.
unsafe extern "C" fn name_hash(obj: *const c_void, flags: c_int) -> c_int {
    match flags as u32 & sys::OBJ_SEARCH_MASK {
        sys::OBJ_SEARCH_OBJECT | sys::OBJ_SEARCH_KEY => {}
        _ => return 0,
    }
    // SAFETY: the container holds only objects that start with a name, and
    // keys are C strings.
    let s = std::ffi::CStr::from_ptr(obj.cast::<c_char>()).to_bytes();
    if s.is_empty() {
        return 5381;
    }
    let hash = s.iter().fold(5381u32, |h, &c| h.wrapping_mul(33) ^ u32::from(c.to_ascii_lowercase()));
    (hash & 0x7fff_ffff) as c_int
}

/// The compare function of those containers: `strcasecmp` of the names
/// (`strncasecmp` with the key's length for OBJ_SEARCH_PARTIAL_KEY).
unsafe extern "C" fn name_cmp(obj: *mut c_void, arg: *mut c_void, flags: c_int) -> c_int {
    let (name, key) = (obj.cast::<c_char>(), arg.cast::<c_char>());
    // SAFETY: as in `name_hash`.
    let differ = match flags as u32 & sys::OBJ_SEARCH_MASK {
        sys::OBJ_SEARCH_OBJECT | sys::OBJ_SEARCH_KEY => libc::strcasecmp(name, key) != 0,
        sys::OBJ_SEARCH_PARTIAL_KEY => libc::strncasecmp(name, key, libc::strlen(key)) != 0,
        _ => false,
    };
    if differ {
        0
    } else {
        sys::CMP_MATCH as c_int
    }
}

/// A hash container (mutex locked) of objects whose first bytes are a
/// NUL-terminated name, hashed and compared case-insensitively.
pub fn named_container(buckets: u32) -> *mut Container {
    let (file, line, func) = here!("ao2::named_container");
    // SAFETY: the hash and compare functions match the objects linked into
    // the container (see `name_hash`).
    unsafe {
        sys::__ao2_container_alloc_hash(
            sys::AO2_ALLOC_OPT_LOCK_MUTEX,
            0,
            buckets,
            Some(name_hash),
            None,
            Some(name_cmp),
            std::ptr::null(),
            file,
            line,
            func,
        )
    }
}

/// `ao2_link(c, obj)`.
///
/// # Safety
/// `c` and `obj` must be live ao2 objects.
pub unsafe fn link<T>(c: *mut Container, obj: *mut T) -> bool {
    let (file, line, func) = here!("ao2::link");
    sys::__ao2_link(c, obj.cast(), 0, std::ptr::null(), file, line, func) != 0
}

/// `ao2_unlink(c, obj)`.
///
/// # Safety
/// `c` and `obj` must be live ao2 objects.
pub unsafe fn unlink<T>(c: *mut Container, obj: *mut T) {
    let (file, line, func) = here!("ao2::unlink");
    sys::__ao2_unlink(c, obj.cast(), 0, std::ptr::null(), file, line, func);
}

/// `ao2_find(c, key, OBJ_SEARCH_KEY)`: the object with a reference, or NULL.
///
/// # Safety
/// `c` must be NULL or a live container of named objects; `key` NULL or a
/// C string.
pub unsafe fn find_key(c: *mut Container, key: *const c_char) -> *mut c_void {
    if c.is_null() || key.is_null() {
        return std::ptr::null_mut();
    }
    let (file, line, func) = here!("ao2::find_key");
    sys::__ao2_find(c, key.cast(), sys::OBJ_SEARCH_KEY, std::ptr::null(), file, line, func)
}

/// `ao2_callback(c, OBJ_NODATA | OBJ_MULTIPLE, cb, arg)`: call `cb` for
/// every object, with the container locked.
///
/// # Safety
/// `c` must be a live container and `cb` safe to call with its objects
/// and `arg`.
pub unsafe fn callback_all(c: *mut Container, cb: CallbackFn, arg: *mut c_void) {
    let (file, line, func) = here!("ao2::callback_all");
    sys::__ao2_callback(c, sys::OBJ_NODATA | sys::OBJ_MULTIPLE, Some(cb), arg, std::ptr::null(), file, line, func);
}

/// An `ao2_iterator` over a container (`ao2_iterator_init(c, 0)`),
/// destroyed on drop.
pub struct Iter(sys::ao2_iterator);

impl Iter {
    /// # Safety
    /// `c` must be a live container.
    pub unsafe fn new(c: *mut Container) -> Iter {
        Iter(sys::ao2_iterator_init(c, 0))
    }

    /// `ao2_iterator_next`: the next object with a reference the caller
    /// must drop, or NULL at the end.
    pub fn next_ref(&mut self) -> *mut c_void {
        let (file, line, func) = here!("ao2::Iter::next_ref");
        // SAFETY: the iterator was initialized on a live container, which
        // it holds a reference on.
        unsafe { sys::__ao2_iterator_next(&mut self.0, std::ptr::null(), file, line, func) }
    }
}

impl Drop for Iter {
    fn drop(&mut self) {
        // SAFETY: initialized by `new`, destroyed once.
        unsafe { sys::ao2_iterator_destroy(&mut self.0) };
    }
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
    let mut it = Iter::new(c);
    loop {
        let o = it.next_ref();
        if o.is_null() {
            break;
        }
        out.push(o);
    }
    out
}
