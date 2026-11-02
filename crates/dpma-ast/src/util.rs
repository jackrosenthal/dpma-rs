//! C strings, the Asterisk allocator (`ast_free`, `ast_strdup`), strings
//! handed to APIs that keep them, statics handed to C, and small Asterisk
//! utilities.

use crate::sys;
use std::cell::UnsafeCell;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_long, c_void};
use std::sync::Mutex;

/// The `__FILE__`, `__LINE__`, and function name arguments of the
/// Asterisk functions behind the allocation, astobj2, and task macros, as
/// C strings: `here!("function")`.  Asterisk only uses them in debug
/// output (memory, reference, and lock debugging).
#[doc(hidden)]
#[macro_export]
macro_rules! here {
    ($func:literal) => {
        (
            concat!(file!(), "\0").as_ptr().cast::<::std::os::raw::c_char>(),
            line!() as ::std::os::raw::c_int,
            concat!($func, "\0").as_ptr().cast::<::std::os::raw::c_char>(),
        )
    };
}

/// A C string with the bytes of `s` up to its first NUL (where C would
/// see the string end).
pub fn cstr(s: impl AsRef<[u8]>) -> CString {
    dpma_bytes::cstring(s)
}

/// Copy a (possibly NULL) C string's bytes.
///
/// # Safety
/// `p` must be NULL or point to a NUL terminated string.
pub unsafe fn from_ptr(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        None
    } else {
        Some(CStr::from_ptr(p).to_bytes().to_vec())
    }
}

/// `ast_free(p)`.
///
/// # Safety
/// `p` must be NULL or memory from the Asterisk allocator, not used
/// afterwards.
pub unsafe fn ast_free(p: *mut c_void) {
    let (file, line, func) = here!("ast_free");
    sys::__ast_free(p, file, line, func);
}

/// Take ownership of an ast_malloc'ed string, copy it, and free it.
///
/// # Safety
/// `p` must be NULL or a string allocated by the Asterisk allocator.
pub unsafe fn take_ast_string(p: *mut c_char) -> Option<Vec<u8>> {
    let s = from_ptr(p)?;
    ast_free(p.cast());
    Some(s)
}

/// `ast_strdup(s)`: a copy from the Asterisk allocator, for values handed
/// to C code that frees them (NULL on allocation failure).
pub fn ast_strdup(s: impl AsRef<[u8]>) -> *mut c_char {
    let c = cstr(s);
    let (file, line, func) = here!("ast_strdup");
    // SAFETY: `c` is a valid C string for the duration of the call.
    unsafe { sys::__ast_strdup(c.as_ptr(), file, line, func) }
}

/// A C string that lives as long as the module, for the Asterisk APIs
/// that keep the pointer they are given instead of copying the string
/// (manager action names, dialplan registrars).  Each distinct string is
/// copied once, so registering the same name again (e.g., after a reload)
/// reuses the copy.
pub fn intern(s: &str) -> &'static CStr {
    static INTERNED: Mutex<Option<HashSet<&'static CStr>>> = Mutex::new(None);
    let c = cstr(s);
    let mut g = INTERNED.lock().unwrap_or_else(|e| e.into_inner());
    let set = g.get_or_insert_with(HashSet::new);
    if let Some(&found) = set.get(c.as_c_str()) {
        return found;
    }
    let leaked: &'static CStr = Box::leak(c.into_boxed_c_str());
    set.insert(leaked);
    leaked
}

/// A static whose address is handed to C (a registration structure that
/// Asterisk keeps, and may write: list links, the module's `self`).
/// Rust code only takes its raw pointer.
#[repr(transparent)]
pub struct CStatic<T>(UnsafeCell<T>);

// SAFETY: the contents are only reached through the raw pointer `get`
// returns, by C code that serializes its own accesses (the registries'
// locks) or by Rust code that reads fields Asterisk sets once.
unsafe impl<T> Sync for CStatic<T> {}

impl<T> CStatic<T> {
    pub const fn new(value: T) -> CStatic<T> {
        CStatic(UnsafeCell::new(value))
    }

    /// The address handed to C.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// `S_OR(s, "")` on a C string: its bytes, or "" for NULL.
///
/// # Safety
/// `p` must be NULL or point to a NUL terminated string.
pub unsafe fn bytes_or_empty<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        b""
    } else {
        CStr::from_ptr(p).to_bytes()
    }
}

/// Asterisk's `ast_true`: "yes", "true", "y", "t", "1", or "on", in any
/// case.
pub fn ast_true(s: &[u8]) -> bool {
    [&b"yes"[..], b"true", b"y", b"t", b"1", b"on"].iter().any(|t| dpma_bytes::eq_ic(s, t))
}

/// Asterisk's `ast_false`: "no", "false", "n", "f", "0", or "off", in any
/// case.
pub fn ast_false(s: &[u8]) -> bool {
    [&b"no"[..], b"false", b"n", b"f", b"0", b"off"].iter().any(|t| dpma_bytes::eq_ic(s, t))
}

/// `ast_register_atexit(func)`: run `func` when Asterisk exits, also on a
/// fast shutdown (`core stop now`) that does not unload modules.  A module
/// must remove it with `unregister_atexit` when it unloads.
pub fn register_atexit(func: unsafe extern "C" fn()) -> i32 {
    // SAFETY: `func` is a function of this module, removed again at unload.
    unsafe { sys::ast_register_atexit(Some(func)) }
}

/// `ast_unregister_atexit(func)`.
pub fn unregister_atexit(func: unsafe extern "C" fn()) {
    // SAFETY: as above.
    unsafe { sys::ast_unregister_atexit(Some(func)) }
}

/// `ast_random()`: Asterisk's thread-safe `random()`.
pub fn random() -> c_long {
    // SAFETY: no arguments.
    unsafe { sys::ast_random() }
}

/// `ast_strlen_zero`.
///
/// # Safety
/// `p` must be NULL or point to a NUL terminated string.
pub unsafe fn strlen_zero(p: *const c_char) -> bool {
    p.is_null() || *p == 0
}

