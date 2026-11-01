use std::ffi::{CStr, CString};
use std::os::raw::c_char;

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

/// Take ownership of an ast_malloc'ed string, copy it, and free it.
///
/// # Safety
/// `p` must be NULL or a string allocated by the Asterisk allocator.
pub unsafe fn take_ast_string(p: *mut c_char) -> Option<Vec<u8>> {
    let s = from_ptr(p)?;
    crate::ffi::dpma_glue_free(p as *mut _);
    Some(s)
}

/// Duplicate a string with the Asterisk allocator (for values handed to C).
pub fn ast_strdup(s: impl AsRef<[u8]>) -> *mut c_char {
    let c = cstr(s);
    unsafe { crate::ffi::dpma_glue_strdup(c.as_ptr()) }
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

extern "C" {
    fn ast_random() -> std::os::raw::c_long;
    fn ast_register_atexit(func: extern "C" fn()) -> std::os::raw::c_int;
    fn ast_unregister_atexit(func: extern "C" fn());
}

/// `ast_register_atexit(func)`: run `func` when Asterisk exits, also on a
/// fast shutdown (`core stop now`) that does not unload modules.  A module
/// must remove it with `unregister_atexit` when it unloads.
pub fn register_atexit(func: extern "C" fn()) -> i32 {
    unsafe { ast_register_atexit(func) }
}

/// `ast_unregister_atexit(func)`.
pub fn unregister_atexit(func: extern "C" fn()) {
    unsafe { ast_unregister_atexit(func) }
}

/// `ast_random()`: Asterisk's thread-safe `random()`.
pub fn random() -> std::os::raw::c_long {
    unsafe { ast_random() }
}
