use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Convert a Rust string to a C string, dropping any interior NUL bytes.
pub fn cstr(s: &str) -> CString {
    match CString::new(s) {
        Ok(c) => c,
        Err(_) => CString::new(s.replace('\0', "")).unwrap_or_default(),
    }
}

/// Copy a (possibly NULL) C string into an owned Rust string.
///
/// # Safety
/// `p` must be NULL or point to a NUL terminated string.
pub unsafe fn from_ptr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(CStr::from_ptr(p).to_string_lossy().into_owned())
    }
}

/// Copy a (possibly NULL) C string, mapping NULL and "" to None.
///
/// # Safety
/// `p` must be NULL or point to a NUL terminated string.
pub unsafe fn from_ptr_nonempty(p: *const c_char) -> Option<String> {
    from_ptr(p).filter(|s| !s.is_empty())
}

/// Take ownership of an ast_malloc'ed string, copy it, and free it.
///
/// # Safety
/// `p` must be NULL or a string allocated by the Asterisk allocator.
pub unsafe fn take_ast_string(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    crate::ffi::dpma_glue_free(p as *mut _);
    Some(s)
}

/// Duplicate a string with the Asterisk allocator (for values handed to C).
pub fn ast_strdup(s: &str) -> *mut c_char {
    let c = cstr(s);
    unsafe { crate::ffi::dpma_glue_strdup(c.as_ptr()) }
}

/// Asterisk's notion of a true value (yes, true, y, t, 1, on).
pub fn ast_true(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "yes" | "true" | "y" | "t" | "1" | "on"
    )
}

/// Asterisk's notion of a false value (no, false, n, f, 0, off).
pub fn ast_false(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "no" | "false" | "n" | "f" | "0" | "off"
    )
}
