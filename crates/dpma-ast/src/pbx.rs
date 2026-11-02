//! Dialplan manipulation.

use crate::sys;
use crate::util::{ast_strdup, cstr, intern};

fn opt(s: Option<&[u8]>) -> Option<std::ffi::CString> {
    s.map(cstr)
}

fn ptr(c: &Option<std::ffi::CString>) -> *const std::os::raw::c_char {
    c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr())
}

/// Create (or find) a context owned by `registrar`.
pub fn context_create(name: impl AsRef<[u8]>, registrar: &str) -> bool {
    let n = cstr(name);
    let r = cstr(registrar);
    // SAFETY: valid C strings (the context copies its registrar).
    unsafe {
        !sys::ast_context_find_or_create(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            n.as_ptr(),
            r.as_ptr(),
        )
        .is_null()
    }
}

/// Remove everything `registrar` added to the context `name`.
pub fn context_destroy(name: impl AsRef<[u8]>, registrar: &str) {
    let n = cstr(name);
    let r = cstr(registrar);
    // SAFETY: valid C strings; a context found is destroyed by registrar.
    unsafe {
        let con = sys::ast_context_find(n.as_ptr());
        if !con.is_null() {
            sys::ast_context_destroy(con, r.as_ptr());
        }
    }
}

pub fn context_exists(name: impl AsRef<[u8]>) -> bool {
    let n = cstr(name);
    // SAFETY: a valid C string.
    unsafe { !sys::ast_context_find(n.as_ptr()).is_null() }
}

#[allow(clippy::too_many_arguments)]
pub fn add_extension(
    context: &[u8],
    replace: bool,
    exten: &[u8],
    priority: i32,
    label: Option<&[u8]>,
    callerid: Option<&[u8]>,
    app: &[u8],
    data: Option<&[u8]>,
    registrar: &str,
) -> bool {
    let c = cstr(context);
    let e = cstr(exten);
    let l = opt(label);
    let cid = opt(callerid);
    let a = cstr(app);
    // The extension keeps (and frees) its data, and keeps the registrar
    // pointer (contexts copy theirs).
    let d = ast_strdup(data.unwrap_or_default());
    let r = intern(registrar);
    // SAFETY: valid C strings; `d` is handed over with ast_free_ptr as its
    // destructor.
    unsafe {
        sys::ast_add_extension(
            c.as_ptr(),
            replace as i32,
            e.as_ptr(),
            priority,
            ptr(&l),
            ptr(&cid),
            a.as_ptr(),
            d.cast(),
            Some(sys::ast_free_ptr),
            r.as_ptr(),
        ) == 0
    }
}

pub fn remove_extension(
    context: impl AsRef<[u8]>,
    exten: impl AsRef<[u8]>,
    priority: i32,
    registrar: &str,
) -> bool {
    let c = cstr(context);
    let e = cstr(exten);
    let r = cstr(registrar);
    // SAFETY: valid C strings.
    unsafe { sys::ast_context_remove_extension(c.as_ptr(), e.as_ptr(), priority, r.as_ptr()) == 0 }
}

/// Priority used for hints.
pub const PRIORITY_HINT: i32 = -1;

/// Remove every context and extension that `registrar` added.
pub fn context_destroy_registrar(registrar: &str) {
    let r = cstr(registrar);
    // SAFETY: a valid C string.
    unsafe { sys::ast_context_destroy(std::ptr::null_mut(), r.as_ptr()) };
}

/// Set a global dialplan variable or function (`pbx_builtin_setvar_helper`
/// with no channel).
pub fn set_global(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> bool {
    let n = cstr(name);
    let v = cstr(value);
    // SAFETY: valid C strings, copied.
    unsafe { sys::pbx_builtin_setvar_helper(std::ptr::null_mut(), n.as_ptr(), v.as_ptr()) == 0 }
}
