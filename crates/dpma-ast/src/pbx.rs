//! Dialplan manipulation.

use crate::ffi;
use crate::util::cstr;

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
    unsafe { ffi::dpma_glue_context_create(n.as_ptr(), r.as_ptr()) == 0 }
}

/// Remove everything `registrar` added to the context `name`.
pub fn context_destroy(name: impl AsRef<[u8]>, registrar: &str) {
    let n = cstr(name);
    let r = cstr(registrar);
    unsafe { ffi::dpma_glue_context_destroy(n.as_ptr(), r.as_ptr()) };
}

pub fn context_exists(name: impl AsRef<[u8]>) -> bool {
    let n = cstr(name);
    unsafe { ffi::dpma_glue_context_exists(n.as_ptr()) != 0 }
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
    let d = opt(data);
    let r = cstr(registrar);
    unsafe {
        ffi::dpma_glue_add_extension(
            c.as_ptr(),
            replace as i32,
            e.as_ptr(),
            priority,
            ptr(&l),
            ptr(&cid),
            a.as_ptr(),
            ptr(&d),
            r.as_ptr(),
        ) == 0
    }
}

pub fn remove_extension(context: impl AsRef<[u8]>, exten: impl AsRef<[u8]>, priority: i32, registrar: &str) -> bool {
    let c = cstr(context);
    let e = cstr(exten);
    let r = cstr(registrar);
    unsafe { ffi::dpma_glue_remove_extension(c.as_ptr(), e.as_ptr(), priority, r.as_ptr()) == 0 }
}

/// Priority used for hints.
pub const PRIORITY_HINT: i32 = -1;

/// Remove every context and extension that `registrar` added.
pub fn context_destroy_registrar(registrar: &str) {
    let r = cstr(registrar);
    unsafe { ffi::dpma_glue_context_destroy_registrar(r.as_ptr()) };
}

/// Set a global dialplan variable or function (`pbx_builtin_setvar_helper`
/// with no channel).
pub fn set_global(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> bool {
    let n = cstr(name);
    let v = cstr(value);
    unsafe { ffi::pbx_builtin_setvar_helper(std::ptr::null_mut(), n.as_ptr(), v.as_ptr()) == 0 }
}
