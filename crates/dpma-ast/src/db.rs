//! AstDB access.

use crate::sys;
use crate::util::{cstr, from_ptr, take_ast_string};

pub fn put(family: &str, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> bool {
    let f = cstr(family);
    let k = cstr(key);
    let v = cstr(value);
    // SAFETY: valid C strings, copied by the database.
    unsafe { sys::ast_db_put(f.as_ptr(), k.as_ptr(), v.as_ptr()) == 0 }
}

/// `ast_db_get_allocated(family, key, &out)`.
pub fn get(family: &str, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let f = cstr(family);
    let k = cstr(key);
    let mut out = std::ptr::null_mut();
    // SAFETY: valid C strings; `out` receives an ast_malloc'ed string that
    // is copied and freed.
    unsafe {
        if sys::ast_db_get_allocated(f.as_ptr(), k.as_ptr(), &mut out) != 0 {
            return None;
        }
        take_ast_string(out)
    }
}

pub fn del(family: &str, key: impl AsRef<[u8]>) -> bool {
    let f = cstr(family);
    let k = cstr(key);
    // SAFETY: valid C strings.
    unsafe { sys::ast_db_del(f.as_ptr(), k.as_ptr()) == 0 }
}

/// All entries in `family`, as (full key, value).  Keys look like
/// "/family/key".
pub fn tree(family: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let f = cstr(family);
    let mut out = Vec::new();
    // SAFETY: the tree is a list of entries owned here until freed.
    unsafe {
        let head = sys::ast_db_gettree(f.as_ptr(), std::ptr::null());
        let mut e = head;
        while !e.is_null() {
            out.push((
                from_ptr((*e).key).unwrap_or_default(),
                from_ptr((*e).data.as_ptr()).unwrap_or_default(),
            ));
            e = (*e).next;
        }
        if !head.is_null() {
            sys::ast_db_freetree(head);
        }
    }
    out
}
