//! AstDB access.

use crate::ffi;
use crate::util::{cstr, from_ptr, take_ast_string};

pub fn put(family: &str, key: &str, value: &str) -> bool {
    let f = cstr(family);
    let k = cstr(key);
    let v = cstr(value);
    unsafe { ffi::ast_db_put(f.as_ptr(), k.as_ptr(), v.as_ptr()) == 0 }
}

pub fn get(family: &str, key: &str) -> Option<String> {
    let f = cstr(family);
    let k = cstr(key);
    unsafe { take_ast_string(ffi::dpma_glue_db_get(f.as_ptr(), k.as_ptr())) }
}

pub fn del(family: &str, key: &str) -> bool {
    let f = cstr(family);
    let k = cstr(key);
    unsafe { ffi::ast_db_del(f.as_ptr(), k.as_ptr()) == 0 }
}

/// All entries in `family`, as (full key, value).  Keys look like
/// "/family/key".
pub fn tree(family: &str) -> Vec<(String, String)> {
    let f = cstr(family);
    let mut out = Vec::new();
    unsafe {
        let head = ffi::ast_db_gettree(f.as_ptr(), std::ptr::null());
        let mut e = head as *const crate::types::AstDbEntry;
        while !e.is_null() {
            out.push((
                from_ptr(ffi::dpma_glue_db_entry_key(e)).unwrap_or_default(),
                from_ptr(ffi::dpma_glue_db_entry_data(e)).unwrap_or_default(),
            ));
            e = ffi::dpma_glue_db_entry_next(e);
        }
        if !head.is_null() {
            ffi::ast_db_freetree(head);
        }
    }
    out
}
