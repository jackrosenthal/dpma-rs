//! Asterisk's JSON API (`ast_json_*`, main/json.c, a wrapper around
//! jansson).
//!
//! The official DPMA builds the user list and parses the JSON phone
//! requests with it, so wherever key order, escaping, or number formatting
//! must match the official DPMA's, the same library is used.  Values are
//! raw `struct ast_json *` pointers; [`Json`] and [`Value`] wrap
//! the parsing side.

use crate::sys;
use crate::util::{cstr, from_ptr};
use std::marker::PhantomData;
use std::os::raw::{c_int, c_void};

/// The raw API, for building documents as the official DPMA does
/// (`ast_json_object_set` and `ast_json_array_append` take over the
/// value's reference, also on failure).
pub use sys::{
    ast_json, ast_json_array_append, ast_json_array_create, ast_json_dump_string_format,
    ast_json_free, ast_json_load_string, ast_json_object_create, ast_json_object_get,
    ast_json_object_set, ast_json_pack, ast_json_string_create, ast_json_string_get,
    ast_json_typeof, ast_json_unref,
};

/// `AST_JSON_COMPACT`.
pub const COMPACT: sys::ast_json_encoding_format = sys::AST_JSON_COMPACT;
/// `AST_JSON_OBJECT`.
pub const OBJECT: c_int = sys::AST_JSON_OBJECT as c_int;
/// `AST_JSON_STRING`.
pub const STRING: c_int = sys::AST_JSON_STRING as c_int;

/// `ast_json_dump_string(root)` (compact), copied and freed; None when
/// jansson refuses (anything but an object or an array).
///
/// # Safety
/// `root` must be a live `struct ast_json`.
pub unsafe fn dump_string(root: *mut ast_json) -> Option<Vec<u8>> {
    let s = ast_json_dump_string_format(root, COMPACT);
    if s.is_null() {
        return None;
    }
    let r = from_ptr(s);
    ast_json_free(s as *mut c_void);
    r
}

/// A parsed document (an owned reference).
pub struct Json(*mut ast_json);

/// A value inside a [`Json`] (a borrowed reference).
#[derive(Clone, Copy)]
pub struct Value<'a>(*mut ast_json, PhantomData<&'a Json>);

impl Json {
    /// `ast_json_load_string` of the C string in `text` (up to a NUL);
    /// None when it is not valid JSON (jansson also refuses invalid UTF-8).
    pub fn load(text: &[u8]) -> Option<Json> {
        let c = cstr(text);
        let p = unsafe { ast_json_load_string(c.as_ptr(), std::ptr::null_mut()) };
        (!p.is_null()).then_some(Json(p))
    }

    pub fn get(&self, key: &str) -> Option<Value<'_>> {
        Value(self.0, PhantomData).get(key)
    }
}

impl Drop for Json {
    fn drop(&mut self) {
        unsafe { ast_json_unref(self.0) };
    }
}

impl<'a> Value<'a> {
    /// `ast_json_object_get` (None for a missing key or a non-object).
    pub fn get(&self, key: &str) -> Option<Value<'a>> {
        let k = cstr(key);
        let p = unsafe { ast_json_object_get(self.0, k.as_ptr()) };
        (!p.is_null()).then_some(Value(p, PhantomData))
    }

    /// `ast_json_typeof`.
    pub fn kind(&self) -> c_int {
        unsafe { ast_json_typeof(self.0) as c_int }
    }

    /// `ast_json_string_get` ("" for a non-string).
    pub fn string(&self) -> Vec<u8> {
        unsafe { from_ptr(ast_json_string_get(self.0)).unwrap_or_default() }
    }

    /// `ast_json_dump_string` (compact); None when jansson refuses
    /// (anything but an object or an array).
    pub fn dump(&self) -> Option<Vec<u8>> {
        unsafe { dump_string(self.0) }
    }
}
