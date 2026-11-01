//! Asterisk's JSON API (`ast_json_*`, main/json.c, a wrapper around
//! jansson).
//!
//! The original module builds the user list and parses the JSON phone
//! requests with it, so wherever key order, escaping, or number formatting
//! must match the original, the same library is used.  Values are raw
//! `struct ast_json *` pointers (`*mut c_void`); [`Json`] and [`Value`] wrap
//! the parsing side.

use crate::util::{cstr, from_ptr};
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_void};

extern "C" {
    pub fn ast_json_load_string(input: *const c_char, error: *mut c_void) -> *mut c_void;
    pub fn ast_json_object_create() -> *mut c_void;
    pub fn ast_json_array_create() -> *mut c_void;
    pub fn ast_json_string_create(s: *const c_char) -> *mut c_void;
    /// Takes over `value`'s reference, also on failure.
    pub fn ast_json_object_set(object: *mut c_void, key: *const c_char, value: *mut c_void) -> c_int;
    /// Takes over `value`'s reference, also on failure.
    pub fn ast_json_array_append(array: *mut c_void, value: *mut c_void) -> c_int;
    pub fn ast_json_object_get(object: *mut c_void, key: *const c_char) -> *mut c_void;
    pub fn ast_json_typeof(value: *const c_void) -> c_int;
    pub fn ast_json_string_get(string: *const c_void) -> *const c_char;
    pub fn ast_json_pack(format: *const c_char, ...) -> *mut c_void;
    pub fn ast_json_dump_string_format(root: *mut c_void, format: c_int) -> *mut c_char;
    pub fn ast_json_free(p: *mut c_void);
    pub fn ast_json_unref(value: *mut c_void);
}

/// `AST_JSON_COMPACT`.
pub const COMPACT: c_int = 0;
/// `AST_JSON_OBJECT`.
pub const OBJECT: c_int = 0;
/// `AST_JSON_STRING`.
pub const STRING: c_int = 2;

/// `ast_json_dump_string(root)` (compact), copied and freed; None when
/// jansson refuses (anything but an object or an array).
///
/// # Safety
/// `root` must be a live `struct ast_json`.
pub unsafe fn dump_string(root: *mut c_void) -> Option<Vec<u8>> {
    let s = ast_json_dump_string_format(root, COMPACT);
    if s.is_null() {
        return None;
    }
    let r = from_ptr(s);
    ast_json_free(s as *mut c_void);
    r
}

/// A parsed document (an owned reference).
pub struct Json(*mut c_void);

/// A value inside a [`Json`] (a borrowed reference).
#[derive(Clone, Copy)]
pub struct Value<'a>(*mut c_void, PhantomData<&'a Json>);

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
        unsafe { ast_json_typeof(self.0) }
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
