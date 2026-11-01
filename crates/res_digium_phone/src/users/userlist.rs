//! The user list returned to UserlistRequest
//! (`phone_user_list_build_json` FUN_00161830).
//!
//! The JSON is built and serialized with Asterisk's `ast_json` (jansson),
//! as the original does, so key order, escaping, and the compact format
//! are the same.

use super::*;
use dpma_ast::json::{
    ast_json_array_append, ast_json_array_create, ast_json_object_create, ast_json_object_set, ast_json_string_create,
    ast_json_unref, dump_string,
};
use dpma_ast::util::cstr;
use std::os::raw::c_void;

/// Set `key` to the string `value` in `obj` (which takes the value).
/// Fails, as jansson does, when `value` is not valid UTF-8.
unsafe fn set_str(obj: *mut c_void, key: &str, value: &[u8]) -> Result<(), ()> {
    let k = cstr(key);
    let v = cstr(value);
    if ast_json_object_set(obj, k.as_ptr(), ast_json_string_create(v.as_ptr())) != 0 {
        return Err(());
    }
    Ok(())
}

/// One entry: `{"extension": ..., "name": ..., "assigned": ...}`.
fn user_entry(reg: &Registry, p: &Phone) -> (Vec<u8>, Vec<u8>, &'static str) {
    let extension = match build_config::primary_line(reg, p) {
        Some(line) => line.dialable_exten().to_vec(),
        None => {
            let slot0 = p.lines.first().map_or(&b""[..], |l| l.name.as_slice());
            if slot0.is_empty() { p.name.clone() } else { slot0.to_vec() }
        }
    };
    let name = if p.full_name.is_empty() { p.name.clone() } else { p.full_name.clone() };
    // "1" when the phone has a session (it is in use), "0" otherwise.
    let assigned = if p.last_session_id.is_empty() { "0" } else { "1" };
    (extension, name, assigned)
}

/// `phone_user_list_build_json`: append `{"users":[...]}` to `out`, listing
/// every phone in container order with its extension (the primary line's
/// `exten`, or the line name, or the phone name), name (`full_name` or the
/// phone name), and whether it is assigned.  With `filter_group_pin` only
/// phones whose `group_pin` equals `config_password` are listed.
///
/// Every value goes through jansson, which refuses text that is not valid
/// UTF-8: a phone with such an extension or name makes the whole list
/// fail (Err), as in the original.
///
/// `handle_request_userlist` passes `filter_group_pin` when
/// `userlist_auth=globalpin` is in force and the supplied configuration
/// password is not the global pin.  Returns the number of users listed;
/// the caller treats zero as an authentication failure.  (The original's
/// fourth parameter selects a variant keyed on a phone field that nothing
/// sets; its only caller passes 0, so that variant is not ported.)
pub fn build_userlist_json(out: &mut Vec<u8>, filter_group_pin: bool, config_password: &[u8]) -> Result<usize, ()> {
    let entries: Vec<(Vec<u8>, Vec<u8>, &'static str)> = {
        // The original locks each primary line while it reads it.
        let _lines = crate::exports::objects::lock_all_lines();
        let g = read();
        let Some(reg) = g.as_ref() else { return Err(()) };
        reg.phones
            .values()
            .filter(|p| !filter_group_pin || (!p.group_pin.is_empty() && p.group_pin == config_password))
            .map(|p| user_entry(reg, p))
            .collect()
    };
    unsafe {
        let root = ast_json_object_create();
        if root.is_null() {
            return Err(());
        }
        let users = ast_json_array_create();
        let key = cstr("users");
        if users.is_null() || ast_json_object_set(root, key.as_ptr(), users) != 0 {
            ast_json_unref(root);
            return Err(());
        }
        let mut count = 0;
        for (extension, name, assigned) in &entries {
            let obj = ast_json_object_create();
            if obj.is_null() {
                ast_json_unref(root);
                return Err(());
            }
            if set_str(obj, "extension", extension).is_err()
                || set_str(obj, "name", name).is_err()
                || set_str(obj, "assigned", assigned.as_bytes()).is_err()
            {
                ast_json_unref(obj);
                ast_json_unref(root);
                return Err(());
            }
            // The array takes the object, also on failure.
            if ast_json_array_append(users, obj) != 0 {
                ast_json_unref(root);
                return Err(());
            }
            count += 1;
        }
        let s = dump_string(root);
        ast_json_unref(root);
        out.extend_from_slice(&s.ok_or(())?);
        Ok(count)
    }
}
