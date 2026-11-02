//! Presence methods (phone_method_internal_api.c): getInfo
//! (FUN_0017d0e0), update (FUN_0017cf20), options.getList
//! (`handle_request_json_presence_getlist` FUN_0017dd50).
//!
//! Each answers `{"response":{"method":M,"result":...}}` (replacing
//! `out`) and returns 0, or puts the JSON error document in `out` and
//! returns -1, as the official DPMA does.
//!
//! The official DPMA builds the documents with `ast_json_pack`, which fails
//! for text that is not valid UTF-8; the failures are reproduced where
//! they happen.

use crate::method::MethodCall;
use crate::request::error_response_json;
use crate::users::presence;
use dpma_proto::errors::request as err;
use dpma_proto::json::utf8;
use serde_json::{json, Value};

/// Replace `out` with the success document for `result`.  (A method name
/// that is not UTF-8 makes the official DPMA's last `ast_json_pack` fail:
/// then nothing is written, and the result is still 0.)
fn respond(c: &MethodCall, result: Value, out: &mut Vec<u8>) -> i32 {
    if let Some(method) = utf8(&c.method) {
        *out = dpma_proto::json::dump(&json!({"response": {"method": method, "result": result}}))
            .into_bytes();
    }
    0
}

fn fail(c: &MethodCall, code: i32, detail: &str, out: &mut Vec<u8>) -> i32 {
    error_response_json(out, &c.method, code, detail);
    -1
}

/// `switchvox.users.presence.getInfo`: the phone's current presence
/// option and message:
/// `{"presence":{"id":"<id>","presence":<state>,"sub_presence":<sub>,"message":<msg>}}`.
/// Error 10002 when no option matches the current presence, and when the
/// sub-state or the message is not UTF-8 ("pack presence").
pub fn get_info(c: &MethodCall, _p: &Value, out: &mut Vec<u8>) -> i32 {
    let Some((Some(o), message)) = presence::get_current(&c.phone) else {
        return fail(c, err::PARSE, "presence_option", out);
    };
    let state = dpma_ast::presence::state2str(o.state);
    let sub = o.subtype.unwrap_or_default();
    let message = message.unwrap_or_default();
    let (Some(state), Some(sub), Some(message)) = (utf8(&state), utf8(&sub), utf8(&message)) else {
        return fail(c, err::PARSE, "pack presence", out);
    };
    let result = json!({"presence": {
        "id": o.id.to_string(),
        "presence": state,
        "sub_presence": sub,
        "message": message,
    }});
    respond(c, result, out)
}

/// `%30u` as `sscanf` reads it (None when nothing was converted).
fn scan_option_id(s: &str) -> Option<i32> {
    let t = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let end = t.char_indices().nth(30).map_or(t.len(), |(i, _)| i);
    crate::util::scan_u32(&t.as_bytes()[..end]).map(|v| v as i32)
}

/// `switchvox.users.presence.update`: set the phone's presence to the
/// option `presence_option_id` (a string holding the number) with the
/// optional `message` (a string).  Answers `{"success":{}}`; error 10011
/// for a missing or unreadable id, 42013 when the option does not exist.
pub fn update(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    let Some(Value::String(id)) = p.get("presence_option_id") else {
        return fail(c, err::PARAMS_NOT_FOUND, "j_option_id", out);
    };
    let message = match p.get("message") {
        Some(Value::String(m)) => Some(m.as_bytes()),
        _ => None,
    };
    let Some(id) = scan_option_id(id) else {
        return fail(c, err::PARAMS_NOT_FOUND, "option_id_str", out);
    };
    if presence::update(&c.phone, id, message).is_err() {
        return fail(
            c,
            err::PRESENCE_ACCOUNT_MISMATCH,
            "phone_presence_update",
            out,
        );
    }
    respond(c, json!({"success": {}}), out)
}

/// `switchvox.users.presence.options.getList`: synchronize the phone's
/// options with its status applications, then list them:
/// `{"presence_options":{"presence_option":[{"id":"<id>","presence":<state>,
/// "sub_presence":<sub>,"owner":"system","active":"1"|"0"},...]}}`, with
/// "1" for the current one.  Error 10002 ("pack options array") when a
/// sub-state is not UTF-8.
pub fn options_get_list(c: &MethodCall, _p: &Value, out: &mut Vec<u8>) -> i32 {
    presence::user_application_sync(&c.phone);
    let current = presence::get_current(&c.phone)
        .and_then(|(o, _)| o)
        .map(|o| o.id);
    let Some(options) = presence::options(&c.phone) else {
        // The official DPMA always has the phone; its only failure here is
        // the option iterator's allocation.
        return fail(c, err::PARSE, "presence option iterator", out);
    };
    let mut list: Vec<Value> = Vec::new();
    for o in &options {
        let state = dpma_ast::presence::state2str(o.state);
        let (Some(state), Some(sub)) = (utf8(&state), utf8(o.subtype.as_deref().unwrap_or(b"")))
        else {
            return fail(c, err::PARSE, "pack options array", out);
        };
        list.push(json!({
            "id": o.id.to_string(),
            "presence": state,
            "sub_presence": sub,
            "owner": o.owner_name(),
            "active": if current == Some(o.id) { "1" } else { "0" },
        }));
    }
    respond(
        c,
        json!({"presence_options": {"presence_option": list}}),
        out,
    )
}
