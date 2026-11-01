//! Call-related methods: queues, parking lots, recording, phonebook, and
//! the echo test method, plus the AMI hook helper (`amihook_action`) and
//! the parked-call Stasis router (phone_method_internal_api.c).
//!
//! The methods talk to Asterisk the way the original does: through
//! in-process manager actions (`ast_hook_send_action`), whose response
//! text is split into blocks at every "\r\n\r\n" and searched for
//! headers with `strcasestr` (so "Name:" also matches "CallerIDName:",
//! for example).  Those helpers reproduce the original's parsing exactly,
//! including its quirks:
//!
//! * The recording start methods read the MixMonitor response into an
//!   8-byte buffer (the original passes `sizeof` of a pointer), which
//!   cannot hold "Success", so they report error 27168 even though
//!   MixMonitor was started, and never send the
//!   `digium.startRecording.success` INFO.
//! * `getTodaysStatus` answers nothing at all (return 0, empty response)
//!   when the phone has no application for the queue or Asterisk does
//!   not know the queue.
//! * `getList` reports `total_members` as a number with the `overview`
//!   permission and as strings with `details`.
//!
//! Deviation (plan section 8, item 6): no chan_sip.  The original also
//! looks for recording channels named "SIP/<account>" and handles parker
//! dial strings "SIP/<peer>" (reading `SIPPEER(<peer>,useragent)`); both
//! only ever matched chan_sip channels and are left out.
//!
//! Owner: P10 "methods-calls" (wave 2).

use crate::method::MethodCall;
use crate::request::{error_response_json, error_response_xml};
use crate::users::{self, AppKind, QueueApp, QueuePermission};
use dpma_ast::astxml;
use dpma_ast::channel::{self, Channel};
use dpma_ast::{dpma_debug, dpma_log};
use dpma_proto::errors::request as rq;
use dpma_proto::json::dump;
use serde_json::{json, Map, Value};

/// The `ast_str` buffers the original fills from manager responses (and
/// most of its header value buffers) hold 0x400 bytes.
const BUF: usize = 0x400;

// ---------------------------------------------------------------------
// Manager hook helpers
// ---------------------------------------------------------------------

/// `strstr` on bytes.
fn strstr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `strcasestr` on bytes (ASCII case folding, as in the C locale).
fn strcasestr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

/// `strtol(s, NULL, 10)`.
fn strtol(s: &str) -> i64 {
    let c = dpma_ast::cstr(s);
    unsafe { libc::strtol(c.as_ptr(), std::ptr::null_mut(), 10) as i64 }
}

/// `amihook_action` (FUN_0017adc0): run `action` through the manager hook
/// and split the response at each "\r\n\r\n".  The original counts the
/// separators first (searching again from one byte after each match) and
/// keeps one block per separator: the text before it, starting one byte
/// after the previous separator (so later blocks begin with "\n\r\n").
/// Text after the last separator is dropped.  An empty response, or one
/// without a separator, gives no blocks (the original's failure).
fn amihook_action(action: &str) -> Vec<Vec<u8>> {
    const SEP: &[u8] = b"\r\n\r\n";
    let Some(text) = dpma_ast::manager::hook_action(action) else {
        return Vec::new();
    };
    let buf = text.as_bytes();
    let Some(mut at) = strstr(buf, SEP) else {
        return Vec::new();
    };
    let mut count = 1;
    while let Some(i) = strstr(&buf[at + 1..], SEP) {
        at += 1 + i;
        count += 1;
    }
    let mut blocks = Vec::with_capacity(count);
    let mut p = 0;
    while p < buf.len() {
        match strstr(&buf[p..], SEP) {
            Some(i) => {
                if blocks.len() < count {
                    blocks.push(buf[p..p + i].to_vec());
                }
                p += i + 1;
            }
            None => {
                if blocks.len() < count {
                    blocks.push(buf[p..].to_vec());
                }
                break;
            }
        }
    }
    blocks
}

/// Where a header's value starts and how long the original thinks it is:
/// after `key` (found with `strcasestr`), blanks (bytes 1..=0x20) are
/// skipped; the length runs to the first "\r\n" after the key (searched
/// before skipping, so it is negative when the value is empty) or to the
/// end of the block.
fn header_span(block: &[u8], key: &str) -> Option<(usize, i32)> {
    let pos = strcasestr(block, key.as_bytes())?;
    let mut p = pos + key.len();
    let end = strstr(&block[p..], b"\r\n").map(|i| p + i);
    while p < block.len() && (1..=0x20).contains(&block[p]) {
        p += 1;
    }
    let len = match end {
        Some(e) => (e as i64 - p as i64) as i32,
        None => (block.len() - p) as i32,
    };
    Some((p, len))
}

/// Trailing bytes below 0x21 removed (`ast_trim_blanks`).
fn trim_end(mut v: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = v.split_last() {
        if last >= 0x21 {
            break;
        }
        v = rest;
    }
    v
}

/// FUN_0017bdd0 / FUN_0017bf20 (`amihook_get_header_value`): the value of
/// header `key` in `block`, copied into a buffer of `size` bytes, or ""
/// when the header is missing or the value (plus its terminator) does not
/// fit, i.e., unless `len + 1 < size`.
fn header_value(block: &[u8], key: &str, size: usize) -> String {
    let Some((p, len)) = header_span(block, key) else {
        return String::new();
    };
    // (unsigned long)(int)(len + 1): a negative length is huge.
    let n = len.wrapping_add(1) as i64 as u64;
    if n >= size as u64 {
        return String::new();
    }
    // ast_copy_string(buf, value, n): at most n - 1 bytes.
    let take = (n as usize).saturating_sub(1).min(block.len() - p);
    String::from_utf8_lossy(trim_end(&block[p..p + take])).into_owned()
}

/// `amihook_append_header_value` (FUN_0017bb30): set `obj[name]` to the
/// value of header `key` (`ast_strndup(value, len + 1)`, trimmed).  A
/// negative length makes the original copy the rest of the block.  Err
/// when the header is missing.
fn append_header_value(obj: &mut Map<String, Value>, name: &str, block: &[u8], key: &str) -> Result<(), ()> {
    let (p, len) = header_span(block, key).ok_or(())?;
    let n = (len as i64) + 1;
    let rest = &block[p..];
    let take = if n < 0 { rest.len() } else { (n as usize).min(rest.len()) };
    let v = String::from_utf8_lossy(trim_end(&rest[..take])).into_owned();
    obj.insert(name.to_string(), Value::String(v));
    Ok(())
}

/// The "Response:" of a manager action, read into a buffer of `size`
/// bytes; None when the action produced no response blocks.
fn action_response(action: &str, size: usize) -> Option<String> {
    let blocks = amihook_action(action);
    let first = blocks.first()?;
    Some(header_value(first, "Response:", size))
}

fn is_success(response: &str) -> bool {
    !response.is_empty() && response.eq_ignore_ascii_case("success")
}

// ---------------------------------------------------------------------
// Queue status (`queues_get_status`, FUN_0017d360)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct QueueMember {
    name: String,
    location: String,
    paused: bool,
    is_static: bool,
    status: i32,
}

#[derive(Debug, Clone, Default)]
struct QueueEntry {
    caller_id_num: String,
    caller_id_name: String,
    position: i32,
    wait: i64,
}

#[derive(Debug, Clone, Default)]
struct QueueStatus {
    name: String,
    completed: i32,
    abandoned: i32,
    members: Vec<QueueMember>,
    entries: Vec<QueueEntry>,
}

/// `queues_get_status`: every queue with its members and callers, from
/// the QueueStatus action.  (The original only fails when out of memory;
/// a failed action gives an empty list.)
fn queues_get_status() -> Vec<QueueStatus> {
    let mut queues: Vec<QueueStatus> = Vec::new();
    for b in amihook_action("Action: QueueStatus\n") {
        let hv = |key: &str| header_value(&b, key, BUF);
        match hv("Event:").as_str() {
            "QueueParams" => queues.push(QueueStatus {
                name: hv("Queue:"),
                completed: strtol(&hv("Completed:")) as i32,
                abandoned: strtol(&hv("Abandoned:")) as i32,
                ..Default::default()
            }),
            "QueueMember" => match queues.last_mut() {
                None => dpma_log!("Got a QueueMember without first getting a QueueParam?"),
                Some(q) => q.members.push(QueueMember {
                    name: hv("Name:"),
                    location: hv("Location:"),
                    paused: hv("Paused:") == "1",
                    is_static: hv("Membership:") == "static",
                    status: strtol(&hv("Status:")) as i32,
                }),
            },
            "QueueEntry" => match queues.last_mut() {
                None => dpma_log!("Got a QueueEntry without first getting a QueueParam?"),
                Some(q) => q.entries.push(QueueEntry {
                    caller_id_num: hv("CallerIDNum:"),
                    caller_id_name: hv("CallerIDName:"),
                    position: strtol(&hv("Position:")) as i32,
                    wait: strtol(&hv("Wait:")),
                }),
            },
            _ => {}
        }
    }
    queues
}

// ---------------------------------------------------------------------
// The phone's applications
// ---------------------------------------------------------------------

/// One entry of the phone's application list, resolved
/// (`phone_application_find`).
enum UserApp {
    Missing(String),
    Queue(QueueApp),
    Other,
}

/// The phone's applications in list order (empty for an unknown phone).
fn user_apps(phone: &str) -> Vec<UserApp> {
    let g = users::read();
    let Some(reg) = g.as_ref() else {
        return Vec::new();
    };
    let Some(p) = reg.phones.get(phone) else {
        return Vec::new();
    };
    p.applications
        .iter()
        .map(|name| match reg.applications.get(name) {
            None => UserApp::Missing(name.clone()),
            Some(a) => match &a.kind {
                Some(AppKind::Queue(q)) => UserApp::Queue(q.clone()),
                _ => UserApp::Other,
            },
        })
        .collect()
}

/// `phone_user_get_primary_line_name`.
fn primary_line_name(phone: &str) -> String {
    let g = users::read();
    g.as_ref()
        .and_then(|r| r.phones.get(phone))
        .and_then(|p| p.primary_line())
        .map(|l| l.name.clone())
        .unwrap_or_default()
}

/// `user_can_read_parkinglot`: true when the phone has no parking
/// application, or one of its parking applications lists `lot`
/// (`phone_application_list_get_type(user, PARKING)` matches the phone's
/// application names exactly).
fn user_can_read_parkinglot(phone: &str, lot: &str) -> bool {
    let g = users::read();
    let Some(reg) = g.as_ref() else {
        return true;
    };
    let Some(p) = reg.phones.get(phone) else {
        return true;
    };
    let mut denied = false;
    for app in reg.applications.values() {
        if !p.applications.contains(&app.name) {
            continue;
        }
        let Some(AppKind::Parking(pk)) = &app.kind else {
            continue;
        };
        if pk.parkinglots.iter().any(|l| l == lot) {
            dpma_debug!(3, "This parkinglot is registered to the user via {}", app.name);
            return true;
        }
        denied = true;
    }
    !denied
}

/// `ast_json_string_get(ast_json_object_get(params, key))`.
fn param_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key)?.as_str()
}

/// `{"response": {"method": M, "result": R}}`, appended to `out`.
fn append_result(out: &mut String, method: &str, result: Value) {
    out.push_str(&dump(&json!({"response": {"method": method, "result": result}})));
}

fn append_success(out: &mut String, method: &str) {
    append_result(out, method, json!({"success": {}}));
}

/// The XML success document (`ast_str_set`, so it replaces `out`).
fn set_xml_success(out: &mut String, method: &str) {
    out.clear();
    out.push_str(&format!("<response method=\"{}\">\r\n", method));
    out.push_str("<result>\r\n<success />\r\n</result>\r\n</response>\r\n");
}

/// `json_stringify`: "%lld".
fn s(v: i64) -> Value {
    Value::String(v.to_string())
}

/// `snprintf(buf, size, ...)`: at most `size - 1` bytes (on a character
/// boundary).
fn truncate(mut text: String, size: usize) -> String {
    if text.len() >= size {
        let mut n = size - 1;
        while !text.is_char_boundary(n) {
            n -= 1;
        }
        text.truncate(n);
    }
    text
}

// ---------------------------------------------------------------------
// Load and unload
// ---------------------------------------------------------------------

/// Parking topic forwarding and the parked-call router (FUN_00186920
/// part): the topic "dpma" receives everything published on the parking
/// topic, and `handle_parked_call_message` gets the parked call messages.
pub fn load() -> Result<(), ()> {
    if dpma_ast::stasis::parking_subscribe("dpma", handle_parked_call_message) {
        Ok(())
    } else {
        Err(())
    }
}

/// FUN_00186840 part.
pub fn unload() {
    dpma_ast::stasis::parking_unsubscribe();
}

/// `phone_user_get_show_call_parking` (FUN_0016ab70): the
/// `show_call_parking` setting of the phone with a line named `line`
/// (case insensitive), true when there is none.
fn phone_user_get_show_call_parking(line: &str) -> bool {
    let g = users::read();
    g.as_ref()
        .and_then(|r| {
            r.phones
                .values()
                .find(|p| p.lines.iter().any(|l| l.name.eq_ignore_ascii_case(line)))
        })
        .is_none_or(|p| p.show_call_parking)
}

/// `handle_parked_call_message` (FUN_0017b130): when a call is parked by a
/// Digium phone's PJSIP endpoint (the parker dial string is
/// "PJSIP/<endpoint>") whose phone shows the call parking application,
/// send the endpoint an out-of-call MESSAGE with `X-Event-Name:
/// digium.parkingLot.parked` and the body `{"lotnumber":"<space>"}`.
fn handle_parked_call_message(parker_dial_string: &str, event_type: i32, parkingspace: u32) {
    if parker_dial_string.is_empty() || event_type != dpma_ast::stasis::PARKED_CALL {
        return;
    }
    let Some(endpoint) = parker_dial_string.strip_prefix("PJSIP/") else {
        return;
    };
    let is_dphone = {
        let c = dpma_ast::cstr(endpoint);
        unsafe { crate::exports::handlers::dpma_pjsip_endpoint_is_dphone(c.as_ptr()) != 0 }
    };
    let show = phone_user_get_show_call_parking(endpoint);
    if !is_dphone || !show {
        return;
    }
    let Some(msg) = dpma_ast::msg::Msg::alloc() else {
        return;
    };
    // "%d" of the unsigned parking space.
    let body = dump(&json!({"lotnumber": (parkingspace as i32).to_string()}));
    let to = truncate(format!("pjsip:{}", endpoint), 0x100);
    msg.set_var_outbound("X-Event-Name", "digium.parkingLot.parked");
    msg.set_body(&body);
    msg.send(&to, None);
}

// ---------------------------------------------------------------------
// Parking lots
// ---------------------------------------------------------------------

/// switchvox.users.parkingLots.getList (FUN_00181040).
pub fn parking_lots_get_list(c: &MethodCall, _p: &Value, out: &mut String) -> i32 {
    let parked = amihook_action("Action: ParkedCalls\n");
    let lots = amihook_action("Action: Parkinglots\n");
    let mut lot_list = Vec::new();
    for block in &lots {
        if !header_value(block, "Event:", BUF).eq_ignore_ascii_case("Parkinglot") {
            continue;
        }
        let name = header_value(block, "Name:", BUF);
        let mut lot = Map::new();
        lot.insert("account_id".into(), Value::String(name.clone()));
        lot.insert("parked_calls".into(), json!({"parked_call": []}));
        for (field, key) in [("parking_lot_stop", "StopSpace:"), ("timeout", "Timeout:"), ("parking_lot_start", "StartSpace:")] {
            if append_header_value(&mut lot, field, block, key).is_err() {
                error_response_json(out, &c.method, rq::PARSE, field);
                return -1;
            }
        }
        let mut calls = Vec::new();
        for pb in &parked {
            if !header_value(pb, "Parkinglot:", BUF).eq_ignore_ascii_case(&name) {
                continue;
            }
            if !user_can_read_parkinglot(&c.phone, &name) {
                continue;
            }
            let mut call = Map::new();
            for (field, key) in [
                ("from_caller_id_name", "ParkeeCallerIDName:"),
                ("from_caller_id_number", "ParkeeCallerIDNum:"),
                ("duration", "ParkingDuration:"),
                ("lotnum", "ParkingSpace:"),
                ("current_call_id", "ParkeeChannel:"),
            ] {
                if append_header_value(&mut call, field, pb, key).is_err() {
                    error_response_json(out, &c.method, rq::PARSE, field);
                    return -1;
                }
            }
            calls.push(Value::Object(call));
        }
        lot.insert("parked_calls".into(), json!({"parked_call": calls}));
        lot_list.push(Value::Object(lot));
    }
    append_result(out, &c.method, json!({"parking_lots": {"parking_lot": lot_list}}));
    0
}

// ---------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------

/// `find_channel_by_callid_tech(account, call_id, "PJSIP")`.
fn find_call_channel(account: &str, call_id: &str) -> Option<Channel> {
    Channel::find_by_callid(&truncate(format!("PJSIP/{}", account), 0x80), call_id)
}

/// The MixMonitor action of the recording start methods.  The response is
/// read into an 8-byte buffer (the original's `sizeof` of its action
/// pointer), so "Success" never fits: Some("") then, Some(value) for a
/// shorter response, None when the action produced no response.
fn start_mixmonitor(chan: &Channel, mailbox: &str) -> Option<String> {
    let (name, uniqueid) = chan.name_and_uniqueid();
    let action = format!(
        "Action: MixMonitor\nFile: {}.wav\nOptions: m({}/Cust5)\nChannel: {}\n",
        uniqueid, mailbox, name
    );
    action_response(&action, 8)
}

/// The StopMixMonitor action (a 0x80-byte action buffer and response
/// buffer); None when the action produced no response.
fn stop_mixmonitor(chan: &Channel) -> Option<String> {
    let (name, _) = chan.name_and_uniqueid();
    let action = truncate(format!("Action: StopMixMonitor\nChannel: {}\n", name), 0x80);
    action_response(&action, 0x80)
}

/// Tell the phone over the call's dialog (`dpma_info_send`).  0 on
/// success.
fn send_recording_event(chan: &Channel, event: &str) -> i32 {
    unsafe { crate::exports::info_send(chan.as_ptr(), &[("X-Event-Type", event)], "", "") }
}

/// `handle_request_json_recording_start` (FUN_0017f730).
fn handle_request_json_recording_start(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    let Some(account) = param_str(p, "requested_account_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "requested_account_id");
        return -1;
    };
    let Some(call_id) = param_str(p, "call_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "call_id");
        return -1;
    };
    let Some(mailbox) = users::runtime::mailbox_by_line(account) else {
        error_response_json(out, &c.method, rq::NOT_PERMITTED, "mailbox");
        return -1;
    };
    let Some(chan) = find_call_channel(account, call_id) else {
        error_response_json(out, &c.method, rq::NOT_PERMITTED, "channel");
        return -1;
    };
    let Some(response) = start_mixmonitor(&chan, &mailbox) else {
        return -1;
    };
    if !is_success(&response) {
        error_response_json(out, &c.method, rq::NOT_PERMITTED, "MixMonitor");
        dpma_log!("Failed to start MixMonitor. {}", response);
        return -1;
    }
    append_success(out, &c.method);
    if send_recording_event(&chan, "digium.startRecording.success") != 0 {
        return -1;
    }
    0
}

/// `handle_request_json_recording_stop` (FUN_0017e0e0).
fn handle_request_json_recording_stop(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    let Some(account) = param_str(p, "requested_account_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "requested_account_id");
        return -1;
    };
    let Some(call_id) = param_str(p, "call_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "call_id");
        return -1;
    };
    let Some(chan) = find_call_channel(account, call_id) else {
        error_response_json(out, &c.method, rq::NOT_PERMITTED, "channel");
        return -1;
    };
    let Some(response) = stop_mixmonitor(&chan) else {
        return -1;
    };
    if !is_success(&response) {
        error_response_json(out, &c.method, rq::NOT_PERMITTED, "MixMonitor");
        dpma_log!("Failed to stop MixMonitor. {}", response);
        return -1;
    }
    append_success(out, &c.method);
    if send_recording_event(&chan, "digium.stopRecording.success") != 0 {
        return -1;
    }
    0
}

/// The `<parameters>` element of an XML request, parsed.
struct XmlParams(Option<astxml::Doc>);

impl XmlParams {
    fn parse(params: &str) -> XmlParams {
        XmlParams(astxml::Doc::read_memory(params))
    }

    /// The text of the first child element `name` of `<parameters>`
    /// (`ast_xml_find_element(ast_xml_node_get_children(params), name)`).
    fn get(&self, name: &str) -> Option<String> {
        let doc = self.0.as_ref()?;
        doc.root()?.children()?.find_element(name, None)?.text()
    }
}

/// `handle_request_xml_recording_start` (FUN_0017c910).
fn handle_request_xml_recording_start(c: &MethodCall, params: &str, out: &mut String) -> i32 {
    let x = XmlParams::parse(params);
    let Some(account) = x.get("requested_account_id") else {
        error_response_xml(out, &c.method, rq::PARAMS_NOT_FOUND);
        return -1;
    };
    let Some(mailbox) = users::runtime::mailbox_by_line(&account) else {
        error_response_xml(out, &c.method, rq::NOT_PERMITTED);
        return -1;
    };
    let Some(call_id) = x.get("call_id") else {
        error_response_xml(out, &c.method, rq::PARAMS_NOT_FOUND);
        return -1;
    };
    let Some(chan) = find_call_channel(&account, &call_id) else {
        error_response_xml(out, &c.method, rq::NOT_PERMITTED);
        return -1;
    };
    let Some(response) = start_mixmonitor(&chan, &mailbox) else {
        return -1;
    };
    if !is_success(&response) {
        error_response_xml(out, &c.method, rq::NOT_PERMITTED);
        dpma_log!("Failed to start MixMonitor. {}", response);
        return -1;
    }
    set_xml_success(out, &c.method);
    if send_recording_event(&chan, "digium.startRecording.success") != 0 {
        return -1;
    }
    0
}

/// `handle_request_xml_recording_stop` (FUN_0017c3d0).
fn handle_request_xml_recording_stop(c: &MethodCall, params: &str, out: &mut String) -> i32 {
    let x = XmlParams::parse(params);
    let Some(account) = x.get("requested_account_id") else {
        error_response_xml(out, &c.method, rq::PARAMS_NOT_FOUND);
        return -1;
    };
    let Some(call_id) = x.get("call_id") else {
        error_response_xml(out, &c.method, rq::PARAMS_NOT_FOUND);
        return -1;
    };
    let Some(chan) = find_call_channel(&account, &call_id) else {
        error_response_xml(out, &c.method, rq::NOT_PERMITTED);
        return -1;
    };
    let Some(response) = stop_mixmonitor(&chan) else {
        return -1;
    };
    if !is_success(&response) {
        error_response_xml(out, &c.method, rq::NOT_PERMITTED);
        dpma_log!("Failed to stop MixMonitor. {}", response);
        return -1;
    }
    set_xml_success(out, &c.method);
    if send_recording_event(&chan, "digium.stopRecording.success") != 0 {
        return -1;
    }
    0
}

/// switchvox.users.currentCalls.startRecording, XML form.
pub fn start_recording_xml(c: &MethodCall, p: &str, out: &mut String) -> i32 {
    handle_request_xml_recording_start(c, p, out)
}

/// switchvox.users.currentCalls.startRecording, JSON form.
pub fn start_recording_json(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    handle_request_json_recording_start(c, p, out)
}

/// switchvox.users.currentCalls.stopRecording, XML form.
pub fn stop_recording_xml(c: &MethodCall, p: &str, out: &mut String) -> i32 {
    handle_request_xml_recording_stop(c, p, out)
}

/// switchvox.users.currentCalls.stopRecording, JSON form.
pub fn stop_recording_json(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    handle_request_json_recording_stop(c, p, out)
}

// ---------------------------------------------------------------------
// Queues
// ---------------------------------------------------------------------

/// `handle_request_json_queue_getlist` (FUN_00180960).
fn handle_request_json_queue_getlist(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    if param_str(p, "account_id").is_none() {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "account_id");
        return -1;
    }
    let queues = queues_get_status();
    let mut list = Vec::new();
    for app in user_apps(&c.phone) {
        let qa = match app {
            UserApp::Missing(name) => {
                dpma_log!("Failed to find application '{}'", name);
                continue;
            }
            UserApp::Queue(qa) => qa,
            UserApp::Other => continue,
        };
        let mut e = Map::new();
        e.insert("name".into(), Value::String(qa.queue.clone()));
        e.insert("account_id".into(), Value::String(qa.queue.clone()));
        let mut found = false;
        for q in queues.iter().filter(|q| q.name.eq_ignore_ascii_case(&qa.queue)) {
            let (mut total, mut logged_in) = (0i32, 0i32);
            found = false;
            for m in &q.members {
                total += 1;
                logged_in += i32::from(!m.paused);
                if !found && qa.member && m.location.eq_ignore_ascii_case(&qa.location) {
                    if m.paused {
                        e.insert("paused_time".into(), json!("1"));
                    }
                    let status = if m.is_static { "permanent" } else { "logged_in" };
                    e.insert("loggedin_status".into(), json!(status));
                    found = true;
                }
            }
            let waiting = q.entries.len() as i64;
            match qa.permission {
                QueuePermission::Overview => {
                    e.insert("total_members".into(), json!(total));
                }
                QueuePermission::Details => {
                    e.insert("total_members".into(), s(total.into()));
                    e.insert("members_logged_in".into(), s(logged_in.into()));
                    e.insert("callers_waiting".into(), s(waiting));
                }
                QueuePermission::Status => {}
            }
            if found {
                break;
            }
        }
        if !found {
            let status = if qa.member { "logged_out" } else { "manager" };
            e.insert("loggedin_status".into(), json!(status));
        }
        list.push(Value::Object(e));
    }
    append_result(out, &c.method, json!({"callQueues": {"callQueue": list}}));
    0
}

/// `handle_request_json_queue_gettodaysstatus` (FUN_0017fbb0).
fn handle_request_json_queue_gettodaysstatus(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    if param_str(p, "account_id").is_none() {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "account_id");
        return -1;
    }
    let Some(cq) = param_str(p, "call_queue_account_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "call_queue_account_id");
        return -1;
    };
    let queues = queues_get_status();
    let mut app = None;
    for a in user_apps(&c.phone) {
        match a {
            UserApp::Missing(name) => dpma_log!("Failed to find application '{}'", name),
            UserApp::Queue(qa) if qa.queue.eq_ignore_ascii_case(cq) => {
                app = Some(qa);
                break;
            }
            _ => {}
        }
    }
    // No application or no such queue: no answer at all.
    let Some(qa) = app else {
        return 0;
    };
    let Some(q) = queues.iter().find(|q| q.name.eq_ignore_ascii_case(cq)) else {
        return 0;
    };
    let details = qa.permission == QueuePermission::Details;
    let (mut total, mut logged_in, mut on_call) = (0i32, 0i32, 0i32);
    let mut members = Vec::new();
    for m in &q.members {
        total += 1;
        logged_in += i32::from(!m.paused);
        // In use, busy, ringing while in use, or on hold.
        if (m.status as u32) < 9 && (1u32 << m.status) & 0x18c != 0 {
            on_call += 1;
        }
        if !details {
            continue;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let status = if m.is_static { "permanent" } else { "logged_in" };
        match channel::queue_member_call_created(&m.location) {
            Some(created) if now - created >= 1 => members.push(json!({
                "loggedin_status": status,
                "call_duration": s(now - created),
                "fullname": m.name,
            })),
            _ => members.push(json!({"loggedin_status": status, "fullname": m.name})),
        }
    }
    let mut waiting = Vec::new();
    if details {
        for e in &q.entries {
            waiting.push(json!({
                "talking_to_number": e.caller_id_num,
                "talking_to_name": e.caller_id_name,
                "position": s(e.position.into()),
                "waiting_duration": s(e.wait),
            }));
        }
    }
    let mut call_queue = json!({
        "account_id": cq,
        "name": cq,
        "overview": {
            "total_members": s(total.into()),
            "logged_in_count": s(logged_in.into()),
            "members_on_call": s(on_call.into()),
            "callers_waiting": s(q.entries.len() as i64),
            "total_calls": s(q.abandoned.wrapping_add(q.completed).into()),
            "completed_calls_today": s(q.completed.into()),
            "abandoned_calls": s(q.abandoned.into()),
            "redirected_calls": "0",
            "longest_queue_length": "0",
            "avg_entry_position": "0",
        },
        "my_status": {"login_status": ""},
    });
    if details {
        call_queue["detailed_view"] = json!({
            "queue_members": {"queue_member": members},
            "waiting_callers": {"waiting_caller": waiting},
        });
    }
    append_result(out, &c.method, json!({"callQueue": call_queue}));
    0
}

/// `queue_pause_member` (FUN_0017c070): QueuePause for every queue
/// application of the phone matching `queue` ("all" for every one).
/// Failures are only logged; always 0.
fn queue_pause_member(phone: &str, queue: &str, paused: i32, reason: Option<&str>) -> i32 {
    for app in user_apps(phone) {
        let qa = match app {
            UserApp::Missing(name) => {
                dpma_log!("Failed to find application '{}'", name);
                continue;
            }
            UserApp::Queue(qa) => qa,
            UserApp::Other => continue,
        };
        if !queue.eq_ignore_ascii_case("all") && !qa.queue.eq_ignore_ascii_case(queue) {
            continue;
        }
        let mut action = format!(
            "Action: QueuePause\r\nQueue: {}\r\nInterface: {}\r\nPaused: {}\r\n",
            qa.queue, qa.location, paused
        );
        if let Some(r) = reason.filter(|r| !r.is_empty()) {
            action.push_str(&format!("Reason: {}\r\n", r));
        }
        let Some(response) = action_response(&action, BUF) else {
            continue;
        };
        if !is_success(&response) {
            dpma_log!("Failed to pause queue member {} on queue {}", qa.location, qa.queue);
        }
    }
    0
}

/// The Originate the login and logout methods use when the application
/// has a login or logout extension: a Local channel to `exten` running
/// Wait(30), with the phone's primary line as caller id.
fn originate_exten(phone: &str, exten: &str) -> Option<String> {
    let action = format!(
        "Action: Originate\r\nCallerID: <{}>\r\nChannel: Local/{}\r\nApplication: Wait\r\nData: 30\r\nAsync: true\r\n",
        primary_line_name(phone),
        exten
    );
    action_response(&action, BUF)
}

/// Is the application's member (its location) in the queue already?
fn find_member<'a>(queues: &'a [QueueStatus], qa: &QueueApp) -> Option<&'a QueueMember> {
    queues
        .iter()
        .filter(|q| q.name.eq_ignore_ascii_case(&qa.queue))
        .flat_map(|q| q.members.iter())
        .find(|m| m.location.eq_ignore_ascii_case(&qa.location))
}

/// `handle_request_json_queue_login` (FUN_0017f030): for each member
/// queue application matching `call_queue_account_id` ("all" for every
/// one) whose location is not in the queue yet, QueueAdd (or dial the
/// login extension).  Failures are only logged.
fn handle_request_json_queue_login(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    if param_str(p, "account_id").is_none() {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "account_id");
        return -1;
    }
    let Some(cq) = param_str(p, "call_queue_account_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "call_queue_account_id");
        return -1;
    };
    let queues = queues_get_status();
    for app in user_apps(&c.phone) {
        let qa = match app {
            UserApp::Missing(name) => {
                dpma_log!("Failed to find application '{}'", name);
                continue;
            }
            UserApp::Queue(qa) => qa,
            UserApp::Other => continue,
        };
        if !cq.eq_ignore_ascii_case("all") && !qa.queue.eq_ignore_ascii_case(cq) {
            continue;
        }
        if !qa.member || find_member(&queues, &qa).is_some() {
            continue;
        }
        let response = if qa.login_exten.is_empty() {
            let action = format!(
                "Action: QueueAdd\r\nQueue: {}\r\nMemberName: {}\r\nInterface: {}\r\n",
                qa.queue, qa.membername, qa.location
            );
            action_response(&action, BUF)
        } else {
            originate_exten(&c.phone, &qa.login_exten)
        };
        let Some(response) = response else {
            continue;
        };
        if !is_success(&response) {
            dpma_log!("Failed to add queue member {} to queue {}", qa.location, qa.queue);
        }
    }
    append_success(out, &c.method);
    0
}

/// `handle_request_json_queue_logout` (FUN_0017e990): for each member
/// queue application matching `call_queue_account_id` ("all" for every
/// one) whose location is a dynamic member of the queue, QueueRemove (or
/// dial the logout extension).  Static members stay.  Failures are only
/// logged.  (The original crashes on an application that does not exist;
/// here it is skipped.)
fn handle_request_json_queue_logout(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    if param_str(p, "account_id").is_none() {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "account_id");
        return -1;
    }
    let Some(cq) = param_str(p, "call_queue_account_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "call_queue_account_id");
        return -1;
    };
    let queues = queues_get_status();
    for app in user_apps(&c.phone) {
        let UserApp::Queue(qa) = app else {
            continue;
        };
        if !cq.eq_ignore_ascii_case("all") && !qa.queue.eq_ignore_ascii_case(cq) {
            continue;
        }
        if !qa.member {
            continue;
        }
        let Some(m) = find_member(&queues, &qa) else {
            continue;
        };
        if m.is_static {
            continue;
        }
        let response = if qa.logout_exten.is_empty() {
            let action = format!("Action: QueueRemove\r\nQueue: {}\r\nInterface: {}\r\n", qa.queue, qa.location);
            action_response(&action, BUF)
        } else {
            originate_exten(&c.phone, &qa.logout_exten)
        };
        let Some(response) = response else {
            continue;
        };
        if !is_success(&response) {
            dpma_log!("Failed to remove queue member {} from queue {}", qa.location, qa.queue);
        }
    }
    append_success(out, &c.method);
    0
}

/// switchvox.users.callQueues.getList.
pub fn queues_get_list(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    handle_request_json_queue_getlist(c, p, out)
}

/// switchvox.users.callQueues.getTodaysStatus.
pub fn queues_get_todays_status(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    handle_request_json_queue_gettodaysstatus(c, p, out)
}

/// switchvox.users.callQueues.login.
pub fn queue_login(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    handle_request_json_queue_login(c, p, out)
}

/// switchvox.users.callQueues.logout.
pub fn queue_logout(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    handle_request_json_queue_logout(c, p, out)
}

/// switchvox.users.callQueues.pause (FUN_0017cd80): `account_id`,
/// `reason`, and `call_queue_account_id` are required.
pub fn queue_pause(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    if param_str(p, "account_id").is_none() {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "account_id");
        return -1;
    }
    let Some(reason) = param_str(p, "reason") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "reason");
        return -1;
    };
    let Some(cq) = param_str(p, "call_queue_account_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "call_queue_account_id");
        return -1;
    };
    if queue_pause_member(&c.phone, cq, 1, Some(reason)) != 0 {
        error_response_json(out, &c.method, rq::PARSE, "queue_pause_member");
        return -1;
    }
    append_success(out, &c.method);
    0
}

/// switchvox.users.callQueues.resume (FUN_0017c7b0).
pub fn queue_resume(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    if param_str(p, "account_id").is_none() {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "account_id");
        return -1;
    }
    let Some(cq) = param_str(p, "call_queue_account_id") else {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, "call_queue_account_id");
        return -1;
    };
    if queue_pause_member(&c.phone, cq, 0, None) != 0 {
        error_response_json(out, &c.method, rq::PARSE, "queue_pause_member");
        return -1;
    }
    append_success(out, &c.method);
    0
}

// ---------------------------------------------------------------------
// Phonebook
// ---------------------------------------------------------------------

/// switchvox.users.phonebooks.entries.add (FUN_0017e4a0): add a contact
/// (`name`, `extension`) to the `<contacts id="phonebook_id">` list of the
/// first of the phone's contact files that has one, unless a contact there
/// already has a number dialing `extension`; then reconfigure the phone.
pub fn phonebook_entries_add(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    let mut missing = None;
    let mut get = |key: &'static str| {
        let v = param_str(p, key);
        if v.is_none() && missing.is_none() {
            missing = Some(key);
        }
        v.unwrap_or_default()
    };
    let _account = get("account_id");
    let phonebook_id = get("phonebook_id");
    let extension = get("extension");
    let name = get("name");
    if let Some(key) = missing {
        error_response_json(out, &c.method, rq::PARAMS_NOT_FOUND, key);
        return -1;
    }
    let contacts = {
        let g = users::read();
        g.as_ref()
            .and_then(|r| r.phones.get(&c.phone))
            .map(|ph| ph.contacts.clone())
            .unwrap_or_default()
    };
    let file_dir = crate::config::get().file_directory.clone();
    for contact in &contacts {
        // dpma_append_config_file_dir(buf, 0x1000, contact, NULL)
        let path = truncate(format!("{}/{}", file_dir, contact), 0x1000);
        let Some(doc) = astxml::Doc::open(&path) else {
            continue;
        };
        let Some(root) = doc.root() else {
            continue;
        };
        let attr = Some(("id", phonebook_id));
        let list = if root.name() == "phonebooks" {
            root.children().and_then(|n| n.find_element("contacts", attr))
        } else {
            root.find_element("contacts", attr)
        };
        let Some(list) = list else {
            continue;
        };
        let mut child = list.children();
        while let Some(ch) = child {
            if ch.name() == "contact" {
                let number = ch
                    .children()
                    .and_then(|n| n.find_element("numbers", None))
                    .and_then(|n| n.children())
                    .and_then(|n| n.find_element("number", Some(("dial", extension))));
                if number.is_some() {
                    error_response_json(out, &c.method, rq::PHONEBOOK_ENTRY_EXISTS, "contact_list_entry_exists");
                    return -1;
                }
            }
            child = ch.next();
        }
        let added = list.new_child("contact").and_then(|entry| {
            let number = entry.new_child("numbers")?.new_child("number")?;
            Some((entry, number))
        });
        let Some((entry, number)) = added else {
            error_response_json(out, &c.method, rq::PHONEBOOK_ENTRY_EXISTS, "contact_list_entry_add");
            return -1;
        };
        entry.set_attribute("first_name", name);
        entry.set_attribute("last_name", "");
        entry.set_attribute("contact_type", "sip|external");
        entry.set_attribute("subscribe_to", extension);
        number.set_attribute("dial", extension);
        number.set_attribute("label", "Extension");
        number.set_attribute("primary", "1");
        if !doc.dump_file(&path) {
            error_response_json(out, &c.method, rq::PHONEBOOK_ENTRY_EXISTS, "contact_list_entry_add");
            return -1;
        }
        append_success(out, &c.method);
        drop(doc);
        let _ = users::reconfigure(&c.phone, false);
        return 0;
    }
    error_response_json(out, &c.method, rq::INVALID_PHONEBOOK_ID, "contact not found");
    -1
}

// ---------------------------------------------------------------------
// Echo
// ---------------------------------------------------------------------

/// test.dpma.api.echo (FUN_0017c340): `{"response":{"method":M,"result":PARAMS}}`.
pub fn echo(c: &MethodCall, p: &Value, out: &mut String) -> i32 {
    append_result(out, &c.method, p.clone());
    0
}

// ---------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------

#[cfg(feature = "devtest")]
mod devtest {
    use super::*;
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

    /// Show a manager response block with its CR and LF visible.
    fn show(b: &[u8]) -> String {
        String::from_utf8_lossy(b).replace('\r', "\\r").replace('\n', "\\n")
    }

    fn xml_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 6 {
            return CliResult::ShowUsage;
        }
        let method = a.argv[4].clone();
        let params = a.argv[5..].join(" ");
        let Some(f) = crate::method::find_xml(&method) else {
            a.out(&format!("No XML method '{}'\n", method));
            return CliResult::Success;
        };
        let call = MethodCall { phone: a.argv[3].clone(), method, tx: None };
        let mut out = String::new();
        let code = f(&call, &params, &mut out);
        a.out(&format!("Return code: {}\n{}\n", code, show(out.as_bytes())));
        CliResult::Success
    }

    fn hook_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 4 {
            return CliResult::ShowUsage;
        }
        // "Key: Value" pairs separated by "|" become action lines.
        let action: String = a.argv[3..].join(" ").split('|').map(|l| format!("{}\n", l.trim())).collect();
        let blocks = amihook_action(&action);
        a.out(&format!("{} block(s)\n", blocks.len()));
        for (i, b) in blocks.iter().enumerate() {
            a.out(&format!("[{}] {}\n", i, show(b)));
        }
        CliResult::Success
    }

    fn queues_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        for q in queues_get_status() {
            a.out(&format!("queue '{}' completed={} abandoned={}\n", q.name, q.completed, q.abandoned));
            for m in &q.members {
                a.out(&format!(
                    "  member '{}' location='{}' paused={} static={} status={}\n",
                    m.name, m.location, m.paused, m.is_static, m.status
                ));
            }
            for e in &q.entries {
                a.out(&format!(
                    "  entry num='{}' name='{}' position={} wait={}\n",
                    e.caller_id_num, e.caller_id_name, e.position, e.wait
                ));
            }
        }
        CliResult::Success
    }

    fn parked_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 5 || a.argc() > 6 {
            return CliResult::ShowUsage;
        }
        let space = a.argv[4].parse::<u32>().unwrap_or(0);
        let event = a.argv.get(5).and_then(|e| e.parse::<i32>().ok()).unwrap_or(0);
        handle_parked_call_message(&a.argv[3], event, space);
        a.out("done\n");
        CliResult::Success
    }

    fn header_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 6 {
            return CliResult::ShowUsage;
        }
        let size = a.argv[3].parse::<usize>().unwrap_or(BUF);
        let key = &a.argv[4];
        let block = a.argv[5..].join(" ").replace("\\r", "\r").replace("\\n", "\n");
        let mut obj = Map::new();
        let appended = append_header_value(&mut obj, "v", block.as_bytes(), key);
        a.out(&format!(
            "header_value: '{}'\nappend_header_value: {}\n",
            show(header_value(block.as_bytes(), key, size).as_bytes()),
            match appended {
                Ok(()) => format!("'{}'", show(obj["v"].as_str().unwrap_or_default().as_bytes())),
                Err(()) => "missing".into(),
            }
        ));
        CliResult::Success
    }

    pub fn commands() -> Vec<CliCommand> {
        vec![
            CliCommand {
                command: "dpmadev calls xml",
                summary: "Invoke an XML method for a phone",
                usage: "Usage: dpmadev calls xml <phone> <method> <parameters element>\n",
                exec: xml_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev calls hook",
                summary: "Run a manager action through the method API's hook",
                usage: "Usage: dpmadev calls hook <Header: value>[|<Header: value>...]\n       Prints the response blocks as the methods split them.\n",
                exec: hook_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev calls queues",
                summary: "Show the queue status the queue methods see",
                usage: "Usage: dpmadev calls queues\n",
                exec: queues_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev calls parked",
                summary: "Feed a parked call message to the parking handler",
                usage: "Usage: dpmadev calls parked <parker dial string> <space> [event type]\n",
                exec: parked_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev calls header",
                summary: "Extract a header the way the methods do",
                usage: "Usage: dpmadev calls header <buffer size> <Header:> <text with \\r and \\n>\n",
                exec: header_cmd,
                complete: None,
            },
        ]
    }
}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    devtest::commands()
}
