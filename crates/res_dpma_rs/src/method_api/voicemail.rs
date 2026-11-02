//! Voicemail methods and the voicemail message trackers
//! (phone_method_internal_api.c).
//!
//! Message ids.  A phone addresses a message as `<folder>-<msg_id>`, where
//! `msg_id` is app_voicemail's message id (`<time>-<counter>`) and
//! `<folder>` is the folder's "canonical" name: Old and Urgent messages
//! are shown in INBOX, so their ids start with `INBOX-`.  getList builds
//! these ids; the other methods split them at the first `-`.
//!
//! Message trackers.  Each phone has a user tracker holding message
//! trackers.  getList replaces a phone's trackers with the messages of the
//! page it returns; the other methods look an id up there and, when it is
//! missing, find the message in a snapshot of the folder the id names.
//! markRead/markUnread update the tracker of a message they move; move,
//! remove, and forward do not.  A user tracker is dropped when its phone
//! goes away (`remove_user_tracker`).
//!
//! Every handler answers with `{"response":{"method":M,"result":...}}`
//! appended to `out` and returns 0, or replaces `out` with an error
//! document (`request::error_response_json`) and returns -1, as the
//! official DPMA does (its caller ignores the value).
//!
//! The official DPMA works on fixed-size C buffers; the same truncations
//! are applied here.

use crate::method::MethodCall;
use crate::request::error_response_json;
use crate::translation::Table;
use crate::users;
use dpma_ast::channel;
use dpma_ast::dial::{self, AstDial};
use dpma_ast::log::LOG_WARNING;
use dpma_ast::vm::{self, SortBy};
use dpma_ast::{ast_log, bformat, dpma_log};
use dpma_proto::errors::request::{
    INVALID_MAILBOX_FOLDER, NOT_PERMITTED, PARAMS_NOT_FOUND, PARSE, PHONE_EVENT_APP_FAILED,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::{Arc, Mutex};

/// app_voicemail's folders by index (the table at 0x5bd140).
const FOLDERS: [&str; 12] = [
    "INBOX", "Old", "Work", "Family", "Friends", "Cust1", "Cust2", "Cust3", "Cust4", "Cust5",
    "Deleted", "Urgent",
];

/// The folder a phone sees each folder as (the table at 0x5bd0e0).
const CANONICAL: [&str; 12] = [
    "INBOX", "INBOX", "Work", "Family", "Friends", "Cust1", "Cust2", "Cust3", "Cust4", "Cust5",
    "Deleted", "INBOX",
];

/// Folder indexes getFolderList reports (bit mask 0x21d: INBOX, Work,
/// Family, Friends, and Cust5).
const LISTED_FOLDERS: u32 = 0x21d;

/// Phones call Cust5 "Recordings".
const RECORDINGS: &[u8] = b"Recordings";
const CUST5: &[u8] = b"Cust5";

/// Sizes of the official DPMA's buffers.
const MSG_ID_BUF: usize = 0x80;
const MAILBOX_BUF: usize = 0x400;
const CALLERID_BUF: usize = 0x100;
const LINE_NAME_BUF: usize = 0x80;
const TECH_BUF: usize = 0x20;
const HEADER_BUF: usize = 0x80;

/// The dialplan application a phone's playback call runs when answered.
const PLAYBACK_APP: &str = "DigiumVoicemailPlayback";
const PLAYBACK_EVENT: &str = "digium.incomingCall.voicemail";

// ---------------------------------------------------------------------------
// Message trackers
// ---------------------------------------------------------------------------

/// `vm_message_tracker`: a message id as the phone knows it and the
/// folder the message is in.
#[derive(Debug)]
struct MsgTracker {
    id: Vec<u8>,
    folder: Vec<u8>,
}

/// `vm_phone_user_tracker`: one phone's message trackers.  The official
/// DPMA's container allows duplicate ids and finds the first one linked; a
/// vector searched from the front does the same.
#[derive(Debug, Default)]
struct UserTracker {
    messages: Mutex<Vec<Arc<MsgTracker>>>,
}

/// The phone-user tracker container (0x5eff48), keyed by phone name (case
/// sensitive).  None while the module is not loaded.
static USER_TRACKERS: Mutex<Option<HashMap<Vec<u8>, Arc<UserTracker>>>> = Mutex::new(None);

/// `vm_phone_user_tracker_find_or_create` (FUN_00181950).
fn user_tracker_find_or_create(name: &[u8]) -> Arc<UserTracker> {
    let mut g = USER_TRACKERS.lock().unwrap();
    match g.as_mut() {
        Some(map) => map.entry(name.to_vec()).or_default().clone(),
        // No container: the official DPMA's link fails but the tracker is
        // still used for the request.
        None => Arc::new(UserTracker::default()),
    }
}

/// `vm_phone_user_tracker_remove` (FUN_0017b390): drop a phone's
/// trackers.
pub fn remove_user_tracker(name: &[u8]) {
    if let Some(map) = USER_TRACKERS.lock().unwrap().as_mut() {
        map.remove(name);
    }
}

/// `vm_message_tracker_list_reset` (FUN_00181880).
fn list_reset(ut: &UserTracker) {
    ut.messages.lock().unwrap().clear();
}

/// `vm_message_tracker_add` (FUN_00184fe0).
fn tracker_add(ut: &UserTracker, id: &[u8], folder: &[u8]) -> Result<(), ()> {
    ut.messages.lock().unwrap().push(Arc::new(MsgTracker {
        id: id.to_vec(),
        folder: folder.to_vec(),
    }));
    Ok(())
}

fn tracker_unlink(ut: &UserTracker, t: &Arc<MsgTracker>) {
    let mut v = ut.messages.lock().unwrap();
    if let Some(i) = v.iter().position(|x| Arc::ptr_eq(x, t)) {
        v.remove(i);
    }
}

/// FUN_0017bc60: find the message `id` (`<folder>-<msg_id>`) in a snapshot
/// of `folder` of `mailbox` (`box@context`) and make a tracker for it.
fn tracker_from_snapshot(id: &[u8], folder: &[u8], mailbox: &[u8]) -> Option<MsgTracker> {
    let dash = find(id, b'-')?;
    let msg_id = &id[dash + 1..];
    if msg_id.is_empty() {
        return None;
    }
    let at = find(mailbox, b'@')?;
    let snap = vm::mailbox_snapshot_create(
        &mailbox[..at],
        Some(&mailbox[at + 1..]),
        Some(folder),
        true,
        SortBy::Time,
        true,
    )?;
    snap.folders
        .iter()
        .flatten()
        .find(|m| m.msg_id == msg_id)
        .map(|m| MsgTracker {
            id: id.to_vec(),
            folder: m.folder_name.clone(),
        })
}

/// `vm_message_tracker_find` (FUN_00181aa0): the tracker for `id`, made
/// from a snapshot when there is none, provided the message's folder shows
/// as `folder` (compared case sensitively).
fn tracker_find(
    ut: &UserTracker,
    id: &[u8],
    folder: &[u8],
    mailbox: &[u8],
) -> Option<Arc<MsgTracker>> {
    let found = ut
        .messages
        .lock()
        .unwrap()
        .iter()
        .find(|t| t.id == id)
        .cloned();
    let t = match found {
        Some(t) => t,
        None => {
            let t = Arc::new(tracker_from_snapshot(id, folder, mailbox)?);
            ut.messages.lock().unwrap().push(t.clone());
            t
        }
    };
    // The official DPMA compares a NULL name (a folder it does not know)
    // and crashes; such a tracker cannot be made, so it simply does not
    // match.
    match canonical(&t.folder) {
        Some(c) if c.as_bytes() == folder => Some(t),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find(s: &[u8], c: u8) -> Option<usize> {
    s.iter().position(|&b| b == c)
}

/// A C string's view of `s` (up to the first NUL).
fn c_view(s: &[u8]) -> &[u8] {
    &s[..find(s, 0).unwrap_or(s.len())]
}

/// `ast_copy_string(buf, src, size)`.
fn copy_trunc(src: &[u8], size: usize) -> Vec<u8> {
    let src = c_view(src);
    src[..src.len().min(size - 1)].to_vec()
}

/// `strcasecmp(a, b) == 0` (ASCII).
fn eq_ic(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The folder index of a folder name (case insensitive).
fn folder_index(name: &[u8]) -> Option<usize> {
    FOLDERS.iter().position(|f| eq_ic(name, f.as_bytes()))
}

/// The canonical name of a folder (None for an unknown folder).
fn canonical(name: &[u8]) -> Option<&'static str> {
    folder_index(name).map(|i| CANONICAL[i])
}

/// `snprintf(buf, 0x80, "%s-%s", folder, msg_id)`; glibc prints a NULL
/// folder as "(null)".
fn make_id(folder: Option<&str>, msg_id: &[u8]) -> Vec<u8> {
    let mut v = folder.unwrap_or("(null)").as_bytes().to_vec();
    v.push(b'-');
    v.extend_from_slice(msg_id);
    v.truncate(MSG_ID_BUF - 1);
    v
}

/// A string for printf-style output; None prints as "(null)".
fn show(s: Option<&[u8]>) -> &[u8] {
    s.unwrap_or(b"(null)")
}

/// Split `box@context` at the first '@' (no '@': no context).
fn split_mailbox(mailbox: &[u8]) -> (&[u8], Option<&[u8]>) {
    match find(mailbox, b'@') {
        Some(i) => (&mailbox[..i], Some(&mailbox[i + 1..])),
        None => (mailbox, None),
    }
}

/// `ast_json_string_get(ast_json_object_get(params, key))`.
fn json_str<'a>(p: &'a Value, key: &str) -> Option<&'a [u8]> {
    p.as_object()?
        .get(key)?
        .as_str()
        .map(|s| c_view(s.as_bytes()))
}

/// `ast_json_object_get(params, key)` (any type).
fn json_get<'a>(p: &'a Value, key: &str) -> Option<&'a Value> {
    p.as_object()?.get(key)
}

/// A JSON string from bytes; None (a failed `ast_json_pack`) when they are
/// not UTF-8, which jansson refuses.
fn jstr(b: &[u8]) -> Option<Value> {
    std::str::from_utf8(b)
        .ok()
        .map(|s| Value::String(s.to_string()))
}

/// `strtol(s, NULL, 10)`.
fn strtol10(s: &[u8]) -> i64 {
    let s = c_view(s);
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let neg = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let mut v: i64 = 0;
    let mut overflow = false;
    while let Some(d) = s.get(i).filter(|c| c.is_ascii_digit()) {
        let d = (d - b'0') as i64;
        match v.checked_mul(10).and_then(|x| {
            if neg {
                x.checked_sub(d)
            } else {
                x.checked_add(d)
            }
        }) {
            Some(n) => v = n,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        if neg {
            i64::MIN
        } else {
            i64::MAX
        }
    } else {
        v
    }
}

/// Replace `out` with a JSON error document; the handlers then return -1.
fn fail(out: &mut Vec<u8>, method: &[u8], code: i32, detail: impl AsRef<[u8]>) -> i32 {
    error_response_json(out, method, code, detail);
    -1
}

/// Append `{"response":{"method":M,"result":R}}` to `out` (nothing when
/// the method is not UTF-8, where the official DPMA's `ast_json_pack`
/// fails).
fn respond(out: &mut Vec<u8>, method: &[u8], result: Value) {
    let Some(method) = dpma_proto::json::utf8(method) else {
        return;
    };
    let doc = json!({"response": {"method": method, "result": result}});
    out.extend_from_slice(dpma_proto::json::dump(&doc).as_bytes());
}

/// `phone_user_get_application_settings(user, voicemail)` and its folder
/// translation table (logs "Failed to find application" like the official
/// DPMA).
fn vm_translation(phone: &[u8]) -> Option<Arc<Table>> {
    let g = users::read();
    let reg = g.as_ref()?;
    let p = reg.phones.get(phone)?;
    let app = users::build_config::application_settings(reg, p, "Voicemail")?;
    match &app.kind {
        Some(users::AppKind::Voicemail(v)) => {
            v.translation.as_deref().and_then(crate::translation::get)
        }
        _ => None,
    }
}

/// Phone folder name to voicemail folder (a translation's value to its
/// key), case insensitive.
fn untranslate(t: &Option<Arc<Table>>, folder: &[u8]) -> Vec<u8> {
    if let Some(t) = t {
        if let Some((k, _)) = t.entries.iter().find(|(_, v)| eq_ic(folder, v)) {
            return k.clone();
        }
    }
    folder.to_vec()
}

/// Voicemail folder to the name the phone shows (key to value).
fn translate(t: &Option<Arc<Table>>, folder: &[u8]) -> Vec<u8> {
    if let Some(t) = t {
        if let Some((_, v)) = t.entries.iter().find(|(k, _)| eq_ic(folder, k)) {
            return v.clone();
        }
    }
    folder.to_vec()
}

/// "Recordings" (exactly) is Cust5.
fn unrecordings(folder: &[u8]) -> &[u8] {
    if folder == RECORDINGS {
        CUST5
    } else {
        folder
    }
}

/// `phone_user_has_line(user, line)` and then `phone_mailbox_by_line(line)`:
/// the mailbox of one of the phone's own lines.
fn own_mailbox(phone: &[u8], line: &[u8]) -> Option<Vec<u8>> {
    let has = {
        let g = users::read();
        g.as_ref()
            .and_then(|r| r.phones.get(phone))
            .is_some_and(|p| p.has_line(line))
    };
    if !has {
        return None;
    }
    line_mailbox(line)
}

/// `phone_mailbox_by_line` into the official DPMA's 0x400-byte buffer.
fn line_mailbox(line: &[u8]) -> Option<Vec<u8>> {
    users::runtime::mailbox_by_line(line).map(|m| copy_trunc(&m, MAILBOX_BUF))
}

/// Split a message id (already copied into its 0x80-byte buffer) into its
/// folder part and its message id; None when there is no `-` or nothing
/// after it.
fn split_id(buf: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let dash = find(buf, b'-')?;
    let msg_id = &buf[dash + 1..];
    if msg_id.is_empty() {
        return None;
    }
    Some((buf[..dash].to_vec(), msg_id.to_vec()))
}

/// The message ids of `message_ids` grouped by the folder their trackers
/// say they are in.  On error, `out` holds the error document.
struct Grouped {
    ids: [Vec<Vec<u8>>; 12],
    /// The id buffer as the last parsed id left it (move reuses it).
    last_buf: Vec<u8>,
}

enum GroupError {
    /// No `-` or nothing after it.
    Decode {
        buf: Vec<u8>,
    },
    NotFound,
}

/// The loop shared by remove, forward, and move.
fn group_messages(ut: &UserTracker, ids: &[Value], mailbox: &[u8]) -> Result<Grouped, GroupError> {
    let mut g = Grouped {
        ids: Default::default(),
        last_buf: Vec::new(),
    };
    for el in ids {
        let Some(s) = el.as_str() else { continue };
        let buf = copy_trunc(s.as_bytes(), MSG_ID_BUF);
        g.last_buf = buf.clone();
        let Some(dash) = find(&buf, b'-') else {
            return Err(GroupError::Decode { buf });
        };
        g.last_buf.truncate(dash);
        let msg_id = &buf[dash + 1..];
        if msg_id.is_empty() {
            return Err(GroupError::Decode {
                buf: g.last_buf.clone(),
            });
        }
        let folder = unrecordings(&g.last_buf).to_vec();
        let Some(t) = tracker_find(ut, &buf, &folder, mailbox) else {
            return Err(GroupError::NotFound);
        };
        if let Some(i) = folder_index(&t.folder) {
            g.ids[i].push(msg_id.to_vec());
        }
    }
    Ok(g)
}

/// The `message_ids` array, when it is a non-empty array.
fn id_array(v: &Value) -> Option<&Vec<Value>> {
    v.as_array().filter(|a| !a.is_empty())
}

// ---------------------------------------------------------------------------
// Load and unload
// ---------------------------------------------------------------------------

/// Create the phone-user tracker container (FUN_00186920 part).
pub fn load() -> Result<(), ()> {
    *USER_TRACKERS.lock().unwrap() = Some(HashMap::new());
    Ok(())
}

/// Drop the container and every tracker (FUN_00186840 part).
pub fn unload() {
    USER_TRACKERS.lock().unwrap().take();
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

/// `switchvox.users.voicemail.getList` (`handle_request_json_vm_getlist`,
/// FUN_001859c0): one page of a folder's messages.
pub fn get_list(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    let m = c.method.as_slice();
    let tr = vm_translation(&c.phone);
    let Some(account) = json_str(p, "account_id") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_id");
    };
    let Some(mailbox) = own_mailbox(&c.phone, account) else {
        return fail(out, m, NOT_PERMITTED, "must have line with mailbox");
    };
    let (mbox, context) = split_mailbox(&mailbox);
    let ut = user_tracker_find_or_create(&c.phone);
    list_reset(&ut);

    // Deviation: the official DPMA dereferences a missing folder and
    // crashes.
    let Some(folder) = json_str(p, "folder") else {
        return fail(out, m, PARAMS_NOT_FOUND, "folder");
    };
    let folder = untranslate(&tr, folder);
    let descending = json_str(p, "sort_order").is_some_and(|s| eq_ic(s, b"DESC"));
    let by_date = json_str(p, "sort_field").is_some_and(|s| eq_ic(s, b"date"));
    let per_page: i32 = match json_get(p, "items_per_page") {
        // ast_json_integer_get: 0 for anything but an integer.
        Some(v) => v.as_i64().unwrap_or(0) as i32,
        None => 50,
    };
    let page: i32 = json_str(p, "page_number").map_or(1, |s| strtol10(s) as i32);

    let sort = if by_date { SortBy::Time } else { SortBy::Id };
    let Some(snap) = vm::mailbox_snapshot_create(
        mbox,
        context,
        Some(unrecordings(&folder)),
        descending,
        sort,
        true,
    ) else {
        return fail(
            out,
            m,
            INVALID_MAILBOX_FOLDER,
            bformat!(
                "could not create snapshot of {}@{} {}",
                show(Some(mbox)),
                show(context),
                show(Some(unrecordings(&folder)))
            ),
        );
    };

    // Deviation: the official DPMA divides by zero (SIGFPE) for a zero (or
    // non-integer) items_per_page.
    let Some(pages) = snap.total_msg_num.checked_div(per_page) else {
        return fail(out, m, PARAMS_NOT_FOUND, "items_per_page");
    };
    let shown = translate(&tr, &folder);
    let Some(shown) = jstr(&shown) else {
        return fail(out, m, PARSE, "pack messages");
    };
    let mut messages = Vec::new();
    let (mut on_page, mut cur_page) = (0i32, 1i32);
    for msg in snap.folders.iter().flatten() {
        let emit = if on_page < per_page {
            on_page += 1;
            page == cur_page
        } else {
            cur_page = cur_page.wrapping_add(1);
            on_page = 1;
            page == cur_page
        };
        if !emit {
            continue;
        }
        let folder_name = &msg.folder_name;
        if msg.msg_id.is_empty() {
            ast_log!(
                LOG_WARNING,
                "Cannot retrieve full list. Missing message id for folder {}",
                show(Some(folder_name))
            );
        }
        let id = make_id(canonical(folder_name), &msg.msg_id);
        if tracker_add(&ut, &id, folder_name).is_err() {
            dpma_log!(
                "Failed to track a voicemail message '{}' id sent to '{}'",
                show(Some(&msg.msg_id)),
                c.phone
            );
        }
        let (number, name) = parse_callerid(&copy_trunc(&msg.callerid, CALLERID_BUF));
        let read = if eq_ic(folder_name, b"INBOX") || eq_ic(folder_name, b"Urgent") {
            "No"
        } else {
            "Yes"
        };
        let entry = (|| {
            Some(json!({
                "id": jstr(&id)?,
                "caller_id": jstr(&msg.callerid)?,
                "caller_id_number": jstr(&number)?,
                "caller_id_name": jstr(&name)?,
                "date": jstr(&msg.origdate)?,
                "date_UTC": jstr(&msg.origdate)?,
                "duration": jstr(&msg.duration)?,
                "read": read,
            }))
        })();
        let Some(entry) = entry else {
            return fail(out, m, PARSE, "message_entry");
        };
        messages.push(entry);
    }
    let result = json!({"messages": {
        "folder": shown,
        "page_number": page.to_string(),
        "total_pages": pages.wrapping_add(1).to_string(),
        "items_per_page": per_page.to_string(),
        "total_items": snap.total_msg_num.to_string(),
        "message": messages,
    }});
    respond(out, m, result);
    0
}

/// The caller id parsing of getList: `"name" <number>` and the forms
/// without quotes or brackets.  Returns (number, name).
fn parse_callerid(cid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (name, rest): (&[u8], Option<&[u8]>) = match find(cid, b'"') {
        None => (b"", Some(cid)),
        Some(q) => {
            let after = &cid[q + 1..];
            match find(after, b'"') {
                Some(q2) => (&after[..q2], Some(&after[q2 + 1..])),
                // No closing quote: everything after the quote is the name.
                None => (after, None),
            }
        }
    };
    let mut number: &[u8] = rest.unwrap_or(b"");
    if !number.is_empty() {
        if let Some(lt) = find(number, b'<') {
            number = &number[lt + 1..];
        }
        if let Some(gt) = number.iter().rposition(|&b| b == b'>') {
            number = &number[..gt];
        }
    }
    (number.to_vec(), name.to_vec())
}

/// `switchvox.users.voicemail.getFolderList` (FUN_0017d8d0): the folders
/// and their message counts.
pub fn get_folder_list(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    let m = c.method.as_slice();
    let tr = vm_translation(&c.phone);
    let Some(account) = json_str(p, "account_id") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_id");
    };
    let Some(mailbox) = own_mailbox(&c.phone, account) else {
        return fail(out, m, NOT_PERMITTED, "must have line with mailbox");
    };
    let (mbox, context) = split_mailbox(&mailbox);
    let Some(snap) = vm::mailbox_snapshot_create(mbox, context, None, false, SortBy::Time, true)
    else {
        return fail(
            out,
            m,
            INVALID_MAILBOX_FOLDER,
            bformat!(
                "could not create snapshot of {}@{}",
                show(Some(mbox)),
                show(context)
            ),
        );
    };
    let mut folders = Vec::new();
    for (i, list) in snap.folders.iter().enumerate() {
        if i >= 10 || (LISTED_FOLDERS >> i) & 1 == 0 {
            continue;
        }
        let mut name = vm::index_to_foldername(i as i32).unwrap_or_default();
        if name == CUST5 {
            name = RECORDINGS.to_vec();
        }
        let shown = translate(&tr, &name);
        let Some(shown) = jstr(&shown) else {
            return fail(out, m, PARSE, "append folder");
        };
        folders.push(json!({"name": shown, "count": list.len().to_string()}));
    }
    respond(out, m, json!({"folders": {"folder": folders}}));
    0
}

/// `switchvox.users.voicemail.move` (`handle_request_json_vm_move`,
/// FUN_00184200).
pub fn move_message(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    let m = c.method.as_slice();
    let tr = vm_translation(&c.phone);
    let Some(account) = json_str(p, "account_id") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_id");
    };
    let ut = user_tracker_find_or_create(&c.phone);
    let Some(folder_from) = json_str(p, "folder_from") else {
        return fail(out, m, PARAMS_NOT_FOUND, "folder_from");
    };
    let Some(folder_to) = json_str(p, "folder_to") else {
        return fail(out, m, PARAMS_NOT_FOUND, "folder_to");
    };
    let Some(ids) = json_get(p, "message_ids") else {
        return fail(out, m, PARAMS_NOT_FOUND, "message_ids");
    };
    let folder_to = untranslate(&tr, folder_to);
    let folder_from = untranslate(&tr, folder_from);
    let Some(mailbox) = own_mailbox(&c.phone, account) else {
        return fail(out, m, NOT_PERMITTED, "must have line with mailbox");
    };
    let Some(ids) = id_array(ids) else {
        return fail(out, m, PARAMS_NOT_FOUND, "total_msgs");
    };
    let mut g = match group_messages(&ut, ids, &mailbox) {
        Ok(g) => g,
        Err(GroupError::Decode { buf }) => {
            dpma_log!("ERROR decoding message id {}", show(Some(&buf)));
            return fail(out, m, PARAMS_NOT_FOUND, "id decode");
        }
        Err(GroupError::NotFound) => return fail(out, m, PARSE, "failed to find message"),
    };
    let (mbox, context) = split_mailbox(&mailbox);
    let mut moved = Vec::new();
    for (i, group) in g.ids.iter().enumerate() {
        if group.is_empty() {
            continue;
        }
        if vm::msg_move(
            mbox,
            context,
            FOLDERS[i].as_bytes(),
            group,
            unrecordings(&folder_to),
        ) < 0
        {
            dpma_log!(
                "Could not move msgs from {} to {}",
                show(Some(&folder_from)),
                show(Some(&folder_to))
            );
            return fail(out, m, PARAMS_NOT_FOUND, "could not move message");
        }
        for old in group {
            if old.is_empty() {
                ast_log!(
                    LOG_WARNING,
                    "Cannot move due to missing old message id for folder {}",
                    show(Some(&g.last_buf))
                );
            }
            // The official DPMA rebuilds the id in the buffer that still
            // holds the folder part of the last id parsed, so only the
            // first moved message gets a folder name; the others get
            // "(null)".
            g.last_buf = make_id(canonical(&g.last_buf), old);
            let Some(id) = jstr(&g.last_buf) else {
                return fail(out, m, PARSE, "append message");
            };
            moved.push(json!({"id": id.clone(), "old_id": id}));
        }
    }
    respond(out, m, json!({"messages": {"message": moved}}));
    0
}

/// `switchvox.users.voicemail.remove` (`handle_request_json_vm_remove`,
/// FUN_00183500).
pub fn remove(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    let m = c.method.as_slice();
    let tr = vm_translation(&c.phone);
    let Some(account) = json_str(p, "account_id") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_id");
    };
    let ut = user_tracker_find_or_create(&c.phone);
    let Some(folder) = json_str(p, "folder") else {
        return fail(out, m, PARAMS_NOT_FOUND, "folder");
    };
    let Some(ids) = json_get(p, "message_ids") else {
        return fail(out, m, PARAMS_NOT_FOUND, "message_ids");
    };
    // The folder parameter only appears in the failure log.
    let folder = untranslate(&tr, folder);
    let folder = unrecordings(&folder).to_vec();
    let Some(mailbox) = own_mailbox(&c.phone, account) else {
        return fail(out, m, NOT_PERMITTED, "must have line with mailbox");
    };
    let Some(ids) = id_array(ids) else {
        return fail(out, m, PARAMS_NOT_FOUND, "total_msgs");
    };
    let g = match group_messages(&ut, ids, &mailbox) {
        Ok(g) => g,
        Err(GroupError::Decode { .. }) => return fail(out, m, PARAMS_NOT_FOUND, "message id"),
        Err(GroupError::NotFound) => return fail(out, m, PARSE, "failed to find message"),
    };
    let (mbox, context) = split_mailbox(&mailbox);
    for (i, group) in g.ids.iter().enumerate() {
        if group.is_empty() {
            continue;
        }
        if vm::msg_remove(mbox, context, FOLDERS[i].as_bytes(), group) != 0 {
            dpma_log!("Could not remove msgs from {}", show(Some(&folder)));
            return fail(out, m, PARAMS_NOT_FOUND, "could not remove message");
        }
    }
    respond(out, m, json!({"success": {}}));
    0
}

/// `switchvox.users.voicemail.forward` (`handle_request_json_vm_forward`,
/// FUN_00182660): copy messages to the INBOX of another line's mailbox.
pub fn forward(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    let m = c.method.as_slice();
    let Some(account_from) = json_str(p, "account_from") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_from");
    };
    let ut = user_tracker_find_or_create(&c.phone);
    let Some(account_to) = json_str(p, "account_to") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_to");
    };
    if json_str(p, "folder").is_none() {
        return fail(out, m, PARAMS_NOT_FOUND, "folder");
    }
    let Some(ids) = json_get(p, "message_ids") else {
        return fail(out, m, PARAMS_NOT_FOUND, "message_ids");
    };
    let Some(mailbox) = own_mailbox(&c.phone, account_from) else {
        return fail(out, m, NOT_PERMITTED, "must have line with mailbox");
    };
    // Any line with a mailbox can receive.
    let to_mailbox = line_mailbox(account_to).unwrap_or_default();
    if to_mailbox.is_empty() {
        return fail(out, m, NOT_PERMITTED, "to_mailbox");
    }
    let (to_box, to_context) = split_mailbox(&to_mailbox);
    let Some(ids) = id_array(ids) else {
        return fail(out, m, PARAMS_NOT_FOUND, "total_msgs");
    };
    let g = match group_messages(&ut, ids, &mailbox) {
        Ok(g) => g,
        Err(GroupError::Decode { .. }) => return fail(out, m, PARAMS_NOT_FOUND, "message id"),
        Err(GroupError::NotFound) => return fail(out, m, PARSE, "failed to find message"),
    };
    let (mbox, context) = split_mailbox(&mailbox);
    for (i, group) in g.ids.iter().enumerate() {
        if group.is_empty() {
            continue;
        }
        if vm::msg_forward(
            mbox,
            context,
            FOLDERS[i].as_bytes(),
            to_box,
            to_context,
            b"INBOX",
            group,
            false,
        ) < 0
        {
            dpma_log!(
                "Could not forward msgs from {}@{} to {}@{}",
                show(Some(mbox)),
                show(context),
                show(Some(to_box)),
                show(to_context)
            );
            return fail(out, m, PARAMS_NOT_FOUND, "could not forward message");
        }
    }
    respond(out, m, json!({"success": {}}));
    0
}

/// `mark_read_unread_helper_json` (FUN_001850e0): move INBOX, Old, or
/// Urgent messages to Old (`read`) or INBOX, and update their trackers.
fn mark_read_unread(c: &MethodCall, p: &Value, out: &mut Vec<u8>, read: bool) -> i32 {
    let m = c.method.as_slice();
    let target: &[u8] = if read { b"Old" } else { b"INBOX" };
    let tr = vm_translation(&c.phone);
    let Some(account) = json_str(p, "account_id") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_id");
    };
    let Some(ids) = json_get(p, "message_ids") else {
        return fail(out, m, PARAMS_NOT_FOUND, "message_ids");
    };
    let Some(mailbox) = own_mailbox(&c.phone, account) else {
        return fail(out, m, NOT_PERMITTED, "must have line with mailbox");
    };
    let (mbox, context) = split_mailbox(&mailbox);
    let ut = user_tracker_find_or_create(&c.phone);
    let Some(ids) = id_array(ids) else {
        return fail(out, m, PARAMS_NOT_FOUND, "total_msgs");
    };
    for el in ids {
        let Some(s) = el.as_str() else { continue };
        let buf = copy_trunc(s.as_bytes(), MSG_ID_BUF);
        let Some((folder, msg_id)) = split_id(&buf) else {
            return fail(out, m, PARAMS_NOT_FOUND, "message id");
        };
        let folder = untranslate(&tr, &folder);
        let folder = unrecordings(&folder).to_vec();
        let Some(t) = tracker_find(&ut, &buf, &folder, &mailbox) else {
            return fail(out, m, PARSE, "failed to find message");
        };
        if eq_ic(&t.folder, target) {
            continue;
        }
        if !(eq_ic(&t.folder, b"INBOX") || eq_ic(&t.folder, b"Old") || eq_ic(&t.folder, b"Urgent"))
        {
            dpma_log!(
                "Attempted to mark read/unread on {} folder",
                show(Some(&folder))
            );
            continue;
        }
        if vm::msg_move(mbox, context, &t.folder, &[&msg_id], target) < 0 {
            dpma_log!(
                "Could not move msgs from {} to {}",
                show(Some(&folder)),
                show(Some(target))
            );
            return fail(out, m, PARAMS_NOT_FOUND, "could not move message");
        }
        tracker_unlink(&ut, &t);
        let _ = tracker_add(&ut, &buf, target);
    }
    respond(out, m, json!({"success": {}}));
    0
}

/// `switchvox.users.voicemail.markRead` (FUN_001859b0).
pub fn mark_read(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    mark_read_unread(c, p, out, true)
}

/// `switchvox.users.voicemail.markUnread` (FUN_001859a0).
pub fn mark_unread(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    mark_read_unread(c, p, out, false)
}

/// `switchvox.users.voicemail.play` (`handle_request_json_vm_play`,
/// FUN_00181d40): call the phone's primary line; when answered, the call
/// runs `DigiumVoicemailPlayback(<mailbox>,<folder>,<msg_id>)`.
pub fn play(c: &MethodCall, p: &Value, out: &mut Vec<u8>) -> i32 {
    let m = c.method.as_slice();
    let Some(account) = json_str(p, "account_id") else {
        return fail(out, m, PARAMS_NOT_FOUND, "account_id");
    };
    let Some(message_id) = json_str(p, "message_id") else {
        return fail(out, m, PARAMS_NOT_FOUND, "message_id");
    };
    let Some(mailbox) = own_mailbox(&c.phone, account) else {
        return fail(out, m, NOT_PERMITTED, "must have line with mailbox");
    };
    let buf = copy_trunc(message_id, MSG_ID_BUF);
    let ut = user_tracker_find_or_create(&c.phone);
    let Some((folder, msg_id)) = split_id(&buf) else {
        return fail(out, m, PARAMS_NOT_FOUND, "msg_id_decode");
    };
    // Unlike the other methods, the folder is neither translated nor
    // mapped from "Recordings".
    let Some(t) = tracker_find(&ut, &buf, &folder, &mailbox) else {
        return fail(out, m, PARSE, "failed to find message");
    };
    let mut app = format!("{},", PLAYBACK_APP).into_bytes();
    for (i, part) in [&mailbox[..], &t.folder, &msg_id].iter().enumerate() {
        if i > 0 {
            app.push(b',');
        }
        app.extend_from_slice(part);
    }
    dial_phone_event_app(&c.phone, out, m, &app);
    if !out.is_empty() {
        return -1;
    }
    respond(out, m, json!({"success": {}}));
    0
}

/// The user data of a playback call (`dial_phone_event_app_data`; the
/// official DPMA's result callback is always NULL and is left out).
struct DialData {
    app_and_args: Vec<u8>,
}

/// `dial_phone_event_app` (in FUN_00181d40): dial the phone's primary
/// line with `X-Event-Name: digium.incomingCall.voicemail` and run `app`
/// ("app,args") when it answers, on a detached thread.  Errors replace
/// `out`.
fn dial_phone_event_app(phone: &[u8], out: &mut Vec<u8>, method: &[u8], app: &[u8]) {
    let (tech, line) = {
        let g = users::read();
        match g.as_ref().and_then(|r| r.phones.get(phone).map(|p| (r, p))) {
            Some((reg, p)) => (
                users::build_config::primary_line(reg, p)
                    .map_or_else(Vec::new, |l| copy_trunc(&l.tech, TECH_BUF)),
                p.lines
                    .first()
                    .map_or_else(Vec::new, |l| copy_trunc(&l.name, LINE_NAME_BUF)),
            ),
            None => (Vec::new(), Vec::new()),
        }
    };
    let (tech_s, line_s) = (show(Some(&tech)), show(Some(&line)));
    unsafe {
        let d = dial::create();
        if dial::append(d, &tech, &line) != 0 {
            fail(out, method, PHONE_EVENT_APP_FAILED, "rejected destination");
            dial::destroy(d);
            dpma_log!("Failed dialing to {}/{} (append)", tech_s, line_s);
            return;
        }
        if dial::prerun(d) != 0 {
            fail(out, method, PHONE_EVENT_APP_FAILED, "channel could not run");
            dial::destroy(d);
            dpma_log!("Failed dialing to {}/{} (prerun)", tech_s, line_s);
            return;
        }
        let chan = dial::get_channel(d, 0);
        if chan.is_null() {
            fail(out, method, PHONE_EVENT_APP_FAILED, "channel missing");
            dial::destroy(d);
            dpma_log!("Failed to get channel from dial to {}/{}", tech_s, line_s);
            return;
        }
        if tech == b"SIP" {
            let header = copy_trunc(
                format!("X-Event-Name:{}", PLAYBACK_EVENT).as_bytes(),
                HEADER_BUF,
            );
            channel::setvar(chan, "__SIPADDHEADER1", &header);
        } else {
            channel::setvar(
                chan,
                "PJSIP_HEADER(add,X-Event-Name)",
                PLAYBACK_EVENT.as_bytes(),
            );
        }
        let data = Box::into_raw(Box::new(DialData {
            app_and_args: app.to_vec(),
        }));
        dial::set_user_data(d, data as *mut c_void);
        dial::option_global_enable(d, dial::OPTION_ANSWER_EXEC, app);
        let res = dial::spawn_detached(
            dial_phone_event_app_thread,
            d as *mut c_void,
            "phone_method_internal_api.c",
            "dial_phone_event_app",
            0x624,
            "dial_phone_event_app_thread",
        );
        if res != 0 {
            fail(
                out,
                method,
                PHONE_EVENT_APP_FAILED,
                "dial thread did not start",
            );
            drop(Box::from_raw(data));
            // The official DPMA reads the name after destroying the dial.
            let name = channel::name(chan);
            dial::destroy(d);
            dpma_log!("Failed to start thread for call to {}", name);
        }
    }
}

/// `dial_phone_event_app_thread` (FUN_0017b9f0): run the dial to its end
/// and destroy it.
unsafe extern "C" fn dial_phone_event_app_thread(data: *mut c_void) -> *mut c_void {
    dpma_ast::guard(std::ptr::null_mut(), || {
        let d = data as *mut AstDial;
        let ud = dial::get_user_data(d) as *mut DialData;
        let chan = dial::get_channel(d, 0);
        // Read before the run: the official DPMA reads it afterwards, when
        // an unanswered channel may already be gone.
        let name = channel::name(chan);
        if ud.is_null() {
            dpma_log!("Unable to get userdata during dial thread to {}", name);
        } else {
            let res = dial::run(d, false);
            let ud = Box::from_raw(ud);
            if res != dial::RESULT_ANSWERED {
                dpma_log!(
                    "Call to {} for {} was not answered",
                    name,
                    show(Some(&ud.app_and_args))
                );
            }
        }
        dial::destroy(d);
        std::ptr::null_mut()
    })
}

// ---------------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------------

#[cfg(feature = "devtest")]
mod devtest {
    use super::*;
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

    /// dpmadev vm trackers [<phone>]
    fn trackers(a: &CliArgs) -> CliResult {
        if !(3..=4).contains(&a.argc()) {
            return CliResult::ShowUsage;
        }
        let g = USER_TRACKERS.lock().unwrap();
        let Some(map) = g.as_ref() else {
            a.out("Tracker container does not exist\n");
            return CliResult::Success;
        };
        let mut names: Vec<&Vec<u8>> = map
            .keys()
            .filter(|n| a.argc() == 3 || **n == a.argv[3])
            .collect();
        names.sort();
        a.out(bformat!("{} user tracker(s)\n", names.len()));
        for n in names {
            let msgs = map[n].messages.lock().unwrap();
            a.out(bformat!("{}: {} message(s)\n", n, msgs.len()));
            for t in msgs.iter() {
                a.out(bformat!(
                    "  {} => {}\n",
                    show(Some(&t.id)),
                    show(Some(&t.folder))
                ));
            }
        }
        CliResult::Success
    }

    /// dpmadev vm snapshot <box@context> [<folder>|-] [combine]
    fn snapshot(a: &CliArgs) -> CliResult {
        if !(4..=6).contains(&a.argc()) {
            return CliResult::ShowUsage;
        }
        let (mbox, context) = split_mailbox(&a.argv[3]);
        let folder = a.argv.get(4).filter(|f| *f != b"-").map(Vec::as_slice);
        let combine = a.argv.get(5).is_some_and(|s| s == b"combine");
        let Some(snap) =
            vm::mailbox_snapshot_create(mbox, context, folder, false, SortBy::Time, combine)
        else {
            a.out("No snapshot\n");
            return CliResult::Success;
        };
        a.out(bformat!(
            "total {} in {} folders\n",
            snap.total_msg_num,
            snap.folders.len()
        ));
        for (i, list) in snap.folders.iter().enumerate() {
            for msg in list {
                a.out(bformat!(
                    "[{}] #{} id={} folder={} callerid={} origtime={} duration={} flag={}\n",
                    i,
                    msg.msg_number,
                    show(Some(&msg.msg_id)),
                    show(Some(&msg.folder_name)),
                    show(Some(&msg.callerid)),
                    show(Some(&msg.origtime)),
                    show(Some(&msg.duration)),
                    show(Some(&msg.flag)),
                ));
            }
        }
        CliResult::Success
    }

    /// dpmadev vm forget <phone>: `remove_user_tracker`.
    fn forget(a: &CliArgs) -> CliResult {
        if a.argc() != 4 {
            return CliResult::ShowUsage;
        }
        remove_user_tracker(&a.argv[3]);
        a.out(bformat!("Removed the user tracker of '{}'\n", a.argv[3]));
        CliResult::Success
    }

    pub fn commands() -> Vec<CliCommand> {
        vec![
            CliCommand {
                command: "dpmadev vm trackers",
                summary: "Show the voicemail message trackers",
                usage: "Usage: dpmadev vm trackers [<phone>]\n",
                exec: trackers,
                complete: None,
            },
            CliCommand {
                command: "dpmadev vm snapshot",
                summary: "Show a voicemail mailbox snapshot",
                usage: "Usage: dpmadev vm snapshot <mailbox@context> [<folder>|-] [combine]\n",
                exec: snapshot,
                complete: None,
            },
            CliCommand {
                command: "dpmadev vm forget",
                summary: "Drop a phone's voicemail message trackers",
                usage: "Usage: dpmadev vm forget <phone>\n",
                exec: forget,
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
