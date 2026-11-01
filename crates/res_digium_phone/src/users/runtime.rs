//! Runtime state of phone users: tokens, authentication lookups, last
//! known location, AstDB `DigiumPhoneUsers` updates, reconfigure and
//! event messages (phone_users.c).
//!
//! Functions: `phone_user_token_set_last_info` (0x170630),
//! `phone_user_config_token_build` (0x170f00),
//! `standard_phone_user_find_by_token` (0x1710e0),
//! `phone_user_find_w_grouppin` (0x171720),
//! `phone_user_find_authenticated(_w_mac)` (0x170370 / 0x170250),
//! `phone_user_find_w_mac` (0x170470), `phone_user_for_last_token_mac`
//! (0x170560), `phone_username_for_token` (0x161340),
//! `phone_line_find_authenticated` (0x15b2b0), `phone_line_get_user`
//! (0x161300 with `phone_user_exten_match_cb` 0x152180),
//! `phone_mailbox_by_line` (0x161710), `phone_user_has_line` (0x16aab0),
//! `phone_application_list_get_type` (0x1612a0),
//! `phone_user_del_stale_response_uri` (0x152410), the URI comparison
//! FUN_00152570, `phone_user_update_db_info` (0x152660),
//! `phone_user_send_reconfigure` (0x151c80), `phone_user_send_event`
//! (0x159a10), and the `last_session_id` part of `phone_user_db_restore`.
//! The session side effects of `phone_user_delme_cb` (0x159720) are in
//! `load.rs`.
//!
//! Lookups return the phone's (or line's) name instead of a referenced
//! object.  Functions that change phones do so under the registry write
//! lock and then perform the side effects that leave the users layer
//! (sessions, AstDB, messages, and their log lines) in the original's
//! order, after releasing it.

use super::*;
use crate::session::{self, Outgoing};
use dpma_ast::dpma_bytes::ByteSlice;
use dpma_ast::{bformat, dpma_log};
use dpma_proto::uri::same_uri;

/// Event name of a reconfigure message.
const EVENT_CONFIG_UPDATE: &str = "digium.config.update";
/// The event that `phone_user_send_event` turns into a "boot reset".
const EVENT_ASSIGNMENT_UPDATE: &str = "digium.assignment.update";
/// Transaction id of that message (as in the original's binary).
const BOOT_RESET_ID: &str = "bootcReset";
/// Buffer size of tokens and of the AstDB value.
const BUF: usize = 0x400;

// ---------------------------------------------------------------------------
// Side effects
// ---------------------------------------------------------------------------

/// A side effect, performed in order after the registry lock is released.
enum Fx {
    /// A DPMA log line, with the original function's name.
    Log(&'static str, Vec<u8>),
    /// `phone_user_send_reconfigure(session, uri, 0)`.
    Reconfigure { session: Vec<u8>, uri: Vec<u8> },
    /// `phone_msg_session_mark_inactive(phone_msg_session_find(id))`.
    MarkInactive(Vec<u8>),
    /// `phone_msg_session_mark_authenticated(phone_msg_session_find(id), uri)`.
    MarkAuthenticated { session: Vec<u8>, uri: Vec<u8> },
    /// If the session's response URI differs from `uri`, log it and make
    /// `uri` the session's response URI.
    SessionUri { phone: Vec<u8>, session: Vec<u8>, uri: Vec<u8> },
    /// `vm_phone_user_tracker_remove(phone)`.
    VmTrackerRemove(Vec<u8>),
    DbPut(Vec<u8>, Vec<u8>),
    DbDel(Vec<u8>),
}

fn run(effects: Vec<Fx>) {
    for f in effects {
        match f {
            Fx::Log(func, msg) => {
                dpma_ast::log::log(dpma_ast::log::custom_level(), file!(), line!(), func, &bformat!("{}\n", msg))
            }
            Fx::Reconfigure { session, uri } => {
                let _ = send_reconfigure(&session, &uri, false);
            }
            Fx::MarkInactive(id) => mark_session_inactive(&id),
            Fx::MarkAuthenticated { session, uri } => {
                if let Some(s) = find_session(&session) {
                    session::mark_authenticated(&s, Some(&uri).filter(|u| !u.is_empty()).map(|u| u.as_slice()));
                }
            }
            Fx::SessionUri { phone, session, uri } => {
                let Some(s) = find_session(&session) else { continue };
                let current = s.state.lock().map(|st| st.response_uri.clone()).unwrap_or_default();
                if !current.is_empty() && !same_uri(&uri, &current) {
                    dpma_ast::log::log(
                        dpma_ast::log::custom_level(),
                        file!(),
                        line!(),
                        "phone_user_token_set_last_info",
                        &bformat!(
                            "Phone user '{}' session update due to uri change - was '{}' now '{}'\n",
                            phone, current, uri
                        ),
                    );
                    session::mark_authenticated(&s, Some(&uri).filter(|u| !u.is_empty()).map(|u| u.as_slice()));
                }
            }
            Fx::VmTrackerRemove(phone) => crate::method_api::voicemail::remove_user_tracker(&phone),
            Fx::DbPut(phone, value) => {
                dpma_ast::db::put(DB_FAMILY, &phone, &value);
            }
            Fx::DbDel(phone) => {
                dpma_ast::db::del(DB_FAMILY, &phone);
            }
        }
    }
}

/// `phone_msg_session_find`; an empty id finds nothing.
fn find_session(id: &[u8]) -> Option<std::sync::Arc<session::Session>> {
    if id.is_empty() {
        return None;
    }
    session::find(id)
}

/// Mark the session `id` inactive, if it exists (`phone_msg_session_find`
/// plus `phone_msg_session_mark_inactive`).
pub fn mark_session_inactive(id: &[u8]) {
    if let Some(s) = find_session(id) {
        session::mark_inactive(&s);
    }
}

// ---------------------------------------------------------------------------
// AstDB
// ---------------------------------------------------------------------------

/// The AstDB value of a phone (`phone_user_update_db_info` 0x152660).
fn db_value(p: &Phone) -> Vec<u8> {
    crate::util::truncate(
        &bformat!("last_mac={};last_uri={};last_session_id={}", p.last_mac, p.last_uri, p.last_session_id),
        BUF,
    )
}

/// `phone_user_update_db_info`: store the phone's last MAC, URI, and
/// session id in AstDB `DigiumPhoneUsers/<phone>`.
pub fn update_db_info(phone: &[u8]) {
    let v = {
        let g = read();
        let Some(p) = g.as_ref().and_then(|r| r.phones.get(phone)) else { return };
        (p.name.clone(), db_value(p))
    };
    dpma_ast::db::put(DB_FAMILY, &v.0, &v.1);
}

/// Split an AstDB value as `phone_user_db_restore` does: the values of
/// `last_mac=`, `last_uri=`, and `last_session_id=`, each up to the next
/// `;` that does not start a `;trans...` URI parameter.
pub fn parse_db_value(value: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let field = |tag: &str| -> Vec<u8> {
        let Some(i) = value.find(tag) else { return Vec::new() };
        let rest = &value[i + tag.len()..];
        let b = rest;
        let mut end = 0;
        while end < b.len() {
            if b[end] == b';' && !rest[end + 1..].starts_with(b"trans") {
                break;
            }
            end += 1;
        }
        rest[..end].to_vec()
    };
    (field("last_mac="), field("last_uri="), field("last_session_id="))
}

/// Restore `last_session_id`s from AstDB once sessions are loaded
/// (`phone_user_db_restore`, second half): each phone with a stored
/// session id that still exists gets it back and the session is marked
/// authenticated.
pub fn restore_sessions() {
    for (key, value) in dpma_ast::db::tree(DB_FAMILY) {
        let Some((_, name)) = key.rsplit_once_str("/") else { continue };
        if value.is_empty() || name.is_empty() {
            continue;
        }
        let (_, _, sid) = parse_db_value(&value);
        if sid.is_empty() {
            continue;
        }
        let Some(s) = session::find(&sid) else {
            dpma_log!("Unable to locate session '{}' while restoring user '{}'", sid, name);
            continue;
        };
        session::mark_authenticated(&s, None);
        if let Some(p) = write().as_mut().and_then(|r| r.phones.get_mut(name)) {
            p.last_session_id = sid;
        }
    }
}

// ---------------------------------------------------------------------------
// Last known location
// ---------------------------------------------------------------------------

/// `phone_user_token_set_last_info`: record that phone `phone` was seen
/// at `uri` with `session_id` and `mac` (None for either: not supplied,
/// as the PJSIP helper calls it on REGISTER).
///
/// - A MAC that another phone was last seen with orphans that phone (its
///   last MAC, URI, and session are dropped).
/// - A MAC different from the phone's last MAC sends a reconfigure to the
///   old location.
/// - A new location (URI by address and transport, or MAC) is logged and
///   stored, and the phone's session follows a changed URI.
/// - A new session id replaces the old session (marked inactive), and the
///   session is marked authenticated with `uri`.
/// - AstDB is updated unless nothing changed.
pub fn set_last_info(phone: &[u8], uri: &[u8], session_id: Option<&[u8]>, mac: Option<&[u8]>) {
    let mut fx = Vec::new();
    {
        let mut g = write();
        let Some(reg) = g.as_mut() else { return };
        set_last_info_locked(reg, phone, uri, session_id, mac, &mut fx);
    }
    run(fx);
}

fn set_last_info_locked(
    reg: &mut Registry,
    phone: &[u8],
    uri: &[u8],
    session_id: Option<&[u8]>,
    mac: Option<&[u8]>,
    fx: &mut Vec<Fx>,
) {
    const FUNC: &str = "phone_user_token_set_last_info";
    if !reg.phones.contains(phone) {
        return;
    }
    // The phone last seen with this MAC loses it.
    if let Some(m) = mac.filter(|m| !m.is_empty()) {
        if let Some(other) = for_last_token_mac_in(reg, m).filter(|o| !o.eq_ignore_ascii_case(phone)) {
            let o = reg.phones.get_mut(&other).unwrap();
            fx.push(Fx::Log(FUNC, bformat!("Phone user '{}' configuration orphaned by mac '{}'", o.name, m)));
            o.last_mac.clear();
            o.last_uri.clear();
            fx.push(Fx::MarkInactive(std::mem::take(&mut o.last_session_id)));
            fx.push(Fx::DbDel(o.name.clone()));
        }
    }

    let p = reg.phones.get_mut(phone).unwrap();
    let mut changed = false;
    if let Some(m) = mac {
        if !p.last_uri.is_empty() && !m.is_empty() && !p.last_mac.is_empty() && m != p.last_mac {
            fx.push(Fx::Log(
                FUNC,
                bformat!("Phone user '{}' reconfigure due to mac mismatch - was '{}' now '{}'", p.name, p.last_mac, m),
            ));
            fx.push(Fx::Reconfigure { session: p.last_session_id.clone(), uri: p.last_uri.clone() });
            p.last_uri.clear();
            changed = true;
        }
    }
    if !p.last_uri.is_empty() && !same_uri(&p.last_uri, uri) {
        p.last_uri.clear();
        changed = true;
    }
    let mac = match mac {
        Some(m) if !m.is_empty() => m.to_vec(),
        _ => p.last_mac.clone(),
    };
    let session_id = session_id.filter(|s| !s.is_empty());

    if !p.last_uri.is_empty() && mac == p.last_mac {
        // Same place: only a new session id is news.
        if session_id.is_none() && !changed {
            return;
        }
    } else {
        fx.push(Fx::Log(FUNC, bformat!("Phone user '{}' now connected from '{}' mac '{}'", p.name, uri, mac)));
        p.last_uri = uri.to_vec();
        p.last_mac = mac;
        fx.push(Fx::SessionUri { phone: p.name.clone(), session: p.last_session_id.clone(), uri: uri.to_vec() });
    }
    if let Some(sid) = session_id {
        if p.last_session_id != sid {
            fx.push(Fx::VmTrackerRemove(p.name.clone()));
            fx.push(Fx::MarkInactive(p.last_session_id.clone()));
            p.last_session_id = sid.to_vec();
        }
        fx.push(Fx::MarkAuthenticated { session: sid.to_vec(), uri: uri.to_vec() });
    }
    fx.push(Fx::DbPut(p.name.clone(), db_value(p)));
}

/// `phone_user_del_stale_response_uri` (0x152410) over every phone: a
/// phone last seen at `uri` with another session than `session_id` is
/// no longer there.
fn del_stale_response_uri_locked(reg: &mut Registry, uri: &[u8], session_id: &[u8], fx: &mut Vec<Fx>) {
    for p in reg.phones.values_mut() {
        if p.last_uri == uri && p.last_session_id != session_id {
            fx.push(Fx::Log(
                "phone_user_del_stale_response_uri",
                bformat!("Removing stale user '{}' from '{}'", p.name, p.last_uri),
            ));
            p.last_mac.clear();
            p.last_uri.clear();
            fx.push(Fx::MarkInactive(std::mem::take(&mut p.last_session_id)));
            fx.push(Fx::DbDel(p.name.clone()));
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration tokens
// ---------------------------------------------------------------------------

/// The hash in tokens: djb2 (`h * 33 ^ c`, seed 5381) of `s`, or of
/// "blah" when `s` is empty, masked to 31 bits.
fn token_hash(s: &[u8]) -> i32 {
    let s: &[u8] = if s.is_empty() { b"blah" } else { s };
    let mut h: u32 = 5381;
    for &b in s {
        h = h.wrapping_mul(33) ^ u32::from(b);
    }
    (h & 0x7fff_ffff) as i32
}

/// The sum of a token's characters as signed chars.
fn token_sum(token: &[u8]) -> i32 {
    token.iter().fold(0i32, |a, &b| a.wrapping_add(i32::from(b as i8)))
}

/// `phone_user_config_token_build`: issue a configuration token for
/// phone `phone` requested from `mac`, `session_id`, and `uri` (the
/// TokenRequest's), with `secret` the global pin.  The token is
/// `<phone>/<mac>/<hash("blah")>/<hash(secret)>` (at most 1023
/// characters).  Records the phone's location (`set_last_info`), then
/// drops any other phone last seen at `uri` with another session.  None
/// when the phone does not exist.
pub fn config_token_build(phone: &[u8], mac: &[u8], session_id: &[u8], uri: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    let mut fx = Vec::new();
    let token = {
        let mut g = write();
        let reg = g.as_mut()?;
        let p = reg.phones.get_mut(phone)?;
        let token = crate::util::truncate(
            &bformat!("{}/{}/{}/{}", p.name, mac, token_hash(b""), token_hash(secret)),
            BUF,
        );
        if p.token_state == 0 {
            p.token_state = 1;
        }
        p.prev_token_sum = p.token_sum;
        p.token_sum = token_sum(&token);
        let name = p.name.clone();
        set_last_info_locked(reg, &name, uri, Some(session_id), Some(mac), &mut fx);
        del_stale_response_uri_locked(reg, uri, session_id, &mut fx);
        token
    };
    run(fx);
    Some(token)
}

/// The result of `find_by_token`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenLookup {
    /// The phone the token belongs to.
    pub phone: Option<Vec<u8>>,
    /// No match, but the token's character sum equals the one of the
    /// token issued before the phone's latest (the original's sixth
    /// parameter, cleared in that case; every 3.6.13 caller passes NULL).
    pub previous_token: bool,
}

/// `standard_phone_user_find_by_token`: the phone a configuration token
/// (`<phone>/<mac>/...`, or with `-` separators) belongs to, presented
/// from `mac`, `session_id`, and `uri`; `secret` is the global pin.  On a
/// match the phone's location is recorded (`set_last_info`).
///
/// Only `<phone><sep><last MAC>` is compared: the original builds four
/// candidate tokens (with hashes of "blah", the phone's pin, "none", the
/// global pin, and the group pin) but compares each only up to its second
/// separator, which is the same for all four.  So a token matches when it
/// starts with the phone's name (case sensitive), the separator, and the
/// MAC the phone was last seen with.
pub fn find_by_token(token: &[u8], mac: &[u8], session_id: &[u8], uri: &[u8], secret: &[u8]) -> TokenLookup {
    let mut res = TokenLookup::default();
    let (name, sep) = match token.find_byte(b'/') {
        Some(0) => return res,
        Some(i) => (&token[..i], '/'),
        None => match token.find_byte(b'-') {
            Some(i) if i > 0 => (&token[..i], '-'),
            _ => return res,
        },
    };
    let found = {
        let g = read();
        let Some(p) = g.as_ref().and_then(|r| r.phones.get(name)) else { return res };
        // The first candidate; the hashes (and so `secret`) are never
        // compared.
        let _ = secret;
        let h = token_hash(b"");
        let candidate = crate::util::truncate(&bformat!("{}{sep}{}{sep}{h}{sep}{h}", p.name, p.last_mac), BUF);
        if prefix_matches(&candidate, sep, token) {
            Some(p.name.clone())
        } else {
            if p.prev_token_sum == token_sum(token) {
                res.previous_token = true;
            }
            None
        }
    };
    if let Some(name) = &found {
        set_last_info(name, uri, Some(session_id), Some(mac));
    }
    res.phone = found;
    res
}

/// `strncmp(candidate, token, <offset of candidate's second separator>)`.
fn prefix_matches(candidate: &[u8], sep: char, token: &[u8]) -> bool {
    let Some(first) = candidate.find_char(sep) else { return false };
    let Some(second) = candidate[first + 1..].find_char(sep).map(|i| first + 1 + i) else { return false };
    token.get(..second) == Some(&candidate[..second])
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// `phone_user_find_authenticated`: phone `name` if its pin equals
/// `password` (both empty also matches).
pub fn find_authenticated(name: &[u8], password: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() {
        return None;
    }
    let g = read();
    let p = g.as_ref()?.phones.get(name)?;
    (p.pin == password).then(|| p.name.clone())
}

/// `phone_user_find_authenticated_w_mac`: phone `name` if its pin equals
/// `password` and its MAC equals `mac` (case insensitive); every argument
/// must be non-empty.
pub fn find_authenticated_w_mac(name: &[u8], password: &[u8], mac: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || password.is_empty() || mac.is_empty() {
        return None;
    }
    let g = read();
    let p = g.as_ref()?.phones.get(name)?;
    (p.pin == password && p.mac.eq_ignore_ascii_case(mac)).then(|| p.name.clone())
}

/// `phone_user_find_w_mac`: phone `name` if its MAC equals `mac` (case
/// insensitive); both must be non-empty.
pub fn find_w_mac(name: &[u8], mac: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || mac.is_empty() {
        return None;
    }
    let g = read();
    let p = g.as_ref()?.phones.get(name)?;
    p.mac.eq_ignore_ascii_case(mac).then(|| p.name.clone())
}

/// `phone_user_find_w_grouppin`: phone `name` if its group pin equals
/// `group_pin` (case insensitive); both must be non-empty.
pub fn find_w_grouppin(name: &[u8], group_pin: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || group_pin.is_empty() {
        return None;
    }
    let g = read();
    let p = g.as_ref()?.phones.get(name)?;
    p.group_pin.eq_ignore_ascii_case(group_pin).then(|| p.name.clone())
}

fn for_last_token_mac_in(reg: &Registry, mac: &[u8]) -> Option<Vec<u8>> {
    if mac.is_empty() {
        return None;
    }
    reg.phones.values().find(|p| p.last_mac.eq_ignore_ascii_case(mac)).map(|p| p.name.clone())
}

/// `phone_user_for_last_token_mac`: the first phone (container order)
/// last seen with `mac` (case insensitive).
pub fn for_last_token_mac(mac: &[u8]) -> Option<Vec<u8>> {
    for_last_token_mac_in(read().as_ref()?, mac)
}

/// `phone_username_for_token`: the phone a TokenRequest is for.  With a
/// `username`, the first phone (container order) whose primary line has
/// that name or extension (case insensitive); otherwise, with a `mac`,
/// the first phone with that MAC.  Failing that, the phone named
/// `username`.
pub fn username_for_token(username: &[u8], mac: &[u8]) -> Option<Vec<u8>> {
    // The original locks each primary line while comparing it; take those
    // line locks first, before the registry lock (see "Line locks" in
    // exports::objects).
    let primaries: Vec<Vec<u8>> = if username.is_empty() {
        Vec::new()
    } else {
        read()
            .as_ref()
            .map(|reg| reg.phones.values().filter_map(|p| p.lines.first().map(|l| l.name.clone())).collect())
            .unwrap_or_default()
    };
    let _lines = crate::exports::objects::lock_lines(primaries.iter().map(Vec::as_slice));
    let g = read();
    let reg = g.as_ref()?;
    for p in reg.phones.values() {
        if !username.is_empty() {
            if let Some(line) = build_config::primary_line(reg, p) {
                if line.name.eq_ignore_ascii_case(username) || line.exten.eq_ignore_ascii_case(username) {
                    return Some(p.name.clone());
                }
            }
        } else if !mac.is_empty() && p.mac.eq_ignore_ascii_case(mac) {
            return Some(p.name.clone());
        }
    }
    if username.is_empty() {
        return None;
    }
    reg.phones.get(username).map(|p| p.name.clone())
}

/// `phone_line_find_authenticated`: line `name` if its secret equals
/// `secret` (both empty also matches).
pub fn line_find_authenticated(name: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() {
        return None;
    }
    // The original compares under the line's lock (see "Line locks").
    let _line = crate::exports::objects::lock_lines([name]);
    let g = read();
    let l = g.as_ref()?.lines.get(name)?;
    (l.secret == secret).then(|| l.name.clone())
}

/// `phone_line_get_user`: the first phone (container order) with `line`
/// in any of its line slots (case insensitive).
pub fn phone_for_line(line: &[u8]) -> Option<Vec<u8>> {
    let g = read();
    let found = g
        .as_ref()?
        .phones
        .values()
        .find(|p| p.lines.iter().any(|l| l.name.eq_ignore_ascii_case(line)))
        .map(|p| p.name.clone());
    found
}

/// `phone_user_has_line`: does phone `phone` have `line` in one of its
/// line slots (case insensitive)?
pub fn has_line(phone: &[u8], line: &[u8]) -> bool {
    read()
        .as_ref()
        .and_then(|r| r.phones.get(phone))
        .is_some_and(|p| p.lines.iter().any(|l| line.eq_ignore_ascii_case(&l.name)))
}

/// `phone_mailbox_by_line`: the mailbox of line `line`, if it has one.
/// The line's lock is held for the read, as in the original.
pub fn mailbox_by_line(line: &[u8]) -> Option<Vec<u8>> {
    let _line = crate::exports::objects::lock_lines([line]);
    let g = read();
    let l = g.as_ref()?.lines.get(line)?;
    (!l.mailbox.is_empty()).then(|| l.mailbox.clone())
}

/// `phone_application_list_get_type`: the names of the applications of
/// type `type_name` (`AppKind::type_name`) in phone `phone`'s list, in
/// the applications' container order.
pub fn applications_of_type(phone: &[u8], type_name: &str) -> Vec<Vec<u8>> {
    let g = read();
    let Some(reg) = g.as_ref() else { return Vec::new() };
    let Some(p) = reg.phones.get(phone) else { return Vec::new() };
    reg.applications
        .values()
        .filter(|a| {
            a.kind.as_ref().is_some_and(|k| k.type_name() == type_name) && p.applications.contains(&a.name)
        })
        .map(|a| a.name.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Messages to phones
// ---------------------------------------------------------------------------

/// `phone_user_send_reconfigure`: send `digium.config.update` to the
/// session `session_id` (body `<config></config>`, or with
/// `delete_token` the form that also drops the phone's token), addressed
/// to `uri`.  Err only when the session does not exist.
pub fn send_reconfigure(session_id: &[u8], uri: &[u8], delete_token: bool) -> Result<(), ()> {
    let body = if delete_token {
        "<config>\t<section id=\"all\"/>\t<option id=\"delete_token\" value=\"true\"/></config>"
    } else {
        "<config></config>"
    };
    let Some(s) = find_session(session_id) else {
        dpma_log!("Unable to find session '{}'", session_id);
        return Err(());
    };
    let mut out = Outgoing::new();
    out.response_uri = uri.to_vec();
    out.event_name = EVENT_CONFIG_UPDATE.into();
    out.append_str(body);
    let _ = session::send(&out, &s);
    Ok(())
}

/// `phone_user_send_event` (used by AMI `DPMAMessageSend`): send event
/// `event` with `body` to the phone's last known location and session.
/// `digium.assignment.update` goes out instead as id `bootcReset` with
/// message error -398 (Session Timeout) and no event name.  The error is
/// the text the original writes to its caller's buffer.
pub fn send_event(phone: &[u8], event: &[u8], body: &[u8]) -> Result<(), Vec<u8>> {
    let (name, uri, sid) = {
        let g = read();
        match g.as_ref().and_then(|r| r.phones.get(phone)) {
            Some(p) => (p.name.clone(), p.last_uri.clone(), p.last_session_id.clone()),
            None => {
                dpma_log!("Unable to send without user");
                return Err("Memory allocation error".into());
            }
        }
    };
    if uri.is_empty() {
        dpma_log!("Unable to send event to '{}' with no uri", name);
        return Err("Phone has not contacted server".into());
    }
    if sid.is_empty() {
        dpma_log!("Unable to send event to '{}' with no session id", name);
        return Err("Phone has no active session id".into());
    }
    let mut out = Outgoing::new();
    out.response_uri = uri;
    if event == EVENT_ASSIGNMENT_UPDATE.as_bytes() {
        out.id = BOOT_RESET_ID.into();
        out.error = dpma_proto::errors::msg::SESSION_TIMEOUT;
    } else {
        out.event_name = event.to_vec();
    }
    out.append(body);
    let Some(s) = session::find(&sid) else {
        dpma_log!("Unable to send event to '{}' without session", name);
        return Err("Phone session no longer exists".into());
    };
    let _ = session::send(&out, &s);
    Ok(())
}

// ---------------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------------

#[cfg(feature = "devtest")]
mod devtest {
    use super::*;
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

    /// "-" stands for NULL, "." for an empty string.
    fn opt(s: &[u8]) -> Option<&[u8]> {
        match s {
            b"-" => None,
            b"." => Some(b""),
            s => Some(s),
        }
    }

    fn arg(s: &[u8]) -> &[u8] {
        opt(s).unwrap_or(b"")
    }

    fn show(r: Option<Vec<u8>>) -> Vec<u8> {
        r.unwrap_or_else(|| "(none)".into())
    }

    /// dpmadev token build <phone> <mac> <session> <uri> [secret]
    fn build_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 7 && a.argc() != 8 {
            return CliResult::ShowUsage;
        }
        let secret = a.argv.get(7).map_or_else(|| crate::config::get().globalpin.clone(), |s| arg(s).to_vec());
        let r = config_token_build(&a.argv[3], arg(&a.argv[4]), arg(&a.argv[5]), arg(&a.argv[6]), &secret);
        a.out(bformat!("token: {}\n", show(r)));
        CliResult::Success
    }

    /// dpmadev token find <token> <mac> <session> <uri> [secret]
    fn find_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 7 && a.argc() != 8 {
            return CliResult::ShowUsage;
        }
        let secret = a.argv.get(7).map_or_else(|| crate::config::get().globalpin.clone(), |s| arg(s).to_vec());
        let r = find_by_token(&a.argv[3], arg(&a.argv[4]), arg(&a.argv[5]), arg(&a.argv[6]), &secret);
        a.out(bformat!("phone: {}  previous_token: {}\n", show(r.phone), r.previous_token));
        CliResult::Success
    }

    /// dpmadev token lastinfo <phone> <uri> <session|-|.> <mac|-|.>
    fn lastinfo_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 7 {
            return CliResult::ShowUsage;
        }
        set_last_info(&a.argv[3], arg(&a.argv[4]), opt(&a.argv[5]), opt(&a.argv[6]));
        info(a, &a.argv[3]);
        CliResult::Success
    }

    fn info(a: &CliArgs, phone: &[u8]) {
        let line = {
            let g = read();
            match g.as_ref().and_then(|r| r.phones.get(phone)) {
                Some(p) => bformat!(
                    "{}: last_mac='{}' last_uri='{}' last_session_id='{}' token_state={} token_sum={} prev_token_sum={}\n",
                    p.name, p.last_mac, p.last_uri, p.last_session_id, p.token_state, p.token_sum, p.prev_token_sum
                ),
                None => bformat!("{}: no such phone\n", phone),
            }
        };
        a.out(&line);
        a.out(bformat!("AstDB: {}\n", show(dpma_ast::db::get(DB_FAMILY, phone))));
    }

    /// dpmadev token info <phone>
    fn info_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 4 {
            return CliResult::ShowUsage;
        }
        info(a, &a.argv[3]);
        CliResult::Success
    }

    /// dpmadev token lookup <kind> <args...>
    fn lookup_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 5 {
            return CliResult::ShowUsage;
        }
        let v: Vec<&[u8]> = a.argv[4..].iter().map(|s| arg(s)).collect();
        let r = match (a.argv[3].as_slice(), v.as_slice()) {
            (b"auth", [n, p]) => show(find_authenticated(n, p)),
            (b"authmac", [n, p, m]) => show(find_authenticated_w_mac(n, p, m)),
            (b"mac", [n, m]) => show(find_w_mac(n, m)),
            (b"grouppin", [n, g]) => show(find_w_grouppin(n, g)),
            (b"lastmac", [m]) => show(for_last_token_mac(m)),
            (b"username", [u, m]) => show(username_for_token(u, m)),
            (b"line", [l, s]) => show(line_find_authenticated(l, s)),
            (b"lineuser", [l]) => show(phone_for_line(l)),
            (b"mailbox", [l]) => show(mailbox_by_line(l)),
            (b"hasline", [p, l]) => bformat!("{}", has_line(p, l)),
            (b"apps", [p, t]) => {
                // As `{:?}` of a list of strings: ["a", "b"].
                let names = applications_of_type(p, &String::from_utf8_lossy(t));
                let quoted: Vec<Vec<u8>> = names.iter().map(|n| bformat!("\"{}\"", n)).collect();
                bformat!("[{}]", quoted.join(&b", "[..]))
            }
            _ => return CliResult::ShowUsage,
        };
        a.out(bformat!("{}\n", r));
        CliResult::Success
    }

    /// dpmadev token event <phone> <event> <body...>
    fn event_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 6 {
            return CliResult::ShowUsage;
        }
        let r = send_event(&a.argv[3], &a.argv[4], &a.argv[5..].join(&b" "[..]));
        a.out(bformat!("send_event: {:?}\n", r));
        CliResult::Success
    }

    /// dpmadev token reconfigure <session> <uri> [delete]
    fn reconfigure_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 5 && a.argc() != 6 {
            return CliResult::ShowUsage;
        }
        let r = send_reconfigure(arg(&a.argv[3]), arg(&a.argv[4]), a.argc() == 6);
        a.out(bformat!("send_reconfigure: {:?}\n", r));
        CliResult::Success
    }

    /// dpmadev token restore
    fn restore_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        restore_sessions();
        a.out("restore_sessions done\n");
        CliResult::Success
    }

    pub fn commands() -> Vec<CliCommand> {
        vec![
            CliCommand {
                command: "dpmadev token build",
                summary: "Issue a configuration token (phone_user_config_token_build)",
                usage: "Usage: dpmadev token build <phone> <mac> <session> <uri> [secret]\n       \".\" is an empty argument; the secret defaults to the global pin.\n",
                exec: build_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev token find",
                summary: "Look a configuration token up (standard_phone_user_find_by_token)",
                usage: "Usage: dpmadev token find <token> <mac> <session> <uri> [secret]\n       \".\" is an empty argument; the secret defaults to the global pin.\n",
                exec: find_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev token lastinfo",
                summary: "Record a phone's location (phone_user_token_set_last_info)",
                usage: "Usage: dpmadev token lastinfo <phone> <uri> <session> <mac>\n       \"-\" passes NULL, \".\" an empty string.\n",
                exec: lastinfo_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev token info",
                summary: "Show a phone's runtime state and AstDB entry",
                usage: "Usage: dpmadev token info <phone>\n",
                exec: info_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev token lookup",
                summary: "Run a phone or line lookup",
                usage: "Usage: dpmadev token lookup auth <phone> <pin>\n       dpmadev token lookup authmac <phone> <pin> <mac>\n       dpmadev token lookup mac <phone> <mac>\n       dpmadev token lookup grouppin <phone> <group pin>\n       dpmadev token lookup lastmac <mac>\n       dpmadev token lookup username <username> <mac>\n       dpmadev token lookup line <line> <secret>\n       dpmadev token lookup lineuser <line>\n       dpmadev token lookup mailbox <line>\n       dpmadev token lookup hasline <phone> <line>\n       dpmadev token lookup apps <phone> <Queue|Status|Parking|Voicemail|Custom>\n       \".\" is an empty argument.\n",
                exec: lookup_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev token event",
                summary: "Send an event to a phone (phone_user_send_event)",
                usage: "Usage: dpmadev token event <phone> <event> <body...>\n",
                exec: event_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev token reconfigure",
                summary: "Send a reconfigure to a session (phone_user_send_reconfigure)",
                usage: "Usage: dpmadev token reconfigure <session> <uri> [delete]\n",
                exec: reconfigure_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev token restore",
                summary: "Restore last_session_id from AstDB",
                usage: "Usage: dpmadev token restore\n",
                exec: restore_cmd,
                complete: None,
            },
        ]
    }
}

/// Test hooks (feature "devtest"): `dpmadev token ...`.
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    devtest::commands()
}
