//! The default contacts document returned for `file://default`
//! (`phone_user_get_default_contacts_xml` FUN_00161cd0).
//!
//! Owner: P4 "config-xml" (wave 1).

use super::*;
use crate::util::truncate;
use std::fmt::Write;
use std::sync::Mutex;

/// The document, built on first use after each load or reload of
/// res_digium_phone.conf (the original keeps it in a global `ast_str`
/// guarded by `users_cfg_lock` and empties it in `phone_user_load_config`).
static CACHE: Mutex<String> = Mutex::new(String::new());

/// Forget the cached document (end of `phone_user_load_config`).
pub fn reset_cache() {
    CACHE.lock().unwrap().clear();
}

/// Build the document: one contact per phone with a primary line, in
/// container order.  Values are not XML-escaped, as in the original.
fn build(reg: Option<&Registry>, s: &mut String) {
    s.push_str("<contacts group_name=\"Internal Extensions\" editable=\"0\" >\n");
    let phones = reg.into_iter().flat_map(|r| r.phones.values().map(move |p| (r, p)));
    for (reg, p) in phones {
        let Some(line) = build_config::primary_line(reg, p) else { continue };
        let first_name = if line.first_name.is_empty() {
            truncate(if p.full_name.is_empty() { &p.name } else { &p.full_name }, 0x100)
        } else {
            line.first_name.clone()
        };
        let _ = write!(s, "<contact first_name=\"{}\" ", first_name);
        let last_name = if line.last_name.is_empty() { " " } else { &line.last_name };
        let _ = write!(s, "last_name=\"{}\" ", last_name);
        s.push_str("contact_type=\"sip\" ");
        let _ = write!(s, "account_id=\"{}\" ", line.name);
        if !line.location.is_empty() {
            let _ = write!(s, "location=\"{}\" ", line.location);
        }
        let _ = write!(s, "subscribe_to=\"auto_hint_{}\"", line.name);
        s.push_str(">\n");
        s.push_str("<numbers>\n");
        let _ = writeln!(s, "<number dial=\"{}\" label=\"Extension\" primary=\"1\" />", line.dialable_exten());
        s.push_str("</numbers>\n");
        s.push_str("</contact>\n");
    }
    s.push_str("</contacts>\n");
}

/// `phone_user_get_default_contacts_xml`: append the default contacts
/// document to `out`.
pub fn default_contacts_xml(out: &mut String) {
    let mut cache = CACHE.lock().unwrap();
    if cache.is_empty() {
        build(read().as_ref(), &mut cache);
    }
    out.push_str(&cache);
}
