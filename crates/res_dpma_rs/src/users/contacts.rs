//! The default contacts document returned for `file://default`
//! (`phone_user_get_default_contacts_xml` FUN_00161cd0).

use super::*;
use crate::util::truncate;
use dpma_ast::dpma_bytes::ByteVec;
use dpma_ast::{bwrite, bwriteln};
use std::sync::Mutex;

/// The document, built on first use after each load or reload of
/// res_digium_phone.conf (the official DPMA keeps it in a global `ast_str`
/// guarded by `users_cfg_lock` and empties it in `phone_user_load_config`).
static CACHE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Forget the cached document (end of `phone_user_load_config`).
pub fn reset_cache() {
    CACHE.lock().unwrap().clear();
}

/// Build the document: one contact per phone with a primary line, in
/// container order.  Values are not XML-escaped, as in the official DPMA.
fn build(reg: Option<&Registry>, s: &mut Vec<u8>) {
    s.push_str("<contacts group_name=\"Internal Extensions\" editable=\"0\" >\n");
    let phones = reg.into_iter().flat_map(|r| r.phones.values().map(move |p| (r, p)));
    for (reg, p) in phones {
        let Some(line) = build_config::primary_line(reg, p) else { continue };
        let first_name = if line.first_name.is_empty() {
            truncate(if p.full_name.is_empty() { &p.name } else { &p.full_name }, 0x100)
        } else {
            line.first_name.clone()
        };
        bwrite!(*s, "<contact first_name=\"{}\" ", first_name);
        let last_name = if line.last_name.is_empty() { &b" "[..] } else { &line.last_name };
        bwrite!(*s, "last_name=\"{}\" ", last_name);
        s.push_str("contact_type=\"sip\" ");
        bwrite!(*s, "account_id=\"{}\" ", line.name);
        if !line.location.is_empty() {
            bwrite!(*s, "location=\"{}\" ", line.location);
        }
        bwrite!(*s, "subscribe_to=\"auto_hint_{}\"", line.name);
        s.push_str(">\n");
        s.push_str("<numbers>\n");
        bwriteln!(*s, "<number dial=\"{}\" label=\"Extension\" primary=\"1\" />", line.dialable_exten());
        s.push_str("</numbers>\n");
        s.push_str("</contact>\n");
    }
    s.push_str("</contacts>\n");
}

/// `phone_user_get_default_contacts_xml`: append the default contacts
/// document to `out`.
pub fn default_contacts_xml(out: &mut Vec<u8>) {
    let mut cache = CACHE.lock().unwrap();
    if cache.is_empty() {
        build(read().as_ref(), &mut cache);
    }
    out.extend_from_slice(&cache);
}
