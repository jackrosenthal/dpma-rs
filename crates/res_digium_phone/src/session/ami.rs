//! AMI action `DPMAShowPhones` (`action_dpma_show_phones` FUN_001500d0),
//! with the phone user details of FUN_0016aa10.
//!
//! Owner: P7 "session" (wave 2).

use super::now;
use crate::ami::AmiAction;
use dpma_ast::manager::{self, Request};

fn one_zero(b: bool) -> &'static str {
    if b {
        "1"
    } else {
        "0"
    }
}

/// `phone_user_for_last_token_mac` (0x170560) plus FUN_0016aa10: the
/// "Username" and "TokenURI" lines of the first phone (in container order)
/// whose last token MAC equals `mac`, ignoring case.
fn user_details(mac: &str) -> Option<String> {
    if mac.is_empty() {
        return None;
    }
    let g = crate::users::read();
    let p = g.as_ref()?.phones.values().find(|p| p.last_mac.eq_ignore_ascii_case(mac))?;
    Some(format!("Username: {}\r\nTokenURI: {}\r\n", p.name, p.last_uri))
}

/// `action_dpma_show_phones`: one `DPMAShowPhonesList` event per session.
fn action_show_phones(r: &Request) -> i32 {
    let id = r.header("ActionID");
    // snprintf into an 80-byte buffer.
    let idtext = if id.is_empty() { String::new() } else { crate::util::truncate(&format!("ActionID: {}\r\n", id), 0x50) };
    r.send_listack("DPMA phone list will follow", "start");
    let mut count = 0;
    for s in super::store::all() {
        let (event, mac) = {
            let st = s.lock();
            let t = now();
            (
                format!(
                    "Event: DPMAShowPhonesList\r\n{}SessionID: {}\r\nSecondsAlive: {}\r\nSecondsLastActivity: {}\r\nContact: {}\r\nURI: {}\r\nAuth: {}\r\nInactive: {}\r\nConfigured: {}\r\nMAC: {}\r\nUserAgent: {}\r\n",
                    idtext,
                    s.id,
                    t - st.created,
                    t - st.last_activity,
                    st.contact,
                    st.response_uri,
                    one_zero(st.authenticated),
                    one_zero(st.inactive),
                    one_zero(st.configured),
                    st.mac,
                    st.user_agent
                ),
                st.mac.clone(),
            )
        };
        let mut text = event;
        if let Some(user) = user_details(&mac) {
            text.push_str(&user);
        }
        text.push_str("\r\n");
        r.append(&text);
        count += 1;
    }
    let mut done = String::from("Event: DPMAShowPhonesComplete\r\n");
    if !id.is_empty() {
        done.push_str(&format!("ActionID: {}\r\n", id));
    }
    done.push_str(&format!("EventList: Complete\r\nListItems: {}\r\n\r\n", count));
    r.append(&done);
    0
}

/// Actions contributed to the AMI registration (see `ami::register_actions`).
pub fn actions() -> Vec<AmiAction> {
    vec![AmiAction { name: "DPMAShowPhones", authority: manager::AUTH_CALL, handler: action_show_phones }]
}
