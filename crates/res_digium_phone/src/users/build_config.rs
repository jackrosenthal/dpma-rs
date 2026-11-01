//! The phone configuration document (`phone_user_build_config`
//! FUN_0016ae70 with `add_firmware_settings`, `add_internal_line_account`,
//! `add_external_line_account`, `add_option_firmware_settings`, and
//! `phone_user_has_queue`; `phone_user_get_config` FUN_00170070;
//! `phone_user_read_config` FUN_00156d10; `phone_user_get_primary_line`
//! FUN_0015abe0; `phone_user_set_primary_line_name` FUN_0016ac20;
//! `phone_user_get_primary_line_name` FUN_0016acf0;
//! `phone_user_get_primary_line_tech` FUN_00170190;
//! `phone_user_get_show_call_parking` FUN_0016ab70;
//! `phone_user_get_application_settings` FUN_0016add0;
//! `insert_display_rules` FUN_001558e0).
//!
//! The document is built as text with the original's format strings, one
//! append per `ast_str_append` of the original, in the same order and
//! under the same conditions.  The only libxml2 round trip is the one the
//! original makes to merge a `contacts_display_rules` file.
//!
//! Owner: P4 "config-xml" (wave 1).

use super::*;
use crate::xmlutil;
use dpma_ast::dpma_log;
use dpma_ast::xml::Doc;

/// Size of the original's escape buffers.
const ESC_BUF: usize = 0x100;

/// Allocated size of the `ast_str` the original's ConfigRequest handler
/// builds the document in (`ast_str_create(0x400)`).
pub const INITIAL_BUF: usize = 0x400;

fn esc(s: &str) -> String {
    xmlutil::escape(s, ESC_BUF)
}

/// The output buffer.  Besides the text it tracks the allocation size the
/// original's `ast_str` would have, because `insert_display_rules` stores
/// the merged document with `ast_str_set(buf, len, ...)`, which drops the
/// last character when the buffer has to grow (see `insert_display_rules`).
struct Out<'a> {
    s: &'a mut String,
    cap: usize,
}

impl Out<'_> {
    /// `ast_str_append(&buf, 0, "%s", text)` as `__ast_str_helper` sizes it.
    fn ap(&mut self, text: &str) {
        let need = self.s.len() + text.len() + 1;
        if need > self.cap {
            self.cap = need + 16 + need / 4;
        }
        self.s.push_str(text);
    }
}

macro_rules! ap {
    ($o:expr, $($arg:tt)*) => {
        $o.ap(&format!($($arg)*))
    };
}

/// The URL prefix to put in front of `path`: none when the path is
/// absolute or already a URL (contains "//").
fn url_prefix<'a>(path: &str, prefix: &'a str) -> &'a str {
    if path.starts_with('/') || path.contains("//") {
        ""
    } else {
        prefix
    }
}

/// The value of a certificate or file setting: `value`, or else the file
/// name part of `url` (empty when the URL has no '/').
fn file_value<'a>(url: &'a str, value: &'a str) -> &'a str {
    if !value.is_empty() {
        return value;
    }
    match url.rfind('/') {
        Some(i) => &url[i + 1..],
        None => "",
    }
}

fn or<'a>(s: &'a str, default: &'a str) -> &'a str {
    if s.is_empty() {
        default
    } else {
        s
    }
}

/// `phone_user_get_primary_line`: the line object named by the phone's
/// first line slot.
pub fn primary_line<'a>(reg: &'a Registry, phone: &Phone) -> Option<&'a Line> {
    let name = phone.lines.first().map_or("", |l| l.name.as_str());
    if name.is_empty() {
        return None;
    }
    reg.lines.get(name)
}

/// `phone_user_has_queue`.
fn has_queue(reg: &Registry, phone: &Phone) -> bool {
    phone.applications.iter().any(|a| {
        matches!(reg.applications.get(a).and_then(|a| a.kind.as_ref()), Some(AppKind::Queue(_)))
    })
}

/// `phone_user_get_application_settings`: the first of the phone's
/// applications of the given type (`AppKind::type_name`), logging every
/// application name that does not exist on the way.
pub fn application_settings<'a>(reg: &'a Registry, phone: &Phone, type_name: &str) -> Option<&'a Application> {
    for name in &phone.applications {
        match reg.applications.get(name) {
            None => dpma_log!("Failed to find application '{}'", name),
            Some(app) => {
                if app.kind.as_ref().is_some_and(|k| k.type_name() == type_name) {
                    return Some(app);
                }
            }
        }
    }
    None
}

/// The `<account .../>` element of the phone's applications.
fn app_account(o: &mut Out, server_uuid: &str, account_id: &str, phone: &Phone, net: &Network) {
    ap!(o, "<account ");
    if !server_uuid.is_empty() {
        ap!(o, "server_uuid=\"{}\" ", server_uuid);
    }
    ap!(o, "account_id=\"{}\" ", esc(account_id));
    ap!(o, "username=\"{}\" ", esc(&phone.name));
    ap!(o, "password=\"{}\" ", esc(&phone.pin));
    ap!(o, "appserver=\"dasp://{}/json\" apiformat=\"json\" />\n", net.registration_address);
}

/// The phone's networks that exist, in the phone's order.
fn networks<'a>(reg: &'a Registry, phone: &'a Phone) -> impl Iterator<Item = &'a Network> + 'a {
    phone.networks.iter().filter_map(|n| reg.networks.get(n))
}

/// `parking_lot_extension` and the parking transfer type.
fn parking_settings(o: &mut Out, phone: &Phone) {
    if phone.parking_exten.is_empty() {
        return;
    }
    ap!(o, "<setting id=\"parking_lot_extension\" value=\"{}\" />\n", phone.parking_exten);
    match phone.parking_transfer_type {
        ParkingTransfer::Blind => ap!(o, "<setting id=\"parking_lot_enable_blind_transfer\" value=\"1\" />\n"),
        ParkingTransfer::Attended => ap!(o, "<setting id=\"parking_lot_enable_blind_transfer\" value=\"0\" />\n"),
        ParkingTransfer::Default => {}
    }
}

/// The registration timer attributes of `<host_primary>` and
/// `<host_alternate>`.
fn registration_timers(o: &mut Out, line: &Line) {
    if line.reregistration_timeout != 0 {
        ap!(o, "reregister=\"{}\" ", line.reregistration_timeout as u32);
    }
    if line.registration_retry_interval != 0 {
        ap!(o, "retry=\"{}\" ", line.registration_retry_interval as u32);
    }
    if line.registration_max_retries != 0 {
        ap!(o, "num_retries=\"{}\" ", line.registration_max_retries as u32);
    }
}

/// The outbound proxy attributes of a line account.
fn outbound_proxy(o: &mut Out, line: &Line) {
    if line.outboundproxy_address.is_empty() {
        return;
    }
    ap!(o, "outbound_proxy=\"{}\"\n", esc(&line.outboundproxy_address));
    let port = if line.outboundproxy_port.is_empty() { "5060".to_string() } else { esc(&line.outboundproxy_port) };
    ap!(o, "outbound_port=\"{}\"\n", port);
}

/// `add_internal_line_account`.  Returns the line, whose CustomPresence
/// state the caller initializes (the original does it here).
fn add_internal_line_account(o: &mut Out, phone: &Phone, line: &Line, net: &Network, index: i32, server_uuid: &str) {
    ap!(o, "<account \n");
    if !server_uuid.is_empty() {
        ap!(o, "server_uuid=\"{}\" ", server_uuid);
    }
    ap!(o, "network_id=\"{}\"\n", net.name);
    ap!(o, "index=\"{}\"\n", index);
    if index == 0 {
        if line.voicemail_uri.is_empty() {
            if !line.mailbox.is_empty() {
                ap!(o, "visual_voicemail=\"1\"\n");
            }
        } else {
            ap!(o, "visual_voicemail=\"0\"\n");
            ap!(o, "voicemail=\"{}\"\n", line.voicemail_uri);
        }
    }
    ap!(o, "account_id=\"{}\"\n", esc(&line.name));
    ap!(o, "username=\"{}\"\n", esc(&line.name));
    ap!(o, "password=\"{}\"\n", esc(&line.secret));
    ap!(o, "passcode=\"{}\"\n", esc(&line.secret));
    ap!(o, "caller_id=\"{}\"\n", esc(&line.callerid));
    ap!(o, "number=\"{}\"\n", esc(&line.name));
    ap!(o, "server=\"{}\"\n", esc(&net.registration_address));
    ap!(o, "dial_plan=\"{}\"\n", esc(&line.digit_map));
    ap!(o, "display=\"{}\"\n", esc(&line.name));
    ap!(o, "first_name=\"{}\"\n", esc(&line.first_name));
    ap!(o, "last_name=\"{}\"\n", esc(&line.last_name));
    ap!(o, "title=\"{}\"\n", esc(&line.title));
    ap!(o, "status=\"{}\"\n", "1");
    ap!(o, "type=\"{}\"\n", "sip");
    ap!(o, "type_display=\"{}\"\n", "SIP Extension");
    ap!(o, "location=\"{}\"\n", esc(&line.location));
    ap!(o, "authname=\"{}\"\n", esc(or(&line.authname, &line.name)));
    ap!(o, "line_label=\"{}\"\n", esc(or(&line.line_label, &line.name)));
    ap!(o, "subscription_extension=\"{}{}\"\n", "auto_hint_", esc(&line.name));
    outbound_proxy(o, line);
    ap!(o, "plar_number=\"{}\"\n", esc(&line.plar_number));
    ap!(o, "register=\"{}\"", i32::from(!line.no_register));
    ap!(o, ">\n");

    ap!(o, "<host_primary server=\"{}\" ", esc(&net.registration_address));
    ap!(o, "port=\"{}\" ", esc(&net.registration_port));
    let transport = if line.transport == Transport::Unset { net.transport } else { line.transport };
    ap!(o, "transport=\"{}\" ", transport.string());
    if !line.media_encryption.is_empty() {
        ap!(o, "media_encryption=\"{}\" ", line.media_encryption);
    }
    registration_timers(o, line);
    ap!(o, "/>\n");

    if !net.alternate_registration_address.is_empty() {
        ap!(o, "<host_alternate server=\"{}\" ", esc(&net.alternate_registration_address));
        ap!(o, "port=\"{}\" ", esc(&net.alternate_registration_port));
        let transport = if line.secondary_server_transport == Transport::Unset {
            net.alternate_transport
        } else {
            line.secondary_server_transport
        };
        ap!(o, "transport=\"{}\" ", transport.string());
        if !line.secondary_media_encryption.is_empty() {
            ap!(o, "media_encryption=\"{}\" ", line.secondary_media_encryption);
        }
        registration_timers(o, line);
        ap!(o, "/>\n");
    }

    parking_settings(o, phone);
    ap!(o, "<permission id=\"use_voicemail\" value=\"{}\" />\n", i32::from(!line.mailbox.is_empty()));
    ap!(o, "<permission id=\"send_to_voicemail\" value=\"{}\" />\n", i32::from(phone.send_to_vm));
    ap!(o, "<permission id=\"record_own_calls\" value=\"{}\" />\n", i32::from(phone.record_own_calls));
    ap!(o, "</account>\n");
}

/// `add_external_line_account`.
fn add_external_line_account(o: &mut Out, line: &Line, net: &Network, index: i32) {
    ap!(o, "<account \n");
    ap!(o, "network_id=\"{}\"\n", net.name);
    ap!(o, "index=\"{}\"\n", index);
    ap!(o, "visual_voicemail=\"0\"\n");
    ap!(o, "voicemail=\"{}\"\n", line.voicemail_uri);
    ap!(o, "username=\"{}\"\n", esc(or(&line.userid, &line.name)));
    let authname = if !line.authname.is_empty() {
        &line.authname
    } else if !line.userid.is_empty() {
        &line.userid
    } else {
        &line.name
    };
    ap!(o, "authname=\"{}\"\n", esc(authname));
    ap!(o, "caller_id=\"{}\"\n", esc(&line.callerid));
    let label = if !line.line_label.is_empty() {
        &line.line_label
    } else if !line.exten.is_empty() {
        &line.exten
    } else if !line.userid.is_empty() {
        &line.userid
    } else {
        &line.name
    };
    ap!(o, "line_label=\"{}\"\n", esc(label));
    ap!(o, "password=\"{}\"\n", esc(&line.secret));
    ap!(o, "passcode=\"{}\"\n", esc(&line.secret));
    ap!(o, "number=\"{}\"\n", esc(or(&line.exten, &line.name)));
    ap!(o, "dial_plan=\"{}\"\n", esc(&line.digit_map));
    ap!(o, "display=\"{}\"\n", esc(&line.name));
    ap!(o, "first_name=\"{}\"\n", esc(&line.first_name));
    ap!(o, "last_name=\"{}\"\n", esc(&line.last_name));
    ap!(o, "title=\"{}\"\n", esc(&line.title));
    ap!(o, "status=\"{}\"\n", "1");
    ap!(o, "type=\"{}\"\n", "sip | external");
    ap!(o, "type_display=\"{}\"\n", "SIP Extension");
    ap!(o, "location=\"{}\"\n", esc(&line.location));
    outbound_proxy(o, line);
    ap!(o, "register=\"{}\" ", i32::from(!line.no_register));
    ap!(o, "plar_number=\"{}\"\n", esc(&line.plar_number));
    ap!(o, ">\n");

    ap!(o, "<host_primary server=\"{}\" ", esc(&line.server_address));
    ap!(o, "port=\"{}\" ", esc(&line.server_port));
    ap!(o, "transport=\"{}\" ", line.transport.string());
    if !line.media_encryption.is_empty() {
        ap!(o, "media_encryption=\"{}\" ", line.media_encryption);
    }
    registration_timers(o, line);
    ap!(o, "/>\n");

    if !line.secondary_server_address.is_empty() {
        ap!(o, "<host_alternate server=\"{}\" ", esc(&line.secondary_server_address));
        ap!(o, "port=\"{}\" ", esc(&line.secondary_server_port));
        ap!(o, "transport=\"{}\" ", line.secondary_server_transport.string());
        if !line.secondary_media_encryption.is_empty() {
            ap!(o, "media_encryption=\"{}\" ", line.secondary_media_encryption);
        }
        registration_timers(o, line);
        ap!(o, "/>\n");
    }
    ap!(o, "<setting id=\"parking_lot_extension\" value=\"\" />\n");
    ap!(o, "</account>\n");
}

/// `add_firmware_settings` (with `add_option_firmware_settings` and the
/// firmware package fallback).
fn add_firmware_settings(o: &mut Out, reg: &Registry, phone: &Phone) {
    for net_name in &phone.networks {
        let Some(net) = reg.networks.get(net_name) else {
            dpma_log!("Failed to find network '{}'", net_name);
            continue;
        };
        if phone.firmware.is_empty() {
            crate::firmware::no_option_settings(&mut |s| o.ap(s), &net.file_url_prefix, &net.name);
            continue;
        }
        ap!(o, "<firmwares>\n");
        for fw_name in &phone.firmware {
            let Some(fw) = reg.firmware.get(fw_name) else {
                dpma_log!("Could not find firmware profile '{}' for phone '{}'", fw_name, phone.name);
                continue;
            };
            if !net.file_url_prefix.is_empty() && !fw.version.is_empty() && !fw.file.is_empty() {
                ap!(
                    o,
                    "<firmware model=\"{}\" version=\"{}\" url=\"{}{}\" network_id=\"{}\" />\n",
                    fw.model,
                    fw.version,
                    url_prefix(&fw.file, &net.file_url_prefix),
                    fw.file,
                    net.name
                );
            }
        }
        ap!(o, "</firmwares>\n");
        ap!(o, "<public_firmwares>\n");
        for fw_name in &phone.firmware {
            let Some(fw) = reg.firmware.get(fw_name) else {
                dpma_log!("Could not find firmware profile '{}' for phone '{}'", fw_name, phone.name);
                continue;
            };
            if fw.public_firmware && !fw.version.is_empty() && !fw.file.is_empty() {
                let prefix = or(&net.public_firmware_url_prefix, "http://dphone.dl.digium.com/firmware/asterisk/");
                ap!(
                    o,
                    "<public_firmware model=\"{}\" version=\"{}\" url=\"{}{}/{}_{}_firmware.eff\" network_id=\"{}\" />\n",
                    fw.model,
                    fw.version,
                    prefix,
                    fw.version,
                    fw.version,
                    fw.model,
                    net.name
                );
            }
        }
        ap!(o, "</public_firmwares>\n");
    }
}

/// Does `dir/name` exist (and can it be opened)?  FUN_001523a0.
fn file_exists(dir: &str, name: &str) -> bool {
    std::fs::File::open(crate::util::truncate(&format!("{}/{}", dir, name), 0x1000)).is_ok()
}

/// A user image setting (`logo_file`, `wallpaper_file`): served from the
/// file directory when the file is there, otherwise from every network's
/// file URL prefix.
fn user_image(o: &mut Out, reg: &Registry, phone: &Phone, dir: &str, id: &str, file: &str, path: &str) {
    if file_exists(dir, file) {
        ap!(
            o,
            "<setting id=\"{}\" value=\"user\" url=\"file://{}\" path=\"{}\" conflict=\"freeze\" />\n",
            id,
            file,
            path
        );
        return;
    }
    for net in networks(reg, phone) {
        ap!(
            o,
            "<setting id=\"{}\" value=\"user\" url=\"{}{}\" path=\"{}\" conflict=\"freeze\" network_id=\"{}\" />\n",
            id,
            url_prefix(file, &net.file_url_prefix),
            file,
            path,
            net.name
        );
    }
}

/// `phone_user_build_config`.  Returns the internal lines whose
/// CustomPresence state must be initialized, which the original does
/// while adding their accounts.
fn build_config(reg: &Registry, phone: &Phone, out: &mut String, dir: &str, model: &str) -> Vec<String> {
    let p = phone;
    out.clear();
    let mut o = Out { s: out, cap: INITIAL_BUF };
    let general = crate::config::get();
    let uuid = general.server_uuid.as_str();
    let has_queue = has_queue(reg, p);
    let primary = primary_line(reg, p);
    let conflict = if p.lock_preferences { "freeze" } else { "replace" };
    let slot0 = p.lines.first().map_or("", |l| l.name.as_str());

    // Softkeys.
    ap!(o, "<config>\n");
    ap!(o, "<keymap>\n");
    ap!(o, "<state id=\"idle\" conflict=\"freeze\">\n");
    ap!(o, "<softkeys>\n");
    let mut key = 0;
    if p.show_call_log {
        ap!(o, "<key id=\"{}\" action=\"missed_or_call_log\" />\n", 0);
        key = 1;
    }
    ap!(o, "<key id=\"{}\" action=\"show_application\" label1=\"_CONTACTS\">\n", key);
    ap!(o, "<arg>contacts</arg>\n");
    ap!(o, "</key>\n");
    ap!(o, "<key id=\"{}\" action=\"show_application\" label1=\"_STATUS\">\n", key + 1);
    ap!(o, "<arg>status</arg>\n");
    ap!(o, "</key>\n");
    ap!(o, "<key id=\"{}\" action=\"info\" />\n", key + 2);
    key += 3;
    if p.show_call_parking {
        ap!(o, "<key id=\"{}\" action=\"show_application\" label1=\"_PARKED_CALLS\">\n", key);
        ap!(o, "<arg>parking</arg>\n");
        ap!(o, "</key>\n");
        key += 1;
    }
    if has_queue {
        ap!(o, "<key id=\"{}\" action=\"show_application\" label1=\"_QUEUES\">\n", key);
        ap!(o, "<arg>queues</arg>\n");
        ap!(o, "</key>\n");
        key += 1;
    }
    for name in &p.applications {
        let Some(app) = reg.applications.get(name) else {
            dpma_log!("Failed to find application '{}'", name);
            continue;
        };
        if let Some(AppKind::Custom(c)) = &app.kind {
            if c.idlescreen_softkey {
                ap!(o, "<key id=\"{}\" action=\"show_application\" label1=\"{}\">\n", key, c.name);
                key += 1;
                ap!(o, "<arg>{}</arg>\n", c.name);
                ap!(o, "</key>\n");
            }
        }
    }
    if p.can_forward_calls {
        ap!(o, "<key id=\"{}\" action=\"forward_calls\" label1=\"_FORWARD\" />\n", key);
        key += 1;
    }
    ap!(o, "<key id=\"{}\" action=\"menu\" />\n", key);
    ap!(o, "</softkeys>\n");
    ap!(o, "</state>\n");

    ap!(o, "<state id=\"incoming\" conflict=\"freeze\">\n");
    ap!(o, "<softkeys>\n");
    ap!(o, "<key id=\"0\" action=\"accept_call\" />\n");
    ap!(o, "<key id=\"1\" action=\"reject_call\" />\n");
    ap!(o, "<key id=\"2\" action=\"transfer_call\" />\n");
    if p.send_to_vm {
        ap!(o, "<key id=\"3\" action=\"send_to_vmail\" />\n");
    } else {
        ap!(o, "<key id=\"3\" action=\"none\" />\n");
    }
    ap!(o, "</softkeys>\n");
    ap!(o, "</state>\n");

    ap!(o, "<state id=\"dialing\" conflict=\"freeze\">\n");
    ap!(o, "<softkeys>\n");
    ap!(o, "<key id=\"0\" action=\"make_call\" />\n");
    ap!(o, "<key id=\"1\" action=\"show_application\" label1=\"_CONTACTS\">\n");
    ap!(o, "<arg>contacts</arg>\n");
    ap!(o, "</key>\n");
    ap!(o, "<key id=\"2\" action=\"backspace\" />\n");
    ap!(o, "<key id=\"3\" action=\"cancel_call\" />\n");
    ap!(o, "</softkeys>\n");
    ap!(o, "</state>\n");

    let record = |o: &mut Out| {
        if p.record_own_calls {
            ap!(o, "<key id=\"2\" action=\"record_call\" />\n");
        } else {
            ap!(o, "<key id=\"2\" action=\"none\" />\n");
        }
    };
    ap!(o, "<state id=\"connected\" conflict=\"freeze\">\n");
    ap!(o, "<softkeys>\n");
    ap!(o, "<key id=\"0\" action=\"conference\" />\n");
    if p.parking_exten.is_empty() {
        ap!(o, "<key id=\"1\" action=\"none\" />\n");
    } else {
        ap!(o, "<key id=\"1\" action=\"park_call\" />\n");
    }
    record(&mut o);
    ap!(o, "<key id=\"3\" action=\"end_call\" />\n");
    ap!(o, "</softkeys>\n");
    ap!(o, "</state>\n");

    ap!(o, "<state id=\"connected/conference\" conflict=\"freeze\">\n");
    ap!(o, "<softkeys>\n");
    ap!(o, "<key id=\"0\" action=\"none\" />\n");
    ap!(o, "<key id=\"1\" action=\"split_conference\" />\n");
    record(&mut o);
    ap!(o, "<key id=\"3\" action=\"end_call\" />\n");
    ap!(o, "</softkeys>\n");
    ap!(o, "</state>\n");
    ap!(o, "</keymap>\n");

    // Networks.
    ap!(o, "<networks>\n");
    for net in networks(reg, p) {
        ap!(o, "<network id=\"{}\" display_name=\"{}\" cidr=\"{}\" />\n", net.name, net.alias, net.cidr);
    }
    ap!(o, "</networks>\n");

    // Application screen and phone menu.
    ap!(o, "<appconfig id=\"appscreen\">\n");
    if primary.is_some_and(|l| !l.mailbox.is_empty()) {
        ap!(o, "<application id=\"voicemail\"/>\n");
    }
    if p.show_call_parking {
        ap!(o, "<application id=\"parking\"/>\n");
    }
    ap!(o, "<application id=\"status\"/>\n");
    ap!(o, "<application id=\"contacts\"/>\n");
    if has_queue {
        ap!(o, "<application id=\"queues\"/>\n");
    }
    if p.can_forward_calls {
        ap!(o, "<application id=\"forward_calls\"/>\n");
    }
    if p.show_call_log {
        ap!(o, "<application id=\"call_log\"/>\n");
    }
    if p.logout_enabled {
        ap!(o, "<application id=\"LogOut\"/>\n");
    }
    ap!(o, "<auto_start />\n");
    ap!(o, "</appconfig>\n");
    if !p.show_call_parking {
        ap!(o, "<appconfig id=\"parking\">\n");
        ap!(o, "<disabled />\n");
        ap!(o, "</appconfig>\n");
    }
    if p.logout_enabled {
        ap!(o, "<appconfig id=\"LogOut\">\n");
        ap!(o, "<auto_start />\n");
        ap!(o, "</appconfig>\n");
    }
    ap!(o, "<appconfig id=\"phonemenu\">\n");
    ap!(o, "<auto_start/>\n");
    ap!(o, "<hide_options id=\"admin\">\n");
    ap!(o, "<option id=\"sipLines\"/>\n");
    ap!(o, "</hide_options>\n");
    if p.lock_preferences {
        ap!(o, "<hide_options id=\"preferences\">\n");
        ap!(o, "<option id=\"display\"/>\n");
        ap!(o, "<option id=\"sound\"/>\n");
        ap!(o, "<option id=\"answering\"/>\n");
        ap!(o, "<option id=\"localization\"/>\n");
        ap!(o, "<option id=\"network_select\"/>\n");
        ap!(o, "</hide_options>\n");
    }
    ap!(o, "</appconfig>\n");

    // General settings.
    if p.transport_tls_allowed != -1 {
        ap!(o, "<setting id=\"transport_tls_allowed\" value=\"{}\" />\n", p.transport_tls_allowed);
    }
    ap!(o, "<setting id=\"server_environment\" value=\"DPMA\" />\n");
    ap!(o, "<setting id=\"enable_check_sync\" value=\"{}\" />\n", i32::from(p.enable_check_sync));
    if p.default_fontsize != 0 {
        ap!(o, "<setting id=\"default_fontsize\" value=\"{}\" />\n", p.default_fontsize as u32);
    }
    ap!(o, "<setting id=\"enable_blf_on_unused_line_keys\" value=\"{}\" />\n", i32::from(p.blf_unused_linekeys));
    ap!(o, "<setting id=\"blf_page_return_timeout\" value=\"{}\" />\n", p.blf_page_return_timeout);
    if !p.timezone.is_empty() {
        ap!(o, "<setting id=\"time_zone\" value=\"{}\" />\n", p.timezone);
    }
    ap!(o, "<setting id=\"time_source\" value=\"ntp\" />\n");
    if p.ntp_resync != 0 {
        ap!(o, "<setting id=\"ntp_resync\" value=\"{}\" />\n", p.ntp_resync as u32);
    }
    if p.contacts_max_subscriptions != 0 {
        ap!(o, "<setting id=\"contacts_max_subscriptions\" value=\"{}\" />\n", p.contacts_max_subscriptions);
    }

    // Contacts application and per-network settings.
    for net in networks(reg, p) {
        ap!(o, "<appconfig id=\"contacts\">\n");
        app_account(&mut o, uuid, slot0, p, net);
        ap!(o, "<auto_start/>\n");
        ap!(o, "<settings \n");
        ap!(o, "use_local_storage=\"{}\" \n", i32::from(p.use_local_storage));
        ap!(o, "can_transfer_vm=\"{}\" \n", i32::from(p.send_to_vm));
        if !p.name_format.is_empty() {
            ap!(o, "name_format=\"{}\" \n", p.name_format);
        }
        ap!(o, "/>\n");
        ap!(o, "</appconfig>\n");
        let transport = match primary {
            Some(l) if l.transport != Transport::Unset => l.transport,
            _ => net.transport,
        };
        ap!(
            o,
            "<setting id=\"config_server_url\" value=\"sip:proxy@{}:{}{}\" network_id=\"{}\" />\n",
            net.registration_address,
            net.registration_port,
            transport.uri_option(),
            net.name
        );
        if !net.ntp_server.is_empty() {
            ap!(o, "<setting id=\"ntp_server\" value=\"{}\" network_id=\"{}\" />\n", net.ntp_server, net.name);
        }
        if net.syslog_server.is_empty() || net.syslog_level.is_empty() {
            ap!(o, "<setting id=\"enable_logging\" value=\"0\" network_id=\"{}\" />\n", net.name);
        } else {
            ap!(o, "<setting id=\"enable_logging\" value=\"1\" network_id=\"{}\" />\n", net.name);
            ap!(o, "<setting id=\"log_server\" value=\"{}\" network_id=\"{}\" />\n", net.syslog_server, net.name);
            if !net.syslog_port.is_empty() {
                ap!(o, "<setting id=\"log_port\" value=\"{}\" network_id=\"{}\" />\n", net.syslog_port, net.name);
            }
        }
        if !net.syslog_level.is_empty() {
            ap!(o, "<setting id=\"log_level\" value=\"{}\" network_id=\"{}\" />\n", net.syslog_level, net.name);
        }
        if !net.network_vlan_discovery_mode.is_empty() {
            ap!(
                o,
                "<setting id=\"network_vlan_discovery_mode\" value=\"{}\" network_id=\"{}\" />\n",
                net.network_vlan_discovery_mode,
                net.name
            );
            if net.network_vlan_id > 0 {
                ap!(o, "<setting id=\"network_vlan_id\" value=\"{}\" network_id=\"{}\" />\n", net.network_vlan_id, net.name);
                let rtp_qos = if net.rtp_qos == -1 { 6 } else { net.rtp_qos };
                ap!(o, "<setting id=\"rtp_qos\" value=\"{}\" network_id=\"{}\" />\n", rtp_qos, net.name);
                ap!(o, "<setting id=\"sip_qos\" value=\"{}\" network_id=\"{}\" />\n", net.sip_qos, net.name);
            }
        }
        if net.sip_dscp >= 0 {
            ap!(o, "<setting id=\"sip_dscp\" value=\"{}\" network_id=\"{}\" />\n", net.sip_dscp, net.name);
        }
        if net.rtp_dscp >= 0 {
            ap!(o, "<setting id=\"rtp_dscp\" value=\"{}\" network_id=\"{}\" />\n", net.rtp_dscp, net.name);
        }
        if net.pc_vlan_id >= 0 {
            ap!(o, "<setting id=\"pc_vlan_id\" value=\"{}\" network_id=\"{}\" />\n", net.pc_vlan_id, net.name);
        }
        if net.pc_qos >= 0 {
            ap!(o, "<setting id=\"pc_qos\" value=\"{}\" network_id=\"{}\" />\n", net.pc_qos, net.name);
        }
        if net.udp_ka_interval >= 0 {
            ap!(o, "<setting id=\"udp_ka_interval\" value=\"{}\" network_id=\"{}\" />\n", net.udp_ka_interval, net.name);
        }
    }

    // Phone settings.
    ap!(o, "<setting id=\"web_ui_enabled\" value=\"{}\" />\n", i32::from(p.web_ui_enabled));
    if !p.login_password.is_empty() {
        ap!(o, "<setting id=\"login_password\" value=\"{}\" />\n", p.login_password);
    }
    if !p.accept_local_calls.is_empty() {
        ap!(o, "<setting id=\"accept_local_calls\" value=\"{}\" />\n", p.accept_local_calls);
    }
    if !p.name_format.is_empty() {
        ap!(o, "<setting id=\"name_format\" value=\"{}\" />\n", p.name_format);
    }
    if !p.lan_port_mode.is_empty() {
        ap!(o, "<setting id=\"lan_port_mode\" value=\"{}\" />\n", p.lan_port_mode);
    }
    if !p.pc_port_mode.is_empty() {
        ap!(o, "<setting id=\"pc_port_mode\" value=\"{}\" />\n", p.pc_port_mode);
    }
    if p.brightness >= 0 {
        ap!(o, "<setting id=\"brightness\" value=\"{}\" conflict=\"{}\" />\n", p.brightness, conflict);
    }
    if p.contrast >= 0 {
        ap!(o, "<setting id=\"contrast\" value=\"{}\" conflict=\"{}\" />\n", p.contrast, conflict);
    }
    if p.backlight_dim_level >= 0 {
        ap!(o, "<setting id=\"backlight_dim_level\" value=\"{}\" conflict=\"{}\" />\n", p.backlight_dim_level, conflict);
    }
    if p.backlight_timeout > 0 {
        ap!(o, "<setting id=\"backlight_timeout\" value=\"{}\" conflict=\"{}\" />\n", p.backlight_timeout, conflict);
    }
    if p.dim_backlight && p.backlight_timeout != 0 {
        ap!(o, "<setting id=\"dim_backlight\" value=\"1\" conflict=\"{}\" />\n", conflict);
    } else {
        ap!(o, "<setting id=\"dim_backlight\" value=\"0\" conflict=\"{}\" />\n", conflict);
    }
    ap!(
        o,
        "<setting id=\"display_mc_notification\" value=\"{}\" conflict=\"{}\" />\n",
        i32::from(p.display_mc_notification),
        conflict
    );
    if !p.idle_company_text.is_empty() {
        ap!(o, "<setting id=\"idle_company_text\" value=\"{}\" />\n", p.idle_company_text);
    }
    if p.small_clock {
        ap!(o, "<setting id=\"small_clock\" value=\"{}\" conflict=\"{}\" />\n", 1, conflict);
    }
    ap!(o, "<setting id=\"handshake_timeout\" value=\"{}\" />\n", p.handshake_timeout);
    if p.allow_insecure_ssl {
        ap!(o, "<setting id=\"allow_insecure_ssl\" value=\"1\" conflict=\"freeze\" />\n");
    } else {
        ap!(o, "<setting id=\"allow_insecure_ssl\" value=\"0\" />\n");
    }
    ap!(o, "<setting id=\"locale\" value=\"{}\" conflict=\"{}\" />\n", p.active_locale, conflict);
    if p.ringer_volume >= 0 {
        ap!(o, "<setting id=\"ringer_volume\" value=\"{}\" conflict=\"{}\" />\n", p.ringer_volume, conflict);
    }
    if p.speaker_volume != 0 {
        ap!(o, "<setting id=\"speaker_volume\" value=\"{}\" conflict=\"{}\" />\n", p.speaker_volume, conflict);
    }
    if p.handset_volume != 0 {
        ap!(o, "<setting id=\"handset_volume\" value=\"{}\" conflict=\"{}\" />\n", p.handset_volume, conflict);
    }
    if p.headset_volume != 0 {
        ap!(o, "<setting id=\"headset_volume\" value=\"{}\" conflict=\"{}\" />\n", p.headset_volume, conflict);
    }
    if p.handset_sidetone_db != 0 {
        let v = if p.handset_sidetone_db == -1 { -25 } else { p.handset_sidetone_db };
        ap!(o, "<setting id=\"handset_sidetone_db\" value=\"{}\" />\n", v);
    }
    if p.headset_sidetone_db != 0 {
        let v = if p.headset_sidetone_db == -1 { -15 } else { p.headset_sidetone_db };
        ap!(o, "<setting id=\"headset_sidetone_db\" value=\"{}\" />\n", v);
    }
    ap!(o, "<setting id=\"reset_call_volume\" value=\"{}\" conflict=\"{}\" />\n", i32::from(p.reset_call_volume), conflict);
    ap!(o, "<setting id=\"headset_answer\" value=\"{}\" conflict=\"{}\" />\n", i32::from(p.headset_answer), conflict);
    ap!(o, "<setting id=\"ring_headset_only\" value=\"{}\" conflict=\"{}\" />\n", i32::from(p.ring_headset_only), conflict);
    ap!(o, "<setting id=\"call_waiting_tone\" value=\"{}\" conflict=\"{}\" />\n", i32::from(p.call_waiting_tone), conflict);
    if !p.ehs.is_empty() {
        ap!(o, "<setting id=\"ehs\" value=\"{}\" />\n", p.ehs);
    }
    ap!(
        o,
        "<setting id=\"expansion_enable\" value=\"{}\" type=\"EXP100\" page_indicators=\"{}\"/>\n",
        i32::from(p.expansion_enabled),
        i32::from(p.expansion_page_indicators_enabled)
    );
    ap!(o, "<setting id=\"8021x_passthrough\" value=\"{}\" />\n", p.dot1x_passthrough);
    ap!(o, "<setting id=\"8021x_method\" value=\"{}\" />\n", p.dot1x_method);
    ap!(o, "<setting id=\"8021x_eapol_on_disconnect\" value=\"{}\" />\n", or(&p.dot1x_eapol_on_disconnect, "0"));
    ap!(o, "<setting id=\"8021x_identity\" value=\"{}\" />\n", p.dot1x_identity);
    ap!(o, "<setting id=\"8021x_anonymous_identity\" value=\"{}\" />\n", p.dot1x_anonymous_identity);
    ap!(o, "<setting id=\"8021x_password\" value=\"{}\" />\n", p.dot1x_password);
    ap!(
        o,
        "<setting id=\"8021x_client_cert\" url=\"{}\" value=\"{}\" />\n",
        p.dot1x_client_cert_url,
        file_value(&p.dot1x_client_cert_url, &p.dot1x_client_cert_value)
    );
    ap!(
        o,
        "<setting id=\"8021x_root_cert\" url=\"{}\" value=\"{}\" />\n",
        p.dot1x_root_cert_url,
        file_value(&p.dot1x_root_cert_url, &p.dot1x_root_cert_value)
    );
    if !p.dot1x_debug.is_empty() {
        ap!(o, "<setting id=\"8021x_debug\" value=\"{}\" />\n", p.dot1x_debug);
    }
    ap!(o, "<setting id=\"network_default_enable_openvpn\" value=\"{}\" />\n", p.openvpn_enable);
    ap!(
        o,
        "<setting id=\"openvpn_config_file\" url=\"{}\" value=\"{}\" />\n",
        p.openvpn_config_file_url,
        file_value(&p.openvpn_config_file_url, &p.openvpn_config_file_value)
    );
    ap!(
        o,
        "<setting id=\"openvpn_root_cert\" url=\"{}\" value=\"{}\" />\n",
        p.openvpn_root_cert_url,
        file_value(&p.openvpn_root_cert_url, &p.openvpn_root_cert_value)
    );
    ap!(
        o,
        "<setting id=\"openvpn_client_cert\" url=\"{}\" value=\"{}\" />\n",
        p.openvpn_client_cert_url,
        file_value(&p.openvpn_client_cert_url, &p.openvpn_client_cert_value)
    );
    ap!(
        o,
        "<setting id=\"openvpn_client_key\" url=\"{}\" value=\"{}\" />\n",
        p.openvpn_client_key_url,
        file_value(&p.openvpn_client_key_url, &p.openvpn_client_key_value)
    );
    if !p.openvpn_logging.is_empty() {
        ap!(o, "<setting id=\"openvpn_logging\" value=\"{}\" />\n", p.openvpn_logging);
    }

    // Status (and queues) applications, per network.
    for net in networks(reg, p) {
        ap!(o, "<appconfig id=\"status\" network_id=\"{}\">\n", net.name);
        if p.send486_custom {
            for state in 0..7 {
                if p.send486_mask & (1 << state) != 0 {
                    ap!(o, "<send_dnd status=\"{}\" />", dpma_ast::presence::state2str(state));
                }
            }
        } else {
            ap!(o, "<send_dnd status=\"dnd\" />");
            ap!(o, "<send_dnd status=\"xa\" />");
        }
        app_account(&mut o, uuid, slot0, p, net);
        ap!(o, "<auto_start />\n");
        ap!(o, "<full_application />\n");
        ap!(o, "</appconfig>\n");
        if has_queue {
            ap!(o, "<appconfig id=\"queues\" network_id=\"{}\">\n", net.name);
            app_account(&mut o, uuid, slot0, p, net);
            ap!(o, "<auto_start />\n");
            ap!(o, "</appconfig>\n");
        }
    }

    // Custom applications.
    for name in &p.applications {
        let Some(app) = reg.applications.get(name) else {
            dpma_log!("Failed to find application '{}'", name);
            continue;
        };
        let Some(AppKind::Custom(c)) = &app.kind else { continue };
        for net in networks(reg, p) {
            if c.filename.is_empty() || net.file_url_prefix.is_empty() {
                continue;
            }
            ap!(o, "<appconfig id=\"{}\" network_id=\"{}\">\n", c.name, net.name);
            ap!(o, "<url url=\"{}{}\" ", url_prefix(&c.filename, &net.file_url_prefix), c.filename);
            if !c.md5.is_empty() {
                ap!(o, "md5=\"{}\" ", c.md5);
            }
            ap!(o, "/>\n");
            app_account(&mut o, uuid, slot0, p, net);
            if c.autostart {
                ap!(o, "<auto_start/>\n");
            }
            if !c.settings.is_empty() {
                ap!(o, "<settings \n");
                for (k, v) in &c.settings {
                    ap!(o, "{}=\"{}\" \n", k, v);
                }
                ap!(o, "/>\n");
            }
            ap!(o, "</appconfig>\n");
        }
    }

    // Contacts.
    if p.contacts.is_empty() {
        ap!(o, "<contacts url=\"file://{}\" id=\"{}\" />\n", "null", 0);
    }
    for (i, contact) in p.contacts.iter().enumerate() {
        if file_exists(dir, contact) {
            ap!(o, "<contacts url=\"file://{}\" id=\"{}\" />\n", contact, i);
            continue;
        }
        for net in networks(reg, p) {
            ap!(
                o,
                "<contacts id=\"{}\" url=\"{}{}\" network_id=\"{}\" />\n",
                i,
                url_prefix(contact, &net.file_url_prefix),
                contact,
                net.name
            );
        }
    }
    ap!(o, "<setting id=\"default_blf_contact_group\" value=\"{}\" />\n", "Internal Extensions");
    if !p.blf_contact_group.is_empty() {
        ap!(o, "<setting id=\"blf_contact_group\" value=\"{}\" />\n", p.blf_contact_group);
    }
    parking_settings(&mut o, p);

    // Ringtones and alerts.
    let active_ringtone = or(&p.active_ringtone, "Digium");
    ap!(o, "<ringtones>\n");
    ap!(o, "<tones>\n");
    for name in &p.ringtones {
        let Some(tone) = reg.ringtones.get(name) else { continue };
        for net in networks(reg, p) {
            if tone.filename.is_empty() || net.file_url_prefix.is_empty() {
                continue;
            }
            ap!(
                o,
                "<tone id=\"{}\" display=\"{}\" url=\"{}{}\" type=\"user\" network_id=\"{}\" />\n",
                tone.name,
                or(&tone.alias, &tone.name),
                url_prefix(&tone.filename, &net.file_url_prefix),
                tone.filename,
                net.name
            );
        }
    }
    ap!(o, "</tones>\n");
    ap!(o, "<alerts>\n");
    ap!(o, "<alert alert_info=\"normal\" ringtone_id=\"{}\" ring_type=\"normal\" />\n", active_ringtone);
    ap!(o, "<alert alert_info=\"ring-answer\" ringtone_id=\"{}\" ring_type=\"ring-answer\" />\n", active_ringtone);
    ap!(o, "<alert alert_info=\"visual\" ringtone_id=\"\" ring_type=\"visual\" />\n");
    ap!(o, "<alert alert_info=\"intercom\" ringtone_id=\"\" ring_type=\"answer\" />\n");
    for name in &p.alerts {
        let Some(alert) = reg.alerts.get(name) else { continue };
        if !alert.alert_info.is_empty() {
            ap!(
                o,
                "<alert alert_info=\"{}\" ringtone_id=\"{}\" ring_type=\"{}\" />\n",
                alert.alert_info,
                alert.ringtone,
                or(&alert.ring_type, "normal")
            );
        }
    }
    ap!(o, "</alerts>\n");
    ap!(o, "</ringtones>\n");
    ap!(o, "<setting id=\"active_ringtone\" value=\"{}\" />\n", active_ringtone);

    // Multicast pages.
    let mut listeners = 0;
    for name in &p.multicastpages {
        if name.is_empty() {
            continue;
        }
        let Some(page) = reg.pages.get(name) else { continue };
        if listeners == 0 {
            ap!(o, "<multicastpage>\n");
        }
        listeners += 1;
        ap!(
            o,
            "<listener id=\"{}\" name=\"{}\" addr=\"{}\" port=\"{}\" priority=\"{}\" interrupt_calls=\"{}\" />\n",
            listeners,
            or(&page.alias, &page.name),
            page.address,
            page.port,
            page.priority,
            page.interrupt
        );
    }
    if listeners != 0 {
        ap!(o, "</multicastpage>\n");
    }

    // Codecs.
    for (i, codec) in p.codecs.iter().enumerate() {
        if i == 0 {
            ap!(o, "<codecs>\n");
        }
        let (name, attrs) = CODECS[codec.index];
        if codec.enabled {
            ap!(
                o,
                "<codec id=\"{}\" enabled=\"{}\" priority=\"{}\" {} {}/>\n",
                name,
                1,
                codec.priority,
                "jitter_min=\"0\" jitter_max=\"0\" jitter_target=\"0\"",
                attrs
            );
        } else {
            ap!(o, "<codec id=\"{}\" enabled=\"{}\"/>\n", name, 0);
        }
    }
    if !p.codecs.is_empty() {
        ap!(o, "</codecs>\n");
    }

    add_firmware_settings(&mut o, reg, p);

    // Logo for the requesting phone's model, and wallpaper.
    if let Some((_, file)) = p.logos.iter().find(|(m, _)| m.eq_ignore_ascii_case(model)) {
        if !file.is_empty() {
            user_image(&mut o, reg, p, dir, "logo_file", file, "/user_image.png");
        }
    }
    if !p.wallpaper_file.is_empty() {
        user_image(&mut o, reg, p, dir, "wallpaper_file", &p.wallpaper_file, "/user_wallpaper.png");
    }

    // Parking and voicemail applications of the primary line.
    if let Some(line) = primary.filter(|l| !l.external) {
        for net in networks(reg, p) {
            if p.show_call_parking {
                ap!(o, "<appconfig id=\"parking\" network_id=\"{}\">\n", net.name);
                app_account(&mut o, uuid, &line.name, p, net);
                ap!(o, "<auto_start />\n");
                ap!(o, "</appconfig>\n");
            }
            if !line.mailbox.is_empty() {
                let require_password = matches!(
                    application_settings(reg, p, "Voicemail").and_then(|a| a.kind.as_ref()),
                    Some(AppKind::Voicemail(vm)) if vm.require_password
                );
                if line.voicemail_uri.is_empty() {
                    ap!(o, "<appconfig id=\"voicemail\" network_id=\"{}\">\n", net.name);
                    app_account(&mut o, uuid, &line.name, p, net);
                    if require_password {
                        ap!(o, "<settings require_password=\"1\"/>\n");
                    }
                    ap!(o, "</appconfig>\n");
                }
            }
        }
        ap!(o, "<events>");
        ap!(o, "<event id=\"digium.incomingCall.voicemail\" action=\"app\" />");
        if p.show_call_parking {
            ap!(o, "<event id=\"digium.parkingLot.parked\" action=\"app\" />");
        }
        ap!(o, "</events>\n");
    }

    // Line accounts.
    let mut presence_lines = Vec::new();
    ap!(o, "<accounts>\n");
    let mut index = 0;
    for slot in p.lines.iter().take(MAX_LINES) {
        if slot.name.is_empty() {
            continue;
        }
        let Some(line) = reg.lines.get(&slot.name) else { continue };
        for net in networks(reg, p) {
            if slot.external {
                add_external_line_account(&mut o, line, net, index);
            } else {
                if !presence_lines.contains(&line.name) {
                    presence_lines.push(line.name.clone());
                }
                add_internal_line_account(&mut o, p, line, net, index, uuid);
            }
        }
        index += 1;
    }
    ap!(o, "</accounts>\n");

    // Smart BLF.
    ap!(o, "<smart_blf>\n");
    for net in networks(reg, p) {
        if !p.blf_items.is_empty() && !net.file_url_prefix.is_empty() {
            ap!(
                o,
                "<blf_items url=\"{}{}\" network_id=\"{}\"/>\n",
                url_prefix(&p.blf_items, &net.file_url_prefix),
                p.blf_items,
                net.name
            );
        }
    }
    ap!(o, "</smart_blf>\n");
    ap!(o, "</config>\n");

    insert_display_rules(&p.contacts_display_rules, &mut o, dir);
    presence_lines
}

/// `insert_display_rules`: merge the phone's `contacts_display_rules` file
/// into the first contacts application of the document.
///
/// The original parses the document with libxml2, adds the file's root
/// element to `//config/appconfig[@id='contacts']`, and replaces the text
/// with the formatted dump (`xmlDocDumpFormatMemory`, which also adds the
/// XML declaration and normalizes the markup).  It stores the dump with
/// `ast_str_set(&buf, len, "%s", dump)`; when the dump does not fit in the
/// buffer's current allocation, that caps the buffer at `len` bytes and the
/// last character (the final newline) is lost.  Reproduced.
fn insert_display_rules(rules: &str, o: &mut Out, dir: &str) {
    if rules.is_empty() {
        return;
    }
    let Some(doc) = Doc::parse_memory(o.s.as_bytes()) else {
        dpma_log!("Error Parsing phone user config, phone configuration may be invalid.");
        return;
    };
    let Some(contacts) = xmlutil::xml_find(&doc, "//config/appconfig[@id='contacts']") else {
        drop(doc);
        dpma_ast::dpma_debug!(3, "Contacts not found in phone config, display rules not added.");
        return;
    };
    let path = crate::util::truncate(&format!("{}/{}", dir, rules), 0x1000);
    xmlutil::xml_add_file(contacts, &path, None);
    let mut dump = doc.dump_format();
    if dump.len() >= o.cap {
        dump.pop();
        o.cap = dump.len() + 1;
    }
    *o.s = String::from_utf8_lossy(&dump).into_owned();
}

/// `phone_user_read_config`: append the file `dir/file` to `out`, the way
/// the original does (in 2047 byte reads, each cut at its first NUL).
pub fn read_config(out: &mut String, dir: &str, file: &str) -> Result<(), ()> {
    use std::io::Read;
    let path = crate::util::truncate(&format!("{}/{}", dir, file), 0x1000);
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            dpma_log!("Failed to open file {}", path);
            return Err(());
        }
    };
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; 0x7ff];
    loop {
        // fread(buf, 1, 0x7ff, fp): fill the chunk unless the file ends.
        let mut n = 0;
        while n < chunk.len() {
            match f.read(&mut chunk[n..]) {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
        }
        if n == 0 {
            break;
        }
        let end = chunk[..n].iter().position(|&b| b == 0).unwrap_or(n);
        bytes.extend_from_slice(&chunk[..end]);
        if n < chunk.len() {
            break;
        }
    }
    out.push_str(&String::from_utf8_lossy(&bytes));
    Ok(())
}

/// `phone_user_get_config`: put the configuration document of phone `phone`
/// into `out` (replacing what is there, as the original's `ast_str_set`
/// does), or, when the phone has `config_file` set, append that file from
/// `file_dir`.  `file_dir` is the file directory
/// (`dpma_append_config_file_dir(buf, len, NULL, cfg)`, i.e., the
/// `file_directory` setting); `model` is the requesting phone's model from
/// its user agent (e.g., "D65"), which selects the `<model>_logo_file`.
/// Calls `users::presence::user_application_sync` first, as the original
/// does.  Err when the phone does not exist.
pub fn get_config(phone: &str, out: &mut String, file_dir: &str, model: &str) -> Result<(), ()> {
    super::presence::user_application_sync(phone);
    let presence_lines = {
        let g = read();
        let reg = g.as_ref().ok_or(())?;
        let p = reg.phones.get(phone).ok_or(())?;
        if !p.config_file.is_empty() {
            let file = p.config_file.clone();
            drop(g);
            let _ = read_config(out, file_dir, &file);
            return Ok(());
        }
        build_config(reg, p, out, file_dir, model)
    };
    // add_internal_line_account: give a line without a CustomPresence
    // state "available", so its hint works.
    for line in presence_lines {
        options::init_custom_presence(&line);
    }
    Ok(())
}

/// `phone_user_get_primary_line_tech`: the technology ("SIP", "PJSIP") of
/// the phone's primary line; empty when unknown.
pub fn primary_line_tech(phone: &str) -> String {
    let g = read();
    let Some(reg) = g.as_ref() else { return String::new() };
    let Some(p) = reg.phones.get(phone) else { return String::new() };
    primary_line(reg, p).map(|l| l.tech.clone()).unwrap_or_default()
}

/// `phone_user_get_primary_line_name`: the name in the phone's first line
/// slot (empty when it has none).  None when the phone does not exist.
pub fn primary_line_name(phone: &str) -> Option<String> {
    let g = read();
    let p = g.as_ref()?.phones.get(phone)?;
    Some(p.lines.first().map(|l| l.name.clone()).unwrap_or_default())
}

/// `phone_user_set_primary_line_name`: put `line` in the phone's first
/// line slot.
pub fn set_primary_line_name(phone: &str, line: &str) -> Result<(), ()> {
    let mut g = write();
    let p = g.as_mut().and_then(|r| r.phones.get_mut(phone)).ok_or(())?;
    let name = crate::util::truncate(line, 0x80);
    match p.lines.first_mut() {
        Some(slot) => slot.name = name,
        None => p.lines.push(PhoneLine { name, external: false }),
    }
    Ok(())
}

/// `phone_user_get_show_call_parking`: `show_call_parking` of the first
/// phone (in container order) that has `line` in any of its twelve line
/// slots (an empty name matches a phone with a free slot); true when no
/// phone has it.
pub fn show_call_parking(line: &str) -> bool {
    let g = read();
    let Some(reg) = g.as_ref() else { return true };
    let found = reg.phones.values().find(|p| {
        (0..MAX_LINES).any(|i| p.lines.get(i).map_or("", |l| l.name.as_str()).eq_ignore_ascii_case(line))
    });
    found.is_none_or(|p| p.show_call_parking)
}

#[cfg(feature = "devtest")]
mod devtest {
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

    /// `dpmadev config <phone> [model]`: the document a ConfigRequest from
    /// a phone of `model` would get (file directory from the current
    /// configuration).
    fn config(a: &CliArgs) -> CliResult {
        if a.argc() < 3 || a.argc() > 4 {
            return CliResult::ShowUsage;
        }
        let model = a.argv.get(3).map_or("", |s| s.as_str());
        let dir = crate::util::truncate(&crate::config::get().file_directory, 0x1000);
        let mut out = String::new();
        if super::get_config(&a.argv[2], &mut out, &dir, model).is_err() {
            a.out(&format!("No such phone '{}'\n", a.argv[2]));
            return CliResult::Failure;
        }
        a.out(&out);
        CliResult::Success
    }

    /// `dpmadev contacts`: the `file://default` contacts document.
    fn contacts(a: &CliArgs) -> CliResult {
        let mut out = String::new();
        crate::users::contacts::default_contacts_xml(&mut out);
        a.out(&out);
        CliResult::Success
    }

    /// `dpmadev userlist [config password]`: the UserlistResponse body, with
    /// the password check of `handle_request_userlist`.
    fn userlist(a: &CliArgs) -> CliResult {
        if a.argc() > 3 {
            return CliResult::ShowUsage;
        }
        let pass = a.argv.get(2).map_or("", |s| s.as_str());
        let general = crate::config::get();
        let filter = pass != general.globalpin && general.auth_flags & crate::config::auth::USERLIST_GLOBALPIN != 0;
        let mut out = String::new();
        match crate::users::userlist::build_userlist_json(&mut out, filter, pass) {
            Ok(n) => a.out(&format!("{} user(s), group pin filter {}\n{}\n", n, if filter { "on" } else { "off" }, out)),
            Err(()) => a.out("Failed to build the user list\n"),
        }
        CliResult::Success
    }

    pub fn commands() -> Vec<CliCommand> {
        vec![
            CliCommand {
                command: "dpmadev config",
                summary: "Print a phone's configuration document",
                usage: "Usage: dpmadev config <phone> [model]\n",
                exec: config,
                complete: None,
            },
            CliCommand {
                command: "dpmadev contacts",
                summary: "Print the default contacts document",
                usage: "Usage: dpmadev contacts\n",
                exec: contacts,
                complete: None,
            },
            CliCommand {
                command: "dpmadev userlist",
                summary: "Print the user list",
                usage: "Usage: dpmadev userlist [config password]\n",
                exec: userlist,
                complete: None,
            },
        ]
    }
}

/// Test hooks (feature "devtest"): `dpmadev config`, `dpmadev contacts`,
/// and `dpmadev userlist`.
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    devtest::commands()
}
