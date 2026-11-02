//! `digium_phones show ...` and `digium_phones reconfigure ...` CLI
//! commands for configured objects.  Output matches the official DPMA's.

use super::*;
use dpma_ast::cli::{complete_from, CliArgs, CliCommand, CliResult, CompleteArgs};
use dpma_ast::dpma_bytes::ByteVec;
use dpma_ast::{bformat, bwriteln, dpma_log};

fn yes_no(b: bool) -> &'static str {
    if b {
        "Yes"
    } else {
        "No"
    }
}

fn or<'a, D: AsRef<[u8]> + ?Sized>(s: &'a [u8], default: &'a D) -> &'a [u8] {
    if s.is_empty() {
        default.as_ref()
    } else {
        s
    }
}

fn set_or_not(s: &[u8]) -> &'static str {
    if s.is_empty() {
        "<Not Set>"
    } else {
        "<Set>"
    }
}

/// Completion of the 4th word from the names in one of the registry maps.
fn complete_names(a: &CompleteArgs, f: fn(&Registry) -> Vec<Vec<u8>>) -> Option<Vec<u8>> {
    if a.pos != 3 {
        return None;
    }
    let names = read().as_ref().map(f).unwrap_or_default();
    complete_from(a, names)
}

fn phone_names(r: &Registry) -> Vec<Vec<u8>> {
    r.phones.values().map(|p| p.name.clone()).collect()
}
fn line_names(r: &Registry) -> Vec<Vec<u8>> {
    r.lines.values().map(|p| p.name.clone()).collect()
}
fn network_names(r: &Registry) -> Vec<Vec<u8>> {
    r.networks.values().map(|p| p.name.clone()).collect()
}
fn alert_names(r: &Registry) -> Vec<Vec<u8>> {
    r.alerts.values().map(|p| p.name.clone()).collect()
}
fn page_names(r: &Registry) -> Vec<Vec<u8>> {
    r.pages.values().map(|p| p.name.clone()).collect()
}
fn app_names(r: &Registry) -> Vec<Vec<u8>> {
    r.applications.values().map(|p| p.name.clone()).collect()
}
fn firmware_names(r: &Registry) -> Vec<Vec<u8>> {
    r.firmware.values().map(|p| p.name.clone()).collect()
}

pub(crate) fn complete_phone(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_names(a, phone_names)
}
fn complete_line(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_names(a, line_names)
}
fn complete_network(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_names(a, network_names)
}
fn complete_alert(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_names(a, alert_names)
}
fn complete_page(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_names(a, page_names)
}
fn complete_app(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_names(a, app_names)
}
fn complete_firmware(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_names(a, firmware_names)
}

/// Print a list of names (each with `indent` before it) between a header
/// and a count footer.  As in the official DPMA, only some of these
/// commands check their argument count (`check_argc`); the others ignore
/// extra words.
fn show_list(
    a: &CliArgs,
    check_argc: bool,
    header: &str,
    indent: &str,
    footer: &str,
    f: fn(&Registry) -> Vec<Vec<u8>>,
) -> CliResult {
    if check_argc && a.argc() != 3 {
        return CliResult::ShowUsage;
    }
    let names = read().as_ref().map(f).unwrap_or_default();
    a.out(header);
    for n in &names {
        a.out(bformat!("{}{}\n", indent, n));
    }
    a.out(footer.replace("{}", &names.len().to_string()));
    CliResult::Success
}

fn show_phones(a: &CliArgs) -> CliResult {
    show_list(a, false, "---- Digium Phones ----\n", "", "----  {} Phones Found    ----\n", phone_names)
}

fn show_networks(a: &CliArgs) -> CliResult {
    show_list(a, true, "--- Networks ---\n", "    ", "---- {} Networks found ----\n", network_names)
}

fn show_alerts(a: &CliArgs) -> CliResult {
    show_list(a, false, "--- Alerts ---\n", "    ", "---- {} Alerts found ----\n", alert_names)
}

fn show_pages(a: &CliArgs) -> CliResult {
    show_list(a, true, "--- Multicastpages ---\n", "    ", "---- {} Multicastpages found ----\n", page_names)
}

fn show_phone(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(p) = reg.phones.values().find(|p| p.name == a.argv[3]) else { return CliResult::Success };

    let mut o = Vec::new();
    bwriteln!(o, "Name: {}", p.name);
    bwriteln!(o, "Accept Local Calls From: {}", or(&p.accept_local_calls, "None"));
    bwriteln!(o, "Active Locale: {}", p.active_locale);
    bwriteln!(o, "Active Ringtone: {}", or(&p.active_ringtone, "Digium"));
    for x in &p.alerts {
        bwriteln!(o, "Alert: {}", x);
    }
    bwriteln!(o, "Allow insecure ssl: {}", yes_no(p.allow_insecure_ssl));
    for x in &p.applications {
        match reg.applications.get(x) {
            Some(app) => {
                let ty = app.kind.as_ref().map_or("", |k| k.type_name());
                bwriteln!(o, "Application: {}, {}", ty, app.name);
            }
            None => dpma_log!("Failed to find application '{}'", x),
        }
    }
    bwriteln!(o, "BLF on unused Line keys: {}", yes_no(p.blf_unused_linekeys));
    bwriteln!(o, "BLF page return timeout: {}", p.blf_page_return_timeout);
    bwriteln!(o, "BLF phone book: {}", or(&p.blf_contact_group, "None"));
    bwriteln!(o, "BLF Items: {}", or(&p.blf_items, "None"));
    bwriteln!(
        o,
        "Call Forwarding Application: {}",
        if p.can_forward_calls { "Enabled" } else { "Disabled" }
    );
    bwriteln!(o, "Call Waiting Tone: {}", yes_no(p.call_waiting_tone));
    bwriteln!(o, "ConfigFile: {}", or(&p.config_file, "AUTO_GENERATED"));
    for x in &p.contacts {
        bwriteln!(o, "Contact: {}", x);
    }
    bwriteln!(o, "Contacts Display Items: {}", or(&p.contacts_display_rules, "None"));
    if p.contacts_max_subscriptions == 0 {
        bwriteln!(o, "Contacts Max Subscriptions: default");
    } else {
        bwriteln!(o, "Contacts Max Subscriptions: {}", p.contacts_max_subscriptions);
    }
    if p.default_fontsize < 1 {
        bwriteln!(o, "Default Font Size: <Use Default>");
    } else {
        bwriteln!(o, "Default Font Size: {}", p.default_fontsize);
    }
    for (model, file) in &p.logos {
        bwriteln!(o, "{} Logo File: {}", model, file);
    }
    bwriteln!(o, "Display Missed Calls: {}", yes_no(p.display_mc_notification));
    bwriteln!(o, "Display Small-Format Clock: {}", yes_no(p.small_clock));
    bwriteln!(o, "Electronic Hook Switch: {}", or(&p.ehs, "None"));
    bwriteln!(o, "Enable Check Sync: {}", yes_no(p.enable_check_sync));
    bwriteln!(o, "Expansion Enabled: {}", yes_no(p.expansion_enabled));
    bwriteln!(o, "Expansion Page Indicators Enabled: {}", yes_no(p.expansion_page_indicators_enabled));
    bwriteln!(o, "Full Name: {}", p.full_name);
    bwriteln!(o, "Group Pin:  {}", set_or_not(&p.group_pin));
    if p.handset_sidetone_db != -1 {
        bwriteln!(o, "Handset Sidetone dB: {}", p.handset_sidetone_db);
    }
    if p.handset_volume == 0 {
        bwriteln!(o, "Handset Volume: <Use Default>");
    } else {
        bwriteln!(o, "Handset Volume: {}", p.handset_volume);
    }
    bwriteln!(o, "Headset Answer: {}", yes_no(p.headset_answer));
    if p.headset_sidetone_db != -1 {
        bwriteln!(o, "Headset Sidetone dB: {}", p.headset_sidetone_db);
    }
    if p.headset_volume == 0 {
        bwriteln!(o, "Headset Volume: <Use Default>");
    } else {
        bwriteln!(o, "Headset Volume: {}", p.headset_volume);
    }
    bwriteln!(o, "Idle Company Text: {}", or(&p.idle_company_text, "<Not Set>"));
    bwriteln!(o, "LAN Port Mode: {}", or(&p.lan_port_mode, "<Use Default>"));
    bwriteln!(o, "LCD Backlight Dimming: {}", if p.dim_backlight { "On" } else { "Off" });
    if p.backlight_dim_level < 0 {
        bwriteln!(o, "LCD Backlight Dimming Brightness: <Use Default>");
    } else {
        bwriteln!(o, "LCD Backlight Dimming Brightness: {}", p.backlight_dim_level);
    }
    match p.backlight_timeout {
        t if t > 0 => {
            bwriteln!(o, "LCD Backlight Timeout: {} seconds", t);
        }
        0 => {
            bwriteln!(o, "LCD Backlight Timeout: <timeout disabled>");
        }
        _ => {
            bwriteln!(o, "LCD Backlight Timeout: <use default>");
        }
    }
    if p.brightness < 0 {
        bwriteln!(o, "LCD Brightness: <Use Default>");
    } else {
        bwriteln!(o, "LCD Brightness: {}", p.brightness);
    }
    if p.contrast < 0 {
        bwriteln!(o, "LCD Contrast: <Use Default>");
    } else {
        bwriteln!(o, "LCD Contrast: {}", p.contrast);
    }
    for l in &p.lines {
        bwriteln!(o, "{}:  {}", if l.external { "Line (External)" } else { "Line" }, l.name);
    }
    bwriteln!(o, "Lock Phone Preferences: {}", yes_no(p.lock_preferences));
    bwriteln!(o, "Login Password: {}", set_or_not(&p.login_password));
    bwriteln!(o, "Logout enabled: {}", yes_no(p.logout_enabled));
    bwriteln!(o, "MAC: {}", or(&p.mac, "<none>"));
    for x in &p.multicastpages {
        bwriteln!(o, "Multicast Page: {}", x);
    }
    bwriteln!(o, "Name Format: {}", or(&p.name_format, "None"));
    for x in &p.networks {
        bwriteln!(o, "Network: {}", x);
    }
    if p.ntp_resync == 0 {
        bwriteln!(o, "NTP Resync: default");
    } else {
        bwriteln!(o, "NTP Resync: {}", p.ntp_resync as u32);
    }
    bwriteln!(o, "Parking Extension: {}", or(&p.parking_exten, "None"));
    bwriteln!(
        o,
        "Parking Transfer Type: {}",
        match p.parking_transfer_type {
            ParkingTransfer::Attended => "Attended",
            ParkingTransfer::Default => "Default",
            ParkingTransfer::Blind => "Blind",
        }
    );
    bwriteln!(o, "PC Port Mode: {}", or(&p.pc_port_mode, "<Use Default>"));
    bwriteln!(o, "Pin:  {}", set_or_not(&p.pin));
    bwriteln!(o, "Preferences Locked: {}", yes_no(p.lock_preferences));
    for x in &p.firmware {
        bwriteln!(o, "Preferred Firmware: {}", x);
    }
    bwriteln!(o, "Recording enabled: {}", yes_no(p.record_own_calls));
    bwriteln!(o, "Reset Volume levels between calls: {}", yes_no(p.reset_call_volume));
    bwriteln!(o, "Ring Headset Only: {}", yes_no(p.ring_headset_only));
    if p.ringer_volume < 0 {
        bwriteln!(o, "Ringer Volume: <Use Default>");
    } else {
        bwriteln!(o, "Ringer Volume: {}", p.ringer_volume);
    }
    for x in &p.ringtones {
        bwriteln!(o, "Ringtone: {}", x);
    }
    bwriteln!(
        o,
        "Send To Voicemail and Transfer To Voicemail: {}",
        if p.send_to_vm { "Enabled" } else { "Disabled" }
    );
    bwriteln!(o, "Show Call Log Application: {}", yes_no(p.show_call_log));
    bwriteln!(o, "Show Call Parking Application: {}", yes_no(p.show_call_parking));
    if p.speaker_volume == 0 {
        bwriteln!(o, "Speaker Volume: <Use Default>");
    } else {
        bwriteln!(o, "Speaker Volume: {}", p.speaker_volume);
    }
    bwriteln!(o, "Timezone: {}", p.timezone);
    bwriteln!(
        o,
        "Transport TLS Allowed: {}",
        match p.transport_tls_allowed {
            -1 => "<Use Default>",
            0 => "No",
            _ => "Yes",
        }
    );
    bwriteln!(o, "Use Local Contact Storage: {}", yes_no(p.use_local_storage));
    bwriteln!(o, "Use small clock: {}", yes_no(p.small_clock));
    bwriteln!(o, "Wallpaper File: {}", or(&p.wallpaper_file, "None"));
    bwriteln!(o, "Web UI enabled: {}", yes_no(p.web_ui_enabled));
    o.push(b'\n');
    a.out(&o);
    CliResult::Success
}

/// (No argument count check, as in the official DPMA.)
fn show_lines(a: &CliArgs) -> CliResult {
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let kind = |l: &Line| if l.external { "External" } else { "Internal" };
    a.out("--- Lines Mapped to Phones ---\n");
    for l in reg.lines.values().filter(|l| reg.line_is_mapped(&l.name)) {
        a.out(bformat!("    {}  {}\n", l.name, kind(l)));
    }
    a.out("--- Lines Un-Mapped to Phones ---\n");
    for l in reg.lines.values().filter(|l| !reg.line_is_mapped(&l.name)) {
        a.out(bformat!("    {}  {}\n", l.name, kind(l)));
    }
    a.out(bformat!("---- {} SIP Lines Found ----\n", reg.lines.len()));
    CliResult::Success
}

fn show_line(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    // Locked while shown, as in the official DPMA (see users::objects).
    let _line = crate::users::objects::lock_lines([a.argv[3].as_slice()]);
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(l) = reg.lines.values().find(|l| l.name == a.argv[3]) else { return CliResult::Success };

    let mut o = Vec::new();
    bwriteln!(o, "Name: {}", l.name);
    bwriteln!(o, "Type: {}", if l.external { "External Line" } else { "Internal Line" });
    bwriteln!(o, "Dialable Extension: {}", l.dialable_exten());
    bwriteln!(o, "Context: {}", l.context);
    bwriteln!(o, "Subscribe Context: {}", l.hint_context);
    bwriteln!(o, "Transport: {}", l.transport.type_str());
    bwriteln!(o, "Digitmap: {}", l.digit_map);
    bwriteln!(o, "Line Label: {}", l.line_label);
    bwriteln!(o, "Mailbox: {}", l.mailbox);
    bwriteln!(o, "PLAR Number: {}", l.plar_number);
    if l.reregistration_timeout != 0 {
        bwriteln!(o, "Re-registration: {}", l.reregistration_timeout);
    }
    if l.registration_retry_interval != 0 {
        bwriteln!(o, "Registration Retry Interval: {}", l.registration_retry_interval);
    }
    if l.registration_max_retries != 0 {
        bwriteln!(o, "Registration Max Retries: {}", l.registration_max_retries);
    }
    if !l.server_address.is_empty() {
        bwriteln!(o, "SIP Secret: {}", if l.secret.is_empty() { "<not set>" } else { "<set>" });
        bwriteln!(o, "Server Address: {}", l.server_address);
        bwriteln!(o, "Server Port: {}", l.server_port);
        bwriteln!(o, "Transport: {}", l.transport.type_str());
        bwriteln!(o, "Media Encryption: {}", l.media_encryption);
        bwriteln!(o, "Secondary Server Address: {}", l.secondary_server_address);
        bwriteln!(o, "Secondary Server Port: {}", l.secondary_server_port);
        bwriteln!(o, "Secondary Server Transport: {}", l.secondary_server_transport.type_str());
        bwriteln!(o, "Secondary Media Encryption: {}", l.secondary_media_encryption);
        // Deviation (plan section 8, item 15): the official DPMA prints the
        // secondary server port here (the field at +0x120, not authname's
        // at +0x128).
        bwriteln!(o, "AuthName: {}", l.authname);
        bwriteln!(o, "UserID: {}", l.userid);
        bwriteln!(o, "Register: {}", if l.no_register { "NO" } else { "YES" });
    }
    bwriteln!(o, "First Name: {}", l.first_name);
    bwriteln!(o, "Last Name: {}", l.last_name);
    bwriteln!(o, "Location: {}", l.location);
    bwriteln!(o, "Title: {}", l.title);
    o.push(b'\n');
    a.out(bformat!("{}\n", o));
    CliResult::Success
}

fn show_network(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(n) = reg.networks.values().find(|n| n.name == a.argv[3]) else { return CliResult::Success };
    let ns = |s: &[u8]| or(s, "<Not Set>").to_vec();

    let mut o = Vec::new();
    bwriteln!(o, "Name: {}", n.name);
    bwriteln!(o, "Alias: {}", ns(&n.alias));
    bwriteln!(o, "CIDR: {}", ns(&n.cidr));
    bwriteln!(o, "Registration Address: {}", ns(&n.registration_address));
    bwriteln!(o, "Registration Port: {}", ns(&n.registration_port));
    bwriteln!(o, "Transport: {}", n.transport.type_str());
    bwriteln!(o, "File URL Prefix: {}", ns(&n.file_url_prefix));
    bwriteln!(o, "Public Firmware URL Prefix: {}", or(&n.public_firmware_url_prefix, "<Use Default>"));
    bwriteln!(o, "NTP Server: {}", ns(&n.ntp_server));
    bwriteln!(o, "syslog Server: {}", ns(&n.syslog_server));
    bwriteln!(o, "syslog Port: {}", ns(&n.syslog_port));
    bwriteln!(o, "Network VLAN Discovery Mode: {}", ns(&n.network_vlan_discovery_mode));
    bwriteln!(o, "Network VLAN ID: {}", n.network_vlan_id);
    bwriteln!(o, "PC VLAN ID: {}", n.pc_vlan_id);
    bwriteln!(o, "SIP Quality of Service Level: {}", n.sip_qos);
    bwriteln!(o, "RTP Quality of Service Level: {}", if n.rtp_qos == -1 { 6 } else { n.rtp_qos });
    bwriteln!(o, "PC Quality of Service Level: {}", n.pc_qos);
    bwriteln!(o, "SIP DSCP: {}", n.sip_dscp);
    bwriteln!(o, "RTP DSCP: {}", n.rtp_dscp);
    bwriteln!(o, "UDP Keep Alive Interval: {}", n.udp_ka_interval);
    o.push(b'\n');
    a.out(bformat!("{}\n", o));
    CliResult::Success
}

fn show_alert(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(x) = reg.alerts.values().find(|x| x.name == a.argv[3]) else { return CliResult::Success };
    let mut o = Vec::new();
    bwriteln!(o, "Name: {}", x.name);
    bwriteln!(o, "Alert Info: {}", or(&x.alert_info, "<Not Set>"));
    bwriteln!(o, "Ring Type: {}", or(&x.ring_type, "<Not Set>"));
    bwriteln!(o, "Ring Tone: {}", or(&x.ringtone, "<Not Set>"));
    o.push(b'\n');
    a.out(bformat!("{}\n", o));
    CliResult::Success
}

fn show_page(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(x) = reg.pages.values().find(|x| x.name == a.argv[3]) else { return CliResult::Success };
    let mut o = Vec::new();
    bwriteln!(o, "Name: {}", x.name);
    bwriteln!(o, "Alias: {}", or(&x.alias, "<Not Set>"));
    bwriteln!(o, "Address: {}", or(&x.address, "<Not Set>"));
    bwriteln!(o, "Port: {}", or(&x.port, "<Not Set>"));
    bwriteln!(o, "Priority: {}", or(&x.priority, "<Not Set>"));
    bwriteln!(o, "Interrupt: {}", or(&x.interrupt, "<Not Set>"));
    o.push(b'\n');
    a.out(bformat!("{}\n", o));
    CliResult::Success
}

/// (No argument count check, as in the official DPMA.)
fn show_firmwares(a: &CliArgs) -> CliResult {
    crate::firmware::cli_display(a);
    a.out("--- Configured Firmware Options ---\n");
    for n in read().as_ref().map(firmware_names).unwrap_or_default() {
        a.out(bformat!("{}\n", n));
    }
    a.out("\n");
    CliResult::Success
}

fn show_firmware(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(f) = g.as_ref().and_then(|r| r.firmware.get(&a.argv[3])) else {
        dpma_log!("Unknown Firmware - '{}'", a.argv[3]);
        return CliResult::Success;
    };
    a.out(bformat!("Name: {}\n", f.name));
    a.out(bformat!("Model: {}\n", f.model));
    a.out(bformat!("Version: {}\n", f.version));
    a.out(bformat!("File: {}\n", f.file));
    a.out(bformat!("Use public firmware: {}\n", if f.public_firmware { "yes" } else { "no" }));
    CliResult::Success
}

fn show_applications(a: &CliArgs) -> CliResult {
    if a.argc() != 3 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    a.out("--- Applications ---\n");
    for app in reg.applications.values() {
        let ty = app.kind.as_ref().map_or("", |k| k.type_name());
        a.out(bformat!("    {} : {}\n", ty, app.name));
    }
    a.out(bformat!("---- {} Applications found ----\n", reg.applications.len()));
    CliResult::Success
}

fn show_application(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(app) = reg.applications.values().find(|x| x.name == a.argv[3]) else { return CliResult::Success };
    let mut o = Vec::new();
    bwriteln!(o, "{}", app.name);
    match &app.kind {
        Some(AppKind::Queue(q)) => {
            o.push_str("Queue Application\n-----------------\n");
            bwriteln!(o, "Queue: {}", q.queue);
            bwriteln!(o, "Member Name: {}", q.membername);
            bwriteln!(o, "Location: {}", q.location);
            bwriteln!(o, "Member: {}", if q.member { "yes" } else { "no" });
            bwriteln!(
                o,
                "Permission: {}",
                match q.permission {
                    QueuePermission::Status => "Status",
                    QueuePermission::Overview => "Overview",
                    QueuePermission::Details => "Details",
                }
            );
            bwriteln!(o, "Login Extension: {}", q.login_exten);
            // Deviation (plan section 8, item 15): the official DPMA shows
            // the login extension here (it prints the login field when the
            // logout field's pointer is set).
            bwriteln!(o, "Logout Extension: {}", q.logout_exten);
        }
        Some(AppKind::Status(s)) => {
            o.push_str("Status Application\n-------------------\n");
            bwriteln!(o, "Status: {}", dpma_ast::presence::state2str(s.status));
            // Deviation (plan section 8, item 15): the official DPMA shows
            // send486=yes as "No".
            bwriteln!(
                o,
                "Send486: {}",
                match s.send486 {
                    Send486::NotSet => "<Not Set>",
                    Send486::No => "No",
                    Send486::Yes => "Yes",
                }
            );
            if !s.substatuses.is_empty() {
                o.push_str("Substatuses:\n");
                for x in &s.substatuses {
                    bwriteln!(o, "    {}", x);
                }
            }
        }
        Some(AppKind::Parking(p)) => {
            o.push_str("Parking Application\n--------------------\n");
            if p.parkinglots.is_empty() {
                o.push_str("No Parkinglots specified\n");
            } else {
                o.push_str("Parkinglots:\n");
                for x in &p.parkinglots {
                    bwriteln!(o, "    {}", x);
                }
            }
        }
        Some(AppKind::Voicemail(v)) => {
            o.push_str("Visual Voicemail Application\n----------------------------\n");
            bwriteln!(o, "Require password: {}", yes_no(v.require_password));
            o.push_str("Folder Translations:\n");
            match v.translation.as_deref().and_then(crate::translation::get) {
                Some(t) => {
                    for (k, val) in &t.entries {
                        bwriteln!(o, "    {} ==> {}", k, val);
                    }
                }
                None => o.push_str("    None\n"),
            }
        }
        Some(AppKind::Custom(c)) => {
            o.push_str("Custom Application\n------------------\n");
            bwriteln!(o, "Name: {}", c.name);
            bwriteln!(o, "File Name: {}", c.filename);
            bwriteln!(o, "MD5 Sum: {}", c.md5);
            bwriteln!(o, "Autostart: {}", yes_no(c.autostart));
            bwriteln!(o, "Idle Screen Softkey: {}", yes_no(c.idlescreen_softkey));
            if !c.settings.is_empty() {
                o.push_str("Custom Application Specific Settings:\n");
                for (k, v) in &c.settings {
                    bwriteln!(o, "    {}: {}", k, v);
                }
            }
        }
        None => {}
    }
    a.out(bformat!("{}\n", o));
    CliResult::Success
}

fn show_tokens(a: &CliArgs) -> CliResult {
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    a.out("---- Valid Tokens ----\n");
    let mut n = 0;
    for p in reg.phones.values() {
        if !p.last_mac.is_empty() || !p.last_uri.is_empty() || !p.last_session_id.is_empty() {
            n += 1;
            a.out(bformat!(
                "{}  MAC:{}  URI:{:<30} SessionID:{}\n",
                p.name, p.last_mac, p.last_uri, p.last_session_id
            ));
        }
    }
    a.out(bformat!("----  {} Tokens Found    ----\n", n));
    CliResult::Success
}

fn reconfigure_all(a: &CliArgs) -> CliResult {
    let names = read().as_ref().map(phone_names).unwrap_or_default();
    for n in names {
        let _ = reconfigure(&n, false);
    }
    a.out("Reconfigure message successfully sent to all known device locations.\n");
    CliResult::Success
}

fn reconfigure_phone(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let display = {
        let g = read();
        match g.as_ref().and_then(|r| r.phones.get(&a.argv[3])) {
            Some(p) => or(&p.full_name, &p.name).to_vec(),
            None => {
                a.out(bformat!("Could not find user with name '{}' to reconfigure.\n", a.argv[3]));
                return CliResult::Success;
            }
        }
    };
    if reconfigure(&a.argv[3], false).is_ok() {
        a.out(bformat!("Phone '{}' will reconfigure shortly.\n", display));
    } else {
        a.out(bformat!(
            "Phone '{}' has not contacted the server.  The server is unaware of the location of this device and can not reconfigure it at this time.\n",
            display
        ));
    }
    CliResult::Success
}

macro_rules! cmd {
    ($cmd:expr, $usage:expr, $exec:expr) => {
        CliCommand { command: $cmd, summary: $cmd, usage: $usage, exec: $exec, complete: None }
    };
    ($cmd:expr, $usage:expr, $exec:expr, $complete:expr) => {
        CliCommand { command: $cmd, summary: $cmd, usage: $usage, exec: $exec, complete: Some($complete) }
    };
}

/// The commands registered by the phone users subsystem.
pub fn commands() -> Vec<CliCommand> {
    vec![
        cmd!("digium_phones show phone", "Usage digium_phones show phone <phone name>\n", show_phone, complete_phone),
        cmd!("digium_phones show phones", "Usage digium_phones show phones\n", show_phones),
        cmd!("digium_phones show lines", "Usage digium_phones show lines\n", show_lines),
        cmd!("digium_phones show line", "Usage digium_phones show line <line name>\n", show_line, complete_line),
        cmd!("digium_phones show alerts", "Usage digium_phones show alerts\n", show_alerts),
        // The official DPMA's summary has this typo ("core show help").
        CliCommand {
            command: "digium_phones show alert",
            summary: "digum_phones show alert",
            usage: "Usage digium_phones show alert <alert name>\n",
            exec: show_alert,
            complete: Some(complete_alert),
        },
        cmd!("digium_phones show networks", "Usage digium_phones show networks\n", show_networks),
        cmd!(
            "digium_phones show network",
            "Usage digium_phones show network <network name>\n",
            show_network,
            complete_network
        ),
        cmd!("digium_phones show applications", "Usage digium_phones show applications\n", show_applications),
        cmd!(
            "digium_phones show application",
            "Usage digium_phones show application <application name>\n",
            show_application,
            complete_app
        ),
        cmd!(
            "digium_phones show firmware",
            "Usage digium_phones show firmware <firmware_opt name>\n",
            show_firmware,
            complete_firmware
        ),
        cmd!("digium_phones show firmwares", "Usage digium_phones show firmwares\n", show_firmwares),
        cmd!(
            "digium_phones show tokens",
            "Usage: digium_phones show tokens\n       Shows a list of active configuration tokens by phone user\n",
            show_tokens
        ),
        cmd!("digium_phones show multicastpages", "Usage digium_phones show multicastpages\n", show_pages),
        cmd!(
            "digium_phones show multicastpage",
            "Usage digium_phones show multicastpage <page name>\n",
            show_page,
            complete_page
        ),
        cmd!(
            "digium_phones reconfigure phone",
            "Usage digium_phones reconfigure phone [<phone name>]\n",
            reconfigure_phone,
            complete_phone
        ),
        cmd!("digium_phones reconfigure all", "Usage digium_phones reconfigure all\n", reconfigure_all),
    ]
}
