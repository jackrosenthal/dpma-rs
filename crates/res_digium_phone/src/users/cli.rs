//! `digium_phones show ...` and `digium_phones reconfigure ...` CLI
//! commands for configured objects.  Output matches the original module.

use super::*;
use dpma_ast::cli::{complete_from, CliArgs, CliCommand, CliResult, CompleteArgs};
use dpma_ast::dpma_log;
use std::fmt::Write;

fn yes_no(b: bool) -> &'static str {
    if b {
        "Yes"
    } else {
        "No"
    }
}

fn or<'a>(s: &'a str, default: &'a str) -> &'a str {
    if s.is_empty() {
        default
    } else {
        s
    }
}

fn set_or_not(s: &str) -> &'static str {
    if s.is_empty() {
        "<Not Set>"
    } else {
        "<Set>"
    }
}

/// Completion of the 4th word from the names in one of the registry maps.
fn complete_names(a: &CompleteArgs, f: fn(&Registry) -> Vec<String>) -> Option<String> {
    if a.pos != 3 {
        return None;
    }
    let names = read().as_ref().map(f).unwrap_or_default();
    complete_from(a, names)
}

fn phone_names(r: &Registry) -> Vec<String> {
    r.phones.values().map(|p| p.name.clone()).collect()
}
fn line_names(r: &Registry) -> Vec<String> {
    r.lines.values().map(|p| p.name.clone()).collect()
}
fn network_names(r: &Registry) -> Vec<String> {
    r.networks.values().map(|p| p.name.clone()).collect()
}
fn alert_names(r: &Registry) -> Vec<String> {
    r.alerts.values().map(|p| p.name.clone()).collect()
}
fn page_names(r: &Registry) -> Vec<String> {
    r.pages.values().map(|p| p.name.clone()).collect()
}
fn app_names(r: &Registry) -> Vec<String> {
    r.applications.values().map(|p| p.name.clone()).collect()
}
fn firmware_names(r: &Registry) -> Vec<String> {
    r.firmware.values().map(|p| p.name.clone()).collect()
}

pub(crate) fn complete_phone(a: &CompleteArgs) -> Option<String> {
    complete_names(a, phone_names)
}
fn complete_line(a: &CompleteArgs) -> Option<String> {
    complete_names(a, line_names)
}
fn complete_network(a: &CompleteArgs) -> Option<String> {
    complete_names(a, network_names)
}
fn complete_alert(a: &CompleteArgs) -> Option<String> {
    complete_names(a, alert_names)
}
fn complete_page(a: &CompleteArgs) -> Option<String> {
    complete_names(a, page_names)
}
fn complete_app(a: &CompleteArgs) -> Option<String> {
    complete_names(a, app_names)
}
fn complete_firmware(a: &CompleteArgs) -> Option<String> {
    complete_names(a, firmware_names)
}

/// Print a list of names between a header and a count footer.
fn show_list(a: &CliArgs, header: &str, footer: &str, f: fn(&Registry) -> Vec<String>) -> CliResult {
    if a.argc() != 3 {
        return CliResult::ShowUsage;
    }
    let names = read().as_ref().map(f).unwrap_or_default();
    a.out(header);
    for n in &names {
        a.out(&format!("{}\n", n));
    }
    a.out(&footer.replace("{}", &names.len().to_string()));
    CliResult::Success
}

fn show_phones(a: &CliArgs) -> CliResult {
    show_list(a, "---- Digium Phones ----\n", "----  {} Phones Found    ----\n", phone_names)
}

fn show_networks(a: &CliArgs) -> CliResult {
    show_list(a, "--- Networks ---\n", "---- {} Networks found ----\n", network_names)
}

fn show_alerts(a: &CliArgs) -> CliResult {
    show_list(a, "--- Alerts ---\n", "---- {} Alerts found ----\n", alert_names)
}

fn show_pages(a: &CliArgs) -> CliResult {
    show_list(a, "--- Multicastpages ---\n", "---- {} Multicastpages found ----\n", page_names)
}

fn show_phone(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(p) = reg.phones.values().find(|p| p.name == a.argv[3]) else { return CliResult::Success };

    let mut o = String::new();
    let _ = writeln!(o, "Name: {}", p.name);
    let _ = writeln!(o, "Accept Local Calls From: {}", or(&p.accept_local_calls, "None"));
    let _ = writeln!(o, "Active Locale: {}", p.active_locale);
    let _ = writeln!(o, "Active Ringtone: {}", or(&p.active_ringtone, "Digium"));
    for x in &p.alerts {
        let _ = writeln!(o, "Alert: {}", x);
    }
    let _ = writeln!(o, "Allow insecure ssl: {}", yes_no(p.allow_insecure_ssl));
    for x in &p.applications {
        match reg.applications.get(x) {
            Some(app) => {
                let ty = app.kind.as_ref().map_or("", |k| k.type_name());
                let _ = writeln!(o, "Application: {}, {}", ty, app.name);
            }
            None => dpma_log!("Failed to find application '{}'", x),
        }
    }
    let _ = writeln!(o, "BLF on unused Line keys: {}", yes_no(p.blf_unused_linekeys));
    let _ = writeln!(o, "BLF page return timeout: {}", p.blf_page_return_timeout);
    let _ = writeln!(o, "BLF phone book: {}", or(&p.blf_contact_group, "None"));
    let _ = writeln!(o, "BLF Items: {}", or(&p.blf_items, "None"));
    let _ = writeln!(
        o,
        "Call Forwarding Application: {}",
        if p.can_forward_calls { "Enabled" } else { "Disabled" }
    );
    let _ = writeln!(o, "Call Waiting Tone: {}", yes_no(p.call_waiting_tone));
    let _ = writeln!(o, "ConfigFile: {}", or(&p.config_file, "AUTO_GENERATED"));
    for x in &p.contacts {
        let _ = writeln!(o, "Contact: {}", x);
    }
    let _ = writeln!(o, "Contacts Display Items: {}", or(&p.contacts_display_rules, "None"));
    if p.contacts_max_subscriptions == 0 {
        let _ = writeln!(o, "Contacts Max Subscriptions: default");
    } else {
        let _ = writeln!(o, "Contacts Max Subscriptions: {}", p.contacts_max_subscriptions);
    }
    if p.default_fontsize < 1 {
        let _ = writeln!(o, "Default Font Size: <Use Default>");
    } else {
        let _ = writeln!(o, "Default Font Size: {}", p.default_fontsize);
    }
    for (model, file) in &p.logos {
        let _ = writeln!(o, "{} Logo File: {}", model, file);
    }
    let _ = writeln!(o, "Display Missed Calls: {}", yes_no(p.display_mc_notification));
    let _ = writeln!(o, "Display Small-Format Clock: {}", yes_no(p.small_clock));
    let _ = writeln!(o, "Electronic Hook Switch: {}", or(&p.ehs, "None"));
    let _ = writeln!(o, "Enable Check Sync: {}", yes_no(p.enable_check_sync));
    let _ = writeln!(o, "Expansion Enabled: {}", yes_no(p.expansion_enabled));
    let _ = writeln!(o, "Expansion Page Indicators Enabled: {}", yes_no(p.expansion_page_indicators_enabled));
    let _ = writeln!(o, "Full Name: {}", p.full_name);
    let _ = writeln!(o, "Group Pin:  {}", set_or_not(&p.group_pin));
    if p.handset_sidetone_db != -1 {
        let _ = writeln!(o, "Handset Sidetone dB: {}", p.handset_sidetone_db);
    }
    if p.handset_volume == 0 {
        let _ = writeln!(o, "Handset Volume: <Use Default>");
    } else {
        let _ = writeln!(o, "Handset Volume: {}", p.handset_volume);
    }
    let _ = writeln!(o, "Headset Answer: {}", yes_no(p.headset_answer));
    if p.headset_sidetone_db != -1 {
        let _ = writeln!(o, "Headset Sidetone dB: {}", p.headset_sidetone_db);
    }
    if p.headset_volume == 0 {
        let _ = writeln!(o, "Headset Volume: <Use Default>");
    } else {
        let _ = writeln!(o, "Headset Volume: {}", p.headset_volume);
    }
    let _ = writeln!(o, "Idle Company Text: {}", or(&p.idle_company_text, "<Not Set>"));
    let _ = writeln!(o, "LAN Port Mode: {}", or(&p.lan_port_mode, "<Use Default>"));
    let _ = writeln!(o, "LCD Backlight Dimming: {}", if p.dim_backlight { "On" } else { "Off" });
    if p.backlight_dim_level < 0 {
        let _ = writeln!(o, "LCD Backlight Dimming Brightness: <Use Default>");
    } else {
        let _ = writeln!(o, "LCD Backlight Dimming Brightness: {}", p.backlight_dim_level);
    }
    match p.backlight_timeout {
        t if t > 0 => {
            let _ = writeln!(o, "LCD Backlight Timeout: {} seconds", t);
        }
        0 => {
            let _ = writeln!(o, "LCD Backlight Timeout: <timeout disabled>");
        }
        _ => {
            let _ = writeln!(o, "LCD Backlight Timeout: <use default>");
        }
    }
    if p.brightness < 0 {
        let _ = writeln!(o, "LCD Brightness: <Use Default>");
    } else {
        let _ = writeln!(o, "LCD Brightness: {}", p.brightness);
    }
    if p.contrast < 0 {
        let _ = writeln!(o, "LCD Contrast: <Use Default>");
    } else {
        let _ = writeln!(o, "LCD Contrast: {}", p.contrast);
    }
    for l in &p.lines {
        let _ = writeln!(o, "{}:  {}", if l.external { "Line (External)" } else { "Line" }, l.name);
    }
    let _ = writeln!(o, "Lock Phone Preferences: {}", yes_no(p.lock_preferences));
    let _ = writeln!(o, "Login Password: {}", set_or_not(&p.login_password));
    let _ = writeln!(o, "Logout enabled: {}", yes_no(p.logout_enabled));
    let _ = writeln!(o, "MAC: {}", or(&p.mac, "<none>"));
    for x in &p.multicastpages {
        let _ = writeln!(o, "Multicast Page: {}", x);
    }
    let _ = writeln!(o, "Name Format: {}", or(&p.name_format, "None"));
    for x in &p.networks {
        let _ = writeln!(o, "Network: {}", x);
    }
    if p.ntp_resync == 0 {
        let _ = writeln!(o, "NTP Resync: default");
    } else {
        let _ = writeln!(o, "NTP Resync: {}", p.ntp_resync as u32);
    }
    let _ = writeln!(o, "Parking Extension: {}", or(&p.parking_exten, "None"));
    let _ = writeln!(
        o,
        "Parking Transfer Type: {}",
        match p.parking_transfer_type {
            ParkingTransfer::Attended => "Attended",
            ParkingTransfer::Default => "Default",
            ParkingTransfer::Blind => "Blind",
        }
    );
    let _ = writeln!(o, "PC Port Mode: {}", or(&p.pc_port_mode, "<Use Default>"));
    let _ = writeln!(o, "Pin:  {}", set_or_not(&p.pin));
    let _ = writeln!(o, "Preferences Locked: {}", yes_no(p.lock_preferences));
    for x in &p.firmware {
        let _ = writeln!(o, "Preferred Firmware: {}", x);
    }
    let _ = writeln!(o, "Recording enabled: {}", yes_no(p.record_own_calls));
    let _ = writeln!(o, "Reset Volume levels between calls: {}", yes_no(p.reset_call_volume));
    let _ = writeln!(o, "Ring Headset Only: {}", yes_no(p.ring_headset_only));
    if p.ringer_volume < 0 {
        let _ = writeln!(o, "Ringer Volume: <Use Default>");
    } else {
        let _ = writeln!(o, "Ringer Volume: {}", p.ringer_volume);
    }
    for x in &p.ringtones {
        let _ = writeln!(o, "Ringtone: {}", x);
    }
    let _ = writeln!(
        o,
        "Send To Voicemail and Transfer To Voicemail: {}",
        if p.send_to_vm { "Enabled" } else { "Disabled" }
    );
    let _ = writeln!(o, "Show Call Log Application: {}", yes_no(p.show_call_log));
    let _ = writeln!(o, "Show Call Parking Application: {}", yes_no(p.show_call_parking));
    if p.speaker_volume == 0 {
        let _ = writeln!(o, "Speaker Volume: <Use Default>");
    } else {
        let _ = writeln!(o, "Speaker Volume: {}", p.speaker_volume);
    }
    let _ = writeln!(o, "Timezone: {}", p.timezone);
    let _ = writeln!(
        o,
        "Transport TLS Allowed: {}",
        match p.transport_tls_allowed {
            -1 => "<Use Default>",
            0 => "No",
            _ => "Yes",
        }
    );
    let _ = writeln!(o, "Use Local Contact Storage: {}", yes_no(p.use_local_storage));
    let _ = writeln!(o, "Use small clock: {}", yes_no(p.small_clock));
    let _ = writeln!(o, "Wallpaper File: {}", or(&p.wallpaper_file, "None"));
    let _ = writeln!(o, "Web UI enabled: {}", yes_no(p.web_ui_enabled));
    o.push('\n');
    a.out(&o);
    CliResult::Success
}

fn show_lines(a: &CliArgs) -> CliResult {
    if a.argc() != 3 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let kind = |l: &Line| if l.external { "External" } else { "Internal" };
    a.out("--- Lines Mapped to Phones ---\n");
    for l in reg.lines.values().filter(|l| reg.line_is_mapped(&l.name)) {
        a.out(&format!("    {}  {}\n", l.name, kind(l)));
    }
    a.out("--- Lines Un-Mapped to Phones ---\n");
    for l in reg.lines.values().filter(|l| !reg.line_is_mapped(&l.name)) {
        a.out(&format!("    {}  {}\n", l.name, kind(l)));
    }
    a.out(&format!("---- {} SIP Lines Found ----\n", reg.lines.len()));
    CliResult::Success
}

fn show_line(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    // Locked while shown, as in the original (see exports::objects).
    let _line = crate::exports::objects::lock_lines([a.argv[3].as_str()]);
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(l) = reg.lines.values().find(|l| l.name == a.argv[3]) else { return CliResult::Success };

    let mut o = String::new();
    let _ = writeln!(o, "Name: {}", l.name);
    let _ = writeln!(o, "Type: {}", if l.external { "External Line" } else { "Internal Line" });
    let _ = writeln!(o, "Dialable Extension: {}", l.dialable_exten());
    let _ = writeln!(o, "Context: {}", l.context);
    let _ = writeln!(o, "Subscribe Context: {}", l.hint_context);
    let _ = writeln!(o, "Transport: {}", l.transport.type_str());
    let _ = writeln!(o, "Digitmap: {}", l.digit_map);
    let _ = writeln!(o, "Line Label: {}", l.line_label);
    let _ = writeln!(o, "Mailbox: {}", l.mailbox);
    let _ = writeln!(o, "PLAR Number: {}", l.plar_number);
    if l.reregistration_timeout != 0 {
        let _ = writeln!(o, "Re-registration: {}", l.reregistration_timeout);
    }
    if l.registration_retry_interval != 0 {
        let _ = writeln!(o, "Registration Retry Interval: {}", l.registration_retry_interval);
    }
    if l.registration_max_retries != 0 {
        let _ = writeln!(o, "Registration Max Retries: {}", l.registration_max_retries);
    }
    if !l.server_address.is_empty() {
        let _ = writeln!(o, "SIP Secret: {}", if l.secret.is_empty() { "<not set>" } else { "<set>" });
        let _ = writeln!(o, "Server Address: {}", l.server_address);
        let _ = writeln!(o, "Server Port: {}", l.server_port);
        let _ = writeln!(o, "Transport: {}", l.transport.type_str());
        let _ = writeln!(o, "Media Encryption: {}", l.media_encryption);
        let _ = writeln!(o, "Secondary Server Address: {}", l.secondary_server_address);
        let _ = writeln!(o, "Secondary Server Port: {}", l.secondary_server_port);
        let _ = writeln!(o, "Secondary Server Transport: {}", l.secondary_server_transport.type_str());
        let _ = writeln!(o, "Secondary Media Encryption: {}", l.secondary_media_encryption);
        // The original prints the secondary server port here by mistake.
        let _ = writeln!(o, "AuthName: {}", l.authname);
        let _ = writeln!(o, "UserID: {}", l.userid);
        let _ = writeln!(o, "Register: {}", if l.no_register { "NO" } else { "YES" });
    }
    let _ = writeln!(o, "First Name: {}", l.first_name);
    let _ = writeln!(o, "Last Name: {}", l.last_name);
    let _ = writeln!(o, "Location: {}", l.location);
    let _ = writeln!(o, "Title: {}", l.title);
    o.push('\n');
    a.out(&format!("{}\n", o));
    CliResult::Success
}

fn show_network(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(n) = reg.networks.values().find(|n| n.name == a.argv[3]) else { return CliResult::Success };
    let ns = |s: &str| or(s, "<Not Set>").to_string();

    let mut o = String::new();
    let _ = writeln!(o, "Name: {}", n.name);
    let _ = writeln!(o, "Alias: {}", ns(&n.alias));
    let _ = writeln!(o, "CIDR: {}", ns(&n.cidr));
    let _ = writeln!(o, "Registration Address: {}", ns(&n.registration_address));
    let _ = writeln!(o, "Registration Port: {}", ns(&n.registration_port));
    let _ = writeln!(o, "Transport: {}", n.transport.type_str());
    let _ = writeln!(o, "File URL Prefix: {}", ns(&n.file_url_prefix));
    let _ = writeln!(o, "Public Firmware URL Prefix: {}", or(&n.public_firmware_url_prefix, "<Use Default>"));
    let _ = writeln!(o, "NTP Server: {}", ns(&n.ntp_server));
    let _ = writeln!(o, "syslog Server: {}", ns(&n.syslog_server));
    let _ = writeln!(o, "syslog Port: {}", ns(&n.syslog_port));
    let _ = writeln!(o, "Network VLAN Discovery Mode: {}", ns(&n.network_vlan_discovery_mode));
    let _ = writeln!(o, "Network VLAN ID: {}", n.network_vlan_id);
    let _ = writeln!(o, "PC VLAN ID: {}", n.pc_vlan_id);
    let _ = writeln!(o, "SIP Quality of Service Level: {}", n.sip_qos);
    let _ = writeln!(o, "RTP Quality of Service Level: {}", if n.rtp_qos == -1 { 6 } else { n.rtp_qos });
    let _ = writeln!(o, "PC Quality of Service Level: {}", n.pc_qos);
    let _ = writeln!(o, "SIP DSCP: {}", n.sip_dscp);
    let _ = writeln!(o, "RTP DSCP: {}", n.rtp_dscp);
    let _ = writeln!(o, "UDP Keep Alive Interval: {}", n.udp_ka_interval);
    o.push('\n');
    a.out(&format!("{}\n", o));
    CliResult::Success
}

fn show_alert(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(x) = reg.alerts.values().find(|x| x.name == a.argv[3]) else { return CliResult::Success };
    let mut o = String::new();
    let _ = writeln!(o, "Name: {}", x.name);
    let _ = writeln!(o, "Alert Info: {}", or(&x.alert_info, "<Not Set>"));
    let _ = writeln!(o, "Ring Type: {}", or(&x.ring_type, "<Not Set>"));
    let _ = writeln!(o, "Ring Tone: {}", or(&x.ringtone, "<Not Set>"));
    o.push('\n');
    a.out(&format!("{}\n", o));
    CliResult::Success
}

fn show_page(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(x) = reg.pages.values().find(|x| x.name == a.argv[3]) else { return CliResult::Success };
    let mut o = String::new();
    let _ = writeln!(o, "Name: {}", x.name);
    let _ = writeln!(o, "Alias: {}", or(&x.alias, "<Not Set>"));
    let _ = writeln!(o, "Address: {}", or(&x.address, "<Not Set>"));
    let _ = writeln!(o, "Port: {}", or(&x.port, "<Not Set>"));
    let _ = writeln!(o, "Priority: {}", or(&x.priority, "<Not Set>"));
    let _ = writeln!(o, "Interrupt: {}", or(&x.interrupt, "<Not Set>"));
    o.push('\n');
    a.out(&format!("{}\n", o));
    CliResult::Success
}

fn show_firmwares(a: &CliArgs) -> CliResult {
    if a.argc() != 3 {
        return CliResult::ShowUsage;
    }
    crate::firmware::cli_display(a);
    a.out("--- Configured Firmware Options ---\n");
    for n in read().as_ref().map(firmware_names).unwrap_or_default() {
        a.out(&format!("{}\n", n));
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
    a.out(&format!("Name: {}\n", f.name));
    a.out(&format!("Model: {}\n", f.model));
    a.out(&format!("Version: {}\n", f.version));
    a.out(&format!("File: {}\n", f.file));
    a.out(&format!("Use public firmware: {}\n", if f.public_firmware { "yes" } else { "no" }));
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
        a.out(&format!("    {} : {}\n", ty, app.name));
    }
    a.out(&format!("---- {} Applications found ----\n", reg.applications.len()));
    CliResult::Success
}

fn show_application(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let g = read();
    let Some(reg) = g.as_ref() else { return CliResult::Success };
    let Some(app) = reg.applications.values().find(|x| x.name == a.argv[3]) else { return CliResult::Success };
    let mut o = String::new();
    let _ = writeln!(o, "{}", app.name);
    match &app.kind {
        Some(AppKind::Queue(q)) => {
            o.push_str("Queue Application\n-----------------\n");
            let _ = writeln!(o, "Queue: {}", q.queue);
            let _ = writeln!(o, "Member Name: {}", q.membername);
            let _ = writeln!(o, "Location: {}", q.location);
            let _ = writeln!(o, "Member: {}", if q.member { "yes" } else { "no" });
            let _ = writeln!(
                o,
                "Permission: {}",
                match q.permission {
                    QueuePermission::Status => "Status",
                    QueuePermission::Overview => "Overview",
                    QueuePermission::Details => "Details",
                }
            );
            let _ = writeln!(o, "Login Extension: {}", q.login_exten);
            // The original shows the login extension here.
            let _ = writeln!(o, "Logout Extension: {}", or(&q.logout_exten, "<Not Set>"));
        }
        Some(AppKind::Status(s)) => {
            o.push_str("Status Application\n-------------------\n");
            let _ = writeln!(o, "Status: {}", dpma_ast::presence::state2str(s.status));
            let _ = writeln!(
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
                    let _ = writeln!(o, "{}", x);
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
                    let _ = writeln!(o, "{}", x);
                }
            }
        }
        Some(AppKind::Voicemail(v)) => {
            o.push_str("Visual Voicemail Application\n----------------------------\n");
            let _ = writeln!(o, "Require password: {}", yes_no(v.require_password));
            o.push_str("Folder Translations:\n");
            match v.translation.as_deref().and_then(crate::translation::get) {
                Some(t) => {
                    for (k, val) in &t.entries {
                        let _ = writeln!(o, "    {} ==> {}", k, val);
                    }
                }
                None => o.push_str("    None\n"),
            }
        }
        Some(AppKind::Custom(c)) => {
            o.push_str("Custom Application\n------------------\n");
            let _ = writeln!(o, "Name: {}", c.name);
            let _ = writeln!(o, "File Name: {}", c.filename);
            let _ = writeln!(o, "MD5 Sum: {}", c.md5);
            let _ = writeln!(o, "Autostart: {}", yes_no(c.autostart));
            let _ = writeln!(o, "Idle Screen Softkey: {}", yes_no(c.idlescreen_softkey));
            if !c.settings.is_empty() {
                o.push_str("Custom Application Specific Settings:\n");
                for (k, v) in &c.settings {
                    let _ = writeln!(o, "    {}: {}", k, v);
                }
            }
        }
        None => {}
    }
    a.out(&format!("{}\n", o));
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
            a.out(&format!(
                "{}  MAC:{}  URI:{:<30} SessionID:{}\n",
                p.name, p.last_mac, p.last_uri, p.last_session_id
            ));
        }
    }
    a.out(&format!("----  {} Tokens Found    ----\n", n));
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
            Some(p) => or(&p.full_name, &p.name).to_string(),
            None => {
                a.out(&format!("Could not find user with name '{}' to reconfigure.\n", a.argv[3]));
                return CliResult::Success;
            }
        }
    };
    if reconfigure(&a.argv[3], false).is_ok() {
        a.out(&format!("Phone '{}' will reconfigure shortly.\n", display));
    } else {
        a.out(&format!(
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
        cmd!("digium_phones show alert", "Usage digium_phones show alert <alert name>\n", show_alert, complete_alert),
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
