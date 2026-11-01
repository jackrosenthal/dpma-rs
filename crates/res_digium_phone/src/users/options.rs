//! Option parsers for each object type in res_digium_phone.conf.
//!
//! Each parser returns `Err(())` for an option it does not recognize (or an
//! invalid numeric value); the caller decides whether to log that.

use super::*;
use crate::util::{scan_i32, scan_u32, truncate};
use dpma_ast::dpma_log;
use dpma_ast::util::{ast_false, ast_true};

type Res = Result<(), ()>;

fn u32_opt(field: &mut i32, value: &str) -> Res {
    match scan_u32(value) {
        Some(v) => {
            *field = v as i32;
            Ok(())
        }
        None => Err(()),
    }
}

fn i32_opt(field: &mut i32, value: &str) -> Res {
    match scan_i32(value) {
        Some(v) => {
            *field = v as i32;
            Ok(())
        }
        None => Err(()),
    }
}

/// Context needed while applying phone options.
pub struct UserCtx<'a> {
    pub lines: &'a mut NamedMap<Line>,
    pub networks: &'a mut NamedMap<Network>,
}

/// `set_user_option`.
pub fn set_user_option(ctx: &mut UserCtx, phone: &mut Phone, name: &str, value: &str) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_string();
    match n.as_str() {
        "mac" => phone.mac = value.replace(':', ""),
        "group_pin" => phone.group_pin = s,
        "pin" => {
            if value.eq_ignore_ascii_case("voicemail") {
                phone.pin_is_voicemail = true;
            } else {
                phone.pin_is_voicemail = false;
                phone.pin = s.clone();
                phone.applied_pin = s;
            }
        }
        "full_name" => phone.full_name = s,
        "line" | "external_line" => add_line(ctx, phone, value, n == "external_line"),
        "contact" => phone.contacts.push(truncate(value, 0x400)),
        "network" => phone.networks.push(truncate(value, 0x80)),
        "ringtone" => {
            if BUILTIN_RINGTONES.contains(&value) {
                if phone.active_ringtone.is_empty() {
                    phone.active_ringtone = s;
                }
            } else {
                phone.ringtones.push(truncate(value, 0x80));
            }
        }
        "firmware" => phone.firmware.push(truncate(value, 0x80)),
        "alert" => phone.alerts.push(truncate(value, 0x80)),
        "multicastpage" => phone.multicastpages.push(truncate(value, 0x80)),
        "codecs" => return codecs_add(&mut phone.codecs, value),
        "application" => phone.applications.push(truncate(value, 0x80)),
        "blf_contact_group" => phone.blf_contact_group = s,
        "contacts_display_rules" => phone.contacts_display_rules = s,
        "config_file" => phone.config_file = s,
        "timezone" => phone.timezone = s,
        "active_locale" => phone.active_locale = s,
        "active_ringtone" => phone.active_ringtone = s,
        "login_password" => phone.login_password = s,
        "accept_local_calls" => phone.accept_local_calls = s,
        "name_format" => phone.name_format = s,
        "ntp_resync" => return u32_opt(&mut phone.ntp_resync, value),
        "contacts_max_subscriptions" => return i32_opt(&mut phone.contacts_max_subscriptions, value),
        "web_ui_enabled" => phone.web_ui_enabled = ast_true(value),
        "record_own_calls" => phone.record_own_calls = ast_true(value),
        "blf_unused_linekeys" => phone.blf_unused_linekeys = ast_true(value),
        "blf_page_return_timeout" => return i32_opt(&mut phone.blf_page_return_timeout, value),
        "send_to_vm" => phone.send_to_vm = ast_true(value),
        "can_forward_calls" => phone.can_forward_calls = ast_true(value),
        "show_call_log" => phone.show_call_log = ast_true(value),
        "use_local_storage" => phone.use_local_storage = ast_true(value),
        "lock_preferences" => phone.lock_preferences = ast_true(value),
        "brightness" => return u32_opt(&mut phone.brightness, value),
        "contrast" => return u32_opt(&mut phone.contrast, value),
        "dim_backlight" => phone.dim_backlight = ast_true(value),
        "backlight_timeout" => return u32_opt(&mut phone.backlight_timeout, value),
        "backlight_dim_level" => return u32_opt(&mut phone.backlight_dim_level, value),
        "handshake_timeout" => return u32_opt(&mut phone.handshake_timeout, value),
        "display_mc_notification" => phone.display_mc_notification = ast_true(value),
        "idle_company_text" => phone.idle_company_text = s,
        "small_clock" => phone.small_clock = ast_true(value),
        "allow_insecure_ssl" => phone.allow_insecure_ssl = ast_true(value),
        "default_fontsize" => return u32_opt(&mut phone.default_fontsize, value),
        "ringer_volume" => return u32_opt(&mut phone.ringer_volume, value),
        "speaker_volume" => return u32_opt(&mut phone.speaker_volume, value),
        "handset_volume" => return u32_opt(&mut phone.handset_volume, value),
        "headset_volume" => return u32_opt(&mut phone.headset_volume, value),
        "handset_sidetone_db" => return u32_opt(&mut phone.handset_sidetone_db, value),
        "headset_sidetone_db" => return u32_opt(&mut phone.headset_sidetone_db, value),
        "reset_call_volume" => phone.reset_call_volume = ast_true(value),
        "headset_answer" => phone.headset_answer = ast_true(value),
        "ring_headset_only" => phone.ring_headset_only = ast_true(value),
        "call_waiting_tone" => phone.call_waiting_tone = ast_true(value),
        "wallpaper_file" => phone.wallpaper_file = s,
        "ehs" => phone.ehs = s,
        "8021x_passthrough" => phone.dot1x_passthrough = s,
        "8021x_method" => phone.dot1x_method = s,
        "8021x_eapol_on_disconnect" => phone.dot1x_eapol_on_disconnect = s,
        "8021x_identity" => phone.dot1x_identity = s,
        "8021x_anonymous_identity" => phone.dot1x_anonymous_identity = s,
        "8021x_password" => phone.dot1x_password = s,
        "8021x_client_cert_url" => phone.dot1x_client_cert_url = s,
        "8021x_client_cert_value" => phone.dot1x_client_cert_value = s,
        "8021x_root_cert_url" => phone.dot1x_root_cert_url = s,
        "8021x_root_cert_value" => phone.dot1x_root_cert_value = s,
        "8021x_debug" => phone.dot1x_debug = s,
        "openvpn_enable" => phone.openvpn_enable = if ast_true(value) { "1" } else { "0" }.into(),
        "openvpn_config_file_url" => phone.openvpn_config_file_url = s,
        "openvpn_config_file_value" => phone.openvpn_config_file_value = s,
        "openvpn_root_cert_url" => phone.openvpn_root_cert_url = s,
        "openvpn_root_cert_value" => phone.openvpn_root_cert_value = s,
        "openvpn_client_cert_url" => phone.openvpn_client_cert_url = s,
        "openvpn_client_cert_value" => phone.openvpn_client_cert_value = s,
        "openvpn_client_key_url" => phone.openvpn_client_key_url = s,
        "openvpn_client_key_value" => phone.openvpn_client_key_value = s,
        "openvpn_logging" => phone.openvpn_logging = s,
        "lan_port_mode" => phone.lan_port_mode = s,
        "pc_port_mode" => phone.pc_port_mode = s,
        "parking_exten" => phone.parking_exten = s,
        "show_call_parking" => phone.show_call_parking = ast_true(value),
        "parking_transfer_type" => {
            if value.eq_ignore_ascii_case("blind") {
                phone.parking_transfer_type = ParkingTransfer::Blind;
            } else if value.eq_ignore_ascii_case("attended") {
                phone.parking_transfer_type = ParkingTransfer::Attended;
            } else {
                dpma_log!("Unknown parking transfer type '{}'.", value);
            }
        }
        "blf_items" => phone.blf_items = s,
        // These four configure the implicit network named after the phone.
        "ntp_server" | "syslog_server" | "syslog_port" | "syslog_level" => {
            let (net, _) = ctx.networks.get_or_insert_with(&phone.name, || Network::new(&phone.name));
            net.delme = false;
            if set_network_option(net, name, value).is_err() {
                dpma_log!("Unknown network option '{}'", name);
            }
        }
        "enable_check_sync" => phone.enable_check_sync = ast_true(value),
        "transport_tls_allowed" => phone.transport_tls_allowed = i32::from(ast_true(value)),
        "logout_enabled" => phone.logout_enabled = ast_true(value),
        "expansion_enabled" => phone.expansion_enabled = ast_true(value),
        "expansion_page_indicators_enabled" => phone.expansion_page_indicators_enabled = ast_true(value),
        "type" => {}
        _ if n.contains("logo_file") => {
            let model = crate::util::first_token(name, &['_']);
            if model.is_empty() {
                return Err(());
            }
            phone.logos.push((truncate(model, 0x80), truncate(value, 0x200)));
        }
        _ => return Err(()),
    }
    Ok(())
}

/// `line=` / `external_line=` on a phone.
fn add_line(ctx: &mut UserCtx, phone: &mut Phone, name: &str, external: bool) {
    let (line, _) = ctx.lines.get_or_insert_with(name, || Line::new(name, external));
    // The original leaves the delete mark alone here, so a line that only a
    // phone refers to (no [line] section or pjsip endpoint) survives the
    // first load but disappears on every other reload.  Keep it
    // consistently instead.
    line.set_defaults();
    line.delme = false;
    if phone.lines.len() < MAX_LINES {
        phone.lines.push(PhoneLine { name: truncate(name, 0x80), external });
    }
}

/// New internal lines get a CustomPresence state so their hints work.
pub fn init_custom_presence(line: &str) {
    let (state, _, _) = dpma_ast::presence::query(&format!("CustomPresence:{}", line));
    if state == dpma_ast::presence::INVALID || state == dpma_ast::presence::NOT_SET {
        dpma_ast::pbx::set_global(&format!("PRESENCE_STATE(CustomPresence:{})", line), "available,,");
    }
}

/// `phone_user_codecs_add`.  Codecs are comma separated; a leading `!`
/// disables one.  The first codec gets priority 255, the next 254, ...
pub fn codecs_add(codecs: &mut Vec<Codec>, value: &str) -> Res {
    let mut priority = 255;
    let mut enabled = true;
    let mut rest = value;
    loop {
        let Some(c) = rest.chars().next() else { return Ok(()) };
        if (c as u32) < 0x21 {
            rest = &rest[c.len_utf8()..];
            continue;
        }
        if c == '!' {
            enabled = !enabled;
            rest = &rest[1..];
            continue;
        }
        let (tok, next) = match rest.find(',') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        let Some(index) = CODECS.iter().position(|(n, _)| n.eq_ignore_ascii_case(tok)) else {
            dpma_log!("Unknown codec specified: '{}'", tok);
            return Err(());
        };
        codecs.push(Codec { index, priority, enabled });
        priority -= 1;
        enabled = true;
        match next {
            Some(n) => rest = n,
            None => return Ok(()),
        }
    }
}

/// `phone_users_set_line_option`.
pub fn set_line_option(line: &mut Line, name: &str, value: &str) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_string();
    match n.as_str() {
        "secret" => line.secret = s,
        "callerid" => line.callerid = s,
        "host" => {
            if !value.eq_ignore_ascii_case("dynamic") {
                line.no_register = true;
            }
        }
        "first_name" => line.first_name = s,
        "last_name" => line.last_name = s,
        "title" => line.title = s,
        "line_label" => line.line_label = s,
        "location" => line.location = s,
        "digit_map" => line.digit_map = s,
        "mailbox" => set_line_mailbox(line, value),
        "context" => line.context = s,
        "subscribecontext" => line.subscribecontext = s,
        "exten" | "extension" => line.exten = s,
        "transport" => line.transport = Transport::parse(value),
        "secondary_server_transport" => line.secondary_server_transport = Transport::parse(value),
        "reregistration_timeout" => return u32_opt(&mut line.reregistration_timeout, value),
        "registration_retry_interval" => return u32_opt(&mut line.registration_retry_interval, value),
        "registration_max_retries" => return u32_opt(&mut line.registration_max_retries, value),
        "server_address" => {
            line.server_address = s;
            if line.server_port.is_empty() {
                line.server_port = "5060".into();
            }
        }
        "server_port" => line.server_port = s,
        "media_encryption" => line.media_encryption = s,
        "secondary_server_address" => {
            line.secondary_server_address = s;
            if line.secondary_server_port.is_empty() {
                line.secondary_server_port = "5060".into();
            }
        }
        "secondary_server_port" => line.secondary_server_port = s,
        "secondary_media_encryption" => line.secondary_media_encryption = s,
        "userid" => line.userid = s,
        "authname" => line.authname = s,
        "register" => line.no_register = ast_false(value),
        "voicemail_uri" => line.voicemail_uri = s,
        "outboundproxy_address" => {
            line.outboundproxy_address = s;
            if line.outboundproxy_port.is_empty() {
                line.outboundproxy_port = "5060".into();
            }
        }
        "outboundproxy_port" => line.outboundproxy_port = s,
        "tech" => line.tech = s,
        "pjsip_auth" => line.pjsip_auth = s,
        "plar_number" => line.plar_number = s,
        _ => return Err(()),
    }
    Ok(())
}

/// `set_line_mailbox`: keep the first of a list of mailboxes and qualify it
/// with a context ("default" when none is given).
pub fn set_line_mailbox(line: &mut Line, value: &str) {
    let first = crate::util::first_token(value, &[',', ' ']);
    let (mbox, context) = match first.split_once('@') {
        Some((m, c)) => (m, c),
        None => (first, "default"),
    };
    if mbox.is_empty() {
        line.mailbox.clear();
    } else {
        line.mailbox = format!("{}@{}", mbox, context);
    }
}

/// `set_network_option`.
pub fn set_network_option(net: &mut Network, name: &str, value: &str) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_string();
    let with_slash = |v: &str| {
        if v.is_empty() || v.ends_with('/') {
            v.to_string()
        } else {
            format!("{}/", v)
        }
    };
    match n.as_str() {
        "alias" => net.alias = s,
        "cidr" => net.cidr = s,
        "registration_address" => net.registration_address = s,
        "registration_port" => net.registration_port = s,
        "transport" => net.transport = Transport::parse(value),
        "alternate_registration_address" => net.alternate_registration_address = s,
        "alternate_registration_port" => net.alternate_registration_port = s,
        "alternate_transport" => net.alternate_transport = Transport::parse(value),
        "file_url_prefix" => net.file_url_prefix = with_slash(value),
        "public_firmware_url_prefix" => net.public_firmware_url_prefix = with_slash(value),
        "ntp_server" => net.ntp_server = s,
        "syslog_server" => net.syslog_server = s,
        "syslog_port" => net.syslog_port = s,
        "syslog_level" => net.syslog_level = s,
        "network_vlan_discovery_mode" => net.network_vlan_discovery_mode = s,
        "network_vlan_id" => return u32_opt(&mut net.network_vlan_id, value),
        "network_vlan_qos" => {
            dpma_log!("network_vlan_qos is deprecated. Use rtp_qos and sip_qos instead.");
            if net.rtp_qos != -1 {
                dpma_log!("rtp_qos already set. Ignoring network_vlan_qos.");
                return Ok(());
            }
            return qos(&mut net.rtp_qos, value);
        }
        "rtp_qos" => return qos(&mut net.rtp_qos, value),
        "sip_qos" => return qos(&mut net.sip_qos, value),
        "sip_dscp" => return u32_opt(&mut net.sip_dscp, value),
        "rtp_dscp" => return u32_opt(&mut net.rtp_dscp, value),
        "pc_vlan_id" => return u32_opt(&mut net.pc_vlan_id, value),
        "pc_qos" => return u32_opt(&mut net.pc_qos, value),
        "udp_ka_interval" => return u32_opt(&mut net.udp_ka_interval, value),
        _ => return Err(()),
    }
    Ok(())
}

/// QoS levels are 0-7.
fn qos(field: &mut i32, value: &str) -> Res {
    match scan_u32(value) {
        Some(v) if (0..8).contains(&v) => {
            *field = v as i32;
            Ok(())
        }
        _ => Err(()),
    }
}

/// `set_firmware_opt_option`.
pub fn set_firmware_opt_option(fw: &mut FirmwareOpt, name: &str, value: &str) -> Res {
    match name.to_ascii_lowercase().as_str() {
        "model" => fw.model = value.to_ascii_uppercase(),
        "version" => fw.version = value.to_string(),
        "file" => fw.file = value.to_string(),
        "public_firmware" => {
            if ast_true(value) {
                fw.public_firmware = true;
            } else if ast_false(value) {
                fw.public_firmware = false;
            } else {
                dpma_log!("{} is not a valid option for public_firmware. Value will be ignored.", value);
            }
        }
        _ => return Err(()),
    }
    Ok(())
}

/// Fresh, empty data for an application of type `kind` (the `*_init`
/// functions).
pub fn app_init(kind: &str) -> Option<AppKind> {
    Some(match kind.to_ascii_lowercase().as_str() {
        "queue" => AppKind::Queue(QueueApp {
            queue: String::new(),
            membername: String::new(),
            location: String::new(),
            login_exten: String::new(),
            logout_exten: String::new(),
            member: true,
            permission: QueuePermission::Status,
        }),
        "status" => AppKind::Status(StatusApp::default()),
        "parking" => AppKind::Parking(ParkingApp::default()),
        "voicemail" => AppKind::Voicemail(VoicemailApp::default()),
        "custom" => AppKind::Custom(CustomApp::default()),
        _ => return None,
    })
}

/// Apply one option to an application.
pub fn set_app_option(app: &mut AppKind, name: &str, value: &str) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_string();
    match app {
        AppKind::Queue(q) => match n.as_str() {
            "queue" => q.queue = s,
            "membername" => q.membername = s,
            "location" => q.location = s,
            "member" => q.member = ast_true(value),
            "permission" | "permissions" => {
                if value.eq_ignore_ascii_case("status") {
                    q.permission = QueuePermission::Status;
                } else if value.eq_ignore_ascii_case("overview") {
                    q.permission = QueuePermission::Overview;
                } else if value.eq_ignore_ascii_case("details") {
                    q.permission = QueuePermission::Details;
                } else {
                    dpma_log!("Unknown permission '{}'", value);
                }
            }
            "login_exten" => q.login_exten = s,
            "logout_exten" => q.logout_exten = s,
            _ => return Err(()),
        },
        AppKind::Status(st) => match n.as_str() {
            "status" => {
                let v = dpma_ast::presence::state_val(value);
                if v == dpma_ast::presence::NOT_SET || v == dpma_ast::presence::INVALID || v < 0 {
                    dpma_log!("Status '{}' is not a valid presence state.", value);
                    st.status = v;
                    return Err(());
                }
                st.status = v;
            }
            "substatus" => st.substatuses.push(s),
            "send486" => {
                if ast_true(value) {
                    st.send486 = Send486::Yes;
                } else if ast_false(value) {
                    st.send486 = Send486::No;
                } else {
                    dpma_log!(
                        "Attempted to use send486 option with non true/false value '{}'. Ignoring attribute.",
                        value
                    );
                }
            }
            _ => return Err(()),
        },
        AppKind::Parking(p) => match n.as_str() {
            "parkinglot" => {
                for lot in value.split(',') {
                    let lot = lot.trim_matches(|c: char| (c as u32) <= 0x20 && c != '\0');
                    p.parkinglots.push(lot.to_string());
                }
            }
            _ => return Err(()),
        },
        AppKind::Voicemail(vm) => match n.as_str() {
            "translation" => {
                if crate::translation::exists(value) {
                    vm.translation = Some(s);
                } else {
                    dpma_log!("Unknown translation table {}", value);
                    vm.translation = None;
                }
            }
            "require_password" => vm.require_password = ast_true(value),
            _ => return Err(()),
        },
        AppKind::Custom(c) => match n.as_str() {
            "name" => c.name = s,
            "filename" => c.filename = s,
            "md5" | "md5sum" => c.md5 = s,
            "autostart" => c.autostart = ast_true(value),
            "idlescreen_softkey" => c.idlescreen_softkey = ast_true(value),
            _ => c.settings.push((name.to_string(), s)),
        },
    }
    Ok(())
}

/// Validation after all options were applied (`*_post_setup`).
pub fn app_post_setup(app: &AppKind, name: &str) -> Res {
    if let AppKind::Status(st) = app {
        if st.status == dpma_ast::presence::NOT_SET {
            dpma_log!("Status Application '{}' did not set a valid status.", name);
            return Err(());
        }
    }
    Ok(())
}
