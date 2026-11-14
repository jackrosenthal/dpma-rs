//! Option parsers for each object type in res_digium_phone.conf.
//!
//! Each parser returns `Err(())` for an option it does not recognize (or an
//! invalid numeric value); the caller decides whether to log that.

use super::*;
use crate::util::{scan_i32, scan_u32, truncate};
use dpma_ast::dpma_bytes::ByteSlice;
use dpma_ast::util::{ast_false, ast_true};
use dpma_ast::{bformat, dpma_log};

type Res = Result<(), ()>;

fn u32_opt(field: &mut i32, value: &[u8]) -> Res {
    match scan_u32(value) {
        Some(v) => {
            *field = v as i32;
            Ok(())
        }
        None => Err(()),
    }
}

fn i32_opt(field: &mut i32, value: &[u8]) -> Res {
    match scan_i32(value) {
        Some(v) => {
            *field = v as i32;
            Ok(())
        }
        None => Err(()),
    }
}

/// A yes/no option that has no default: `1` or `0`, or an error for a value
/// that is neither true nor false.
fn tristate_opt(field: &mut Vec<u8>, value: &[u8]) -> Res {
    if ast_true(value) {
        *field = b"1".to_vec();
    } else if ast_false(value) {
        *field = b"0".to_vec();
    } else {
        return Err(());
    }
    Ok(())
}

/// Longest SSH public key line accepted (an RSA 16384 key is about 2800).
const SSH_KEY_LINE_MAX: usize = 0x2000;

/// An SSH public key line (`type base64 [comment]`) with single spaces
/// between its fields, or `None` when `value` is not one.  Lines that
/// start with options are not accepted, and neither is anything else that
/// is not a public key, such as a private key.
pub(super) fn ssh_public_key_line(value: &[u8]) -> Option<Vec<u8>> {
    if value.len() > SSH_KEY_LINE_MAX || value.iter().any(|c| c.is_ascii_control() && *c != b'\t') {
        return None;
    }
    let mut fields = value
        .split(|c| *c == b' ' || *c == b'\t')
        .filter(|f| !f.is_empty());
    let kind = fields.next()?;
    let blob = fields.next()?;
    let known_kind = [&b"ssh-"[..], b"ecdsa-sha2-", b"sk-"]
        .iter()
        .any(|p| kind.starts_with(p))
        && kind
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'@' | b'.'));
    let base64 = blob.len() >= 16
        && blob
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='));
    if !known_kind || !base64 {
        return None;
    }
    let mut line = kind.to_vec();
    line.push(b' ');
    line.extend_from_slice(blob);
    for f in fields {
        line.push(b' ');
        line.extend_from_slice(f);
    }
    Some(line)
}

/// Context needed while applying phone options.
pub struct UserCtx<'a> {
    pub lines: &'a mut NamedMap<Line>,
    pub networks: &'a mut NamedMap<Network>,
}

/// `set_user_option`.
pub fn set_user_option(ctx: &mut UserCtx, phone: &mut Phone, name: &[u8], value: &[u8]) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_vec();
    match n.as_slice() {
        b"mac" => phone.mac = value.replace(":", ""),
        b"group_pin" => phone.group_pin = s,
        b"pin" => {
            if value.eq_ignore_ascii_case(b"voicemail") {
                phone.pin_is_voicemail = true;
            } else {
                phone.pin_is_voicemail = false;
                phone.pin = s.clone();
                phone.applied_pin = s;
            }
        }
        b"full_name" => phone.full_name = s,
        b"line" | b"external_line" => add_line(ctx, phone, value, n == b"external_line"),
        b"contact" => phone.contacts.push(truncate(value, 0x400)),
        b"network" => phone.networks.push(truncate(value, 0x80)),
        b"ringtone" => {
            if BUILTIN_RINGTONES.iter().any(|r| r.as_bytes() == value) {
                if phone.active_ringtone.is_empty() {
                    phone.active_ringtone = s;
                }
            } else {
                phone.ringtones.push(truncate(value, 0x80));
            }
        }
        b"firmware" => phone.firmware.push(truncate(value, 0x80)),
        b"alert" => phone.alerts.push(truncate(value, 0x80)),
        b"multicastpage" => phone.multicastpages.push(truncate(value, 0x80)),
        b"codecs" => return codecs_add(&mut phone.codecs, value),
        b"application" => phone.applications.push(truncate(value, 0x80)),
        b"blf_contact_group" => phone.blf_contact_group = s,
        b"contacts_display_rules" => phone.contacts_display_rules = s,
        b"config_file" => phone.config_file = s,
        b"timezone" => phone.timezone = s,
        b"active_locale" => phone.active_locale = s,
        b"active_ringtone" => phone.active_ringtone = s,
        b"login_password" => phone.login_password = s,
        b"dphone_ssh_enabled" => return tristate_opt(&mut phone.dphone_ssh_enabled, value),
        b"dphone_ignore_provisioned_firmware" => {
            return tristate_opt(&mut phone.dphone_ignore_provisioned_firmware, value)
        }
        b"dphone_metrics_enabled" => return tristate_opt(&mut phone.dphone_metrics_enabled, value),
        b"dphone_ssh_authorized_key" => match ssh_public_key_line(value) {
            Some(line) => {
                if !phone.dphone_ssh_authorized_keys.contains(&line) {
                    phone.dphone_ssh_authorized_keys.push(line);
                }
            }
            None => return Err(()),
        },
        b"accept_local_calls" => phone.accept_local_calls = s,
        b"name_format" => phone.name_format = s,
        b"ntp_resync" => return u32_opt(&mut phone.ntp_resync, value),
        b"contacts_max_subscriptions" => {
            return i32_opt(&mut phone.contacts_max_subscriptions, value)
        }
        b"web_ui_enabled" => phone.web_ui_enabled = ast_true(value),
        b"record_own_calls" => phone.record_own_calls = ast_true(value),
        b"blf_unused_linekeys" => phone.blf_unused_linekeys = ast_true(value),
        b"blf_page_return_timeout" => return i32_opt(&mut phone.blf_page_return_timeout, value),
        b"send_to_vm" => phone.send_to_vm = ast_true(value),
        b"can_forward_calls" => phone.can_forward_calls = ast_true(value),
        b"show_call_log" => phone.show_call_log = ast_true(value),
        b"use_local_storage" => phone.use_local_storage = ast_true(value),
        b"lock_preferences" => phone.lock_preferences = ast_true(value),
        b"brightness" => return u32_opt(&mut phone.brightness, value),
        b"contrast" => return u32_opt(&mut phone.contrast, value),
        b"dim_backlight" => phone.dim_backlight = ast_true(value),
        b"backlight_timeout" => return u32_opt(&mut phone.backlight_timeout, value),
        b"backlight_dim_level" => return u32_opt(&mut phone.backlight_dim_level, value),
        b"handshake_timeout" => return u32_opt(&mut phone.handshake_timeout, value),
        b"display_mc_notification" => phone.display_mc_notification = ast_true(value),
        b"idle_company_text" => phone.idle_company_text = s,
        b"small_clock" => phone.small_clock = ast_true(value),
        b"allow_insecure_ssl" => phone.allow_insecure_ssl = ast_true(value),
        b"default_fontsize" => return u32_opt(&mut phone.default_fontsize, value),
        b"ringer_volume" => return u32_opt(&mut phone.ringer_volume, value),
        b"speaker_volume" => return u32_opt(&mut phone.speaker_volume, value),
        b"handset_volume" => return u32_opt(&mut phone.handset_volume, value),
        b"headset_volume" => return u32_opt(&mut phone.headset_volume, value),
        b"handset_sidetone_db" => return u32_opt(&mut phone.handset_sidetone_db, value),
        b"headset_sidetone_db" => return u32_opt(&mut phone.headset_sidetone_db, value),
        b"reset_call_volume" => phone.reset_call_volume = ast_true(value),
        b"headset_answer" => phone.headset_answer = ast_true(value),
        b"ring_headset_only" => phone.ring_headset_only = ast_true(value),
        b"call_waiting_tone" => phone.call_waiting_tone = ast_true(value),
        b"wallpaper_file" => phone.wallpaper_file = s,
        b"ehs" => phone.ehs = s,
        b"8021x_passthrough" => phone.dot1x_passthrough = s,
        b"8021x_method" => phone.dot1x_method = s,
        b"8021x_eapol_on_disconnect" => phone.dot1x_eapol_on_disconnect = s,
        b"8021x_identity" => phone.dot1x_identity = s,
        b"8021x_anonymous_identity" => phone.dot1x_anonymous_identity = s,
        b"8021x_password" => phone.dot1x_password = s,
        b"8021x_client_cert_url" => phone.dot1x_client_cert_url = s,
        b"8021x_client_cert_value" => phone.dot1x_client_cert_value = s,
        b"8021x_root_cert_url" => phone.dot1x_root_cert_url = s,
        b"8021x_root_cert_value" => phone.dot1x_root_cert_value = s,
        b"8021x_debug" => phone.dot1x_debug = s,
        b"openvpn_enable" => phone.openvpn_enable = if ast_true(value) { "1" } else { "0" }.into(),
        b"openvpn_config_file_url" => phone.openvpn_config_file_url = s,
        b"openvpn_config_file_value" => phone.openvpn_config_file_value = s,
        b"openvpn_root_cert_url" => phone.openvpn_root_cert_url = s,
        b"openvpn_root_cert_value" => phone.openvpn_root_cert_value = s,
        b"openvpn_client_cert_url" => phone.openvpn_client_cert_url = s,
        b"openvpn_client_cert_value" => phone.openvpn_client_cert_value = s,
        b"openvpn_client_key_url" => phone.openvpn_client_key_url = s,
        b"openvpn_client_key_value" => phone.openvpn_client_key_value = s,
        b"openvpn_logging" => phone.openvpn_logging = s,
        b"lan_port_mode" => phone.lan_port_mode = s,
        b"pc_port_mode" => phone.pc_port_mode = s,
        b"parking_exten" => phone.parking_exten = s,
        b"show_call_parking" => phone.show_call_parking = ast_true(value),
        b"parking_transfer_type" => {
            if value.eq_ignore_ascii_case(b"blind") {
                phone.parking_transfer_type = ParkingTransfer::Blind;
            } else if value.eq_ignore_ascii_case(b"attended") {
                phone.parking_transfer_type = ParkingTransfer::Attended;
            } else {
                dpma_log!("Unknown parking transfer type '{}'.", value);
            }
        }
        b"blf_items" => phone.blf_items = s,
        // These four configure the implicit network named after the phone.
        b"ntp_server" | b"syslog_server" | b"syslog_port" | b"syslog_level" => {
            let (net, _) = ctx
                .networks
                .get_or_insert_with(&phone.name, || Network::new(&phone.name));
            net.delme = false;
            if set_network_option(net, name, value).is_err() {
                dpma_log!("Unknown network option '{}'", name);
            }
        }
        b"enable_check_sync" => phone.enable_check_sync = ast_true(value),
        b"transport_tls_allowed" => phone.transport_tls_allowed = i32::from(ast_true(value)),
        b"logout_enabled" => phone.logout_enabled = ast_true(value),
        b"expansion_enabled" => phone.expansion_enabled = ast_true(value),
        b"expansion_page_indicators_enabled" => {
            phone.expansion_page_indicators_enabled = ast_true(value)
        }
        b"type" => {}
        _ if n.contains_str("logo_file") => {
            let model = crate::util::first_token(name, b"_");
            if model.is_empty() {
                return Err(());
            }
            phone
                .logos
                .push((truncate(model, 0x80), truncate(value, 0x200)));
        }
        _ => return Err(()),
    }
    Ok(())
}

/// `line=` / `external_line=` on a phone.
fn add_line(ctx: &mut UserCtx, phone: &mut Phone, name: &[u8], external: bool) {
    let (line, _) = ctx
        .lines
        .get_or_insert_with(name, || Line::new(name, external));
    // The official DPMA leaves the delete mark alone here, so a line that
    // only a phone refers to (no [line] section or pjsip endpoint) survives
    // the first load but disappears on every other reload.  Keep it
    // consistently instead.
    line.set_defaults();
    line.delme = false;
    if phone.lines.len() < MAX_LINES {
        phone.lines.push(PhoneLine {
            name: truncate(name, 0x80),
            external,
        });
    }
}

/// New internal lines get a CustomPresence state so their hints work.
pub fn init_custom_presence(line: &[u8]) {
    let (state, _, _) = dpma_ast::presence::query(&bformat!("CustomPresence:{}", line));
    if state == dpma_ast::presence::INVALID || state == dpma_ast::presence::NOT_SET {
        dpma_ast::pbx::set_global(
            &bformat!("PRESENCE_STATE(CustomPresence:{})", line),
            "available,,",
        );
    }
}

/// `phone_user_codecs_add`.  Codecs are comma separated; a leading `!`
/// disables one.  The first codec gets priority 255, the next 254, ...
pub fn codecs_add(codecs: &mut Vec<Codec>, value: &[u8]) -> Res {
    let mut priority = 255;
    let mut enabled = true;
    let mut rest = value;
    loop {
        let Some(&c) = rest.first() else {
            return Ok(());
        };
        if c < 0x21 {
            rest = &rest[1..];
            continue;
        }
        if c == b'!' {
            enabled = !enabled;
            rest = &rest[1..];
            continue;
        }
        let (tok, next) = match rest.find_byte(b',') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        let Some(index) = CODECS
            .iter()
            .position(|(n, _)| n.as_bytes().eq_ignore_ascii_case(tok))
        else {
            dpma_log!("Unknown codec specified: '{}'", tok);
            return Err(());
        };
        codecs.push(Codec {
            index,
            priority,
            enabled,
        });
        priority -= 1;
        enabled = true;
        match next {
            Some(n) => rest = n,
            None => return Ok(()),
        }
    }
}

/// `phone_users_set_line_option`.
pub fn set_line_option(line: &mut Line, name: &[u8], value: &[u8]) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_vec();
    match n.as_slice() {
        b"secret" => line.secret = s,
        b"callerid" => line.callerid = s,
        b"host" => {
            if !value.eq_ignore_ascii_case(b"dynamic") {
                line.no_register = true;
            }
        }
        b"first_name" => line.first_name = s,
        b"last_name" => line.last_name = s,
        b"title" => line.title = s,
        b"line_label" => line.line_label = s,
        b"location" => line.location = s,
        b"digit_map" => line.digit_map = s,
        b"mailbox" => set_line_mailbox(line, value),
        b"context" => line.context = s,
        b"subscribecontext" => line.subscribecontext = s,
        b"exten" | b"extension" => line.exten = s,
        b"transport" => line.transport = Transport::parse(value),
        b"secondary_server_transport" => line.secondary_server_transport = Transport::parse(value),
        b"reregistration_timeout" => return u32_opt(&mut line.reregistration_timeout, value),
        b"registration_retry_interval" => {
            return u32_opt(&mut line.registration_retry_interval, value)
        }
        b"registration_max_retries" => return u32_opt(&mut line.registration_max_retries, value),
        b"server_address" => {
            line.server_address = s;
            if line.server_port.is_empty() {
                line.server_port = "5060".into();
            }
        }
        b"server_port" => line.server_port = s,
        b"media_encryption" => line.media_encryption = s,
        b"secondary_server_address" => {
            line.secondary_server_address = s;
            if line.secondary_server_port.is_empty() {
                line.secondary_server_port = "5060".into();
            }
        }
        b"secondary_server_port" => line.secondary_server_port = s,
        b"secondary_media_encryption" => line.secondary_media_encryption = s,
        b"userid" => line.userid = s,
        b"authname" => line.authname = s,
        b"register" => line.no_register = ast_false(value),
        b"voicemail_uri" => line.voicemail_uri = s,
        b"outboundproxy_address" => {
            line.outboundproxy_address = s;
            if line.outboundproxy_port.is_empty() {
                line.outboundproxy_port = "5060".into();
            }
        }
        b"outboundproxy_port" => line.outboundproxy_port = s,
        b"tech" => line.tech = s,
        b"pjsip_auth" => line.pjsip_auth = s,
        b"plar_number" => line.plar_number = s,
        _ => return Err(()),
    }
    Ok(())
}

/// `set_line_mailbox`: keep the first of a list of mailboxes and qualify it
/// with a context ("default" when none is given).
pub fn set_line_mailbox(line: &mut Line, value: &[u8]) {
    let first = crate::util::first_token(value, b", ");
    let (mbox, context) = match first.split_once_str("@") {
        Some((m, c)) => (m, c),
        None => (first, &b"default"[..]),
    };
    if mbox.is_empty() {
        line.mailbox.clear();
    } else {
        line.mailbox = bformat!("{}@{}", mbox, context);
    }
}

/// `set_network_option`.
pub fn set_network_option(net: &mut Network, name: &[u8], value: &[u8]) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_vec();
    let with_slash = |v: &[u8]| {
        if v.is_empty() || v.ends_with(b"/") {
            v.to_vec()
        } else {
            bformat!("{}/", v)
        }
    };
    match n.as_slice() {
        b"alias" => net.alias = s,
        b"cidr" => net.cidr = s,
        b"registration_address" => net.registration_address = s,
        b"registration_port" => net.registration_port = s,
        b"transport" => net.transport = Transport::parse(value),
        b"alternate_registration_address" => net.alternate_registration_address = s,
        b"alternate_registration_port" => net.alternate_registration_port = s,
        b"alternate_transport" => net.alternate_transport = Transport::parse(value),
        b"file_url_prefix" => net.file_url_prefix = with_slash(value),
        b"public_firmware_url_prefix" => net.public_firmware_url_prefix = with_slash(value),
        b"ntp_server" => net.ntp_server = s,
        b"syslog_server" => net.syslog_server = s,
        b"syslog_port" => net.syslog_port = s,
        b"syslog_level" => net.syslog_level = s,
        b"network_vlan_discovery_mode" => net.network_vlan_discovery_mode = s,
        b"network_vlan_id" => return u32_opt(&mut net.network_vlan_id, value),
        b"network_vlan_qos" => {
            dpma_log!("network_vlan_qos is deprecated. Use rtp_qos and sip_qos instead.");
            if net.rtp_qos != -1 {
                dpma_log!("rtp_qos already set. Ignoring network_vlan_qos.");
                return Ok(());
            }
            return qos(&mut net.rtp_qos, value);
        }
        b"rtp_qos" => return qos(&mut net.rtp_qos, value),
        b"sip_qos" => return qos(&mut net.sip_qos, value),
        b"sip_dscp" => return u32_opt(&mut net.sip_dscp, value),
        b"rtp_dscp" => return u32_opt(&mut net.rtp_dscp, value),
        b"pc_vlan_id" => return u32_opt(&mut net.pc_vlan_id, value),
        b"pc_qos" => return u32_opt(&mut net.pc_qos, value),
        b"udp_ka_interval" => return u32_opt(&mut net.udp_ka_interval, value),
        _ => return Err(()),
    }
    Ok(())
}

/// QoS levels are 0-7.
fn qos(field: &mut i32, value: &[u8]) -> Res {
    match scan_u32(value) {
        Some(v) if (0..8).contains(&v) => {
            *field = v as i32;
            Ok(())
        }
        _ => Err(()),
    }
}

/// `set_firmware_opt_option`.
pub fn set_firmware_opt_option(fw: &mut FirmwareOpt, name: &[u8], value: &[u8]) -> Res {
    match name.to_ascii_lowercase().as_slice() {
        b"model" => fw.model = value.to_ascii_uppercase(),
        b"version" => fw.version = value.to_vec(),
        b"file" => fw.file = value.to_vec(),
        b"public_firmware" => {
            if ast_true(value) {
                fw.public_firmware = true;
            } else if ast_false(value) {
                fw.public_firmware = false;
            } else {
                dpma_log!(
                    "{} is not a valid option for public_firmware. Value will be ignored.",
                    value
                );
            }
        }
        _ => return Err(()),
    }
    Ok(())
}

/// Fresh, empty data for an application of type `kind` (the `*_init`
/// functions).
pub fn app_init(kind: &[u8]) -> Option<AppKind> {
    Some(match kind.to_ascii_lowercase().as_slice() {
        b"queue" => AppKind::Queue(QueueApp {
            queue: Vec::new(),
            membername: Vec::new(),
            location: Vec::new(),
            login_exten: Vec::new(),
            logout_exten: Vec::new(),
            member: true,
            permission: QueuePermission::Status,
        }),
        b"status" => AppKind::Status(StatusApp::default()),
        b"parking" => AppKind::Parking(ParkingApp::default()),
        b"voicemail" => AppKind::Voicemail(VoicemailApp::default()),
        b"custom" => AppKind::Custom(CustomApp::default()),
        _ => return None,
    })
}

/// Apply one option to an application.
pub fn set_app_option(app: &mut AppKind, name: &[u8], value: &[u8]) -> Res {
    let n = name.to_ascii_lowercase();
    let s = value.to_vec();
    match app {
        AppKind::Queue(q) => match n.as_slice() {
            b"queue" => q.queue = s,
            b"membername" => q.membername = s,
            b"location" => q.location = s,
            b"member" => q.member = ast_true(value),
            b"permission" | b"permissions" => {
                if value.eq_ignore_ascii_case(b"status") {
                    q.permission = QueuePermission::Status;
                } else if value.eq_ignore_ascii_case(b"overview") {
                    q.permission = QueuePermission::Overview;
                } else if value.eq_ignore_ascii_case(b"details") {
                    q.permission = QueuePermission::Details;
                } else {
                    dpma_log!("Unknown permission '{}'", value);
                }
            }
            b"login_exten" => q.login_exten = s,
            b"logout_exten" => q.logout_exten = s,
            _ => return Err(()),
        },
        AppKind::Status(st) => match n.as_slice() {
            b"status" => {
                let v = dpma_ast::presence::state_val(value);
                if v == dpma_ast::presence::NOT_SET || v == dpma_ast::presence::INVALID || v < 0 {
                    dpma_log!("Status '{}' is not a valid presence state.", value);
                    st.status = v;
                    return Err(());
                }
                st.status = v;
            }
            b"substatus" => st.substatuses.push(s),
            b"send486" => {
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
        AppKind::Parking(p) => match n.as_slice() {
            b"parkinglot" => {
                for lot in value.split(|&c| c == b',') {
                    let lot = lot.trim_with(|c| c != '\0' && c <= ' ');
                    p.parkinglots.push(lot.to_vec());
                }
            }
            _ => return Err(()),
        },
        AppKind::Voicemail(vm) => match n.as_slice() {
            b"translation" => {
                if crate::translation::exists(value) {
                    vm.translation = Some(s);
                } else {
                    dpma_log!("Unknown translation table {}", value);
                    vm.translation = None;
                }
            }
            b"require_password" => vm.require_password = ast_true(value),
            _ => return Err(()),
        },
        AppKind::Custom(c) => match n.as_slice() {
            b"name" => c.name = s,
            b"filename" => c.filename = s,
            b"md5" | b"md5sum" => c.md5 = s,
            b"autostart" => c.autostart = ast_true(value),
            b"idlescreen_softkey" => c.idlescreen_softkey = ast_true(value),
            _ => c.settings.push((name.to_vec(), s)),
        },
    }
    Ok(())
}

/// Validation after all options were applied (`*_post_setup`).
pub fn app_post_setup(app: &AppKind, name: &[u8]) -> Res {
    if let AppKind::Status(st) = app {
        if st.status == dpma_ast::presence::NOT_SET {
            dpma_log!("Status Application '{}' did not set a valid status.", name);
            return Err(());
        }
    }
    Ok(())
}
