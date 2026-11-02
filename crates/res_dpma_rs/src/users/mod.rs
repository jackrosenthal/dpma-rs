//! Phones, lines, and the other objects configured in res_digium_phone.conf
//! (the original module's phone_users.c).
//!
//! All objects live in one `Registry` behind a global lock.  Objects refer
//! to each other by name, exactly like the original, so a reload can replace
//! any of them independently.

pub mod build_config;
pub mod cli;
pub mod contacts;
pub mod load;
pub mod objects;
pub mod options;
pub mod presence;
pub mod runtime;
pub mod status;
pub mod userlist;

use crate::util::NamedMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Registrar used for every dialplan object this module creates.
pub const REGISTRAR: &str = "DIGIUM_PHONE_USERS";
/// AstDB family holding per-phone runtime state.
pub const DB_FAMILY: &str = "DigiumPhoneUsers";
/// Maximum number of lines on one phone.
pub const MAX_LINES: usize = 12;
/// Number of buckets in the original's top-level containers.
const BUCKETS: u32 = 257;

/// Line/network transport.  Index into the `TRANSPORT_*` tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    #[default]
    Unset = 0,
    Udp = 1,
    Tcp = 2,
    Tls = 3,
}

impl Transport {
    /// `udp`, `tcp`, or `tls` (case insensitive); anything else is unset.
    pub fn parse(s: &[u8]) -> Transport {
        if s.eq_ignore_ascii_case(b"udp") {
            Transport::Udp
        } else if s.eq_ignore_ascii_case(b"tcp") {
            Transport::Tcp
        } else if s.eq_ignore_ascii_case(b"tls") {
            Transport::Tls
        } else {
            Transport::Unset
        }
    }

    /// `phone_line_transport_type`: "" when unset.
    pub fn type_str(self) -> &'static str {
        ["", "udp", "tcp", "tls"][self as usize]
    }

    /// `phone_line_transport_string`: unset means udp.
    pub fn string(self) -> &'static str {
        ["udp", "udp", "tcp", "tls"][self as usize]
    }

    /// `phone_line_transport_option`: a SIP URI parameter.
    pub fn uri_option(self) -> &'static str {
        ["", ";transport=udp", ";transport=tcp", ";transport=tls"][self as usize]
    }
}

/// One entry of a phone's `codecs` option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codec {
    /// Index into `CODECS`.
    pub index: usize,
    /// 255 for the first codec, decreasing.
    pub priority: i32,
    pub enabled: bool,
}

/// Codecs the phones understand, with the attributes sent in the config.
pub const CODECS: &[(&str, &str)] = &[
    ("PCMU", "packetization=\"20\""),
    ("PCMA", "packetization=\"20\""),
    ("G722", "packetization=\"20\""),
    ("G7221", "packetization=\"20\" samplerate=\"uwb\" bitrate=\"48000\""),
    ("G726-32", "packetization=\"20\""),
    ("opus", "packetization=\"20\" complexity=\"10\" samplerate=\"wb\" use_vbr=\"0\""),
    ("G729", "packetization=\"20\""),
    ("iLBC", "packetization=\"30\""),
    ("L16", "packetization=\"20\""),
    ("L16-256", "packetization=\"20\""),
];

/// Ringtones built into the phone firmware.  Naming one of these in a
/// phone's `ringtone` option selects it as the active ringtone instead of
/// loading a custom one.
pub const BUILTIN_RINGTONES: &[&str] = &[
    "Alarm", "Chimes", "Digium", "GuitarStrum", "Jingle", "Office", "Office2", "RotaryPhone",
    "SteelDrum", "Techno", "Theme", "Tweedle", "Twinkle", "Vibe",
];

/// A line slot on a phone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneLine {
    pub name: Vec<u8>,
    /// Assigned with `external_line=` rather than `line=`.
    pub external: bool,
}

/// How a phone parks a call from the parking softkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParkingTransfer {
    #[default]
    Default = 0,
    Attended = 1,
    Blind = 2,
}

/// A `type=phone` section (the original's `phone_user`).
#[derive(Debug, Clone)]
pub struct Phone {
    pub name: Vec<u8>,

    pub config_file: Vec<u8>,
    pub full_name: Vec<u8>,
    pub timezone: Vec<u8>,
    pub active_ringtone: Vec<u8>,
    pub blf_contact_group: Vec<u8>,
    pub contacts_display_rules: Vec<u8>,
    pub group_pin: Vec<u8>,
    pub pin: Vec<u8>,
    pub mac: Vec<u8>,
    pub parking_exten: Vec<u8>,
    pub wallpaper_file: Vec<u8>,
    pub active_locale: Vec<u8>,
    pub lan_port_mode: Vec<u8>,
    pub pc_port_mode: Vec<u8>,
    pub blf_items: Vec<u8>,
    pub login_password: Vec<u8>,
    pub accept_local_calls: Vec<u8>,
    pub name_format: Vec<u8>,
    pub ehs: Vec<u8>,
    pub dot1x_passthrough: Vec<u8>,
    pub dot1x_method: Vec<u8>,
    pub dot1x_eapol_on_disconnect: Vec<u8>,
    pub dot1x_identity: Vec<u8>,
    pub dot1x_anonymous_identity: Vec<u8>,
    pub dot1x_password: Vec<u8>,
    pub dot1x_client_cert_url: Vec<u8>,
    pub dot1x_client_cert_value: Vec<u8>,
    pub dot1x_root_cert_url: Vec<u8>,
    pub dot1x_root_cert_value: Vec<u8>,
    pub dot1x_debug: Vec<u8>,
    /// "0" or "1".
    pub openvpn_enable: Vec<u8>,
    pub openvpn_config_file_url: Vec<u8>,
    pub openvpn_config_file_value: Vec<u8>,
    pub openvpn_root_cert_url: Vec<u8>,
    pub openvpn_root_cert_value: Vec<u8>,
    pub openvpn_client_cert_url: Vec<u8>,
    pub openvpn_client_cert_value: Vec<u8>,
    pub openvpn_client_key_url: Vec<u8>,
    pub openvpn_client_key_value: Vec<u8>,
    pub openvpn_logging: Vec<u8>,
    pub idle_company_text: Vec<u8>,

    pub lines: Vec<PhoneLine>,
    pub contacts: Vec<Vec<u8>>,
    pub applications: Vec<Vec<u8>>,
    pub networks: Vec<Vec<u8>>,
    pub ringtones: Vec<Vec<u8>>,
    pub firmware: Vec<Vec<u8>>,
    pub alerts: Vec<Vec<u8>>,
    pub multicastpages: Vec<Vec<u8>>,
    /// (model, file) from the `<model>_logo_file` options.
    pub logos: Vec<(Vec<u8>, Vec<u8>)>,
    pub codecs: Vec<Codec>,

    pub ntp_resync: i32,
    pub web_ui_enabled: bool,
    pub record_own_calls: bool,
    pub blf_unused_linekeys: bool,
    pub blf_page_return_timeout: i32,
    pub send_to_vm: bool,
    pub use_local_storage: bool,
    pub contacts_max_subscriptions: i32,
    pub lock_preferences: bool,
    pub brightness: i32,
    pub contrast: i32,
    pub dim_backlight: bool,
    pub backlight_timeout: i32,
    pub backlight_dim_level: i32,
    pub default_fontsize: i32,
    pub handshake_timeout: i32,
    pub display_mc_notification: bool,
    pub small_clock: bool,
    pub ringer_volume: i32,
    pub speaker_volume: i32,
    pub handset_volume: i32,
    pub headset_volume: i32,
    pub handset_sidetone_db: i32,
    pub headset_sidetone_db: i32,
    pub reset_call_volume: bool,
    pub headset_answer: bool,
    pub ring_headset_only: bool,
    pub call_waiting_tone: bool,
    /// Set (+0x960) once `presence::user_application_sync` found one of
    /// the phone's status applications: the presence options and
    /// `send486_mask` then come from the status applications.  Cleared by
    /// `set_user_defaults`.
    pub send486_custom: bool,
    /// Bit mask (by presence state) of the states that make the phone
    /// reject calls with 486.  Defaults to xa and dnd.
    pub send486_mask: u32,
    /// The presence options (+0x8e8), in insertion order; see
    /// `presence::ordered` for the container order.
    pub presence_options: Vec<presence::PresenceOption>,
    pub can_forward_calls: bool,
    pub show_call_log: bool,
    pub show_call_parking: bool,
    pub parking_transfer_type: ParkingTransfer,
    pub allow_insecure_ssl: bool,
    /// The original never resets this, and it starts out off.
    pub enable_check_sync: bool,
    /// -1 when not configured.
    pub transport_tls_allowed: i32,
    pub logout_enabled: bool,
    pub expansion_enabled: bool,
    pub expansion_page_indicators_enabled: bool,

    /// `pin=voicemail`: use the voicemail password of the primary line.
    pub pin_is_voicemail: bool,

    // ---- runtime state (survives reloads) ----
    pub last_mac: Vec<u8>,
    pub last_uri: Vec<u8>,
    pub last_session_id: Vec<u8>,
    /// The phone's pin as last applied (also tracks voicemail pins).
    pub applied_pin: Vec<u8>,
    /// Configuration token state (+0x984): 0 until the first token is
    /// issued, then 1.  (The user list's unported variant also knows 2
    /// and 3.)
    pub token_state: i32,
    /// Sum of the characters (as signed chars) of the latest token
    /// issued (+0x988).
    pub token_sum: i32,
    /// The same for the token issued before it (+0x98c).
    pub prev_token_sum: i32,

    // ---- reload bookkeeping ----
    pub delme: bool,
    pub needs_reconfigure: bool,
}

impl Phone {
    pub fn new(name: &[u8]) -> Phone {
        Phone { name: name.to_vec(), ..Phone::blank() }
    }

    /// Reset everything that comes from configuration (`set_user_defaults`),
    /// including the presence options (back to the six defaults; the
    /// caller runs `presence::sync_applications` with the previous
    /// application list, as the original does).
    pub fn set_defaults(&mut self) {
        let fresh = Phone {
            name: std::mem::take(&mut self.name),
            enable_check_sync: self.enable_check_sync,
            pin_is_voicemail: self.pin_is_voicemail,
            last_mac: std::mem::take(&mut self.last_mac),
            last_uri: std::mem::take(&mut self.last_uri),
            last_session_id: std::mem::take(&mut self.last_session_id),
            applied_pin: std::mem::take(&mut self.applied_pin),
            token_state: self.token_state,
            token_sum: self.token_sum,
            prev_token_sum: self.prev_token_sum,
            delme: self.delme,
            needs_reconfigure: self.needs_reconfigure,
            openvpn_enable: "0".into(),
            presence_options: presence::default_options(),
            ..Phone::blank()
        };
        *self = fresh;
    }

    fn blank() -> Phone {
        // A zeroed phone, as returned by ao2_alloc, with the defaults that
        // set_user_defaults applies.
        Phone {
            name: Vec::new(),
            config_file: Vec::new(),
            full_name: Vec::new(),
            timezone: Vec::new(),
            active_ringtone: Vec::new(),
            blf_contact_group: Vec::new(),
            contacts_display_rules: Vec::new(),
            group_pin: Vec::new(),
            pin: Vec::new(),
            mac: Vec::new(),
            parking_exten: Vec::new(),
            wallpaper_file: Vec::new(),
            active_locale: Vec::new(),
            lan_port_mode: Vec::new(),
            pc_port_mode: Vec::new(),
            blf_items: Vec::new(),
            login_password: Vec::new(),
            accept_local_calls: Vec::new(),
            name_format: Vec::new(),
            ehs: Vec::new(),
            dot1x_passthrough: Vec::new(),
            dot1x_method: Vec::new(),
            dot1x_eapol_on_disconnect: Vec::new(),
            dot1x_identity: Vec::new(),
            dot1x_anonymous_identity: Vec::new(),
            dot1x_password: Vec::new(),
            dot1x_client_cert_url: Vec::new(),
            dot1x_client_cert_value: Vec::new(),
            dot1x_root_cert_url: Vec::new(),
            dot1x_root_cert_value: Vec::new(),
            dot1x_debug: Vec::new(),
            openvpn_enable: "0".into(),
            openvpn_config_file_url: Vec::new(),
            openvpn_config_file_value: Vec::new(),
            openvpn_root_cert_url: Vec::new(),
            openvpn_root_cert_value: Vec::new(),
            openvpn_client_cert_url: Vec::new(),
            openvpn_client_cert_value: Vec::new(),
            openvpn_client_key_url: Vec::new(),
            openvpn_client_key_value: Vec::new(),
            openvpn_logging: Vec::new(),
            idle_company_text: Vec::new(),
            lines: Vec::new(),
            contacts: Vec::new(),
            applications: Vec::new(),
            networks: Vec::new(),
            ringtones: Vec::new(),
            firmware: Vec::new(),
            alerts: Vec::new(),
            multicastpages: Vec::new(),
            logos: Vec::new(),
            codecs: Vec::new(),
            ntp_resync: 0,
            web_ui_enabled: false,
            record_own_calls: false,
            blf_unused_linekeys: false,
            blf_page_return_timeout: 0,
            send_to_vm: true,
            use_local_storage: false,
            contacts_max_subscriptions: 0,
            lock_preferences: false,
            brightness: -1,
            contrast: -1,
            dim_backlight: true,
            backlight_timeout: -1,
            backlight_dim_level: -1,
            default_fontsize: 0,
            handshake_timeout: 946_080_000,
            display_mc_notification: true,
            small_clock: false,
            ringer_volume: -1,
            speaker_volume: 0,
            handset_volume: 0,
            headset_volume: 0,
            handset_sidetone_db: -1,
            headset_sidetone_db: -1,
            reset_call_volume: false,
            headset_answer: false,
            ring_headset_only: false,
            call_waiting_tone: true,
            send486_custom: false,
            send486_mask: 0x50,
            presence_options: Vec::new(),
            can_forward_calls: true,
            show_call_log: true,
            show_call_parking: true,
            parking_transfer_type: ParkingTransfer::Default,
            allow_insecure_ssl: false,
            enable_check_sync: false,
            transport_tls_allowed: -1,
            logout_enabled: false,
            expansion_enabled: false,
            expansion_page_indicators_enabled: false,
            pin_is_voicemail: false,
            last_mac: Vec::new(),
            last_uri: Vec::new(),
            last_session_id: Vec::new(),
            applied_pin: Vec::new(),
            token_state: 0,
            token_sum: 0,
            prev_token_sum: 0,
            delme: false,
            needs_reconfigure: false,
        }
    }

    /// The first line, if any.
    pub fn primary_line(&self) -> Option<&PhoneLine> {
        self.lines.first()
    }

    /// `phone_user_has_line` (FUN_0016aab0): is `line` one of the phone's
    /// line slots (`line=` or `external_line=`, case insensitive)?
    pub fn has_line(&self, line: &[u8]) -> bool {
        self.lines.iter().any(|l| l.name.eq_ignore_ascii_case(line))
    }
}

/// A line: either a SIP endpoint (`type=line`, or only referenced from a
/// phone) or an `external_line`.
#[derive(Debug, Clone, Default)]
pub struct Line {
    pub name: Vec<u8>,
    pub external: bool,

    pub tech: Vec<u8>,
    pub secret: Vec<u8>,
    pub callerid: Vec<u8>,
    pub mailbox: Vec<u8>,
    pub exten: Vec<u8>,
    pub context: Vec<u8>,
    pub first_name: Vec<u8>,
    pub last_name: Vec<u8>,
    pub title: Vec<u8>,
    pub line_label: Vec<u8>,
    pub location: Vec<u8>,
    pub digit_map: Vec<u8>,
    pub outboundproxy_address: Vec<u8>,
    pub outboundproxy_port: Vec<u8>,
    pub voicemail_uri: Vec<u8>,
    pub media_encryption: Vec<u8>,
    pub server_address: Vec<u8>,
    pub server_port: Vec<u8>,
    pub secondary_server_address: Vec<u8>,
    pub secondary_server_port: Vec<u8>,
    pub authname: Vec<u8>,
    pub userid: Vec<u8>,
    pub secondary_media_encryption: Vec<u8>,
    pub subscribecontext: Vec<u8>,
    /// Context the line's auto hint currently lives in.
    pub hint_context: Vec<u8>,
    pub pjsip_auth: Vec<u8>,
    pub plar_number: Vec<u8>,
    pub reregistration_timeout: i32,
    pub registration_retry_interval: i32,
    pub registration_max_retries: i32,
    pub transport: Transport,
    pub secondary_server_transport: Transport,
    /// `register=no`, or a static `host`.
    pub no_register: bool,

    pub delme: bool,
}

impl Line {
    pub fn new(name: &[u8], external: bool) -> Line {
        Line { name: name.to_vec(), external, ..Default::default() }
    }

    /// `set_line_defaults`: applied whenever a phone (re)claims the line.
    /// The context is "default" (the original uses sip.conf's `[general]`
    /// `context` when there is one; chan_sip is not supported).
    pub fn set_defaults(&mut self) {
        self.exten.clear();
        self.context = b"default".to_vec();
        for f in [
            &mut self.first_name,
            &mut self.last_name,
            &mut self.title,
            &mut self.line_label,
            &mut self.location,
            &mut self.digit_map,
            &mut self.mailbox,
            &mut self.server_address,
            &mut self.server_port,
            &mut self.media_encryption,
            &mut self.secondary_server_address,
            &mut self.secondary_server_port,
            &mut self.secondary_media_encryption,
            &mut self.authname,
            &mut self.userid,
            &mut self.secret,
            &mut self.callerid,
            &mut self.voicemail_uri,
            &mut self.outboundproxy_address,
            &mut self.outboundproxy_port,
            &mut self.plar_number,
        ] {
            f.clear();
        }
        self.no_register = false;
        self.reregistration_timeout = 0;
        self.registration_retry_interval = 0;
        self.registration_max_retries = 0;
        self.transport = Transport::Unset;
        self.secondary_server_transport = Transport::Unset;
    }

    /// The extension used to dial this line.
    pub fn dialable_exten(&self) -> &[u8] {
        if self.exten.is_empty() {
            &self.name
        } else {
            &self.exten
        }
    }
}

/// A `type=network` section, or an implicit network named after a phone.
#[derive(Debug, Clone)]
pub struct Network {
    pub name: Vec<u8>,
    pub alias: Vec<u8>,
    pub cidr: Vec<u8>,
    pub registration_address: Vec<u8>,
    pub registration_port: Vec<u8>,
    pub alternate_registration_address: Vec<u8>,
    pub alternate_registration_port: Vec<u8>,
    pub file_url_prefix: Vec<u8>,
    pub ntp_server: Vec<u8>,
    pub syslog_server: Vec<u8>,
    pub syslog_port: Vec<u8>,
    pub syslog_level: Vec<u8>,
    pub network_vlan_discovery_mode: Vec<u8>,
    pub public_firmware_url_prefix: Vec<u8>,
    pub network_vlan_id: i32,
    pub sip_qos: i32,
    pub rtp_qos: i32,
    pub sip_dscp: i32,
    pub rtp_dscp: i32,
    pub pc_vlan_id: i32,
    pub pc_qos: i32,
    pub udp_ka_interval: i32,
    pub transport: Transport,
    pub alternate_transport: Transport,
    pub delme: bool,
}

impl Network {
    /// `phone_network_create`.
    pub fn new(name: &[u8]) -> Network {
        Network {
            name: name.to_vec(),
            alias: Vec::new(),
            cidr: Vec::new(),
            registration_address: Vec::new(),
            registration_port: Vec::new(),
            alternate_registration_address: Vec::new(),
            alternate_registration_port: Vec::new(),
            file_url_prefix: Vec::new(),
            ntp_server: Vec::new(),
            syslog_server: Vec::new(),
            syslog_port: Vec::new(),
            syslog_level: Vec::new(),
            network_vlan_discovery_mode: Vec::new(),
            public_firmware_url_prefix: Vec::new(),
            network_vlan_id: 0,
            sip_qos: 3,
            rtp_qos: -1,
            sip_dscp: -1,
            rtp_dscp: -1,
            pc_vlan_id: 0,
            pc_qos: -1,
            udp_ka_interval: -1,
            transport: Transport::Unset,
            alternate_transport: Transport::Unset,
            delme: false,
        }
    }

    /// The reset applied before a `type=network` section is (re)read.
    pub fn reset_for_section(&mut self) {
        let name = std::mem::take(&mut self.name);
        *self = Network {
            sip_qos: 0,
            rtp_qos: 0,
            sip_dscp: 0,
            rtp_dscp: 0,
            pc_qos: 0,
            udp_ka_interval: 0,
            ..Network::new(&name)
        };
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ringtone {
    pub name: Vec<u8>,
    pub alias: Vec<u8>,
    pub filename: Vec<u8>,
    pub delme: bool,
}

/// A `type=firmware` section.
#[derive(Debug, Clone, Default)]
pub struct FirmwareOpt {
    pub name: Vec<u8>,
    /// Upper-cased.
    pub model: Vec<u8>,
    pub version: Vec<u8>,
    pub file: Vec<u8>,
    pub public_firmware: bool,
    pub delme: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Alert {
    pub name: Vec<u8>,
    pub alert_info: Vec<u8>,
    pub ring_type: Vec<u8>,
    pub ringtone: Vec<u8>,
    pub delme: bool,
}

/// A `type=multicastpage` section.
#[derive(Debug, Clone, Default)]
pub struct Page {
    pub name: Vec<u8>,
    pub alias: Vec<u8>,
    pub address: Vec<u8>,
    pub port: Vec<u8>,
    pub priority: Vec<u8>,
    /// Defaults to "0".
    pub interrupt: Vec<u8>,
    pub delme: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePermission {
    Status = 0,
    Overview = 1,
    Details = 2,
}

#[derive(Debug, Clone)]
pub struct QueueApp {
    pub queue: Vec<u8>,
    pub membername: Vec<u8>,
    pub location: Vec<u8>,
    pub login_exten: Vec<u8>,
    pub logout_exten: Vec<u8>,
    pub member: bool,
    pub permission: QueuePermission,
}

/// `send486` on a status application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Send486 {
    #[default]
    NotSet = 0,
    No = 1,
    Yes = 2,
}

#[derive(Debug, Clone, Default)]
pub struct StatusApp {
    /// Presence state (`dpma_ast::presence`).
    pub status: i32,
    pub send486: Send486,
    pub substatuses: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct ParkingApp {
    pub parkinglots: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct VoicemailApp {
    /// Name of the translation table.
    pub translation: Option<Vec<u8>>,
    pub require_password: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CustomApp {
    pub name: Vec<u8>,
    pub filename: Vec<u8>,
    pub md5: Vec<u8>,
    pub autostart: bool,
    pub idlescreen_softkey: bool,
    /// Any other option, in order.
    pub settings: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub enum AppKind {
    Queue(QueueApp),
    Status(StatusApp),
    Parking(ParkingApp),
    Voicemail(VoicemailApp),
    Custom(CustomApp),
}

impl AppKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            AppKind::Queue(_) => "Queue",
            AppKind::Status(_) => "Status",
            AppKind::Parking(_) => "Parking",
            AppKind::Voicemail(_) => "Voicemail",
            AppKind::Custom(_) => "Custom",
        }
    }
}

/// A `type=application` section.
#[derive(Debug, Clone)]
pub struct Application {
    pub name: Vec<u8>,
    pub kind: Option<AppKind>,
    pub delme: bool,
}

/// Every configured object.
pub struct Registry {
    pub phones: NamedMap<Phone>,
    pub lines: NamedMap<Line>,
    pub applications: NamedMap<Application>,
    pub networks: NamedMap<Network>,
    pub ringtones: NamedMap<Ringtone>,
    pub firmware: NamedMap<FirmwareOpt>,
    pub alerts: NamedMap<Alert>,
    pub pages: NamedMap<Page>,
}

impl Registry {
    fn new() -> Registry {
        Registry {
            phones: NamedMap::new(BUCKETS),
            lines: NamedMap::new(BUCKETS),
            applications: NamedMap::new(BUCKETS),
            networks: NamedMap::new(BUCKETS),
            ringtones: NamedMap::new(BUCKETS),
            firmware: NamedMap::new(BUCKETS),
            alerts: NamedMap::new(BUCKETS),
            pages: NamedMap::new(BUCKETS),
        }
    }

    /// Is `line` assigned to any phone?
    pub fn line_is_mapped(&self, line: &[u8]) -> bool {
        self.phones
            .values()
            .any(|p| p.lines.iter().any(|l| l.name.eq_ignore_ascii_case(line)))
    }

    /// The phone whose primary line is `line`.
    pub fn phone_for_line(&self, line: &[u8]) -> Option<&Phone> {
        self.phones
            .values()
            .find(|p| p.primary_line().is_some_and(|l| l.name.eq_ignore_ascii_case(line)))
    }
}

static REGISTRY: RwLock<Option<Registry>> = RwLock::new(None);

/// Read access to the registry (None when not loaded).
pub fn read() -> RwLockReadGuard<'static, Option<Registry>> {
    REGISTRY.read().unwrap()
}

/// Write access to the registry.
pub fn write() -> RwLockWriteGuard<'static, Option<Registry>> {
    REGISTRY.write().unwrap()
}

/// Ask a phone to fetch its configuration again (`phone_user_reconfigure`).
/// With `delete_token` the phone also discards its configuration token.
pub fn reconfigure(name: &[u8], delete_token: bool) -> Result<(), ()> {
    let (name, uri, session) = {
        let g = read();
        let Some(p) = g.as_ref().and_then(|r| r.phones.get(name)) else { return Err(()) };
        (p.name.clone(), p.last_uri.clone(), p.last_session_id.clone())
    };
    send_reconfigure(&name, &uri, &session, delete_token)
}

/// Send the reconfigure message to the phone's last known location.
pub fn send_reconfigure(name: &[u8], uri: &[u8], session: &[u8], delete_token: bool) -> Result<(), ()> {
    if uri.is_empty() {
        return Err(());
    }
    if session.is_empty() {
        dpma_ast::dpma_log!("Unable to reconfigure '{}': Session is unknown", name);
        return Err(());
    }
    runtime::send_reconfigure(session, uri, delete_token)
}
