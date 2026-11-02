//! The `[general]` section of res_digium_phone.conf.

use dpma_ast::config::{self, LoadResult};
use dpma_ast::{ast_log, bformat, dpma_log, log::LOG_WARNING};
use std::sync::{Arc, RwLock};

/// Authentication flags (shared with the session layer).
pub mod auth {
    /// A user must be selected (everything except plain `mac`).
    pub const USER: u32 = 1 << 0;
    /// The phone's own pin must be supplied.
    pub const PIN: u32 = 1 << 1;
    /// The global pin (or the phone's group_pin) must be supplied.
    pub const GLOBALPIN: u32 = 1 << 2;
    /// The MAC address must match.
    pub const MAC: u32 = 1 << 3;
    /// The global pin is required to fetch the user list.
    pub const USERLIST_GLOBALPIN: u32 = 1 << 4;
}

pub const DEFAULT_APPSERVER_CERTIFICATE: &[u8] = include_bytes!("trust/appserver.pem");
pub const DEFAULT_PHONE_CA: &[u8] = include_bytes!("trust/phone_ca.pem");

pub const DEFAULT_SERVICE_NAME: &str = "Digium Phone Config Server";
pub const DEFAULT_PJSIP_MESSAGE_CONTEXT: &str = "dpma_pjsip_message_context";
pub const DEFAULT_PORT: &str = "5060";
pub const DEFAULT_INITIAL_THREADS: u32 = 1;
pub const DEFAULT_MAX_THREADS: u32 = 4;
pub const DEFAULT_MESSAGE_DELAY: u32 = 5;

#[derive(Debug, Clone)]
pub struct General {
    pub auth_flags: u32,
    pub discovery_enabled: bool,
    pub initial_threads: u32,
    pub max_threads: u32,
    pub message_delay: u32,
    pub globalpin: Vec<u8>,
    pub mdns_address: Vec<u8>,
    pub mdns_port: Vec<u8>,
    pub mdns_transport: Vec<u8>,
    pub service_name: Vec<u8>,
    pub pjsip_message_context: Vec<u8>,
    pub file_directory: Vec<u8>,
    pub firmware_package_file: Vec<u8>,
    pub firmware_package_directory: Vec<u8>,
    pub server_uuid: Vec<u8>,
    pub registration_address: Vec<u8>,
    pub registration_port: Vec<u8>,
    pub firmware_url_prefix: Vec<u8>,
    /// Path to a PEM file with the server certificate sent to phones during
    /// the handshake; empty (the default) uses the embedded
    /// [`DEFAULT_APPSERVER_CERTIFICATE`].
    pub appserver_certificate: Vec<u8>,
    /// Path to a PEM bundle of the CA certificates phone certificates are
    /// verified against; empty (the default) uses the embedded
    /// [`DEFAULT_PHONE_CA`].
    pub phone_ca_file: Vec<u8>,
}

impl General {
    fn defaults() -> General {
        let file_dir = bformat!("{}/digium_phones", dpma_ast::var_dir());
        General {
            auth_flags: auth::USER,
            discovery_enabled: true,
            initial_threads: DEFAULT_INITIAL_THREADS,
            max_threads: DEFAULT_MAX_THREADS,
            message_delay: DEFAULT_MESSAGE_DELAY,
            globalpin: Vec::new(),
            mdns_address: Vec::new(),
            mdns_port: Vec::new(),
            mdns_transport: Vec::new(),
            service_name: DEFAULT_SERVICE_NAME.into(),
            pjsip_message_context: DEFAULT_PJSIP_MESSAGE_CONTEXT.into(),
            file_directory: file_dir,
            firmware_package_file: Vec::new(),
            firmware_package_directory: Vec::new(),
            server_uuid: Vec::new(),
            registration_address: Vec::new(),
            registration_port: Vec::new(),
            firmware_url_prefix: Vec::new(),
            appserver_certificate: Vec::new(),
            phone_ca_file: Vec::new(),
        }
    }

    /// The pjsip message context, never empty.
    pub fn message_context(&self) -> &[u8] {
        if self.pjsip_message_context.is_empty() {
            DEFAULT_PJSIP_MESSAGE_CONTEXT.as_bytes()
        } else {
            &self.pjsip_message_context
        }
    }

    pub fn service_name(&self) -> &[u8] {
        if self.service_name.is_empty() {
            DEFAULT_SERVICE_NAME.as_bytes()
        } else {
            &self.service_name
        }
    }

    pub fn mdns_port(&self) -> &[u8] {
        if self.mdns_port.is_empty() {
            DEFAULT_PORT.as_bytes()
        } else {
            &self.mdns_port
        }
    }

    pub fn registration_port(&self) -> &[u8] {
        if self.registration_port.is_empty() {
            DEFAULT_PORT.as_bytes()
        } else {
            &self.registration_port
        }
    }
}

static CURRENT: RwLock<Option<Arc<General>>> = RwLock::new(None);

/// The current general configuration (defaults if never loaded).
pub fn get() -> Arc<General> {
    if let Some(c) = CURRENT.read().unwrap().as_ref() {
        return c.clone();
    }
    Arc::new(General::defaults())
}

fn parse_uint(name: &str, value: &[u8]) -> Option<u32> {
    match std::str::from_utf8(value.trim_ascii()).ok().and_then(|v| v.parse::<u32>().ok()) {
        Some(v) => Some(v),
        None => {
            ast_log!(
                LOG_WARNING,
                "Invalid value '{}' - '{}' must be an an integer greater or equal to zero",
                value,
                name
            );
            None
        }
    }
}

/// A whole number, as Rust's `str::parse` reads it (surrounding white
/// space ignored).
fn parse_i64(value: &[u8]) -> Option<i64> {
    std::str::from_utf8(value.trim_ascii()).ok()?.parse().ok()
}

/// Load (or reload) the general configuration.  Returns the previous
/// configuration, if any, so callers can react to changes.
pub fn load() -> Result<(Option<Arc<General>>, Arc<General>), ()> {
    let cats = match config::load(crate::CONFIG_FILE, crate::MODULE_NAME, 0) {
        LoadResult::Loaded(c) => c,
        LoadResult::Missing => {
            dpma_log!("'{}' is missing.", crate::CONFIG_FILE);
            return Err(());
        }
        LoadResult::Invalid | LoadResult::Unchanged => {
            dpma_log!("'{}' is invalid.", crate::CONFIG_FILE);
            return Err(());
        }
    };

    let mut g = General::defaults();
    let mut mdns_port_set = false;

    if let Some(cat) = cats.iter().find(|c| c.name.eq_ignore_ascii_case(b"general")) {
        for v in &cat.vars {
            let name = v.name.to_ascii_lowercase();
            let value = v.value.as_slice();
            match name.as_slice() {
                b"globalpin" => g.globalpin = value.into(),
                b"userlist_auth" => {
                    if value.eq_ignore_ascii_case(b"disabled") {
                        g.auth_flags &= !auth::USERLIST_GLOBALPIN;
                    } else if value.eq_ignore_ascii_case(b"globalpin") {
                        g.auth_flags |= auth::USERLIST_GLOBALPIN;
                    }
                }
                b"mdns_address" => g.mdns_address = value.into(),
                b"mdns_port" => {
                    g.mdns_port = value.into();
                    mdns_port_set = true;
                }
                b"mdns_transport" => g.mdns_transport = value.into(),
                b"registration_address" => {
                    g.registration_address = value.into();
                    if g.mdns_address.is_empty() {
                        g.mdns_address = value.into();
                    }
                }
                b"registration_port" => {
                    g.registration_port = value.into();
                    if !mdns_port_set {
                        g.mdns_port = value.into();
                    }
                }
                b"service_name" => g.service_name = value.into(),
                b"service_discovery_enabled" => g.discovery_enabled = dpma_ast::util::ast_true(value),
                b"config_auth" => {
                    let v = value.to_ascii_lowercase();
                    match v.as_slice() {
                        b"mac_pin" => g.auth_flags |= auth::USER | auth::PIN | auth::MAC,
                        b"mac_globalpin" => g.auth_flags |= auth::USER | auth::GLOBALPIN | auth::MAC,
                        b"mac" => g.auth_flags = (g.auth_flags & !auth::USER) | auth::MAC,
                        b"pin" => g.auth_flags |= auth::USER | auth::PIN,
                        b"globalpin" => g.auth_flags |= auth::USER | auth::GLOBALPIN,
                        b"disabled" => g.auth_flags |= auth::USER,
                        _ => {}
                    }
                }
                b"file_directory" => g.file_directory = value.into(),
                b"firmware_url_prefix" => g.firmware_url_prefix = value.into(),
                b"firmware_package_directory" => {
                    let sep = if value.ends_with(b"/") { "" } else { "/" };
                    g.firmware_package_directory = bformat!("{}{}", value, sep);
                    g.firmware_package_file =
                        bformat!("{}{}{}", value, sep, crate::firmware::PACKAGE_CONFIG_FILE);
                }
                b"server_uuid" => g.server_uuid = value.into(),
                b"pjsip_message_context" => g.pjsip_message_context = value.into(),
                b"transaction_max_threads" => match parse_i64(value) {
                    Some(n) if n >= 1 => g.max_threads = n as u32,
                    _ => {
                        dpma_log!(
                            "transaction_max_threads must be numerical value >= 1. Forcing to default value ({}).",
                            DEFAULT_MAX_THREADS
                        );
                        g.max_threads = DEFAULT_MAX_THREADS;
                    }
                },
                b"transaction_initial_threads" => match parse_i64(value) {
                    Some(n) if n >= 1 => g.initial_threads = n as u32,
                    _ => {
                        dpma_log!(
                            "transaction_initial_threads must be numerical value >= 1. Forcing to default value ({}).",
                            DEFAULT_INITIAL_THREADS
                        );
                        g.initial_threads = DEFAULT_INITIAL_THREADS;
                    }
                },
                b"message_delay" => {
                    if let Some(n) = parse_uint("message_delay", value) {
                        g.message_delay = n;
                    }
                }
                // Additions of this implementation (see README).
                b"appserver_certificate" => g.appserver_certificate = value.into(),
                b"phone_ca_file" => g.phone_ca_file = value.into(),
                _ => dpma_log!("Unknown configuration parameter '{}'", v.name),
            }
        }
    }

    if g.initial_threads > g.max_threads {
        g.initial_threads = g.max_threads;
    }

    let new = Arc::new(g);
    let old = CURRENT.write().unwrap().replace(new.clone());
    Ok((old, new))
}

pub fn unload() {
    CURRENT.write().unwrap().take();
}

/// The settings as the official DPMA's `struct dpma_config` holds them for
/// `digium_phones show settings` and service discovery (phone_config.c,
/// `dcfg_alloc` and its getters): each text cut to its buffer in that
/// structure, and the getters' defaults for empty texts.
#[derive(Debug, Clone)]
pub struct Settings {
    pub auth_flags: u32,
    pub enable_discovery: bool,
    pub delay: u32,
    /// `password` (the global pin), 0x100 bytes.
    pub password: Vec<u8>,
    pub mdns_addr: Vec<u8>,
    /// "5060" when empty.
    pub mdns_port: Vec<u8>,
    pub mdns_transport: Vec<u8>,
    /// "Digium Phone Config Server" when empty.
    pub service_name: Vec<u8>,
    /// "dpma_pjsip_message_context" when empty.
    pub pjsip_message_context: Vec<u8>,
    /// "<astvarlibdir>/digium_phones" when empty.
    pub file_dir: Vec<u8>,
    pub firmware_package_dir: Vec<u8>,
    pub server_uuid: Vec<u8>,
}

/// `ast_copy_string` into a buffer of `size` bytes: at most `size - 1`
/// bytes, up to a NUL.
fn cut(value: &[u8], size: usize) -> Vec<u8> {
    let v = dpma_ast::dpma_bytes::c_view(value);
    v[..v.len().min(size - 1)].to_vec()
}

/// `value`, or `default` when it is empty.
fn or(value: Vec<u8>, default: &str) -> Vec<u8> {
    if value.is_empty() {
        default.as_bytes().to_vec()
    } else {
        value
    }
}

/// The settings of the current configuration; None while none is loaded.
pub fn settings() -> Option<Settings> {
    let g = CURRENT.read().unwrap().clone()?;
    Some(Settings {
        auth_flags: g.auth_flags,
        enable_discovery: g.discovery_enabled,
        delay: g.message_delay,
        password: cut(&g.globalpin, 0x100),
        mdns_addr: cut(&g.mdns_address, 0x200),
        mdns_port: or(cut(g.mdns_port(), 10), DEFAULT_PORT),
        mdns_transport: cut(&g.mdns_transport, 10),
        service_name: or(cut(&g.service_name, 0x80), DEFAULT_SERVICE_NAME),
        pjsip_message_context: or(cut(&g.pjsip_message_context, 0x50), DEFAULT_PJSIP_MESSAGE_CONTEXT),
        file_dir: match cut(&g.file_directory, 0x1000) {
            d if d.is_empty() => default_file_dir(),
            d => d,
        },
        firmware_package_dir: cut(&g.firmware_package_directory, 0x1000),
        server_uuid: cut(&g.server_uuid, 0x200),
    })
}

/// "<astvarlibdir>/digium_phones", cut to 0x1000 bytes.
pub fn default_file_dir() -> Vec<u8> {
    cut(&bformat!("{}/digium_phones", dpma_ast::var_dir()), 0x1000)
}
