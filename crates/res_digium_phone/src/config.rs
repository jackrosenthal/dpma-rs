//! The `[general]` section of res_digium_phone.conf.

use dpma_ast::config::{self, LoadResult};
use dpma_ast::{ast_log, dpma_log, log::LOG_ERROR, log::LOG_WARNING};
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
    pub globalpin: String,
    pub mdns_address: String,
    pub mdns_port: String,
    pub mdns_transport: String,
    pub service_name: String,
    pub pjsip_message_context: String,
    pub file_directory: String,
    pub firmware_package_file: String,
    pub firmware_package_directory: String,
    pub server_uuid: String,
    pub registration_address: String,
    pub registration_port: String,
    pub firmware_url_prefix: String,
    /// PEM file with the server certificate presented to phones during the
    /// handshake.  Not part of the original module: the certificate must come
    /// from the user's own copy of the original distribution.
    pub appserver_certificate: String,
    /// PEM bundle of the CA certificates that phone certificates are
    /// verified against.  Same provenance as `appserver_certificate`.
    pub phone_ca_file: String,
}

impl General {
    fn defaults() -> General {
        let file_dir = format!("{}/digium_phones", dpma_ast::var_dir());
        let trust_dir = format!("{}/dpma", dpma_ast::config_dir());
        General {
            auth_flags: auth::USER,
            discovery_enabled: true,
            initial_threads: DEFAULT_INITIAL_THREADS,
            max_threads: DEFAULT_MAX_THREADS,
            message_delay: DEFAULT_MESSAGE_DELAY,
            globalpin: String::new(),
            mdns_address: String::new(),
            mdns_port: String::new(),
            mdns_transport: String::new(),
            service_name: DEFAULT_SERVICE_NAME.into(),
            pjsip_message_context: DEFAULT_PJSIP_MESSAGE_CONTEXT.into(),
            file_directory: file_dir,
            firmware_package_file: String::new(),
            firmware_package_directory: String::new(),
            server_uuid: String::new(),
            registration_address: String::new(),
            registration_port: String::new(),
            firmware_url_prefix: String::new(),
            appserver_certificate: format!("{}/appserver.pem", trust_dir),
            phone_ca_file: format!("{}/phone_ca.pem", trust_dir),
        }
    }

    /// The pjsip message context, never empty.
    pub fn message_context(&self) -> &str {
        if self.pjsip_message_context.is_empty() {
            DEFAULT_PJSIP_MESSAGE_CONTEXT
        } else {
            &self.pjsip_message_context
        }
    }

    pub fn service_name(&self) -> &str {
        if self.service_name.is_empty() {
            DEFAULT_SERVICE_NAME
        } else {
            &self.service_name
        }
    }

    pub fn mdns_port(&self) -> &str {
        if self.mdns_port.is_empty() {
            DEFAULT_PORT
        } else {
            &self.mdns_port
        }
    }

    pub fn registration_port(&self) -> &str {
        if self.registration_port.is_empty() {
            DEFAULT_PORT
        } else {
            &self.registration_port
        }
    }

    /// Path of `name` inside the file directory.
    pub fn file_path(&self, name: &str) -> String {
        if self.file_directory.ends_with('/') {
            format!("{}{}", self.file_directory, name)
        } else {
            format!("{}/{}", self.file_directory, name)
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

fn parse_uint(name: &str, value: &str) -> Option<u32> {
    match value.trim().parse::<u32>() {
        Ok(v) => Some(v),
        Err(_) => {
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

/// Load (or reload) the general configuration.  Returns the previous
/// configuration, if any, so callers can react to changes.
pub fn load() -> Result<(Option<Arc<General>>, Arc<General>), ()> {
    let cats = match config::load(crate::CONFIG_FILE, "res_digium_phone", 0) {
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

    if let Some(cat) = cats.iter().find(|c| c.name.eq_ignore_ascii_case("general")) {
        for v in &cat.vars {
            let name = v.name.to_ascii_lowercase();
            let value = v.value.as_str();
            match name.as_str() {
                "globalpin" => g.globalpin = value.into(),
                "userlist_auth" => {
                    if value.eq_ignore_ascii_case("disabled") {
                        g.auth_flags &= !auth::USERLIST_GLOBALPIN;
                    } else if value.eq_ignore_ascii_case("globalpin") {
                        g.auth_flags |= auth::USERLIST_GLOBALPIN;
                    }
                }
                "mdns_address" => g.mdns_address = value.into(),
                "mdns_port" => {
                    g.mdns_port = value.into();
                    mdns_port_set = true;
                }
                "mdns_transport" => g.mdns_transport = value.into(),
                "registration_address" => {
                    g.registration_address = value.into();
                    if g.mdns_address.is_empty() {
                        g.mdns_address = value.into();
                    }
                }
                "registration_port" => {
                    g.registration_port = value.into();
                    if !mdns_port_set {
                        g.mdns_port = value.into();
                    }
                }
                "service_name" => g.service_name = value.into(),
                "service_discovery_enabled" => g.discovery_enabled = dpma_ast::util::ast_true(value),
                "config_auth" => {
                    let v = value.to_ascii_lowercase();
                    match v.as_str() {
                        "mac_pin" => g.auth_flags |= auth::USER | auth::PIN | auth::MAC,
                        "mac_globalpin" => g.auth_flags |= auth::USER | auth::GLOBALPIN | auth::MAC,
                        "mac" => g.auth_flags = (g.auth_flags & !auth::USER) | auth::MAC,
                        "pin" => g.auth_flags |= auth::USER | auth::PIN,
                        "globalpin" => g.auth_flags |= auth::USER | auth::GLOBALPIN,
                        "disabled" => g.auth_flags |= auth::USER,
                        _ => {}
                    }
                }
                "file_directory" => g.file_directory = value.into(),
                "firmware_url_prefix" => g.firmware_url_prefix = value.into(),
                "firmware_package_directory" => {
                    let sep = if value.ends_with('/') { "" } else { "/" };
                    g.firmware_package_directory = format!("{}{}", value, sep);
                    g.firmware_package_file =
                        format!("{}{}{}", value, sep, crate::firmware::PACKAGE_CONFIG_FILE);
                }
                "server_uuid" => g.server_uuid = value.into(),
                "pjsip_message_context" => g.pjsip_message_context = value.into(),
                "transaction_max_threads" => match value.trim().parse::<i64>() {
                    Ok(n) if n >= 1 => g.max_threads = n as u32,
                    _ => {
                        dpma_log!(
                            "transaction_max_threads must be numerical value >= 1. Forcing to default value ({}).",
                            DEFAULT_MAX_THREADS
                        );
                        g.max_threads = DEFAULT_MAX_THREADS;
                    }
                },
                "transaction_initial_threads" => match value.trim().parse::<i64>() {
                    Ok(n) if n >= 1 => g.initial_threads = n as u32,
                    _ => {
                        dpma_log!(
                            "transaction_initial_threads must be numerical value >= 1. Forcing to default value ({}).",
                            DEFAULT_INITIAL_THREADS
                        );
                        g.initial_threads = DEFAULT_INITIAL_THREADS;
                    }
                },
                "message_delay" => {
                    if let Some(n) = parse_uint("message_delay", value) {
                        g.message_delay = n;
                    }
                }
                // Additions of this implementation (see README).
                "appserver_certificate" => g.appserver_certificate = value.into(),
                "phone_ca_file" => g.phone_ca_file = value.into(),
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

/// Log configuration problems that make the module unusable.
pub fn check_trust_material(g: &General) {
    for (what, path) in [
        ("appserver_certificate", &g.appserver_certificate),
        ("phone_ca_file", &g.phone_ca_file),
    ] {
        if !std::path::Path::new(path).exists() {
            ast_log!(
                LOG_ERROR,
                "{} '{}' does not exist; phones will not be able to complete a handshake. See README.md, \"Phone trust material\".",
                what,
                path
            );
        }
    }
}
