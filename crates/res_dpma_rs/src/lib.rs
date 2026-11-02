//! res_dpma_rs: an open source, drop-in replacement for the Digium Phone
//! Module for Asterisk (DPMA): res_digium_phone.so and its two PJSIP
//! helper modules in one module.
//!
//! This file declares the module to Asterisk's loader and wires the
//! subsystems together in the official DPMA's order (res_digium_phone.c:
//! `load_module`, `load_full_components`, `unload_full_components`,
//! `reload`), followed by the PJSIP side (`pjsip`), which Asterisk loaded
//! after res_digium_phone as two helper modules.

#![allow(clippy::result_unit_err)]

pub mod ami;
pub mod apps;
pub mod auth;
pub mod avahi;
pub mod config;
#[cfg(feature = "devtest")]
pub mod devtest;
pub mod firmware;
pub mod method;
pub mod method_api;
pub mod phone_main;
pub mod pjsip;
pub mod request;
pub mod session;
pub mod settings_cli;
pub mod translation;
pub mod transport;
pub mod users;
pub mod util;
pub mod xmlutil;

use dpma_ast::cli::CliGroup;
use dpma_ast::log::LOG_ERROR;
use dpma_ast::manager::{self, Request};
use dpma_ast::sys;
use dpma_ast::{ast_log, dpma_log};
use std::os::raw::c_int;
use std::sync::Mutex;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The module's name (`AST_MODULE`): also the name it loads its
/// configuration files under, so `config reload` and the config hooks find
/// it.
pub const MODULE_NAME: &str = "res_dpma_rs";
pub const CONFIG_FILE: &str = "res_digium_phone.conf";
pub const LOG_LEVEL_NAME: &str = "DPMA";

const ACTION_RECONFIGURE: &str = "DigiumPhoneReconfigure";
const ACTION_RECONFIGURE_ALL: &str = "DigiumPhoneReconfigureAll";

struct Module {
    /// `digium_phones show settings` and `digium_phones show version`
    /// (registered by `load_module` before the full components).
    _settings_cli: CliGroup,
    /// The full components (`full_loaded`).  This implementation has no
    /// license check, so they are always loaded while the module is.
    full: Option<Full>,
}

struct Full {
    _cli: CliGroup,
    #[cfg(feature = "devtest")]
    _devtest: CliGroup,
}

static MODULE: Mutex<Option<Module>> = Mutex::new(None);

fn action_reconfigure(r: &Request) -> i32 {
    let name = r.header("PhoneName");
    if name.is_empty() {
        r.send_error("PhoneName argument is empty.");
        return 0;
    }
    let exists = users::read().as_ref().is_some_and(|reg| reg.phones.contains(&name));
    if !exists {
        r.send_error("Could not find user to reconfigure.");
    } else if users::reconfigure(&name, false).is_ok() {
        r.send_ack(Some(b"Reconfigure message successfully sent"));
    } else {
        r.send_error(
            "Phone has not contacted the server.  The server is unaware of the location of this device and can not reconfigure it at this time.\n",
        );
    }
    0
}

fn action_reconfigure_all(r: &Request) -> i32 {
    let names: Vec<Vec<u8>> = users::read()
        .as_ref()
        .map(|reg| reg.phones.values().map(|p| p.name.clone()).collect())
        .unwrap_or_default();
    for n in names {
        let _ = users::reconfigure(&n, false);
    }
    r.send_ack(Some(b"Reconfigure message successfully sent to all known device locations."));
    0
}

/// Load the phone configuration (`load_phone_config`) and let the
/// transport layer react to a changed `pjsip_message_context`
/// (`config_replace`).
fn load_config() -> Result<(), ()> {
    let (old, new) = config::load()?;
    transport::config_changed(old.as_deref(), &new);
    Ok(())
}

/// `unload_full_components` (FUN_00146bd0) for loaded or partly loaded
/// components.  Every step tolerates subsystems that were never loaded.
/// (On a failed load the official DPMA skips this and leaves the partly
/// loaded components registered; here they are always unloaded.)
fn unload_components(full: Option<Full>) {
    phone_main::stop();
    avahi::stop();
    ami::sched_destroy();
    firmware::unload();
    drop(full);
    manager::unregister(ACTION_RECONFIGURE);
    manager::unregister(ACTION_RECONFIGURE_ALL);
    users::load::unload();
    translation::unload();
    session::unload();
    apps::unload();
    auth::unload();
    request::unload();
    config::unload();
    ami::unregister_actions();
    method_api::unload();
    method::unload();
    ami::queue_dispose();
}

/// `load_full_components` (FUN_00146e30).  On error the caller unloads
/// whatever was loaded with `unload_components(None)`.
fn load_full() -> Result<Full, ()> {
    fn fail(msg: &str) -> Result<Full, ()> {
        ast_log!(LOG_ERROR, "{}", msg);
        Err(())
    }
    if load_config().is_err() {
        return fail("Failed to load phone config");
    }
    if dpma_proto::uri::parser_init().is_err() {
        return fail("Failed to initialize sip reqresp parser");
    }
    if apps::load().is_err() {
        return fail("Failed to load phone apps");
    }
    if request::load().is_err() {
        return Err(());
    }
    if auth::load().is_err() {
        return fail("Failed to load auth handlers");
    }
    if session::load(CONFIG_FILE.as_bytes()).is_err() {
        return fail("Failed to load phone message");
    }
    if translation::load(CONFIG_FILE).is_err() {
        return fail("Failed to load phone translation");
    }
    if users::load::load(CONFIG_FILE.as_bytes()).is_err() {
        // A missing or invalid res_digium_phone.conf is reported by the
        // config layer; the module still loads, as the official DPMA does.
        dpma_log!("No phones configured from {}", CONFIG_FILE);
    }
    if firmware::load().is_err() {
        return fail("Failed to load phone firmware");
    }

    // The phone users and translation CLI commands and the reconfigure
    // actions (registered by phone_users_load and the translation loader
    // in the official DPMA).
    let mut cmds = users::cli::commands();
    cmds.extend(users::status::commands());
    cmds.extend(translation::commands());
    let cli = CliGroup::register(&cmds);
    manager::register(ACTION_RECONFIGURE, manager::AUTH_MESSAGE, "", "", action_reconfigure);
    manager::register(ACTION_RECONFIGURE_ALL, manager::AUTH_MESSAGE, "", "", action_reconfigure_all);

    if ami::sched_create().is_err() {
        return fail("Failed to create ami schedule context");
    }
    if method::load().is_err() {
        return fail("Failed to load phone method");
    }
    if ami::queue_init().is_err() {
        return fail("Failed to initialize ami queued message container");
    }
    let _ = method_api::load();
    ami::register_actions();
    avahi::start();
    if phone_main::start().is_err() {
        dpma_log!("Unable to start phone_main() thread");
        return fail("Failed to start DPMA thread");
    }

    Ok(Full {
        _cli: cli,
        #[cfg(feature = "devtest")]
        _devtest: CliGroup::register(&devtest::commands()),
    })
}

/// Log hook for dpma-proto: its messages carry the official DPMA's file,
/// line, and function names.
fn proto_log(level: dpma_proto::LogLevel, file: &str, line: u32, func: &str, msg: &[u8]) {
    match level {
        dpma_proto::LogLevel::Dpma => dpma_ast::log::log(dpma_ast::log::custom_level(), file, line, func, msg),
        dpma_proto::LogLevel::Debug(n) => {
            if dpma_ast::log::debug_atleast(n) {
                dpma_ast::log::log(dpma_ast::log::LOG_DEBUG, file, line, func, msg);
            }
        }
    }
}

/// `load_module` of res_digium_phone (FUN_001472a0): 0, or 1 when the
/// module declines.
fn load_main() -> i32 {
    if !dpma_ast::log::register_custom_level(LOG_LEVEL_NAME) {
        ast_log!(LOG_ERROR, "Failed to register LOG_DPMA_NAME");
        return 1;
    }
    dpma_proto::set_log_hook(Some(proto_log));
    let settings_cli = CliGroup::register(&settings_cli::commands());
    let full = match load_full() {
        Ok(f) => f,
        Err(()) => {
            unload_components(None);
            drop(settings_cli);
            dpma_proto::set_log_hook(None);
            dpma_ast::log::unregister_custom_level(LOG_LEVEL_NAME);
            return 1;
        }
    };
    *MODULE.lock().unwrap() = Some(Module { _settings_cli: settings_cli, full: Some(full) });
    0
}

/// `unload_module` of res_digium_phone.
fn unload_main() {
    if let Some(mut m) = MODULE.lock().unwrap().take() {
        if let Some(full) = m.full.take() {
            unload_components(Some(full));
        }
    }
    dpma_proto::set_log_hook(None);
    dpma_ast::log::unregister_custom_level(LOG_LEVEL_NAME);
}

/// The module's `load`: res_digium_phone's `load_module`, then the PJSIP
/// helpers' (`pjsip::load`).  When the PJSIP side fails, the rest is
/// unloaded again and its result returned (AST_MODULE_LOAD_FAILURE when
/// there is no default outbound endpoint, which stops Asterisk from
/// starting, as the official DPMA helper's failure does).
unsafe extern "C" fn load_module() -> sys::ast_module_load_result {
    dpma_ast::module::reopen_if_restarted();
    dpma_ast::guard(sys::AST_MODULE_LOAD_DECLINE, || {
        if load_main() != 0 {
            return sys::AST_MODULE_LOAD_DECLINE;
        }
        let res = pjsip::load();
        if res != sys::AST_MODULE_LOAD_SUCCESS {
            unload_main();
        }
        res
    })
}

/// The module's `unload`: the PJSIP side first, as Asterisk unloads the
/// helpers before res_digium_phone.
unsafe extern "C" fn unload_module() -> c_int {
    dpma_ast::guard(0, || {
        pjsip::unload();
        unload_main();
        0
    })
}

/// `reload` (FUN_00147420), without the official DPMA's license re-check.
/// (The helpers have none; the PJSIP side follows res_digium_phone.conf
/// through its config hook.)
unsafe extern "C" fn reload_module() -> c_int {
    dpma_ast::guard(0, || {
        let g = MODULE.lock().unwrap();
        if !g.as_ref().is_some_and(|m| m.full.is_some()) {
            return 0;
        }
        let mut failed = false;
        failed |= load_config().is_err();
        failed |= translation::reload(CONFIG_FILE).is_err();
        failed |= users::load::reload(CONFIG_FILE.as_bytes()).is_err();
        failed |= session::reload(CONFIG_FILE.as_bytes()).is_err();
        failed |= firmware::reload().is_err();
        avahi::reload();
        let _ = phone_main::start();
        c_int::from(failed)
    })
}

dpma_ast::asterisk_module! {
    name: "res_dpma_rs",
    description: "Digium Phone Module for Asterisk",
    flags: sys::AST_MODFLAG_LOAD_ORDER,
    support_level: sys::AST_MODULE_SUPPORT_EXTENDED,
    load: load_module,
    unload: unload_module,
    reload: Some(reload_module),
    load_pri: sys::AST_MODPRI_DEFAULT,
    requires: "res_pjsip,res_pjsip_session,res_pjsip_pubsub",
    optional_modules: "func_presencestate,app_voicemail,res_parking,app_queue",
}
