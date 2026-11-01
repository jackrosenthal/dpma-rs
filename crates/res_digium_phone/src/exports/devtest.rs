//! Test hooks for the exported API (feature "devtest"):
//!
//! * `dpmadev exports line <name>`: look the line up through
//!   `phone_line_find` and print every setting, its `pjsip_auth` as seen
//!   through `phone_users_line_get_pjsip_auth`, and the object's
//!   reference count.
//! * `dpmadev exports objects`: list the line and phone containers.
//! * `dpmadev exports isdphone <endpoint>`: `dpma_pjsip_endpoint_is_dphone`.
//! * `dpmadev exports config`: the `dpma_config_*` getters.
//! * `dpmadev exports info <channel> [<body>]`: `info_send` with an
//!   `X-Event-Name: digium.test` header (and a JSON body if given).
//! * `dpmadev exports lastinfo [clear]`: the calls of
//!   `phone_user_token_set_last_info` so far (made by the PJSIP helper when
//!   a phone registers), oldest first.

use super::config_api::*;
use super::handlers::dpma_pjsip_endpoint_is_dphone;
use super::objects::{self, LineObj, UserObj};
use super::users_api::*;
use dpma_ast::ao2;
use dpma_ast::cli::{CliArgs, CliCommand, CliResult};
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

unsafe fn s(p: *const c_char) -> String {
    if p.is_null() {
        "(null)".into()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// The reference count of `obj` (without changing it).
unsafe fn refs(obj: *mut c_void) -> i32 {
    ao2::ao2_ref(obj, 0)
}

fn cmd_line(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let name = dpma_ast::cstr(&a.argv[3]);
    unsafe {
        let line = phone_line_find(name.as_ptr());
        if line.is_null() {
            a.out(&format!("phone_line_find('{}') returned NULL\n", a.argv[3]));
            return CliResult::Success;
        }
        let l: &LineObj = &*line;
        a.out(&format!(
            "object {:p} name '{}' refs {} (with ours) linked {}\npjsip_auth (export): '{}'\n",
            line,
            s(phone_users_line_get_name(line)),
            refs(line as *mut c_void),
            l.is_linked(),
            s(phone_users_line_get_pjsip_auth(line)),
        ));
        let user = phone_line_get_user(line);
        if !user.is_null() {
            a.out(&format!("phone_line_get_user: '{}' refs {}\n", (*user).key(), refs(user as *mut c_void)));
            ao2::cleanup(user as *mut c_void);
        }
        l.with_line(|line| {
            a.out(&format!(
                "tech '{}'\nsecret '{}'\ncallerid '{}'\nmailbox '{}'\ncontext '{}'\nauthname '{}'\npjsip_auth '{}'\nline_label '{}'\ndelme {}\n",
                line.tech, line.secret, line.callerid, line.mailbox, line.context, line.authname, line.pjsip_auth, line.line_label, line.delme
            ))
        });
        ao2::cleanup(line as *mut c_void);
    }
    CliResult::Success
}

fn cmd_objects(a: &CliArgs) -> CliResult {
    unsafe {
        a.out(&format!("lines container {:p}\n", phone_users_get_lines()));
        for o in ao2::collect(objects::lines_container()) {
            let l = &*(o as *mut LineObj);
            a.out(&format!("  line {:p} '{}' refs {} pjsip_auth '{}'\n", o, l.key(), refs(o) - 1, s(l.pjsip_auth_ptr())));
            ao2::cleanup(o);
        }
        a.out(&format!("users container {:p}\n", objects::users_container()));
        for o in ao2::collect(objects::users_container()) {
            let u = &*(o as *mut UserObj);
            a.out(&format!("  user {:p} '{}' refs {}\n", o, u.key(), refs(o) - 1));
            ao2::cleanup(o);
        }
    }
    CliResult::Success
}

fn cmd_isdphone(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let e = dpma_ast::cstr(&a.argv[3]);
    let r = unsafe { dpma_pjsip_endpoint_is_dphone(e.as_ptr()) };
    a.out(&format!("dpma_pjsip_endpoint_is_dphone('{}') = {}\n", a.argv[3], r));
    CliResult::Success
}

fn cmd_config(a: &CliArgs) -> CliResult {
    unsafe {
        let cfg = dpma_config_get();
        a.out(&format!("dpma_config_get() = {:p} (refs {})\n", cfg, refs(cfg as *mut c_void)));
        for (what, c) in [("NULL", std::ptr::null_mut()), ("current", cfg)] {
            a.out(&format!(
                "[{}] auth_flags {} discovery {} initial {} max {} delay {}\n",
                what,
                dpma_config_auth_flags(c),
                dpma_config_enable_discovery(c),
                dpma_config_initial_threads(c),
                dpma_config_max_threads(c),
                dpma_config_delay(c)
            ));
            a.out(&format!(
                "[{}] file_dir '{}' reg_port '{}' fw_file '{}' fw_dir '{}' uuid '{}' reg_addr '{}' url_prefix '{}'\n",
                what,
                s(dpma_config_file_dir(c)),
                s(dpma_config_reg_port(c)),
                s(dpma_config_firmware_package_file(c)),
                s(dpma_config_firmware_package_dir(c)),
                s(dpma_config_server_uuid(c)),
                s(dpma_config_reg_addr(c)),
                s(dpma_config_file_url_prefix(c))
            ));
            let mut buf = [0 as c_char; 256];
            dpma_append_config_file_dir(buf.as_mut_ptr(), 256, c"x.xml".as_ptr(), c);
            a.out(&format!("[{}] append_config_file_dir: '{}'\n", what, s(buf.as_ptr())));
        }
        if !cfg.is_null() {
            a.out(&format!(
                "password '{}' mdns_addr '{}' mdns_port '{}' mdns_transport '{}' service '{}' context '{}'\n",
                s(dpma_config_password(cfg)),
                s(dpma_config_mdns_addr(cfg)),
                s(dpma_config_mdns_port(cfg)),
                s(dpma_config_mdns_transport(cfg)),
                s(dpma_config_service_name(cfg)),
                s(dpma_config_pjsip_message_context(cfg))
            ));
        }
        dpma_config_unref(cfg);
    }
    CliResult::Success
}

extern "C" {
    fn ast_channel_get_by_name(search: *const c_char) -> *mut dpma_ast::types::AstChannel;
}

fn cmd_info(a: &CliArgs) -> CliResult {
    if a.argc() != 4 && a.argc() != 5 {
        return CliResult::ShowUsage;
    }
    let name = dpma_ast::cstr(&a.argv[3]);
    unsafe {
        let chan = ast_channel_get_by_name(name.as_ptr());
        if chan.is_null() {
            a.out(&format!("No channel '{}'\n", a.argv[3]));
            return CliResult::Success;
        }
        let body = a.argv.get(4).map(String::as_str).unwrap_or("");
        let ct = if body.is_empty() { "" } else { "application/json" };
        let r = super::info_send(chan, &[("X-Event-Name", "digium.test"), ("X-Extra", "1")], ct, body);
        a.out(&format!("info_send = {}\n", r));
        ao2::cleanup(chan as *mut c_void);
    }
    CliResult::Success
}

static LAST_INFO: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Record a call of `phone_user_token_set_last_info`.
pub fn record_last_info(phone: &str, uri: &str, session: Option<&str>, mac: Option<&str>, linked: bool) {
    let mut v = LAST_INFO.lock().unwrap_or_else(|e| e.into_inner());
    v.push(format!(
        "phone '{}' uri '{}' session {} mac {}{}",
        phone,
        uri,
        session.map_or("NULL".to_string(), |s| format!("'{}'", s)),
        mac.map_or("NULL".to_string(), |s| format!("'{}'", s)),
        if linked { "" } else { " (unlinked)" }
    ));
}

fn cmd_lastinfo(a: &CliArgs) -> CliResult {
    let mut v = LAST_INFO.lock().unwrap_or_else(|e| e.into_inner());
    match a.argc() {
        3 => {
            for (i, l) in v.iter().enumerate() {
                a.out(&format!("{}: {}\n", i + 1, l));
            }
            a.out(&format!("{} calls\n", v.len()));
        }
        4 if a.argv[3] == "clear" => v.clear(),
        _ => return CliResult::ShowUsage,
    }
    CliResult::Success
}

pub fn devtest_commands() -> Vec<CliCommand> {
    vec![
        CliCommand {
            command: "dpmadev exports lastinfo",
            summary: "List the phone_user_token_set_last_info calls",
            usage: "Usage: dpmadev exports lastinfo [clear]\n",
            exec: cmd_lastinfo,
            complete: None,
        },
        CliCommand {
            command: "dpmadev exports info",
            summary: "Send a SIP INFO through dpma_info_send",
            usage: "Usage: dpmadev exports info <channel> [<body>]\n",
            exec: cmd_info,
            complete: None,
        },
        CliCommand {
            command: "dpmadev exports line",
            summary: "Show a line through the exported API",
            usage: "Usage: dpmadev exports line <name>\n",
            exec: cmd_line,
            complete: None,
        },
        CliCommand {
            command: "dpmadev exports objects",
            summary: "List the exported line and phone objects",
            usage: "Usage: dpmadev exports objects\n",
            exec: cmd_objects,
            complete: None,
        },
        CliCommand {
            command: "dpmadev exports isdphone",
            summary: "Call dpma_pjsip_endpoint_is_dphone",
            usage: "Usage: dpmadev exports isdphone <endpoint>\n",
            exec: cmd_isdphone,
            complete: None,
        },
        CliCommand {
            command: "dpmadev exports config",
            summary: "Show the dpma_config_* getters",
            usage: "Usage: dpmadev exports config\n",
            exec: cmd_config,
            complete: None,
        },
    ]
}
