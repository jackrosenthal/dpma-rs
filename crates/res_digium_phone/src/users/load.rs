//! Loading and reloading res_digium_phone.conf, plus the related settings
//! read from sip.conf, users.conf, and voicemail.conf
//! (`phone_users_process_phone_config`).
//!
//! A reload marks every object for deletion, re-reads every section
//! (clearing the mark on what is still configured), then removes whatever is
//! still marked.

use super::options::{self, UserCtx};
use super::*;
use dpma_ast::config::{self, Category, LoadResult};
use dpma_ast::util::{ast_false, ast_true};
use dpma_ast::{ast_debug, dpma_log};
use std::sync::Mutex;

/// The configuration files this module reads.  The ones other than
/// res_digium_phone.conf are refreshed by config hooks whenever their owning
/// module reloads them.
#[derive(Default)]
struct Sources {
    /// res_digium_phone.conf
    phones: Option<Vec<Category>>,
    /// sip.conf
    sip: Option<Vec<Category>>,
    /// users.conf, as seen by chan_sip
    users_sip: Option<Vec<Category>>,
    /// voicemail.conf
    voicemail: Option<Vec<Category>>,
    /// users.conf, as seen by app_voicemail
    users_voicemail: Option<Vec<Category>>,
}

static SOURCES: Mutex<Option<Sources>> = Mutex::new(None);
/// Serializes whole reconfiguration passes (`users_cfg_lock`).
static PROCESS: Mutex<()> = Mutex::new(());

/// Handlers that fill in line details from other configuration (the pjsip
/// helper module registers one).  Called during every reload, after the
/// lines have been created.
pub type LineConfigHandler = fn(&mut NamedMap<Line>);
static LINE_HANDLERS: Mutex<Vec<LineConfigHandler>> = Mutex::new(Vec::new());

pub fn register_line_config_handler(h: LineConfigHandler) {
    LINE_HANDLERS.lock().unwrap().push(h);
}

pub fn unregister_line_config_handler(h: LineConfigHandler) {
    LINE_HANDLERS.lock().unwrap().retain(|x| *x as usize != h as usize);
}

const HOOKS: &[(&str, &str, &str)] = &[
    ("digium_phones_sip", "sip.conf", "chan_sip"),
    ("digium_phones_users_sip", "users.conf", "chan_sip"),
    ("digium_phones_voicemail", "voicemail.conf", "app_voicemail"),
    ("digium_phones_users_voicemail", "users.conf", "app_voicemail"),
];

fn load_file(file: &str) -> Option<Vec<Category>> {
    match config::load(file, "res_digium_phone", config::CONFIG_FLAG_NOCACHE) {
        LoadResult::Loaded(c) => Some(c),
        _ => None,
    }
}

/// Store a refreshed copy of one of the other modules' files and reprocess.
fn set_and_process(which: &str, cats: Option<Vec<Category>>) {
    {
        let mut g = SOURCES.lock().unwrap();
        let Some(src) = g.as_mut() else { return };
        if cats.is_none() {
            dpma_log!("{} settings missing or invalid", which);
        }
        match which {
            "SIP" => src.sip = cats,
            "User SIP" => src.users_sip = cats,
            "Voicemail" => src.voicemail = cats,
            "User voicemail" => src.users_voicemail = cats,
            _ => return,
        }
    }
    let _ = process(which);
    if which == "SIP" {
        check_sip_message_config();
    }
}

fn hook_sip(c: Option<Vec<Category>>) {
    set_and_process("SIP", c);
}
fn hook_users_sip(c: Option<Vec<Category>>) {
    set_and_process("User SIP", c);
}
fn hook_voicemail(c: Option<Vec<Category>>) {
    set_and_process("Voicemail", c);
}
fn hook_users_voicemail(c: Option<Vec<Category>>) {
    set_and_process("User voicemail", c);
}

/// `phone_users_load`.
pub fn load(filename: &str) -> Result<(), ()> {
    *write() = Some(Registry::new());
    *SOURCES.lock().unwrap() = Some(Sources::default());

    set_and_process("SIP", load_file("sip.conf"));
    set_and_process("User SIP", load_file("users.conf"));
    set_and_process("Voicemail", load_file("voicemail.conf"));

    let hooks: [dpma_ast::hooks::HookFn; 4] = [hook_sip, hook_users_sip, hook_voicemail, hook_users_voicemail];
    for ((name, file, module), f) in HOOKS.iter().zip(hooks) {
        dpma_ast::hooks::register(name, file, module, f);
    }

    restore_from_db();
    // last_session_id: needs the sessions restored by session::load.
    super::runtime::restore_sessions();
    reload(filename)
}

/// `phone_users_reload`: re-read res_digium_phone.conf and reprocess.
pub fn reload(filename: &str) -> Result<(), ()> {
    let cats = match config::load(filename, "res_digium_phone", 0) {
        LoadResult::Loaded(c) => Some(c),
        _ => None,
    };
    if let Some(src) = SOURCES.lock().unwrap().as_mut() {
        src.phones = cats;
    }
    process(filename)
}

/// `phone_users_unload`.
pub fn unload() {
    for (name, _, _) in HOOKS {
        dpma_ast::hooks::unregister(name);
    }
    SOURCES.lock().unwrap().take();
    dpma_ast::pbx::context_destroy_registrar(REGISTRAR);
    write().take();
}

/// Bring back the runtime state saved in AstDB for each phone
/// (`phone_user_db_restore`).  Values look like
/// "last_mac=...;last_uri=...;last_session_id=...", where the URI may itself
/// contain ";transport=...".
fn restore_from_db() {
    let entries = dpma_ast::db::tree(DB_FAMILY);
    let mut g = write();
    let Some(reg) = g.as_mut() else { return };
    for (key, value) in entries {
        let Some((_, name)) = key.rsplit_once('/') else { continue };
        if value.is_empty() || name.is_empty() {
            continue;
        }
        let field = |tag: &str| -> String {
            let Some(i) = value.find(tag) else { return String::new() };
            let rest = &value[i + tag.len()..];
            let mut end = 0;
            let b = rest.as_bytes();
            while end < b.len() {
                if b[end] == b';' && !rest[end + 1..].starts_with("trans") {
                    break;
                }
                end += 1;
            }
            rest[..end].to_string()
        };
        let (phone, _) = reg.phones.get_or_insert_with(name, || Phone::new(name));
        let mac = field("last_mac=");
        if !mac.is_empty() {
            phone.last_mac = mac;
        }
        let uri = field("last_uri=");
        if !uri.is_empty() {
            phone.last_uri = uri;
        }
        // last_session_id is restored by the session layer once sessions
        // are persisted; until then a stale id is useless.
    }
}

fn sip_general<'a>(cats: &'a Option<Vec<Category>>, var: &str) -> Option<&'a str> {
    cats.as_ref()?
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case("general"))?
        .get(var)
}

/// Warn about sip.conf settings chan_sip needs for phone messaging and
/// hand the chan_sip message context to the transport layer, which
/// (re)builds its dialplan routing (`process_message_config`).  Only
/// relevant when sip.conf exists.
fn check_sip_message_config() {
    if let Some(context) = sip_message_context() {
        crate::transport::sip_message_context_changed(&context);
    }
}

/// sip.conf's `outofcall_message_context` ("" when unset), logging the
/// settings chan_sip needs; None when sip.conf is not loaded.
fn sip_message_context() -> Option<String> {
    let g = SOURCES.lock().unwrap();
    let src = g.as_ref()?;
    let sip = src.sip.as_ref()?;
    let Some(general) = sip.iter().find(|c| c.name.eq_ignore_ascii_case("general")) else {
        return Some(String::new());
    };
    let mut context = String::new();
    let mut accept = false;
    let mut no_auth = false;
    for v in &general.vars {
        if v.name.eq_ignore_ascii_case("outofcall_message_context") {
            if !v.value.is_empty() {
                context = v.value.clone();
            }
        } else if v.name.eq_ignore_ascii_case("accept_outofcall_message") {
            accept = ast_true(&v.value);
        } else if v.name.eq_ignore_ascii_case("auth_message_requests") {
            no_auth = ast_false(&v.value);
        }
    }
    if context.is_empty() {
        dpma_log!("outofcall_message_context must be configured in sip.conf for res_digium_phone to function properly.");
    }
    if !accept {
        dpma_log!("accept_outofcall_message must be enabled in sip.conf for res_digium_phone to function properly");
    }
    if !no_auth {
        dpma_log!("auth_message_requests must be disabled in sip.conf for res_digium_phone to function properly");
    }
    Some(context)
}

/// Side effects collected while the registry is locked and performed after.
#[derive(Default)]
struct Effects {
    new_internal_lines: Vec<String>,
    remove_hints: Vec<(String, String)>,
    db_del: Vec<String>,
    /// (phone, last_uri, last_session_id)
    reconfigure: Vec<(String, String, String)>,
}

fn is_type(cat: &Category, ty: &str) -> bool {
    cat.get("type").is_some_and(|t| t.eq_ignore_ascii_case(ty))
}

const KNOWN_TYPES: &[&str] = &[
    "phone", "line", "external_line", "application", "network", "ringtone", "firmware", "alert",
    "multicastpage", "translation",
];

/// Reprocess everything (`phone_users_process_phone_config`).
pub fn process(trigger: &str) -> Result<(), ()> {
    dpma_log!("Reconfiguring triggered by {}", trigger);

    let (phones_cfg, sip, users_sip, voicemail, users_voicemail) = {
        let g = SOURCES.lock().unwrap();
        let Some(src) = g.as_ref() else { return Err(()) };
        let Some(p) = src.phones.clone() else { return Err(()) };
        (p, src.sip.clone(), src.users_sip.clone(), src.voicemail.clone(), src.users_voicemail.clone())
    };

    let _pass = PROCESS.lock().unwrap();

    let nonempty = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(str::to_string);
    let sip_context = nonempty(sip_general(&sip, "context")).unwrap_or_else(|| "default".into());
    let users_context = nonempty(sip_general(&voicemail, "userscontext")).unwrap_or_else(|| "default".into());
    let general = crate::config::get();

    let mut fx = Effects::default();
    let hints;
    {
        let mut g = write();
        let Some(reg) = g.as_mut() else { return Err(()) };

        // ---- mark ----
        for p in reg.phones.values_mut() {
            p.delme = true;
            p.needs_reconfigure = false;
        }
        for l in reg.lines.values_mut() {
            l.subscribecontext.clear();
            l.delme = true;
        }
        for a in reg.applications.values_mut() {
            a.delme = true;
        }
        for n in reg.networks.values_mut() {
            n.delme = true;
        }
        for r in reg.ringtones.values_mut() {
            r.delme = true;
        }
        for f in reg.firmware.values_mut() {
            f.delme = true;
        }
        for a in reg.alerts.values_mut() {
            a.delme = true;
        }
        for p in reg.pages.values_mut() {
            p.delme = true;
        }

        // ---- phones ----
        for cat in phones_cfg.iter().filter(|c| !c.name.eq_ignore_ascii_case("general")) {
            match cat.get("type") {
                None => dpma_log!("No type set for {}", cat.name),
                Some(t) if t.eq_ignore_ascii_case("phone") => {
                    build_phone(reg, cat, &sip_context, &general, &mut fx);
                }
                Some(t) if KNOWN_TYPES.iter().any(|k| k.eq_ignore_ascii_case(t)) => {}
                Some(t) => dpma_log!("Unknown type \"{}\" for entry \"{}\"", t, cat.name),
            }
        }

        // ---- lines from sip.conf / users.conf (chan_sip) ----
        if let Some(sip) = &sip {
            for cat in sip.iter().filter(|c| !c.name.eq_ignore_ascii_case("general")) {
                if let Some(line) = reg.lines.get_mut(&cat.name) {
                    line.delme = false;
                    let _ = options::set_line_option(line, "tech", "SIP");
                    for v in &cat.vars {
                        let _ = options::set_line_option(line, &v.name, &v.value);
                    }
                }
            }
        }
        if let Some(users) = &users_sip {
            let all = ast_true(sip_general(&users_sip, "hassip").unwrap_or(""));
            for cat in users.iter().filter(|c| !c.name.eq_ignore_ascii_case("general")) {
                let v = cat.get("hassip").unwrap_or("");
                if (all && !ast_false(v)) || ast_true(v) {
                    if let Some(line) = reg.lines.get_mut(&cat.name) {
                        line.delme = false;
                        for v in &cat.vars {
                            let _ = options::set_line_option(line, &v.name, &v.value);
                        }
                    }
                }
            }
        }

        // ---- other modules (pjsip) ----
        for h in LINE_HANDLERS.lock().unwrap().iter() {
            h(&mut reg.lines);
        }

        // ---- [line] / [external_line] sections ----
        for cat in phones_cfg.iter().filter(|c| !c.name.eq_ignore_ascii_case("general")) {
            if !(is_type(cat, "line") || is_type(cat, "external_line")) {
                continue;
            }
            if let Some(line) = reg.lines.get_mut(&cat.name) {
                line.delme = false;
                for v in &cat.vars {
                    let _ = options::set_line_option(line, &v.name, &v.value);
                }
            }
        }

        // ---- voicemail.conf: pins for phones with pin=voicemail ----
        if let Some(vm) = &voicemail {
            for cat in vm.iter() {
                if cat.name.eq_ignore_ascii_case("general") || cat.name.eq_ignore_ascii_case("zonemessages") {
                    continue;
                }
                for v in &cat.vars {
                    set_voicemail_pin(reg, &v.name, &cat.name, &v.value);
                }
            }
        }

        // ---- users.conf (app_voicemail): mailboxes ----
        if let Some(users) = &users_voicemail {
            let all = ast_true(sip_general(&users_voicemail, "hasvoicemail").unwrap_or(""));
            for cat in users.iter().filter(|c| !c.name.eq_ignore_ascii_case("general")) {
                let v = cat.get("hasvoicemail").unwrap_or("");
                let has = if all { !ast_false(v) || ast_true(v) } else { ast_true(v) };
                if has {
                    if let Some(line) = reg.lines.get_mut(&cat.name) {
                        options::set_line_mailbox(line, &format!("{}@{}", cat.name, users_context));
                    }
                }
            }
        }

        process_applications(reg, &phones_cfg);
        process_networks(reg, &phones_cfg);
        process_simple(reg, &phones_cfg);

        // ---- sweep ----
        reg.pages.retain(|p| !p.delme);
        reg.alerts.retain(|a| !a.delme);
        reg.ringtones.retain(|r| !r.delme);
        reg.firmware.retain(|f| !f.delme);
        reg.networks.retain(|n| !n.delme);
        reg.applications.retain(|a| !a.delme && a.kind.is_some());
        reg.lines.retain(|l| {
            if l.delme {
                if !l.hint_context.is_empty() {
                    fx.remove_hints.push((l.hint_context.clone(), format!("auto_hint_{}", l.name)));
                }
                false
            } else {
                true
            }
        });
        reg.phones.retain(|p| {
            let target = (p.name.clone(), p.last_uri.clone(), p.last_session_id.clone());
            if p.delme {
                fx.reconfigure.push(target);
                fx.db_del.push(p.name.clone());
                false
            } else {
                if p.needs_reconfigure {
                    dpma_log!("Sending reconfigure to user {}", p.name);
                    fx.reconfigure.push(target);
                }
                true
            }
        });
        for p in reg.phones.values_mut() {
            p.needs_reconfigure = false;
        }

        hints = plan_hints(reg, &mut fx);
    }

    // ---- side effects, without the registry lock ----
    for line in &fx.new_internal_lines {
        options::init_custom_presence(line);
    }
    for (context, exten) in &fx.remove_hints {
        dpma_ast::pbx::remove_extension(context, exten, dpma_ast::pbx::PRIORITY_HINT, REGISTRAR);
    }
    for (name, uri, session) in &fx.reconfigure {
        let _ = super::send_reconfigure(name, uri, session, false);
    }
    for name in &fx.db_del {
        dpma_ast::db::del(DB_FAMILY, name);
    }
    apply_hints(hints);
    Ok(())
}

/// `build_user`.
fn build_phone(reg: &mut Registry, cat: &Category, sip_context: &str, general: &crate::config::General, fx: &mut Effects) {
    let name = cat.name.as_str();
    let mut phone = match reg.phones.get_mut(name) {
        Some(p) => std::mem::replace(p, Phone::new(name)),
        None => Phone::new(name),
    };
    phone.delme = false;
    let old_lines = phone.lines.clone();
    phone.set_defaults();

    let lines_before: Vec<String> = reg.lines.values().map(|l| l.name.clone()).collect();
    {
        let mut ctx = UserCtx { lines: &mut reg.lines, networks: &mut reg.networks, sip_context };
        for v in &cat.vars {
            if options::set_user_option(&mut ctx, &mut phone, &v.name, &v.value).is_err() {
                dpma_log!(
                    "Invalid option '{}' at line {} is not supported by phone module.",
                    v.name,
                    v.lineno
                );
            }
        }
    }
    for l in reg.lines.values() {
        if !l.external && !lines_before.iter().any(|b| b.eq_ignore_ascii_case(&l.name)) {
            fx.new_internal_lines.push(l.name.clone());
        }
    }

    // An implicit network, named after the phone, from the [general]
    // registration settings.
    if !general.registration_address.is_empty() || !general.firmware_url_prefix.is_empty() {
        let (net, _) = reg.networks.get_or_insert_with(name, || Network::new(name));
        net.delme = false;
        let _ = options::set_network_option(net, "registration_address", &general.registration_address);
        let _ = options::set_network_option(net, "registration_port", general.registration_port());
        let _ = options::set_network_option(net, "file_url_prefix", &general.firmware_url_prefix);
    }
    if let Some(net) = reg.networks.get_mut(name) {
        net.cidr = "0.0.0.0/0".into();
        net.alias = "Default Network".into();
        phone.networks.push(net.name.clone());
    }

    if !old_lines.is_empty() && old_lines != phone.lines {
        phone.needs_reconfigure = true;
        dpma_log!("Phone user '{}' setting reconfigure due to change in lines", phone.name);
    }
    reg.phones.insert(name, phone);
}

/// `set_voicemail_pin`: a voicemail.conf mailbox entry.  The phone whose
/// primary line has this mailbox takes the voicemail password as its pin
/// when it is configured with `pin=voicemail`.
fn set_voicemail_pin(reg: &mut Registry, mailbox: &str, context: &str, value: &str) {
    let target = format!("{}@{}", mailbox, context);
    let mut found = None;
    for p in reg.phones.values() {
        let Some(primary) = p.primary_line() else { continue };
        let Some(line) = reg.lines.get(&primary.name) else { continue };
        if line.mailbox == target {
            found = Some(p.name.clone());
            break;
        }
    }
    let Some(name) = found else { return };
    let phone = reg.phones.get_mut(&name).unwrap();
    if !phone.pin_is_voicemail {
        return;
    }
    // Asterisk allows a leading '-' or '*' on voicemail passwords.
    let v = match value.chars().next() {
        Some(c) if !c.is_ascii_digit() => &value[c.len_utf8()..],
        _ => value,
    };
    let pin = crate::util::first_token(v, &[',']).to_string();
    if pin != phone.applied_pin {
        ast_debug!(3, "{} pin changed from {} to {} - reconfiguring", phone.name, phone.applied_pin, pin);
        phone.needs_reconfigure = true;
    }
    phone.pin = pin.clone();
    phone.applied_pin = pin;
}

/// `process_applications`.
fn process_applications(reg: &mut Registry, cfg: &[Category]) {
    for cat in cfg.iter().filter(|c| !c.name.eq_ignore_ascii_case("general")) {
        if !is_type(cat, "application") {
            continue;
        }
        let Some(kind) = cat.get("application") else {
            dpma_log!("No application type set for {}", cat.name);
            continue;
        };
        let Some(mut data) = options::app_init(kind) else {
            dpma_log!("Unknown application type '{}' set for {}", kind, cat.name);
            continue;
        };
        for v in &cat.vars {
            if v.name.eq_ignore_ascii_case("type") || v.name.eq_ignore_ascii_case("application") {
                continue;
            }
            if options::set_app_option(&mut data, &v.name, &v.value).is_err() {
                dpma_log!("Unknown application option '{}'", v.name);
            }
        }
        let ok = options::app_post_setup(&data, &cat.name).is_ok();
        if !ok {
            dpma_log!("Application setup failed for {}.", cat.name);
        }
        match reg.applications.get_mut(&cat.name) {
            Some(app) => {
                app.delme = false;
                app.kind = Some(data);
            }
            None if ok => reg.applications.insert(
                &cat.name,
                Application { name: cat.name.clone(), kind: Some(data), delme: false },
            ),
            None => {}
        }
    }
}

/// `process_networks`.
fn process_networks(reg: &mut Registry, cfg: &[Category]) {
    for cat in cfg.iter().filter(|c| !c.name.eq_ignore_ascii_case("general")) {
        if !is_type(cat, "network") {
            continue;
        }
        let (net, _) = reg.networks.get_or_insert_with(&cat.name, || Network::new(&cat.name));
        net.reset_for_section();
        for v in &cat.vars {
            if v.name.eq_ignore_ascii_case("type") {
                continue;
            }
            if options::set_network_option(net, &v.name, &v.value).is_err() {
                dpma_log!("Unknown network option '{}'", v.name);
            }
        }
    }
}

/// Ringtones, firmware profiles, alerts, and multicast pages.
fn process_simple(reg: &mut Registry, cfg: &[Category]) {
    let sections = || cfg.iter().filter(|c| !c.name.eq_ignore_ascii_case("general"));
    let opts = |cat: &Category| cat.vars.iter().filter(|v| !v.name.eq_ignore_ascii_case("type")).cloned().collect::<Vec<_>>();

    for cat in sections().filter(|c| is_type(c, "ringtone")) {
        let r = Ringtone { name: cat.name.clone(), ..Default::default() };
        reg.ringtones.insert(&cat.name, r);
        let r = reg.ringtones.get_mut(&cat.name).unwrap();
        for v in opts(cat) {
            match v.name.to_ascii_lowercase().as_str() {
                "alias" => r.alias = v.value,
                "filename" => r.filename = v.value,
                _ => dpma_log!("Unknown ringtone option '{}'", v.name),
            }
        }
    }

    for cat in sections().filter(|c| is_type(c, "firmware")) {
        reg.firmware.insert(&cat.name, FirmwareOpt { name: cat.name.clone(), ..Default::default() });
        let f = reg.firmware.get_mut(&cat.name).unwrap();
        for v in opts(cat) {
            if options::set_firmware_opt_option(f, &v.name, &v.value).is_err() {
                dpma_log!("Unknown firmware option '{}'", v.name);
            }
        }
    }

    for cat in sections().filter(|c| is_type(c, "alert")) {
        reg.alerts.insert(&cat.name, Alert { name: cat.name.clone(), ..Default::default() });
        let a = reg.alerts.get_mut(&cat.name).unwrap();
        for v in opts(cat) {
            match v.name.to_ascii_lowercase().as_str() {
                "alert_info" => a.alert_info = v.value,
                "ring_type" => a.ring_type = v.value,
                "ringtone" => a.ringtone = v.value,
                _ => dpma_log!("Unknown alert option '{}'", v.name),
            }
        }
    }

    for cat in sections().filter(|c| is_type(c, "multicastpage")) {
        reg.pages.insert(&cat.name, Page { name: cat.name.clone(), interrupt: "0".into(), ..Default::default() });
        let p = reg.pages.get_mut(&cat.name).unwrap();
        for v in opts(cat) {
            match v.name.to_ascii_lowercase().as_str() {
                "alias" => p.alias = v.value,
                "address" => p.address = v.value,
                "port" => p.port = v.value,
                "priority" => p.priority = v.value,
                "interrupt" => p.interrupt = v.value,
                _ => dpma_log!("Unknown multicast page option '{}'", v.name),
            }
        }
    }
}

/// A dialplan hint to (re)create for an internal line.
struct HintPlan {
    line: String,
    tech: String,
    context: String,
}

/// `phone_line_hint_cb`, first half: decide which hints to create and drop
/// hints whose context changed.
fn plan_hints(reg: &mut Registry, fx: &mut Effects) -> Vec<HintPlan> {
    let mut plans = Vec::new();
    for l in reg.lines.values_mut() {
        if l.external {
            continue;
        }
        if l.subscribecontext.is_empty() {
            if l.context.is_empty() {
                continue;
            }
            l.subscribecontext = l.context.clone();
        }
        if !l.hint_context.is_empty() && l.hint_context != l.subscribecontext {
            fx.remove_hints.push((std::mem::take(&mut l.hint_context), format!("auto_hint_{}", l.name)));
        }
        plans.push(HintPlan { line: l.name.clone(), tech: l.tech.clone(), context: l.subscribecontext.clone() });
    }
    plans
}

/// Second half: create the hints and remember where they live.
fn apply_hints(plans: Vec<HintPlan>) {
    let mut results = Vec::new();
    for h in plans {
        if !dpma_ast::pbx::context_create(&h.context, REGISTRAR) {
            dpma_log!("Could not create context '{}' for auto_hint.", h.context);
            results.push((h.line, String::new()));
            continue;
        }
        let exten = format!("auto_hint_{}", h.line);
        let hint = format!("{}/{},CustomPresence:{}", h.tech, h.line, h.line);
        let ok = dpma_ast::pbx::add_extension(
            &h.context,
            true,
            &exten,
            dpma_ast::pbx::PRIORITY_HINT,
            None,
            None,
            &hint,
            None,
            REGISTRAR,
        );
        results.push((h.line, if ok { h.context } else { String::new() }));
    }
    let mut g = write();
    let Some(reg) = g.as_mut() else { return };
    for (line, ctx) in results {
        if let Some(l) = reg.lines.get_mut(&line) {
            l.hint_context = ctx;
        }
    }
}
