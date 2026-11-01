//! res_pjsip_endpoint_identifier_dpma: DPMA PJSIP Support.
//!
//! The PJSIP side of res_digium_phone (the original is
//! `dev/analysis/decomp/helpers/res_pjsip_endpoint_identifier_dpma.c`):
//!
//! * Requests carrying an `X-Digium-User-Agent` header (the phones'
//!   AppServer MESSAGEs) are matched to an endpoint of their own: a new
//!   endpoint with the id of the default outbound endpoint whose context is
//!   res_digium_phone.conf's `pjsip_message_context` (default
//!   `dpma_pjsip_message_context`), set at load and whenever
//!   res_digium_phone loads its configuration (config hook).
//! * Phone lines named after a PJSIP endpoint take their technology,
//!   context, caller ID, auth section, authname, secret, and mailbox from
//!   the PJSIP configuration: a config handler run on every processing of
//!   the phone configuration, and sorcery observers on endpoints, AORs,
//!   and auths.
//! * A REGISTER (contact created or updated) from a Digium or Sangoma user
//!   agent records the contact URI as the last URI of the phone named after
//!   the AOR.
//! * The "PJSIP" info handler sends SIP INFO requests on calls
//!   (`dpma_info_send`), and the endpoint-is-dphone hook says whether an
//!   endpoint has a contact with a phone user agent.
//!
//! This module uses res_digium_phone only through its exported C API
//! (declared below), never by linking to the res_digium_phone Rust crate,
//! so that it also works with the original res_digium_phone.so and vice
//! versa.  The PJSIP structures are handled in C glue (`glue/pjsip.c`).
//! Log messages carry the original's file and function names.

use dpma_ast::ao2;
use dpma_ast::config::Category;
use dpma_ast::log::{debug_atleast, LOG_DEBUG, LOG_ERROR, LOG_NOTICE, LOG_WARNING};
use dpma_ast::types::{AstChannel, AstVariable};
use std::cell::UnsafeCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::null_mut;

/// The original's source file name, used in log messages.
const FILE: &str = "res_pjsip_endpoint_identifier_dpma.c";
/// `AST_MODULE`.
const MODULE: &str = "res_pjsip_endpoint_identifier_dpma";
/// The default of res_digium_phone.conf's `pjsip_message_context`.
const DEFAULT_CONTEXT: &str = "dpma_pjsip_message_context";

/// AST_MODULE_LOAD_SUCCESS / AST_MODULE_LOAD_FAILURE.
const LOAD_SUCCESS: c_int = 0;
const LOAD_FAILURE: c_int = -1;

/// `AST_HANDLER_ONLY_STRING`.
const HANDLER_ONLY_STRING: c_int = 2;
/// The config file flag `CONFIG_FLAG_NOCACHE`.
const CONFIG_FLAG_NOCACHE: u32 = 1 << 2;

/// `ast_log` under the original's file name and the given function name.
macro_rules! log {
    ($level:expr, $func:expr, $($arg:tt)*) => {
        dpma_ast::log::log($level, FILE, line!(), $func, &format!($($arg)*))
    };
}

/// `ast_debug`.
macro_rules! debug {
    ($level:expr, $func:expr, $($arg:tt)*) => {
        if debug_atleast($level) {
            log!(LOG_DEBUG, $func, $($arg)*)
        }
    };
}

// ---------------------------------------------------------------------
// The exported API of res_digium_phone (its src/exports)
// ---------------------------------------------------------------------

/// `struct dpma_config_handler`.
#[repr(C)]
struct ConfigHandler {
    handler: Option<unsafe extern "C" fn(lines: *mut c_void) -> c_int>,
    next: *mut ConfigHandler,
}

type InfoSendFn = unsafe extern "C" fn(
    chan: *mut AstChannel,
    headers: *mut AstVariable,
    content_type: *const c_char,
    body: *const c_char,
    useragent_filter: *const c_char,
) -> c_int;

/// `struct dpma_info_handler`.
#[repr(C)]
struct InfoHandler {
    tech: *const c_char,
    send: Option<InfoSendFn>,
    next: *mut InfoHandler,
}

extern "C" {
    fn dpma_register_config_handler(handler: *mut ConfigHandler) -> c_int;
    fn dpma_unregister_config_handler(handler: *mut ConfigHandler);
    fn dpma_register_info_handler(handler: *mut InfoHandler) -> c_int;
    fn dpma_unregister_info_handler(handler: *mut InfoHandler);
    fn dpma_register_pjsip_endpoint_is_dphone(f: unsafe extern "C" fn(*const c_char) -> c_int) -> c_int;
    fn dpma_unregister_pjsip_endpoint_is_dphone();

    fn phone_users_get_lines() -> *mut ao2::Container;
    fn phone_users_line_get_name(line: *mut c_void) -> *const c_char;
    fn phone_users_line_get_pjsip_auth(line: *mut c_void) -> *const c_char;
    fn phone_users_line_set_delme(line: *mut c_void, delme: c_int);
    fn phone_users_set_line_option(option: *const c_char, value: *const c_char, line: *mut c_void) -> c_int;
    fn phone_users_process_line(line: *mut c_void);
    fn phone_users_process_phone_config(trigger: *const c_char) -> c_int;
    fn phone_line_find(name: *const c_char) -> *mut c_void;
    fn phone_user_find(name: *const c_char) -> *mut c_void;
    fn phone_user_token_set_last_info(user: *mut c_void, uri: *const c_char, session: *const c_char, mac: *const c_char);
    fn phone_utils_parse_uri(uri: *mut c_char, addr: *mut *mut c_char, transport: *mut *mut c_char);
    fn phone_utils_verify_user_agent(user_agent: *const c_char) -> c_int;
}

// ---------------------------------------------------------------------
// Asterisk and the glue
// ---------------------------------------------------------------------

/// `struct ast_sorcery_observer`.
#[repr(C)]
struct SorceryObserver {
    created: Option<unsafe extern "C" fn(object: *const c_void)>,
    updated: Option<unsafe extern "C" fn(object: *const c_void)>,
    deleted: Option<unsafe extern "C" fn(object: *const c_void)>,
    loaded: Option<unsafe extern "C" fn(object_type: *const c_char)>,
}
// SAFETY: immutable function tables.
unsafe impl Sync for SorceryObserver {}

type Ao2CallbackFn = unsafe extern "C" fn(obj: *mut c_void, arg: *mut c_void, flags: c_int) -> c_int;

extern "C" {
    fn ast_sip_get_sorcery() -> *mut c_void;
    fn ast_sip_default_outbound_endpoint() -> *mut c_void;
    fn ast_sip_for_each_aor(aors: *const c_char, on_aor: Ao2CallbackFn, arg: *mut c_void) -> c_int;
    fn ast_sip_for_each_contact(aor: *const c_void, on_contact: Ao2CallbackFn, arg: *mut c_void) -> c_int;
    fn ast_sorcery_objectset_create2(sorcery: *const c_void, object: *const c_void, flags: c_int) -> *mut AstVariable;
    fn ast_sorcery_objectset_apply(sorcery: *const c_void, object: *mut c_void, objectset: *mut AstVariable) -> c_int;
    fn ast_sorcery_retrieve_by_id(sorcery: *const c_void, object_type: *const c_char, id: *const c_char) -> *mut c_void;
    fn ast_sorcery_object_get_id(object: *const c_void) -> *const c_char;
    fn ast_sorcery_alloc(sorcery: *const c_void, object_type: *const c_char, id: *const c_char) -> *mut c_void;
    fn ast_sorcery_observer_add(sorcery: *const c_void, object_type: *const c_char, callbacks: *const SorceryObserver) -> c_int;
    fn ast_sorcery_observer_remove(sorcery: *const c_void, object_type: *const c_char, callbacks: *const SorceryObserver);
    fn ast_variables_destroy(variables: *mut AstVariable);
    fn pj_get_version() -> *const c_char;

    fn dpma_eid_glue_endpoint_ref() -> *mut c_void;
    fn dpma_eid_glue_endpoint_replace(endpoint: *mut c_void);
    fn dpma_eid_glue_register_identifier() -> c_int;
    fn dpma_eid_glue_unregister_identifier();
    fn dpma_eid_glue_endpoint_aors(endpoint: *const c_void) -> *const c_char;
    fn dpma_eid_glue_wrapper_contact(wrapper: *const c_void) -> *const c_void;
    fn dpma_eid_glue_variable_new(name: *const c_char, value: *const c_char, filename: *const c_char) -> *mut AstVariable;
    fn dpma_eid_glue_callback_all(container: *mut ao2::Container, cb: Ao2CallbackFn);
    fn dpma_eid_glue_init_get_dialog() -> c_int;
    fn dpma_eid_glue_send_info(
        chan: *mut AstChannel,
        headers: *mut AstVariable,
        content_type: *const c_char,
        body: *const c_char,
        useragent_filter: *const c_char,
    ) -> c_int;
}

/// A registration structure that res_digium_phone links into its lists
/// (it writes the `next` field).
#[repr(transparent)]
struct Shared<T>(UnsafeCell<T>);
// SAFETY: the structure is only written by res_digium_phone, under its own
// list locks.
unsafe impl<T> Sync for Shared<T> {}

impl<T> Shared<T> {
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

static CONFIG_HANDLER: Shared<ConfigHandler> =
    Shared(UnsafeCell::new(ConfigHandler { handler: Some(pjsip_process_lines), next: null_mut() }));

static INFO_HANDLER: Shared<InfoHandler> = Shared(UnsafeCell::new(InfoHandler {
    tech: c"PJSIP".as_ptr(),
    send: Some(dpma_eid_glue_send_info),
    next: null_mut(),
}));

static ENDPOINT_OBSERVER: SorceryObserver = SorceryObserver {
    created: Some(pjsip_endpoint_changed),
    updated: Some(pjsip_endpoint_changed),
    deleted: Some(pjsip_endpoint_deleted),
    loaded: Some(pjsip_endpoints_loaded),
};

static CONTACT_OBSERVER: SorceryObserver =
    SorceryObserver { created: Some(pjsip_contact_update), updated: Some(pjsip_contact_update), deleted: None, loaded: None };

static AOR_OBSERVER: SorceryObserver =
    SorceryObserver { created: None, updated: Some(pjsip_aor_changed), deleted: Some(pjsip_aor_changed), loaded: None };

static AUTH_OBSERVER: SorceryObserver =
    SorceryObserver { created: None, updated: Some(pjsip_auth_changed), deleted: Some(pjsip_auth_changed), loaded: None };

/// Endpoint options copied to the line (`pjsip_set_line_options`).
const ENDPOINT_OPTIONS: [(&CStr, &CStr); 2] = [(c"context", c"context"), (c"callerid", c"callerid")];
/// Auth options copied to the line.
const AUTH_OPTIONS: [(&CStr, &CStr); 2] = [(c"username", c"authname"), (c"password", c"secret")];

fn sorcery() -> *mut c_void {
    unsafe { ast_sip_get_sorcery() }
}

unsafe fn retrieve(object_type: &CStr, id: *const c_char) -> *mut c_void {
    if id.is_null() {
        return null_mut();
    }
    ast_sorcery_retrieve_by_id(sorcery(), object_type.as_ptr(), id)
}

/// `pjsip_get_config_value`: the value of one field of a sorcery object
/// as a string, None when the field is missing or empty.
unsafe fn get_config_value(object: *const c_void, name: &CStr) -> Option<CString> {
    let set = ast_sorcery_objectset_create2(sorcery(), object, HANDLER_ONLY_STRING);
    if set.is_null() {
        return None;
    }
    let mut v = set as *const AstVariable;
    let mut found = None;
    while !v.is_null() {
        let n = dpma_ast::ffi::dpma_glue_variable_name(v);
        if !n.is_null() && CStr::from_ptr(n) == name {
            let value = dpma_ast::ffi::dpma_glue_variable_value(v);
            if !value.is_null() && *value != 0 {
                found = Some(CStr::from_ptr(value).to_owned());
            }
            break;
        }
        v = dpma_ast::ffi::dpma_glue_variable_next(v);
    }
    ast_variables_destroy(set);
    found
}

/// `get_first_value`: everything before the first comma.
fn first_value(list: &CStr) -> CString {
    let b = list.to_bytes();
    let end = b.iter().position(|&c| c == b',').unwrap_or(b.len());
    CString::new(&b[..end]).unwrap_or_default()
}

unsafe fn set_line_option(option: &CStr, value: &CStr, line: *mut c_void) {
    phone_users_set_line_option(option.as_ptr(), value.as_ptr(), line);
}

unsafe fn lossy<'a>(p: *const c_char) -> std::borrow::Cow<'a, str> {
    if p.is_null() {
        "(null)".into()
    } else {
        CStr::from_ptr(p).to_string_lossy()
    }
}

// ---------------------------------------------------------------------
// Lines from the PJSIP configuration
// ---------------------------------------------------------------------

/// The `ast_sip_for_each_aor` callback of `pjsip_set_aors_options`: the
/// first AOR with `mailboxes` provides them.
unsafe extern "C" fn aor_mailboxes(aor: *mut c_void, arg: *mut c_void, _flags: c_int) -> c_int {
    dpma_ast::guard(0, || {
        let out = &mut *(arg as *mut Option<CString>);
        *out = get_config_value(aor, c"mailboxes");
        c_int::from(out.is_some())
    })
}

/// `process_pjsip_line_info`: apply the line's own configuration sections
/// again, then the settings from `endpoint` (or, with a NULL endpoint, just
/// clear the PJSIP settings).  The line is locked while its settings are
/// replaced, so nobody sees it half updated.
unsafe fn process_pjsip_line_info(endpoint: *const c_void, line: *mut c_void) {
    phone_users_process_line(line);
    ao2::lock(line);
    for option in [c"tech", c"context", c"callerid", c"mailbox", c"secret", c"authname", c"pjsip_auth"] {
        set_line_option(option, c"", line);
    }
    if !endpoint.is_null() {
        phone_users_line_set_delme(line, 0);
        set_line_option(c"tech", c"PJSIP", line);

        // pjsip_set_line_options
        for (from, to) in ENDPOINT_OPTIONS {
            if let Some(v) = get_config_value(endpoint, from) {
                set_line_option(to, &v, line);
            }
        }

        // pjsip_set_auth_options: the first auth section
        if let Some(auths) = get_config_value(endpoint, c"auth") {
            let name = first_value(&auths);
            let auth = retrieve(c"auth", name.as_ptr());
            if !auth.is_null() {
                set_line_option(c"pjsip_auth", &name, line);
                for (from, to) in AUTH_OPTIONS {
                    if let Some(v) = get_config_value(auth, from) {
                        set_line_option(to, &v, line);
                    }
                }
                ao2::cleanup(auth);
            }
        }

        // pjsip_set_aors_options: the endpoint's mailboxes, else those of
        // its first AOR that has some
        if let Some(aors) = get_config_value(endpoint, c"aors") {
            let mut mailboxes = get_config_value(endpoint, c"mailboxes");
            if mailboxes.is_none() {
                ast_sip_for_each_aor(aors.as_ptr(), aor_mailboxes, &mut mailboxes as *mut _ as *mut c_void);
            }
            if let Some(m) = mailboxes {
                set_line_option(c"mailbox", &first_value(&m), line);
            }
        }
    }
    ao2::unlock(line);
}

/// `process_pjsip` (ao2 callback): a line named after an endpoint takes
/// its settings.
unsafe extern "C" fn process_pjsip(line: *mut c_void, _arg: *mut c_void, _flags: c_int) -> c_int {
    dpma_ast::guard(0, || {
        let endpoint = retrieve(c"endpoint", phone_users_line_get_name(line));
        if !endpoint.is_null() {
            process_pjsip_line_info(endpoint, line);
            ao2::cleanup(endpoint);
        }
        0
    })
}

/// `pjsip_process_lines`: the config handler, run by res_digium_phone each
/// time it processes the phone configuration.
unsafe extern "C" fn pjsip_process_lines(lines: *mut c_void) -> c_int {
    dpma_ast::guard(0, || {
        if !lines.is_null() {
            dpma_eid_glue_callback_all(lines as *mut ao2::Container, process_pjsip);
        }
        0
    })
}

/// The line named `id` (with a reference), or NULL.
unsafe fn find_line(id: *const c_char) -> *mut c_void {
    if id.is_null() {
        return null_mut();
    }
    phone_line_find(id)
}

/// `pjsip_endpoint_changed` (endpoint created or updated).
unsafe extern "C" fn pjsip_endpoint_changed(endpoint: *const c_void) {
    dpma_ast::guard((), || {
        let line = find_line(ast_sorcery_object_get_id(endpoint));
        if !line.is_null() {
            process_pjsip_line_info(endpoint, line);
            ao2::cleanup(line);
        }
    })
}

/// `pjsip_endpoint_deleted`: the line loses its PJSIP settings.
unsafe extern "C" fn pjsip_endpoint_deleted(endpoint: *const c_void) {
    dpma_ast::guard((), || {
        let line = find_line(ast_sorcery_object_get_id(endpoint));
        if !line.is_null() {
            process_pjsip_line_info(std::ptr::null(), line);
            ao2::cleanup(line);
        }
    })
}

/// Endpoints (re)loaded: reprocess the whole phone configuration, with the
/// object type ("endpoint") as the trigger.
unsafe extern "C" fn pjsip_endpoints_loaded(object_type: *const c_char) {
    dpma_ast::guard((), || {
        phone_users_process_phone_config(object_type);
    })
}

/// Does the comma-separated `list` contain `item` (exactly)?
fn list_contains(list: Option<&CStr>, item: &CStr) -> bool {
    list.is_some_and(|l| l.to_bytes().split(|&c| c == b',').any(|s| s == item.to_bytes()))
}

/// Every line of res_digium_phone (each with a reference to drop).
unsafe fn all_lines() -> Vec<*mut c_void> {
    ao2::collect(phone_users_get_lines())
}

/// `pjsip_aor_changed` (AOR updated or deleted): lines whose endpoint uses
/// the AOR take their settings again.
///
/// Deviation: the original reads the `aors` of a line's endpoint before
/// checking that the endpoint exists, and so crashes (in
/// `ast_sorcery_objectset_create2`) whenever an AOR changes while any line
/// has no PJSIP endpoint of its name; such lines are skipped here.
unsafe extern "C" fn pjsip_aor_changed(aor: *const c_void) {
    dpma_ast::guard((), || {
        let id = ast_sorcery_object_get_id(aor);
        if id.is_null() {
            return;
        }
        let id = CStr::from_ptr(id);
        for line in all_lines() {
            let endpoint = retrieve(c"endpoint", phone_users_line_get_name(line));
            if !endpoint.is_null() {
                let aors = get_config_value(endpoint, c"aors");
                if list_contains(aors.as_deref(), id) {
                    process_pjsip_line_info(endpoint, line);
                }
                ao2::cleanup(endpoint);
            }
            ao2::cleanup(line);
        }
    })
}

/// `pjsip_auth_changed` (auth updated or deleted): lines using the auth
/// section take their settings again.
unsafe extern "C" fn pjsip_auth_changed(auth: *const c_void) {
    dpma_ast::guard((), || {
        let id = ast_sorcery_object_get_id(auth);
        if id.is_null() {
            return;
        }
        let id = CStr::from_ptr(id);
        for line in all_lines() {
            let line_auth = phone_users_line_get_pjsip_auth(line);
            if !line_auth.is_null() && CStr::from_ptr(line_auth) == id {
                let endpoint = retrieve(c"endpoint", phone_users_line_get_name(line));
                if !endpoint.is_null() {
                    process_pjsip_line_info(endpoint, line);
                    ao2::cleanup(endpoint);
                }
            }
            ao2::cleanup(line);
        }
    })
}

// ---------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------

/// `pjsip_contact_update` (contact created or updated): a contact
/// registered by a Digium or Sangoma phone becomes the last URI of the
/// phone named after its AOR, as `pjsip:<host>;transport=<transport>`.
unsafe extern "C" fn pjsip_contact_update(contact: *const c_void) {
    dpma_ast::guard((), || {
        const FUNC: &str = "pjsip_contact_update";
        let id = ast_sorcery_object_get_id(contact);
        let user_agent = get_config_value(contact, c"user_agent");
        // The original copies the URI with strdupa() unchecked; contacts
        // always have one.
        let uri = get_config_value(contact, c"uri").unwrap_or_default();
        let ua_ptr = user_agent.as_ref().map_or(std::ptr::null(), |u| u.as_ptr());
        if phone_utils_verify_user_agent(ua_ptr) == 0 || id.is_null() {
            return;
        }

        // The contact id is "<aor>;@<hash>".
        let id_bytes = CStr::from_ptr(id).to_bytes();
        let Some(semi) = id_bytes.iter().position(|&c| c == b';') else {
            log!(LOG_WARNING, FUNC, "Unable to parse username from id '{}'\n", lossy(id));
            return;
        };
        let username = CString::new(&id_bytes[..semi]).unwrap_or_default();
        let user = phone_user_find(username.as_ptr());
        if user.is_null() {
            return;
        }

        let mut buf = uri.into_bytes_with_nul();
        let mut addr: *mut c_char = null_mut();
        let mut transport: *mut c_char = null_mut();
        phone_utils_parse_uri(buf.as_mut_ptr() as *mut c_char, &mut addr, &mut transport);
        // The original tests the address (never NULL) rather than the
        // transport, so ";transport=" is always there, even when empty.
        let separator = if addr.is_null() { "" } else { ";transport=" };
        let last_uri = format!("pjsip:{}{}{}", lossy(addr), separator, lossy(transport));
        debug!(
            2,
            FUNC,
            "Updating DPMA user '{}' uri='{}' ua='{}'\n",
            username.to_string_lossy(),
            last_uri,
            lossy(ua_ptr)
        );
        let last_uri = dpma_ast::cstr(&last_uri);
        phone_user_token_set_last_info(user, last_uri.as_ptr(), std::ptr::null(), std::ptr::null());
        ao2::ao2_ref(user, -1);
    })
}

/// `pjsip_contact_is_dphone` (`ast_sip_for_each_contact` callback): stop
/// at the first contact with a phone user agent.
unsafe extern "C" fn contact_is_dphone(wrapper: *mut c_void, arg: *mut c_void, _flags: c_int) -> c_int {
    dpma_ast::guard(-1, || {
        let contact = if wrapper.is_null() { std::ptr::null() } else { dpma_eid_glue_wrapper_contact(wrapper) };
        if contact.is_null() {
            return -1;
        }
        let user_agent = get_config_value(contact, c"user_agent");
        let ua_ptr = user_agent.as_ref().map_or(std::ptr::null(), |u| u.as_ptr());
        if phone_utils_verify_user_agent(ua_ptr) != 0 {
            *(arg as *mut c_int) = 1;
            return -1;
        }
        0
    })
}

/// The `ast_sip_for_each_aor` callback of `pjsip_endpoint_is_dphone`.
unsafe extern "C" fn aor_is_dphone(aor: *mut c_void, arg: *mut c_void, _flags: c_int) -> c_int {
    dpma_ast::guard(-1, || {
        if aor.is_null() {
            return -1;
        }
        ast_sip_for_each_contact(aor, contact_is_dphone, arg);
        if *(arg as *mut c_int) != 0 {
            -1
        } else {
            0
        }
    })
}

/// `pjsip_endpoint_is_dphone`: 1 when one of the endpoint's AORs has a
/// contact registered by a Digium or Sangoma phone.
unsafe extern "C" fn pjsip_endpoint_is_dphone(name: *const c_char) -> c_int {
    dpma_ast::guard(0, || {
        let endpoint = retrieve(c"endpoint", name);
        if endpoint.is_null() {
            return 0;
        }
        let mut is_dphone: c_int = 0;
        ast_sip_for_each_aor(
            dpma_eid_glue_endpoint_aors(endpoint),
            aor_is_dphone,
            &mut is_dphone as *mut c_int as *mut c_void,
        );
        ao2::cleanup(endpoint);
        is_dphone
    })
}

// ---------------------------------------------------------------------
// The DPMA endpoint
// ---------------------------------------------------------------------

/// `ast_variable_retrieve(cfg, category, name)`: the last `name` in the
/// first category called `category`.
fn variable_retrieve<'a>(cfg: &'a [Category], category: &str, name: &str) -> Option<&'a str> {
    let cat = cfg.iter().find(|c| c.name.eq_ignore_ascii_case(category))?;
    cat.vars.iter().rev().find(|v| v.name.eq_ignore_ascii_case(name)).map(|v| v.value.as_str())
}

/// `set_endpoint_context`: the DPMA endpoint's context is
/// res_digium_phone.conf's `pjsip_message_context`.
fn set_endpoint_context(cfg: &[Category]) {
    const FUNC: &str = "set_endpoint_context";
    unsafe {
        let endpoint = dpma_eid_glue_endpoint_ref();
        let context = variable_retrieve(cfg, "general", "pjsip_message_context");
        if endpoint.is_null() {
            log!(LOG_ERROR, FUNC, "Endpoint for DPMA endpoint identifier not found when setting endpoint context\n");
        } else {
            let context = dpma_ast::cstr(context.filter(|c| !c.is_empty()).unwrap_or(DEFAULT_CONTEXT));
            let var = dpma_eid_glue_variable_new(c"context".as_ptr(), context.as_ptr(), c"res_pjsip_endpoint_identifier_dpma".as_ptr());
            if var.is_null() {
                log!(LOG_ERROR, FUNC, "Allocation error while applying context for DPMA endpoint identifier\n");
            } else {
                if ast_sorcery_objectset_apply(sorcery(), endpoint, var) != 0 {
                    log!(LOG_ERROR, FUNC, "Failed to apply endpoint context for DPMA endpoint identifier\n");
                }
                ast_variables_destroy(var);
            }
        }
        ao2::cleanup(endpoint);
    }
}

/// The config hook on res_digium_phone.conf (`dpma_pjsip_hook`).
fn config_hook(cfg: Option<Vec<Category>>) {
    if let Some(cfg) = cfg {
        set_endpoint_context(&cfg);
    }
}

/// `create_endpoint`: a new endpoint with the id of the default outbound
/// endpoint becomes the DPMA endpoint.
unsafe fn create_endpoint() -> bool {
    let default = ast_sip_default_outbound_endpoint();
    let id = if default.is_null() { std::ptr::null() } else { ast_sorcery_object_get_id(default) };
    let endpoint = ast_sorcery_alloc(sorcery(), c"endpoint".as_ptr(), id);
    if endpoint.is_null() {
        log!(
            LOG_ERROR,
            "create_endpoint",
            "Unable to create endpoint used for matching incoming DPMA requests, these requests will fail\n"
        );
    } else {
        dpma_eid_glue_endpoint_replace(endpoint);
    }
    ao2::cleanup(default);
    ao2::cleanup(endpoint);
    !endpoint.is_null()
}

/// `cleanup_module`: undo everything `load_module` may have done.
unsafe fn cleanup_module(res: c_int) -> c_int {
    dpma_unregister_config_handler(CONFIG_HANDLER.get());
    dpma_unregister_info_handler(INFO_HANDLER.get());
    ast_sorcery_observer_remove(sorcery(), c"auth".as_ptr(), &AUTH_OBSERVER);
    ast_sorcery_observer_remove(sorcery(), c"contact".as_ptr(), &CONTACT_OBSERVER);
    ast_sorcery_observer_remove(sorcery(), c"aor".as_ptr(), &AOR_OBSERVER);
    ast_sorcery_observer_remove(sorcery(), c"endpoint".as_ptr(), &ENDPOINT_OBSERVER);
    dpma_unregister_pjsip_endpoint_is_dphone();
    dpma_ast::hooks::unregister("dpma_pjsip_hook");
    dpma_eid_glue_unregister_identifier();
    dpma_eid_glue_endpoint_replace(null_mut());
    res
}

unsafe fn load_module() -> c_int {
    const FUNC: &str = "load_module";
    let default = ast_sip_default_outbound_endpoint();
    let version = lossy(pj_get_version()).into_owned();
    if dpma_eid_glue_init_get_dialog() != 0 {
        log!(LOG_NOTICE, FUNC, "Using ast_sip_session_get_dialog() for pjproject version {}\n", version);
    } else {
        log!(LOG_NOTICE, FUNC, "Using internal session_get_dialog() for pjproject version {}\n", version);
    }

    let res = 'load: {
        if default.is_null() {
            log!(LOG_ERROR, FUNC, "Unable to find default outbound endpoint required for DPMA\n");
            break 'load LOAD_FAILURE;
        }
        if !create_endpoint() {
            log!(LOG_ERROR, FUNC, "Unable to create pjsip endpoint for DPMA\n");
            break 'load LOAD_FAILURE;
        }

        let failure = 'register: {
            if dpma_eid_glue_register_identifier() != 0 {
                break 'register Some((LOG_ERROR, "Unable to register endpoint identifier for DPMA\n"));
            }
            if let dpma_ast::config::LoadResult::Loaded(cfg) =
                dpma_ast::config::load("res_digium_phone.conf", MODULE, CONFIG_FLAG_NOCACHE)
            {
                set_endpoint_context(&cfg);
            }
            if !dpma_ast::hooks::register("dpma_pjsip_hook", "res_digium_phone.conf", "res_digium_phone", config_hook) {
                break 'register Some((LOG_ERROR, "Unable to register hook for pjsip DPMA\n"));
            }
            let observers: [(&CStr, &SorceryObserver, &str); 4] = [
                (c"endpoint", &ENDPOINT_OBSERVER, "Unable to add pjsip endpoint observer\n"),
                (c"contact", &CONTACT_OBSERVER, "Unable to add pjsip contact observer\n"),
                (c"aor", &AOR_OBSERVER, "Unable to add pjsip aor observer\n"),
                (c"auth", &AUTH_OBSERVER, "Unable to add pjsip auth observer\n"),
            ];
            for (object_type, observer, error) in observers {
                if ast_sorcery_observer_add(sorcery(), object_type.as_ptr(), observer) != 0 {
                    break 'register Some((LOG_WARNING, error));
                }
            }
            if dpma_register_config_handler(CONFIG_HANDLER.get()) != 0 {
                break 'register Some((LOG_WARNING, "Unable to register pjsip configuration handler\n"));
            }
            if dpma_register_info_handler(INFO_HANDLER.get()) != 0 {
                break 'register Some((LOG_WARNING, "Unable to register pjsip info handler\n"));
            }
            if dpma_register_pjsip_endpoint_is_dphone(pjsip_endpoint_is_dphone) != 0 {
                break 'register Some((LOG_WARNING, "Unable to register PJSIP endpoint is dphone function\n"));
            }
            None
        };
        match failure {
            Some((level, error)) => {
                log!(level, FUNC, "{}", error);
                cleanup_module(LOAD_FAILURE)
            }
            None => {
                phone_users_process_phone_config(c"identifier load".as_ptr());
                LOAD_SUCCESS
            }
        }
    };
    ao2::cleanup(default);
    res
}

/// `load_module`: AST_MODULE_LOAD_SUCCESS, or AST_MODULE_LOAD_FAILURE as
/// the original returns on any error.
#[no_mangle]
pub extern "C" fn dpma_eid_rust_load() -> i32 {
    dpma_ast::guard(LOAD_FAILURE, || unsafe { load_module() })
}

/// `unload_module`.
#[no_mangle]
pub extern "C" fn dpma_eid_rust_unload() -> i32 {
    dpma_ast::guard(0, || unsafe { cleanup_module(0) })
}
