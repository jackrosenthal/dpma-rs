//! The endpoint identifier side: what the official DPMA ships as
//! res_pjsip_endpoint_identifier_dpma.so, "DPMA PJSIP Support" (decompile:
//! `dev/analysis/decomp/helpers/res_pjsip_endpoint_identifier_dpma.c`).
//!
//! Lines and phones are reached through their objects (`users::objects`),
//! as the official DPMA's helper reaches them through res_digium_phone's
//! exported API.  Log messages carry the official DPMA's file and function
//! names.

use super::{register_is_dphone, set_config_handler, set_info_handler, unregister_is_dphone};
use crate::users::objects::{self, LineObj};
use dpma_ast::config::{Category, VariableList};
use dpma_ast::log::{debug_atleast, LOG_DEBUG, LOG_ERROR, LOG_NOTICE, LOG_WARNING};
use dpma_ast::sys;
use dpma_ast::types::{AstChannel, AstVariable};
use dpma_ast::util::{bytes_or_empty, strlen_zero, CStatic};
use dpma_ast::{ao2, cstr, here};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

/// The official DPMA's source file name, used in log messages.
const FILE: &str = "res_pjsip_endpoint_identifier_dpma.c";
/// The default of res_digium_phone.conf's `pjsip_message_context`.
const DEFAULT_CONTEXT: &str = "dpma_pjsip_message_context";
/// The name of the config hook on res_digium_phone.conf.
const HOOK: &str = "dpma_pjsip_hook";

/// `ast_log` under the official DPMA's file name and the given function
/// name.
macro_rules! log {
    ($level:expr, $func:expr, $($arg:tt)*) => {
        dpma_ast::log::log($level, FILE, line!(), $func, &dpma_ast::bformat!($($arg)*))
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
// The endpoint for DPMA requests (`g_endpoint`)
// ---------------------------------------------------------------------

/// An endpoint reference held by `ENDPOINT`.
struct Held(*mut sys::ast_sip_endpoint);
// SAFETY: an ao2 object reference; the holder's lock serializes access.
unsafe impl Send for Held {}
unsafe impl Sync for Held {}

/// The official DPMA's `AO2_GLOBAL_OBJ_STATIC(g_endpoint)`.
static ENDPOINT: RwLock<Held> = RwLock::new(Held(null_mut()));

/// `ao2_global_obj_ref(g_endpoint)`: the endpoint with a reference, or
/// NULL.
fn endpoint_ref() -> *mut sys::ast_sip_endpoint {
    let held = ENDPOINT.read().unwrap_or_else(|e| e.into_inner());
    // SAFETY: the holder's own reference keeps the endpoint alive while
    // its lock is held.
    unsafe { ao2::ao2_ref(held.0.cast(), 1) };
    held.0
}

/// `ao2_global_obj_replace_unref(g_endpoint, endpoint)`: hold `endpoint`
/// (a new reference of its own; NULL to drop it).
fn endpoint_replace(endpoint: *mut sys::ast_sip_endpoint) {
    // SAFETY: the caller's object gets a reference of the holder's own.
    unsafe { ao2::ao2_ref(endpoint.cast(), 1) };
    let old = std::mem::replace(
        &mut *ENDPOINT.write().unwrap_or_else(|e| e.into_inner()),
        Held(endpoint),
    );
    // SAFETY: the holder's reference on the old endpoint.
    unsafe { ao2::cleanup(old.0) };
}

// ---------------------------------------------------------------------
// Endpoint identifier (identify_endpoint)
// ---------------------------------------------------------------------

/// A request carrying an X-Digium-User-Agent header comes from a phone
/// talking to the module: it gets the DPMA endpoint.  (The official DPMA
/// finds rdata->msg_info.msg by scanning rdata for msg_info.info, the word
/// after it, so that it works with any layout of pjsip_rx_data; this reads
/// the layout of the headers it is built with.)
unsafe extern "C" fn identify_endpoint(
    rdata: *mut sys::pjsip_rx_data,
) -> *mut sys::ast_sip_endpoint {
    dpma_ast::guard(null_mut(), || {
        let name = sys::pj_str_t {
            ptr: c"X-Digium-User-Agent".as_ptr() as *mut c_char,
            slen: 19,
        };
        // SAFETY: PJSIP's received message, valid during the call.
        if rdata.is_null()
            || sys::pjsip_msg_find_hdr_by_name((*rdata).msg_info.msg, &name, std::ptr::null())
                .is_null()
        {
            return null_mut();
        }
        endpoint_ref()
    })
}

static IDENTIFIER: CStatic<sys::ast_sip_endpoint_identifier> =
    CStatic::new(sys::ast_sip_endpoint_identifier {
        identify_endpoint: Some(identify_endpoint),
    });

// ---------------------------------------------------------------------
// Sorcery
// ---------------------------------------------------------------------

static ENDPOINT_OBSERVER: CStatic<sys::ast_sorcery_observer> =
    CStatic::new(sys::ast_sorcery_observer {
        created: Some(pjsip_endpoint_changed),
        updated: Some(pjsip_endpoint_changed),
        deleted: Some(pjsip_endpoint_deleted),
        loaded: Some(pjsip_endpoints_loaded),
    });

static CONTACT_OBSERVER: CStatic<sys::ast_sorcery_observer> =
    CStatic::new(sys::ast_sorcery_observer {
        created: Some(pjsip_contact_update),
        updated: Some(pjsip_contact_update),
        deleted: None,
        loaded: None,
    });

static AOR_OBSERVER: CStatic<sys::ast_sorcery_observer> = CStatic::new(sys::ast_sorcery_observer {
    created: None,
    updated: Some(pjsip_aor_changed),
    deleted: Some(pjsip_aor_changed),
    loaded: None,
});

static AUTH_OBSERVER: CStatic<sys::ast_sorcery_observer> =
    CStatic::new(sys::ast_sorcery_observer {
        created: None,
        updated: Some(pjsip_auth_changed),
        deleted: Some(pjsip_auth_changed),
        loaded: None,
    });

/// Endpoint options copied to the line (`pjsip_set_line_options`).
const ENDPOINT_OPTIONS: [(&CStr, &[u8]); 2] =
    [(c"context", b"context"), (c"callerid", b"callerid")];
/// Auth options copied to the line.
const AUTH_OPTIONS: [(&CStr, &[u8]); 2] = [(c"username", b"authname"), (c"password", b"secret")];

fn sorcery() -> *mut sys::ast_sorcery {
    // SAFETY: res_pjsip's sorcery instance (res_pjsip is required).
    unsafe { sys::ast_sip_get_sorcery() }
}

/// `ast_sorcery_retrieve_by_id(sorcery, type, id)`: the object with a
/// reference, or NULL (also for a NULL id).
unsafe fn retrieve(object_type: &CStr, id: *const c_char) -> *mut c_void {
    if id.is_null() {
        return null_mut();
    }
    sys::ast_sorcery_retrieve_by_id(sorcery(), object_type.as_ptr(), id)
}

/// `pjsip_get_config_value`: the value of one field of a sorcery object
/// as a string, None when the field is missing or empty.
unsafe fn get_config_value(object: *const c_void, name: &CStr) -> Option<CString> {
    let set = sys::ast_sorcery_objectset_create2(sorcery(), object, sys::AST_HANDLER_ONLY_STRING);
    if set.is_null() {
        return None;
    }
    let mut v = set as *const AstVariable;
    let mut found = None;
    while !v.is_null() {
        let n = (*v).name;
        if !n.is_null() && CStr::from_ptr(n) == name {
            let value = (*v).value;
            if !strlen_zero(value) {
                found = Some(CStr::from_ptr(value).to_owned());
            }
            break;
        }
        v = (*v).next;
    }
    sys::ast_variables_destroy(set);
    found
}

/// `get_first_value`: everything before the first comma.
fn first_value(list: &CStr) -> CString {
    let b = list.to_bytes();
    let end = b.iter().position(|&c| c == b',').unwrap_or(b.len());
    CString::new(&b[..end]).unwrap_or_default()
}

/// The bytes of a C string, as `%s` prints it ("(null)" for NULL).
unsafe fn text<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        b"(null)"
    } else {
        CStr::from_ptr(p).to_bytes()
    }
}

/// `phone_utils_verify_user_agent`: the user agent contains "sangoma p" or
/// "digium" (case insensitive).
fn verify_user_agent(user_agent: Option<&CStr>) -> bool {
    let ua = user_agent.map_or(&b""[..], CStr::to_bytes);
    !ua.is_empty()
        && (dpma_ast::dpma_bytes::find_ic(ua, b"sangoma p").is_some()
            || dpma_ast::dpma_bytes::find_ic(ua, b"digium").is_some())
}

// ---------------------------------------------------------------------
// Lines from the PJSIP configuration
// ---------------------------------------------------------------------

/// The `ast_sip_for_each_aor` callback of `pjsip_set_aors_options`: the
/// first AOR with `mailboxes` provides them.
unsafe extern "C" fn aor_mailboxes(aor: *mut c_void, arg: *mut c_void, _flags: c_int) -> c_int {
    dpma_ast::guard(0, || {
        // SAFETY: `arg` is the `Option<CString>` of `process_pjsip_line_info`.
        let out = &mut *(arg as *mut Option<CString>);
        *out = get_config_value(aor, c"mailboxes");
        c_int::from(out.is_some())
    })
}

/// `phone_users_set_line_option` (the result is not used, as in the
/// official DPMA).
fn set_line_option(line: &LineObj, option: &[u8], value: &CStr) {
    let _ = line.set_option(option, value.to_bytes());
}

/// `process_pjsip_line_info`: apply the line's own configuration sections
/// again, then the settings from `endpoint` (or, with a NULL endpoint, just
/// clear the PJSIP settings).  The line is locked while its settings are
/// replaced, so nobody sees it half updated.
unsafe fn process_pjsip_line_info(endpoint: *const c_void, line: &LineObj) {
    objects::process_line(line);
    let _locked = line.lock();
    for option in [
        &b"tech"[..],
        b"context",
        b"callerid",
        b"mailbox",
        b"secret",
        b"authname",
        b"pjsip_auth",
    ] {
        set_line_option(line, option, c"");
    }
    if endpoint.is_null() {
        return;
    }
    line.set_delme(false);
    set_line_option(line, b"tech", c"PJSIP");

    // pjsip_set_line_options
    for (from, to) in ENDPOINT_OPTIONS {
        if let Some(v) = get_config_value(endpoint, from) {
            set_line_option(line, to, &v);
        }
    }

    // pjsip_set_auth_options: the first auth section
    if let Some(auths) = get_config_value(endpoint, c"auth") {
        let name = first_value(&auths);
        let auth = retrieve(c"auth", name.as_ptr());
        if !auth.is_null() {
            set_line_option(line, b"pjsip_auth", &name);
            for (from, to) in AUTH_OPTIONS {
                if let Some(v) = get_config_value(auth, from) {
                    set_line_option(line, to, &v);
                }
            }
            ao2::cleanup(auth);
        }
    }

    // pjsip_set_aors_options: the endpoint's mailboxes, else those of its
    // first AOR that has some
    if let Some(aors) = get_config_value(endpoint, c"aors") {
        let mut mailboxes = get_config_value(endpoint, c"mailboxes");
        if mailboxes.is_none() {
            sys::ast_sip_for_each_aor(
                aors.as_ptr(),
                Some(aor_mailboxes),
                &mut mailboxes as *mut _ as *mut c_void,
            );
        }
        if let Some(m) = mailboxes {
            set_line_option(line, b"mailbox", &first_value(&m));
        }
    }
}

/// `process_pjsip` (ao2 callback on the lines container): a line named
/// after an endpoint takes its settings.
unsafe extern "C" fn process_pjsip(line: *mut c_void, _arg: *mut c_void, _flags: c_int) -> c_int {
    dpma_ast::guard(0, || {
        // SAFETY: the lines container holds line objects.
        let line = &*(line as *const LineObj);
        let endpoint = retrieve(c"endpoint", line.name().as_ptr());
        if !endpoint.is_null() {
            process_pjsip_line_info(endpoint, line);
            ao2::cleanup(endpoint);
        }
        0
    })
}

/// `pjsip_process_lines`: the config handler, run in each processing of
/// the phone configuration (`super::process_lines`).
pub(super) fn process_lines() {
    // SAFETY: `process_pjsip` takes line objects.
    unsafe { objects::callback_all_lines(process_pjsip) };
}

/// `pjsip_endpoint_changed` (endpoint created or updated).
unsafe extern "C" fn pjsip_endpoint_changed(endpoint: *const c_void) {
    dpma_ast::guard((), || {
        if let Some(line) = find_line(sys::ast_sorcery_object_get_id(endpoint)) {
            process_pjsip_line_info(endpoint, &line);
        }
    })
}

/// `pjsip_endpoint_deleted`: the line loses its PJSIP settings.
unsafe extern "C" fn pjsip_endpoint_deleted(endpoint: *const c_void) {
    dpma_ast::guard((), || {
        if let Some(line) = find_line(sys::ast_sorcery_object_get_id(endpoint)) {
            process_pjsip_line_info(std::ptr::null(), &line);
        }
    })
}

/// The line named `id`, or None.
unsafe fn find_line(id: *const c_char) -> Option<objects::LineRef> {
    if id.is_null() {
        return None;
    }
    objects::find_line(CStr::from_ptr(id))
}

/// Endpoints (re)loaded: reprocess the whole phone configuration, with the
/// object type ("endpoint") as the trigger.
unsafe extern "C" fn pjsip_endpoints_loaded(object_type: *const c_char) {
    dpma_ast::guard((), || {
        let _ = crate::users::load::process(bytes_or_empty(object_type));
    })
}

/// Does the comma-separated `list` contain `item` (exactly)?
fn list_contains(list: Option<&CStr>, item: &CStr) -> bool {
    list.is_some_and(|l| {
        l.to_bytes()
            .split(|&c| c == b',')
            .any(|s| s == item.to_bytes())
    })
}

/// `pjsip_aor_changed` (AOR updated or deleted): lines whose endpoint uses
/// the AOR take their settings again.
///
/// Deviation: the official DPMA reads the `aors` of a line's endpoint
/// before checking that the endpoint exists, and so crashes (in
/// `ast_sorcery_objectset_create2`) whenever an AOR changes while any line
/// has no PJSIP endpoint of its name; such lines are skipped here.
unsafe extern "C" fn pjsip_aor_changed(aor: *const c_void) {
    dpma_ast::guard((), || {
        let id = sys::ast_sorcery_object_get_id(aor);
        if id.is_null() {
            return;
        }
        let id = CStr::from_ptr(id);
        for line in objects::all_lines() {
            let endpoint = retrieve(c"endpoint", line.name().as_ptr());
            if !endpoint.is_null() {
                let aors = get_config_value(endpoint, c"aors");
                if list_contains(aors.as_deref(), id) {
                    process_pjsip_line_info(endpoint, &line);
                }
                ao2::cleanup(endpoint);
            }
        }
    })
}

/// `pjsip_auth_changed` (auth updated or deleted): lines using the auth
/// section take their settings again.
unsafe extern "C" fn pjsip_auth_changed(auth: *const c_void) {
    dpma_ast::guard((), || {
        let id = sys::ast_sorcery_object_get_id(auth);
        if id.is_null() {
            return;
        }
        let id = CStr::from_ptr(id);
        for line in objects::all_lines() {
            if line.pjsip_auth() == id.to_bytes() {
                let endpoint = retrieve(c"endpoint", line.name().as_ptr());
                if !endpoint.is_null() {
                    process_pjsip_line_info(endpoint, &line);
                    ao2::cleanup(endpoint);
                }
            }
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
        let id = sys::ast_sorcery_object_get_id(contact);
        let user_agent = get_config_value(contact, c"user_agent");
        // The official DPMA copies the URI with strdupa() unchecked;
        // contacts always have one.
        let uri = get_config_value(contact, c"uri").unwrap_or_default();
        if !verify_user_agent(user_agent.as_deref()) || id.is_null() {
            return;
        }

        // The contact id is "<aor>;@<hash>".
        let id_bytes = CStr::from_ptr(id).to_bytes();
        let Some(semi) = id_bytes.iter().position(|&c| c == b';') else {
            log!(
                LOG_WARNING,
                FUNC,
                "Unable to parse username from id '{}'\n",
                text(id)
            );
            return;
        };
        let username = CString::new(&id_bytes[..semi]).unwrap_or_default();
        let Some(user) = objects::find_user(&username) else {
            return;
        };

        // The official DPMA tests the address (never NULL) rather than the
        // transport, so ";transport=" is always there, even when empty.
        let (addr, transport) = dpma_proto::uri::phone_utils_parse_uri(uri.as_bytes());
        let last_uri =
            dpma_ast::bformat!("pjsip:{};transport={}", addr, transport.unwrap_or_default());
        debug!(
            2,
            FUNC,
            "Updating DPMA user '{}' uri='{}' ua='{}'\n",
            username.as_bytes(),
            last_uri,
            user_agent.as_deref().map_or(&b"(null)"[..], CStr::to_bytes)
        );
        user.set_last_info(dpma_ast::dpma_bytes::c_view(&last_uri), None, None);
    })
}

/// `pjsip_contact_is_dphone` (`ast_sip_for_each_contact` callback): stop
/// at the first contact with a phone user agent.
unsafe extern "C" fn contact_is_dphone(
    wrapper: *mut c_void,
    arg: *mut c_void,
    _flags: c_int,
) -> c_int {
    dpma_ast::guard(-1, || {
        // SAFETY: ast_sip_for_each_contact hands over contact wrappers.
        let wrapper = wrapper as *const sys::ast_sip_contact_wrapper;
        let contact = if wrapper.is_null() {
            null_mut()
        } else {
            (*wrapper).contact
        };
        if contact.is_null() {
            return -1;
        }
        let user_agent = get_config_value(contact.cast(), c"user_agent");
        if verify_user_agent(user_agent.as_deref()) {
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
        sys::ast_sip_for_each_contact(aor.cast(), Some(contact_is_dphone), arg);
        if *(arg as *mut c_int) != 0 {
            -1
        } else {
            0
        }
    })
}

/// `pjsip_endpoint_is_dphone`: 1 when one of the endpoint's AORs has a
/// contact registered by a Digium or Sangoma phone.
pub(super) fn endpoint_is_dphone(name: &[u8]) -> i32 {
    let name = cstr(name);
    // SAFETY: a found endpoint is a reference we release; its `aors` string
    // field is valid while we hold it.
    unsafe {
        let endpoint = retrieve(c"endpoint", name.as_ptr()) as *mut sys::ast_sip_endpoint;
        if endpoint.is_null() {
            return 0;
        }
        let mut is_dphone: c_int = 0;
        sys::ast_sip_for_each_aor(
            (*endpoint).aors,
            Some(aor_is_dphone),
            &mut is_dphone as *mut c_int as *mut c_void,
        );
        ao2::cleanup(endpoint);
        is_dphone
    }
}

// ---------------------------------------------------------------------
// SIP INFO (pjsip_send_info)
// ---------------------------------------------------------------------

type SessionGetDialogFn =
    unsafe extern "C" fn(session: *const sys::ast_sip_session) -> *mut sys::pjsip_dialog;

/// The `ast_sip_session_get_dialog` found at load (0: use the internal
/// accessor).
static SESSION_GET_DIALOG: AtomicUsize = AtomicUsize::new(0);

/// For an Asterisk without `ast_sip_session_get_dialog()`.
unsafe fn internal_session_get_dialog(
    session: *const sys::ast_sip_session,
) -> *mut sys::pjsip_dialog {
    if session.is_null() || (*session).inv_session.is_null() {
        return null_mut();
    }
    (*(*session).inv_session).dlg
}

/// Use Asterisk's `ast_sip_session_get_dialog()` when it has one (looked
/// up at run time, as the official DPMA does).  True when found.
fn init_get_dialog() -> bool {
    // SAFETY: dlsym only looks the name up.
    let f = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"ast_sip_session_get_dialog".as_ptr()) };
    SESSION_GET_DIALOG.store(f as usize, Ordering::SeqCst);
    !f.is_null()
}

unsafe fn session_get_dialog(session: *const sys::ast_sip_session) -> *mut sys::pjsip_dialog {
    match SESSION_GET_DIALOG.load(Ordering::SeqCst) {
        0 => internal_session_get_dialog(session),
        // SAFETY: the address of Asterisk's ast_sip_session_get_dialog.
        f => std::mem::transmute::<usize, SessionGetDialogFn>(f)(session),
    }
}

/// What `send_info` hands to its task on the session's serializer.
struct InfoData<'a> {
    session: *mut sys::ast_sip_session,
    headers: &'a [(CString, CString)],
    content_type: &'a [u8],
    body: &'a CStr,
}

/// Runs on the session's serializer.
unsafe extern "C" fn send_info_task(obj: *mut c_void) -> c_int {
    dpma_ast::guard(-1, || {
        // SAFETY: `send_info` waits for this task, so its data is alive.
        let data = &*(obj as *const InfoData);
        // strsep(&content_type, "/")
        let (kind, subtype) = match data.content_type.iter().position(|&c| c == b'/') {
            Some(i) => (&data.content_type[..i], Some(&data.content_type[i + 1..])),
            None => (data.content_type, None),
        };
        let kind = cstr(kind);
        let subtype = subtype.map(cstr);
        let mut body = sys::ast_sip_body {
            type_: std::ptr::null(),
            subtype: std::ptr::null(),
            body_text: data.body.as_ptr(),
        };
        if !data.body.is_empty() {
            match &subtype {
                Some(s) if !kind.is_empty() && !s.is_empty() => {
                    body.type_ = kind.as_ptr();
                    body.subtype = s.as_ptr();
                }
                _ => return -1,
            }
        }

        let dlg = session_get_dialog(data.session);
        let mut tdata: *mut sys::pjsip_tx_data = null_mut();
        if dlg.is_null()
            || sys::ast_sip_create_request(
                c"INFO".as_ptr(),
                dlg,
                (*data.session).endpoint,
                std::ptr::null(),
                null_mut(),
                &mut tdata,
            ) != 0
        {
            return -1;
        }
        for (name, value) in data.headers {
            if sys::ast_sip_add_header(tdata, name.as_ptr(), value.as_ptr()) != 0 {
                sys::pjsip_tx_data_dec_ref(tdata);
                return -1;
            }
        }
        if !data.body.is_empty() && sys::ast_sip_add_body(tdata, &body) != 0 {
            sys::pjsip_tx_data_dec_ref(tdata);
            return -1;
        }
        sys::ast_sip_session_send_request(data.session, tdata);
        0
    })
}

/// The "PJSIP" info handler's `send` (`pjsip_send_info`): an INFO request
/// on the channel's dialog with `headers` and, when `body` is not empty,
/// the body with `content_type` ("type/subtype").  0 when sent, else -1.
///
/// Deviation: the official DPMA dereferences the channel's PJSIP private
/// data unchecked and would crash on a channel that is already hung up
/// (NULL tech_pvt); this returns -1 instead.
///
/// # Safety
/// `chan` must be a live PJSIP channel the caller holds a reference on.
pub(super) unsafe fn send_info(
    chan: *mut AstChannel,
    headers: &[(&str, &str)],
    content_type: &[u8],
    body: &[u8],
) -> i32 {
    let channel = sys::ast_channel_tech_pvt(chan) as *mut sys::ast_sip_channel_pvt;
    if channel.is_null() || (*channel).session.is_null() {
        return -1;
    }
    let content_type = dpma_ast::dpma_bytes::c_view(content_type);
    let body = cstr(body);
    if !body.is_empty() && content_type.is_empty() {
        return -1;
    }
    let headers: Vec<(CString, CString)> =
        headers.iter().map(|(n, v)| (cstr(n), cstr(v))).collect();
    let session = (*channel).session;
    let data = InfoData {
        session,
        headers: &headers,
        content_type,
        body: &body,
    };
    let (file, line, func) = here!("send_info");
    sys::__ast_sip_push_task_wait_servant(
        (*session).serializer,
        Some(send_info_task),
        &data as *const InfoData as *mut c_void,
        file,
        line,
        func,
    )
}

// ---------------------------------------------------------------------
// The DPMA endpoint
// ---------------------------------------------------------------------

/// `ast_variable_retrieve(cfg, category, name)`: the last `name` in the
/// first category called `category`.
fn variable_retrieve<'a>(cfg: &'a [Category], category: &str, name: &str) -> Option<&'a [u8]> {
    let cat = cfg
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(category.as_bytes()))?;
    cat.vars
        .iter()
        .rev()
        .find(|v| v.name.eq_ignore_ascii_case(name.as_bytes()))
        .map(|v| v.value.as_slice())
}

/// `set_endpoint_context`: the DPMA endpoint's context is
/// res_digium_phone.conf's `pjsip_message_context`.
fn set_endpoint_context(cfg: &[Category]) {
    const FUNC: &str = "set_endpoint_context";
    let endpoint = endpoint_ref();
    let context = variable_retrieve(cfg, "general", "pjsip_message_context");
    if endpoint.is_null() {
        log!(
            LOG_ERROR,
            FUNC,
            "Endpoint for DPMA endpoint identifier not found when setting endpoint context\n"
        );
        return;
    }
    let context = context
        .filter(|c| !c.is_empty())
        .unwrap_or(DEFAULT_CONTEXT.as_bytes());
    match VariableList::new(
        &[(b"context", context)],
        "res_pjsip_endpoint_identifier_dpma",
    ) {
        None => log!(
            LOG_ERROR,
            FUNC,
            "Allocation error while applying context for DPMA endpoint identifier\n"
        ),
        Some(var) => {
            // SAFETY: our endpoint reference; the variables are read.
            if unsafe { sys::ast_sorcery_objectset_apply(sorcery(), endpoint.cast(), var.as_ptr()) }
                != 0
            {
                log!(
                    LOG_ERROR,
                    FUNC,
                    "Failed to apply endpoint context for DPMA endpoint identifier\n"
                );
            }
        }
    }
    // SAFETY: the reference `endpoint_ref` took.
    unsafe { ao2::cleanup(endpoint) };
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
    let default = sys::ast_sip_default_outbound_endpoint();
    let id = if default.is_null() {
        std::ptr::null()
    } else {
        sys::ast_sorcery_object_get_id(default.cast())
    };
    let endpoint =
        sys::ast_sorcery_alloc(sorcery(), c"endpoint".as_ptr(), id) as *mut sys::ast_sip_endpoint;
    if endpoint.is_null() {
        log!(
            LOG_ERROR,
            "create_endpoint",
            "Unable to create endpoint used for matching incoming DPMA requests, these requests will fail\n"
        );
    } else {
        endpoint_replace(endpoint);
    }
    ao2::cleanup(default);
    ao2::cleanup(endpoint);
    !endpoint.is_null()
}

/// `cleanup_module`: undo everything `load` may have done.
fn cleanup_module() {
    set_config_handler(false);
    set_info_handler(false);
    // SAFETY: removing observers and the identifier that may or may not be
    // registered is harmless.
    unsafe {
        sys::ast_sorcery_observer_remove(sorcery(), c"auth".as_ptr(), AUTH_OBSERVER.get());
        sys::ast_sorcery_observer_remove(sorcery(), c"contact".as_ptr(), CONTACT_OBSERVER.get());
        sys::ast_sorcery_observer_remove(sorcery(), c"aor".as_ptr(), AOR_OBSERVER.get());
        sys::ast_sorcery_observer_remove(sorcery(), c"endpoint".as_ptr(), ENDPOINT_OBSERVER.get());
    }
    unregister_is_dphone();
    dpma_ast::hooks::unregister(HOOK);
    // SAFETY: as above.
    unsafe { sys::ast_sip_unregister_endpoint_identifier(IDENTIFIER.get()) };
    endpoint_replace(null_mut());
}

/// The registrations of `load`; Err with the log level and message of
/// the first that fails.
unsafe fn register() -> Result<(), (i32, &'static str)> {
    if sys::ast_sip_register_endpoint_identifier(IDENTIFIER.get()) != 0 {
        return Err((
            LOG_ERROR,
            "Unable to register endpoint identifier for DPMA\n",
        ));
    }
    if let dpma_ast::config::LoadResult::Loaded(cfg) = dpma_ast::config::load(
        crate::CONFIG_FILE,
        crate::MODULE_NAME,
        dpma_ast::config::CONFIG_FLAG_NOCACHE,
    ) {
        set_endpoint_context(&cfg);
    }
    if !dpma_ast::hooks::register(HOOK, crate::CONFIG_FILE, crate::MODULE_NAME, config_hook) {
        return Err((LOG_ERROR, "Unable to register hook for pjsip DPMA\n"));
    }
    let observers: [(&CStr, &CStatic<sys::ast_sorcery_observer>, &'static str); 4] = [
        (
            c"endpoint",
            &ENDPOINT_OBSERVER,
            "Unable to add pjsip endpoint observer\n",
        ),
        (
            c"contact",
            &CONTACT_OBSERVER,
            "Unable to add pjsip contact observer\n",
        ),
        (c"aor", &AOR_OBSERVER, "Unable to add pjsip aor observer\n"),
        (
            c"auth",
            &AUTH_OBSERVER,
            "Unable to add pjsip auth observer\n",
        ),
    ];
    for (object_type, observer, error) in observers {
        if sys::ast_sorcery_observer_add(sorcery(), object_type.as_ptr(), observer.get()) != 0 {
            return Err((LOG_WARNING, error));
        }
    }
    set_config_handler(true);
    set_info_handler(true);
    if !register_is_dphone() {
        return Err((
            LOG_WARNING,
            "Unable to register PJSIP endpoint is dphone function\n",
        ));
    }
    Ok(())
}

/// `load_module`: AST_MODULE_LOAD_SUCCESS, or AST_MODULE_LOAD_FAILURE as
/// the official DPMA returns on any error.
pub(super) fn load() -> sys::ast_module_load_result {
    const FUNC: &str = "load_module";
    dpma_ast::guard(sys::AST_MODULE_LOAD_FAILURE, || unsafe {
        let default = sys::ast_sip_default_outbound_endpoint();
        let version = text(sys::pj_get_version()).to_vec();
        if init_get_dialog() {
            log!(
                LOG_NOTICE,
                FUNC,
                "Using ast_sip_session_get_dialog() for pjproject version {}\n",
                version
            );
        } else {
            log!(
                LOG_NOTICE,
                FUNC,
                "Using internal session_get_dialog() for pjproject version {}\n",
                version
            );
        }

        let res = if default.is_null() {
            log!(
                LOG_ERROR,
                FUNC,
                "Unable to find default outbound endpoint required for DPMA\n"
            );
            sys::AST_MODULE_LOAD_FAILURE
        } else if !create_endpoint() {
            log!(
                LOG_ERROR,
                FUNC,
                "Unable to create pjsip endpoint for DPMA\n"
            );
            sys::AST_MODULE_LOAD_FAILURE
        } else {
            match register() {
                Err((level, error)) => {
                    log!(level, FUNC, "{}", error);
                    cleanup_module();
                    sys::AST_MODULE_LOAD_FAILURE
                }
                Ok(()) => {
                    let _ = crate::users::load::process(b"identifier load");
                    sys::AST_MODULE_LOAD_SUCCESS
                }
            }
        };
        ao2::cleanup(default);
        res
    })
}

/// `unload_module`.
pub(super) fn unload() {
    dpma_ast::guard((), cleanup_module)
}
