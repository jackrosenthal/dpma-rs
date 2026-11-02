//! The dialog-info supplement: what the original distribution ships as
//! res_pjsip_dialog_info_digium_body_supplement.so, "PJSIP Dialog-Info
//! Digium supplement" (decompile:
//! `dev/analysis/decomp/helpers/res_pjsip_dialog_info_digium_body_supplement.c`).
//!
//! A body supplement for `application/dialog-info+xml` NOTIFYs: when the
//! subscriber is a Digium or Sangoma phone and a channel is ringing the
//! watched extension, the `<dialog>` element gets `<local>` and `<remote>`
//! elements (unless they are there already) describing the ringing call:
//! `<target uri=...>` and `<identity display=...>` from the channel's
//! caller and connected line, so the phone can show who is calling.
//!
//! The original refuses to load unless res_digium_phone reports a valid
//! license (`get_license_status`); this rewrite has no license handling
//! (port plan, section 8, item 1).  Log messages carry the original's
//! file and function names.

use dpma_ast::channel::{self, Party};
use dpma_ast::log::{debug_atleast, LOG_DEBUG, LOG_WARNING};
use dpma_ast::sys;
use dpma_ast::types::AstChannel;
use dpma_ast::util::CStatic;
use dpma_ast::{ao2, cstr};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::null_mut;

/// The original's source file name, used in log messages.
const FILE: &str = "res_pjsip_dialog_info_digium_body_supplement.c";

/// `PJSIP_MAX_URL_SIZE`: the size of the original's buffers.
const MAX_URL_SIZE: usize = sys::PJSIP_MAX_URL_SIZE as usize;

/// `ast_log` under the original's file name and the given function name.
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

/// The supplement (`dialog_info_supplement`); res_pjsip_pubsub links it
/// into its list.
static SUPPLEMENT: CStatic<sys::ast_sip_pubsub_body_supplement> = CStatic::new({
    // SAFETY: all-zero is the C empty initializer (NULL pointers, an
    // unlinked list entry).
    let mut s: sys::ast_sip_pubsub_body_supplement = unsafe { std::mem::zeroed() };
    s.type_ = c"application".as_ptr();
    s.subtype = c"dialog-info+xml".as_ptr();
    s.supplement_body = Some(supplement_body);
    s
});

/// The bytes of a C string, as `%s` prints it ("(null)" for NULL).
unsafe fn text<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        b"(null)"
    } else {
        CStr::from_ptr(p).to_bytes()
    }
}

/// `S_COR(valid, s, "")`.
fn s_cor(valid: bool, s: &Option<Vec<u8>>) -> CString {
    match s {
        Some(s) if valid => cstr(s),
        _ => CString::default(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The user and domain of a party's URI: "anonymous" (or "" when the
/// number is not valid) at "anonymous.invalid" when the number is
/// restricted, else the number at `domain`.
fn uri_of(party: &Party, domain: &CStr) -> Vec<u8> {
    let (user, domain): (CString, &CStr) = if party.number_restricted {
        let user = if party.number_valid { c"anonymous" } else { c"" };
        (user.to_owned(), c"anonymous.invalid")
    } else {
        (s_cor(party.number_valid, &party.number), domain)
    };
    dpma_ast::bformat!("sip:{}@{}", user.as_bytes(), domain.to_bytes())
}

/// A party's display name, XML escaped: "anonymous" (or "" when the name is
/// not valid) when the name is restricted.
fn display_name_of(party: &Party) -> CString {
    let name = if party.name_restricted {
        if party.name_valid { c"anonymous" } else { c"" }.to_owned()
    } else {
        s_cor(party.name_valid, &party.name)
    };
    let mut buf = vec![0 as c_char; MAX_URL_SIZE];
    // SAFETY: a C string and a buffer of the size given; the result is
    // NUL-terminated within it.
    unsafe {
        sys::ast_xml_escape(name.as_ptr(), buf.as_mut_ptr(), MAX_URL_SIZE);
        CStr::from_ptr(buf.as_ptr()).to_owned()
    }
}

/// The first child of `parent` called `name`, or NULL.
unsafe fn find_node(parent: *const sys::pj_xml_node, name: &CStr) -> *mut sys::pj_xml_node {
    let s = sys::pj_str_t { ptr: name.as_ptr() as *mut c_char, slen: name.to_bytes().len() as sys::pj_ssize_t };
    sys::pj_xml_find_node(parent, &s)
}

/// `find_ringing_channel`: of the channels causing a ringing device state
/// (RINGING or RINGINUSE), the oldest one, with a reference; NULL if none.
unsafe fn find_ringing_channel(device_state_info: *mut ao2::Container) -> *mut AstChannel {
    let mut found: *mut AstChannel = null_mut();
    let mut tv = sys::timeval { tv_sec: 0, tv_usec: 0 };
    let mut it = ao2::Iter::new(device_state_info);
    loop {
        let device_state = it.next_ref() as *mut sys::ast_device_state_info;
        if device_state.is_null() {
            break;
        }
        let chan = (*device_state).causing_channel;
        let state = (*device_state).device_state;
        if !chan.is_null() && (state == sys::AST_DEVICE_RINGING || state == sys::AST_DEVICE_RINGINUSE) {
            channel::lock(chan);
            let created = channel::creationtime(chan);
            // ast_tvzero(tv) || ast_tvcmp(created, tv) < 0
            if (tv.tv_sec == 0 && tv.tv_usec == 0) || (created.tv_sec, created.tv_usec) < (tv.tv_sec, tv.tv_usec) {
                ao2::cleanup(found);
                found = chan;
                tv = created;
                ao2::ao2_ref(found.cast(), 1);
            }
            channel::unlock(chan);
        }
        ao2::cleanup(device_state);
    }
    found
}

/// `setup_elements`: give `dialog` a `tag` ("local" or "remote") element
/// with `<target uri=...>` and `<identity display=...>uri</identity>`,
/// keeping whatever of them is there already.
unsafe fn setup_elements(
    st: &sys::ast_sip_exten_state_data,
    statestring: &[u8],
    dialog: *mut sys::pj_xml_node,
    tag: &CStr,
    uri: &CStr,
    name: &CStr,
) {
    const FUNC: &str = "setup_elements";
    let exten = text(st.exten);
    let local = text(st.local.as_ptr());
    let t = tag.to_bytes();

    let mut node = find_node(dialog, tag);
    if node.is_null() {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Created {} node\n", exten, statestring, local, t);
        node = sys::ast_sip_presence_xml_create_node(st.pool, dialog, tag.as_ptr());
    } else {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Using existing {} node\n", exten, statestring, local, t);
    }

    if find_node(node, c"target").is_null() {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Created {} target node\n", exten, statestring, local, t);
        let target = sys::ast_sip_presence_xml_create_node(st.pool, node, c"target".as_ptr());
        sys::ast_sip_presence_xml_create_attr(st.pool, target, c"uri".as_ptr(), uri.as_ptr());
    } else {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Skipping due to existing {} target node\n", exten, statestring, local, t);
    }

    if find_node(node, c"identity").is_null() {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Created {} id node\n", exten, statestring, local, t);
        let identity = sys::ast_sip_presence_xml_create_node(st.pool, node, c"identity".as_ptr());
        sys::pj_strdup2(st.pool, &mut (*identity).content, uri.as_ptr());
        if !name.is_empty() {
            sys::ast_sip_presence_xml_create_attr(st.pool, identity, c"display".as_ptr(), name.as_ptr());
        }
    } else {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Skipping due to existing {} id node\n", exten, statestring, local, t);
    }
}

/// `dialog_info_supplement_body`.
unsafe fn supplement(body: *mut sys::pj_xml_node, st: &sys::ast_sip_exten_state_data) -> c_int {
    const FUNC: &str = "dialog_info_supplement_body";
    let exten = text(st.exten);
    let local = text(st.local.as_ptr());
    let remote = text(st.remote.as_ptr());

    // res_pjsip_exten_state lower-cases the subscriber's user agent.
    let is_phone = !st.user_agent.is_null() && {
        let ua = CStr::from_ptr(st.user_agent).to_bytes();
        !ua.is_empty() && (contains(ua, b"digium") || contains(ua, b"sangoma"))
    };
    if !is_phone {
        debug!(2, FUNC, "Exten: {} Local: {}  Remote: {} Bail.  Not a digium or sangoma phone\n", exten, local, remote);
        return 0;
    }

    // Deviation: the original iterates the device state container without
    // checking it, which fails when there is none; that is "no channel"
    // here.
    let callee = if st.device_state_info.is_null() { null_mut() } else { find_ringing_channel(st.device_state_info) };
    if callee.is_null() {
        debug!(2, FUNC, "Exten: {} Local: {}  Remote: {} Bail.  No Channel\n", exten, local, remote);
        return 0;
    }

    let mut statestring: *mut c_char = null_mut();
    let mut pidfstate: *mut c_char = null_mut();
    let mut pidfnote: *mut c_char = null_mut();
    let mut local_state: sys::ast_sip_pidf_state = 0;
    sys::ast_sip_presence_exten_state_to_str(
        st.exten_state,
        &mut statestring,
        &mut pidfstate,
        &mut pidfnote,
        &mut local_state,
        1,
    );
    let state_str = text(statestring);

    // The domain of the local URI.
    let mut local_copy = CStr::from_ptr(st.local.as_ptr()).to_bytes_with_nul().to_vec();
    let stripped = sys::ast_strip_quoted(local_copy.as_mut_ptr() as *mut c_char, c"<".as_ptr(), c">".as_ptr());
    let mut sanitized = vec![0 as c_char; MAX_URL_SIZE];
    sys::ast_sip_sanitize_xml(stripped, sanitized.as_mut_ptr(), MAX_URL_SIZE);
    let sanitized = CStr::from_ptr(sanitized.as_ptr()).to_owned();
    let Some(at) = sanitized.to_bytes().iter().position(|&c| c == b'@') else {
        debug!(
            2,
            FUNC,
            "Exten: {} {} Local: {}  Remote: {}.  No domain in local uri '{}'\n",
            exten,
            state_str,
            local,
            remote,
            sanitized.to_bytes()
        );
        ao2::cleanup(callee);
        return 0;
    };
    let domain = CString::new(&sanitized.to_bytes()[at + 1..]).unwrap_or_default();

    debug!(1, FUNC, "Exten: {} {} Local: {}  Remote: {}  Channel: {}\n", exten, state_str, local, remote, channel::name(callee));

    let mut dialog = find_node(body, c"dialog");
    if dialog.is_null() {
        debug!(1, FUNC, "Exten: {} {} Local: {}  Remote: {}.  Created dialog node\n", exten, state_str, local, remote);
        dialog = sys::ast_sip_presence_xml_create_node(st.pool, body, c"dialog".as_ptr());
        sys::ast_sip_presence_xml_create_attr(st.pool, dialog, c"id".as_ptr(), st.exten);
        if !statestring.is_null() && CStr::from_ptr(statestring) == c"early" {
            sys::ast_sip_presence_xml_create_attr(st.pool, dialog, c"direction".as_ptr(), c"recipient".as_ptr());
        }
    } else {
        debug!(2, FUNC, "Exten: {} {} Local: {}  Remote: {}.  Existing dialog node\n", exten, state_str, local, remote);
    }

    channel::lock(callee);
    // The local side is the channel's caller, the remote side its
    // connected line.
    let party = channel::caller(callee);
    let local_uri = cstr(uri_of(&party, &domain));
    let local_name = display_name_of(&party);
    let party = channel::connected(callee);
    let remote_uri = cstr(uri_of(&party, &domain));
    let remote_name = display_name_of(&party);
    debug!(
        1,
        FUNC,
        "Local: '{}' <{}>  Remote: '{}' <{}>\n",
        local_name.to_bytes(),
        local_uri.to_bytes(),
        remote_name.to_bytes(),
        remote_uri.to_bytes()
    );
    setup_elements(st, state_str, dialog, c"local", &local_uri, &local_name);
    setup_elements(st, state_str, dialog, c"remote", &remote_uri, &remote_name);
    channel::unlock(callee);
    ao2::cleanup(callee);
    0
}

/// The supplement callback (`supplement_body` of the registered
/// `struct ast_sip_pubsub_body_supplement`): res_pjsip_pubsub calls it with
/// the `pj_xml_node` of a dialog-info body and its
/// `struct ast_sip_exten_state_data`.
unsafe extern "C" fn supplement_body(body: *mut c_void, data: *mut c_void) -> c_int {
    dpma_ast::guard(0, || {
        if data.is_null() {
            return 0;
        }
        // SAFETY: the types res_pjsip_pubsub passes for dialog-info+xml.
        supplement(body.cast(), &*(data as *const sys::ast_sip_exten_state_data))
    })
}

/// `load_module` (without the original's license check):
/// AST_MODULE_LOAD_DECLINE when the supplement cannot be registered.
pub(super) fn load() -> sys::ast_module_load_result {
    // SAFETY: a static supplement, unregistered by `unload`.
    if unsafe { sys::ast_sip_pubsub_register_body_supplement(SUPPLEMENT.get()) } != 0 {
        log!(LOG_WARNING, "load_module", "Refusing to load.  Unable to register body supplement.\n");
        return sys::AST_MODULE_LOAD_DECLINE;
    }
    sys::AST_MODULE_LOAD_SUCCESS
}

/// `unload_module`.
pub(super) fn unload() {
    // SAFETY: as above.
    unsafe { sys::ast_sip_pubsub_unregister_body_supplement(SUPPLEMENT.get()) };
}
