//! res_pjsip_dialog_info_digium_body_supplement: PJSIP Dialog-Info Digium
//! supplement.
//!
//! A body supplement for `application/dialog-info+xml` NOTIFYs (the
//! original is
//! `dev/analysis/decomp/helpers/res_pjsip_dialog_info_digium_body_supplement.c`):
//! when the subscriber is a Digium or Sangoma phone and a channel is
//! ringing the watched extension, the `<dialog>` element gets `<local>` and
//! `<remote>` elements (unless they are there already) describing the
//! ringing call: `<target uri=...>` and `<identity display=...>` from the
//! channel's caller and connected line, so the phone can show who is
//! calling.
//!
//! The original refuses to load unless res_digium_phone reports a valid
//! license (`get_license_status`); this rewrite has no license handling
//! (port plan, section 8, item 1).  The PJSIP structures are handled in C
//! glue (`glue/supplement.c`).  Log messages carry the original's file and
//! function names.

use dpma_ast::ao2;
use dpma_ast::log::{debug_atleast, LOG_DEBUG, LOG_WARNING};
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr::null_mut;

/// The original's source file name, used in log messages.
const FILE: &str = "res_pjsip_dialog_info_digium_body_supplement.c";

/// `PJSIP_MAX_URL_SIZE`: the size of the original's buffers.
const MAX_URL_SIZE: usize = 512;

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

/// The fields of `struct ast_sip_exten_state_data` used here (filled by
/// the glue).
#[repr(C)]
struct State {
    exten: *const c_char,
    exten_state: c_int,
    user_agent: *const c_char,
    device_state_info: *mut c_void,
    local: *const c_char,
    remote: *const c_char,
    pool: *mut c_void,
}

/// The name and number of a channel's caller or connected line.
#[repr(C)]
struct Party {
    number_restricted: c_int,
    number_valid: c_int,
    number: *const c_char,
    name_restricted: c_int,
    name_valid: c_int,
    name: *const c_char,
}

extern "C" {
    fn ast_sip_presence_exten_state_to_str(
        state: c_int,
        statestring: *mut *mut c_char,
        pidfstate: *mut *mut c_char,
        pidfnote: *mut *mut c_char,
        local_state: *mut c_int,
        notify_early_inuse_ringing: c_uint,
    );
    fn ast_sip_presence_xml_create_node(pool: *mut c_void, parent: *mut c_void, name: *const c_char) -> *mut c_void;
    fn ast_sip_presence_xml_create_attr(pool: *mut c_void, node: *mut c_void, name: *const c_char, value: *const c_char) -> *mut c_void;
    fn ast_sip_sanitize_xml(input: *const c_char, output: *mut c_char, len: usize);
    fn ast_strip_quoted(s: *mut c_char, beg_quotes: *const c_char, end_quotes: *const c_char) -> *mut c_char;
    fn ast_xml_escape(string: *const c_char, outbuf: *mut c_char, buflen: usize) -> c_int;

    fn dpma_dlg_glue_register() -> c_int;
    fn dpma_dlg_glue_unregister();
    fn dpma_dlg_glue_state(data: *const c_void, out: *mut State);
    fn dpma_dlg_glue_find_ringing_channel(device_state_info: *mut c_void) -> *mut c_void;
    fn dpma_dlg_glue_party(chan: *mut c_void, connected: c_int, out: *mut Party);
    fn dpma_dlg_glue_find_node(parent: *const c_void, name: *const c_char) -> *mut c_void;
    fn dpma_dlg_glue_set_content(pool: *mut c_void, node: *mut c_void, text: *const c_char);
}

unsafe fn lossy<'a>(p: *const c_char) -> Cow<'a, str> {
    if p.is_null() {
        "(null)".into()
    } else {
        CStr::from_ptr(p).to_string_lossy()
    }
}

/// `S_COR(valid, s, "")`.
unsafe fn s_cor(valid: c_int, s: *const c_char) -> CString {
    if valid != 0 && !s.is_null() && *s != 0 {
        CStr::from_ptr(s).to_owned()
    } else {
        CString::default()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The user and domain of a party's URI: "anonymous" (or "" when the
/// number is not valid) at "anonymous.invalid" when the number is
/// restricted, else the number at `domain`.
unsafe fn uri_of(party: &Party, domain: &CStr) -> String {
    let (user, domain): (CString, &CStr) = if party.number_restricted != 0 {
        let user = if party.number_valid != 0 { c"anonymous" } else { c"" };
        (user.to_owned(), c"anonymous.invalid")
    } else {
        (s_cor(party.number_valid, party.number), domain)
    };
    format!("sip:{}@{}", user.to_string_lossy(), domain.to_string_lossy())
}

/// A party's display name, XML escaped: "anonymous" (or "" when the name is
/// not valid) when the name is restricted.
unsafe fn display_name_of(party: &Party) -> CString {
    let name = if party.name_restricted != 0 {
        if party.name_valid != 0 { c"anonymous" } else { c"" }.to_owned()
    } else {
        s_cor(party.name_valid, party.name)
    };
    let mut buf = vec![0 as c_char; MAX_URL_SIZE];
    ast_xml_escape(name.as_ptr(), buf.as_mut_ptr(), MAX_URL_SIZE);
    CStr::from_ptr(buf.as_ptr()).to_owned()
}

/// `setup_elements`: give `dialog` a `tag` ("local" or "remote") element
/// with `<target uri=...>` and `<identity display=...>uri</identity>`,
/// keeping whatever of them is there already.
unsafe fn setup_elements(st: &State, statestring: &str, dialog: *mut c_void, tag: &CStr, uri: &CStr, name: &CStr) {
    const FUNC: &str = "setup_elements";
    let exten = lossy(st.exten);
    let local = lossy(st.local);
    let t = tag.to_string_lossy();

    let mut node = dpma_dlg_glue_find_node(dialog, tag.as_ptr());
    if node.is_null() {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Created {} node\n", exten, statestring, local, t);
        node = ast_sip_presence_xml_create_node(st.pool, dialog, tag.as_ptr());
    } else {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Using existing {} node\n", exten, statestring, local, t);
    }

    if dpma_dlg_glue_find_node(node, c"target".as_ptr()).is_null() {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Created {} target node\n", exten, statestring, local, t);
        let target = ast_sip_presence_xml_create_node(st.pool, node, c"target".as_ptr());
        ast_sip_presence_xml_create_attr(st.pool, target, c"uri".as_ptr(), uri.as_ptr());
    } else {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Skipping due to existing {} target node\n", exten, statestring, local, t);
    }

    if dpma_dlg_glue_find_node(node, c"identity".as_ptr()).is_null() {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Created {} id node\n", exten, statestring, local, t);
        let identity = ast_sip_presence_xml_create_node(st.pool, node, c"identity".as_ptr());
        dpma_dlg_glue_set_content(st.pool, identity, uri.as_ptr());
        if !name.is_empty() {
            ast_sip_presence_xml_create_attr(st.pool, identity, c"display".as_ptr(), name.as_ptr());
        }
    } else {
        debug!(3, FUNC, "Exten: {} {} Local: {}  Skipping due to existing {} id node\n", exten, statestring, local, t);
    }
}

/// `dialog_info_supplement_body`.
unsafe fn supplement_body(body: *mut c_void, data: *mut c_void) -> c_int {
    const FUNC: &str = "dialog_info_supplement_body";
    let mut st = State {
        exten: std::ptr::null(),
        exten_state: 0,
        user_agent: std::ptr::null(),
        device_state_info: null_mut(),
        local: std::ptr::null(),
        remote: std::ptr::null(),
        pool: null_mut(),
    };
    dpma_dlg_glue_state(data, &mut st);
    let exten = lossy(st.exten);
    let local = lossy(st.local);
    let remote = lossy(st.remote);

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
    let callee = if st.device_state_info.is_null() {
        null_mut()
    } else {
        dpma_dlg_glue_find_ringing_channel(st.device_state_info)
    };
    if callee.is_null() {
        debug!(2, FUNC, "Exten: {} Local: {}  Remote: {} Bail.  No Channel\n", exten, local, remote);
        return 0;
    }

    let mut statestring: *mut c_char = null_mut();
    let mut pidfstate: *mut c_char = null_mut();
    let mut pidfnote: *mut c_char = null_mut();
    let mut local_state: c_int = 0;
    ast_sip_presence_exten_state_to_str(st.exten_state, &mut statestring, &mut pidfstate, &mut pidfnote, &mut local_state, 1);
    let state_str = lossy(statestring);

    // The domain of the local URI.
    let mut local_copy = if st.local.is_null() { vec![0] } else { CStr::from_ptr(st.local).to_bytes_with_nul().to_vec() };
    let stripped = ast_strip_quoted(local_copy.as_mut_ptr() as *mut c_char, c"<".as_ptr(), c">".as_ptr());
    let mut sanitized = vec![0 as c_char; MAX_URL_SIZE];
    ast_sip_sanitize_xml(stripped, sanitized.as_mut_ptr(), MAX_URL_SIZE);
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
            sanitized.to_string_lossy()
        );
        ao2::cleanup(callee);
        return 0;
    };
    let domain = CString::new(&sanitized.to_bytes()[at + 1..]).unwrap_or_default();

    debug!(
        1,
        FUNC,
        "Exten: {} {} Local: {}  Remote: {}  Channel: {}\n",
        exten,
        state_str,
        local,
        remote,
        dpma_ast::channel::name(callee as *const dpma_ast::types::AstChannel)
    );

    let mut dialog = dpma_dlg_glue_find_node(body, c"dialog".as_ptr());
    if dialog.is_null() {
        debug!(1, FUNC, "Exten: {} {} Local: {}  Remote: {}.  Created dialog node\n", exten, state_str, local, remote);
        dialog = ast_sip_presence_xml_create_node(st.pool, body, c"dialog".as_ptr());
        ast_sip_presence_xml_create_attr(st.pool, dialog, c"id".as_ptr(), st.exten);
        if !statestring.is_null() && CStr::from_ptr(statestring) == c"early" {
            ast_sip_presence_xml_create_attr(st.pool, dialog, c"direction".as_ptr(), c"recipient".as_ptr());
        }
    } else {
        debug!(2, FUNC, "Exten: {} {} Local: {}  Remote: {}.  Existing dialog node\n", exten, state_str, local, remote);
    }

    ao2::lock(callee);
    let mut party = Party {
        number_restricted: 0,
        number_valid: 0,
        number: std::ptr::null(),
        name_restricted: 0,
        name_valid: 0,
        name: std::ptr::null(),
    };
    // The local side is the channel's caller, the remote side its
    // connected line.
    dpma_dlg_glue_party(callee, 0, &mut party);
    let local_uri = dpma_ast::cstr(&uri_of(&party, &domain));
    let local_name = display_name_of(&party);
    dpma_dlg_glue_party(callee, 1, &mut party);
    let remote_uri = dpma_ast::cstr(&uri_of(&party, &domain));
    let remote_name = display_name_of(&party);
    debug!(
        1,
        FUNC,
        "Local: '{}' <{}>  Remote: '{}' <{}>\n",
        local_name.to_string_lossy(),
        local_uri.to_string_lossy(),
        remote_name.to_string_lossy(),
        remote_uri.to_string_lossy()
    );
    setup_elements(&st, &state_str, dialog, c"local", &local_uri, &local_name);
    setup_elements(&st, &state_str, dialog, c"remote", &remote_uri, &remote_name);
    ao2::unlock(callee);
    ao2::cleanup(callee);
    0
}

/// The supplement callback (`supplement_body` of the registered
/// `struct ast_sip_pubsub_body_supplement`).
///
/// # Safety
/// Called by res_pjsip_pubsub with the `pj_xml_node` of a dialog-info body
/// and its `struct ast_sip_exten_state_data`.
#[no_mangle]
pub unsafe extern "C" fn dpma_dlg_rust_supplement_body(body: *mut c_void, data: *mut c_void) -> c_int {
    dpma_ast::guard(0, || supplement_body(body, data))
}

/// `load_module` (without the original's license check): 0, or 1
/// (AST_MODULE_LOAD_DECLINE) when the supplement cannot be registered.
#[no_mangle]
pub extern "C" fn dpma_dlg_rust_load() -> i32 {
    dpma_ast::guard(1, || {
        if unsafe { dpma_dlg_glue_register() } != 0 {
            log!(LOG_WARNING, "load_module", "Refusing to load.  Unable to register body supplement.\n");
            return 1;
        }
        0
    })
}

/// `unload_module`.
#[no_mangle]
pub extern "C" fn dpma_dlg_rust_unload() -> i32 {
    dpma_ast::guard(0, || {
        unsafe { dpma_dlg_glue_unregister() };
        0
    })
}
