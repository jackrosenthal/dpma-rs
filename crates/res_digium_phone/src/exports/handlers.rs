//! res_digium_phone.c exports: the config and info handler registries,
//! `dpma_info_send`, and the PJSIP "is a Digium phone" hook
//! (0x1476b0..0x147bb0).  `get_license_status` (0x147650) is deliberately
//! not exported: this rewrite has no license handling.  The original's
//! built-in "SIP" info handler (chan_sip's `ast_sipinfo_send`) is not
//! registered: chan_sip support is removed.
//!
//! Both registries are intrusive singly linked lists through the callers'
//! own structures (`AST_RWLIST` in the original): registering writes the
//! `next` field of the previous tail, and unregistering clears the
//! removed handler's `next` field and drops the module reference taken at
//! registration.

use dpma_ast::types::{AstChannel, AstVariable};
use dpma_ast::{cstr, dpma_log};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

/// `struct dpma_config_handler` (16 bytes): called with the lines
/// container whenever the phone users configuration is processed.
#[repr(C)]
pub struct DpmaConfigHandler {
    pub handler: Option<unsafe extern "C" fn(lines: *mut c_void) -> c_int>,
    pub next: *mut DpmaConfigHandler,
}

/// The `send` callback of an info handler: send a SIP INFO on `chan` with
/// extra `headers`, `content_type`, and `body`.  The last argument has the
/// type and meaning of `ast_sipinfo_send`'s `useragent_filter`; every
/// caller in the original passes NULL.
pub type InfoSendFn = unsafe extern "C" fn(
    chan: *mut AstChannel,
    headers: *mut AstVariable,
    content_type: *const c_char,
    body: *const c_char,
    useragent_filter: *const c_char,
) -> c_int;

/// `struct dpma_info_handler` (24 bytes): `tech` is matched
/// case-insensitively against the channel technology name.
#[repr(C)]
pub struct DpmaInfoHandler {
    pub tech: *const c_char,
    pub send: Option<InfoSendFn>,
    pub next: *mut DpmaInfoHandler,
}

/// Head and tail of an intrusive handler list (as addresses).
struct List {
    head: usize,
    tail: usize,
}

static CONFIG_HANDLERS: RwLock<List> = RwLock::new(List { head: 0, tail: 0 });
static INFO_HANDLERS: RwLock<List> = RwLock::new(List { head: 0, tail: 0 });

/// `AST_RWLIST_INSERT_TAIL`.
unsafe fn insert_tail(list: &mut List, item: usize, set_next: unsafe fn(usize, usize)) {
    if list.head == 0 {
        list.head = item;
    } else {
        set_next(list.tail, item);
    }
    list.tail = item;
}

/// `AST_RWLIST_REMOVE`; true when `item` was found (and removed).
unsafe fn remove(list: &mut List, item: usize, next_of: unsafe fn(usize) -> usize, set_next: unsafe fn(usize, usize)) -> bool {
    let mut prev = 0;
    let mut cur = list.head;
    while cur != 0 && cur != item {
        prev = cur;
        cur = next_of(cur);
    }
    if cur == 0 {
        return false;
    }
    let next = next_of(cur);
    set_next(cur, 0);
    if prev == 0 {
        list.head = next;
    } else {
        set_next(prev, next);
    }
    if next == 0 {
        list.tail = prev;
    }
    true
}

unsafe fn config_next(h: usize) -> usize {
    (*(h as *mut DpmaConfigHandler)).next as usize
}
unsafe fn config_set_next(h: usize, next: usize) {
    (*(h as *mut DpmaConfigHandler)).next = next as *mut DpmaConfigHandler;
}
unsafe fn info_next(h: usize) -> usize {
    (*(h as *mut DpmaInfoHandler)).next as usize
}
unsafe fn info_set_next(h: usize, next: usize) {
    (*(h as *mut DpmaInfoHandler)).next = next as *mut DpmaInfoHandler;
}

/// `int dpma_register_config_handler(struct dpma_config_handler *)` (H):
/// append to the list and take a reference on this module.  Always 0.
#[no_mangle]
pub unsafe extern "C" fn dpma_register_config_handler(h: *mut DpmaConfigHandler) -> c_int {
    dpma_ast::guard(-1, || {
        let mut l = CONFIG_HANDLERS.write().unwrap_or_else(|e| e.into_inner());
        insert_tail(&mut l, h as usize, config_set_next);
        dpma_ast::module_ref();
        0
    })
}

/// `void dpma_unregister_config_handler(struct dpma_config_handler *)` (H):
/// remove it and drop the module reference (nothing when not registered).
#[no_mangle]
pub unsafe extern "C" fn dpma_unregister_config_handler(h: *mut DpmaConfigHandler) {
    dpma_ast::guard((), || {
        let mut l = CONFIG_HANDLERS.write().unwrap_or_else(|e| e.into_inner());
        if remove(&mut l, h as usize, config_next, config_set_next) {
            dpma_ast::module_unref();
        }
    })
}

/// `void dpma_process_config_handlers(struct ao2_container *lines)`: call
/// every registered handler with `lines`, holding the list's write lock
/// as the original does.
#[no_mangle]
pub unsafe extern "C" fn dpma_process_config_handlers(lines: *mut c_void) {
    dpma_ast::guard((), || {
        let l = CONFIG_HANDLERS.write().unwrap_or_else(|e| e.into_inner());
        let mut cur = l.head;
        while cur != 0 {
            let h = cur as *mut DpmaConfigHandler;
            if let Some(f) = (*h).handler {
                f(lines);
            }
            cur = (*h).next as usize;
        }
        drop(l);
    })
}

/// `int dpma_register_info_handler(struct dpma_info_handler *)` (H): append
/// and take a module reference.  Always 0.
#[no_mangle]
pub unsafe extern "C" fn dpma_register_info_handler(h: *mut DpmaInfoHandler) -> c_int {
    dpma_ast::guard(-1, || {
        let mut l = INFO_HANDLERS.write().unwrap_or_else(|e| e.into_inner());
        insert_tail(&mut l, h as usize, info_set_next);
        dpma_ast::module_ref();
        0
    })
}

/// `void dpma_unregister_info_handler(struct dpma_info_handler *)` (H).
#[no_mangle]
pub unsafe extern "C" fn dpma_unregister_info_handler(h: *mut DpmaInfoHandler) {
    dpma_ast::guard((), || {
        let mut l = INFO_HANDLERS.write().unwrap_or_else(|e| e.into_inner());
        if remove(&mut l, h as usize, info_next, info_set_next) {
            dpma_ast::module_unref();
        }
    })
}

extern "C" {
    fn dpma_glue_exports_channel_tech_type(chan: *mut AstChannel) -> *const c_char;
    fn dpma_glue_exports_variable_prepend(head: *mut AstVariable, name: *const c_char, value: *const c_char) -> *mut AstVariable;
    fn dpma_glue_exports_variables_destroy(head: *mut AstVariable);
}

/// `int dpma_info_send(chan, headers, content_type, body, useragent_filter)`:
/// hand the INFO to the first handler whose technology matches the
/// channel's (case insensitive); -1 when none does.
#[no_mangle]
pub unsafe extern "C" fn dpma_info_send(
    chan: *mut AstChannel,
    headers: *mut AstVariable,
    content_type: *const c_char,
    body: *const c_char,
    useragent_filter: *const c_char,
) -> c_int {
    dpma_ast::guard(-1, || {
        let l = INFO_HANDLERS.read().unwrap_or_else(|e| e.into_inner());
        let mut cur = l.head;
        while cur != 0 {
            let h = cur as *mut DpmaInfoHandler;
            let tech = dpma_glue_exports_channel_tech_type(chan);
            if libc::strcasecmp((*h).tech, tech) == 0 {
                return match (*h).send {
                    Some(f) => f(chan, headers, content_type, body, useragent_filter),
                    None => -1,
                };
            }
            cur = (*h).next as usize;
        }
        -1
    })
}

type IsDphoneFn = unsafe extern "C" fn(endpoint: *const c_char) -> c_int;

/// The registered `pjsip_endpoint_is_dphone` (no lock, as in the original).
static IS_DPHONE: AtomicUsize = AtomicUsize::new(0);

/// `int dpma_register_pjsip_endpoint_is_dphone(int (*)(const char *))` (H):
/// -1 (and a log) when one is registered already.
#[no_mangle]
pub extern "C" fn dpma_register_pjsip_endpoint_is_dphone(f: Option<IsDphoneFn>) -> c_int {
    dpma_ast::guard(-1, || {
        if IS_DPHONE.load(Ordering::SeqCst) == 0 {
            IS_DPHONE.store(f.map_or(0, |f| f as usize), Ordering::SeqCst);
            return 0;
        }
        dpma_log!("Attempted to register dpma_pjsip_endpoint_is_dphone, but the function is already registerd.");
        -1
    })
}

/// `void dpma_unregister_pjsip_endpoint_is_dphone(void)` (H).
#[no_mangle]
pub extern "C" fn dpma_unregister_pjsip_endpoint_is_dphone() {
    IS_DPHONE.store(0, Ordering::SeqCst);
}

/// `int dpma_pjsip_endpoint_is_dphone(const char *endpoint)`: 0 (and a log)
/// when no function is registered.
#[no_mangle]
pub unsafe extern "C" fn dpma_pjsip_endpoint_is_dphone(endpoint: *const c_char) -> c_int {
    dpma_ast::guard(0, || {
        let f = IS_DPHONE.load(Ordering::SeqCst);
        if f != 0 {
            // SAFETY: only ever set from an `IsDphoneFn`.
            let f: IsDphoneFn = std::mem::transmute::<usize, IsDphoneFn>(f);
            return f(endpoint);
        }
        dpma_log!("dpma_pjsip_endpoint_is_dphone was invoked but the function is unregistered.");
        0
    })
}

/// Rust-side `dpma_info_send`: `headers` become an `ast_variable` list
/// (freed afterwards); an empty `content_type` or `body` is passed as
/// NULL.  -1 when no handler matches the channel technology.
///
/// # Safety
/// `chan` must be a live channel the caller holds a reference on.
pub unsafe fn info_send(chan: *mut AstChannel, headers: &[(&str, &str)], content_type: &str, body: &str) -> i32 {
    let mut list: *mut AstVariable = std::ptr::null_mut();
    for (name, value) in headers.iter().rev() {
        let (n, v) = (cstr(name), cstr(value));
        list = dpma_glue_exports_variable_prepend(list, n.as_ptr(), v.as_ptr());
    }
    let ct = cstr(content_type);
    let b = cstr(body);
    let opt = |s: &std::ffi::CString| if s.as_bytes().is_empty() { std::ptr::null() } else { s.as_ptr() };
    let r = dpma_info_send(chan, list, opt(&ct), opt(&b), std::ptr::null());
    dpma_glue_exports_variables_destroy(list);
    r
}

/// Rust-side `dpma_process_config_handlers` with the lines container
/// (`phone_users_process_phone_config`, between the phones and the
/// res_digium_phone.conf line sections; the original also reads sip.conf
/// and users.conf `hassip` lines before it).  The line and phone objects
/// are brought in step with the registry first.  Must be called without
/// the registry lock: the handlers call back into the exported API.
pub fn process_config_handlers() {
    super::objects::sync(Vec::new());
    unsafe { dpma_process_config_handlers(super::objects::lines_container() as *mut c_void) };
}
