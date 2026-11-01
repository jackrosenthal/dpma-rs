//! phone_config.c exports: `dpma_config_get`, `dpma_config_unref`, the
//! `dpma_config_*` getters (0x178e90..0x1791d0), and
//! `dpma_append_config_file_dir` (0x1791f0).
//!
//! `struct dpma_config` is an ao2 object with the original's exact layout
//! (0x4804 bytes), rebuilt from `config::General` on every configuration
//! load and kept in a global holder.  Getters return pointers into it.
//! The getters reproduce the original's handling of a NULL config: the
//! integer getters, `file_dir`, `reg_port`, and `append_config_file_dir`
//! fall back to the current configuration or a default; the
//! `firmware_package_*`, `server_uuid`, `reg_addr`, and `file_url_prefix`
//! getters return "" for NULL; and `password`, `mdns_addr`, `mdns_port`,
//! `mdns_transport`, `service_name`, and `pjsip_message_context` do not
//! check for NULL at all (they return the field's offset as a pointer, as
//! the original does).

use crate::config::General;
use dpma_ast::ao2;
use std::cell::UnsafeCell;
use std::mem::{offset_of, size_of};
use std::os::raw::{c_char, c_int, c_uint, c_void};

/// `struct dpma_config` (phone_config.c `dcfg_alloc`).
#[repr(C)]
pub struct DpmaConfig {
    pub auth_flags: c_int,
    pub enable_discovery: c_int,
    pub initial_threads: c_int,
    pub max_threads: c_int,
    pub delay: c_int,
    pub password: [c_char; 0x100],
    pub mdns_addr: [c_char; 0x200],
    pub mdns_port: [c_char; 10],
    pub mdns_transport: [c_char; 10],
    pub service_name: [c_char; 0x80],
    pub pjsip_message_context: [c_char; 0x50],
    pub file_dir: [c_char; 0x1000],
    pub firmware_package_file: [c_char; 0x1000],
    pub firmware_package_dir: [c_char; 0x1000],
    pub server_uuid: [c_char; 0x200],
    pub reg_addr: [c_char; 0x200],
    pub reg_port: [c_char; 10],
    pub file_url_prefix: [c_char; 0x1000],
}

const _: () = {
    assert!(size_of::<DpmaConfig>() == 0x4804);
    assert!(offset_of!(DpmaConfig, password) == 0x14);
    assert!(offset_of!(DpmaConfig, mdns_addr) == 0x114);
    assert!(offset_of!(DpmaConfig, mdns_port) == 0x314);
    assert!(offset_of!(DpmaConfig, mdns_transport) == 0x31e);
    assert!(offset_of!(DpmaConfig, service_name) == 0x328);
    assert!(offset_of!(DpmaConfig, pjsip_message_context) == 0x3a8);
    assert!(offset_of!(DpmaConfig, file_dir) == 0x3f8);
    assert!(offset_of!(DpmaConfig, firmware_package_file) == 0x13f8);
    assert!(offset_of!(DpmaConfig, firmware_package_dir) == 0x23f8);
    assert!(offset_of!(DpmaConfig, server_uuid) == 0x33f8);
    assert!(offset_of!(DpmaConfig, reg_addr) == 0x35f8);
    assert!(offset_of!(DpmaConfig, reg_port) == 0x37f8);
    assert!(offset_of!(DpmaConfig, file_url_prefix) == 0x3802);
};

extern "C" {
    fn dpma_glue_exports_config_ref() -> *mut c_void;
    fn dpma_glue_exports_config_replace(cfg: *mut c_void);
}

/// The original's static `"<astvarlibdir>/digium_phones"` buffer
/// (`DAT_005eef40`), returned by `dpma_config_file_dir` without a usable
/// config.  It is rewritten on every load, as in the original.
struct DefaultFileDir(UnsafeCell<[c_char; 0x1000]>);
// SAFETY: written only by the configuration loader (one thread at a
// time); C callers read it as a plain string, as with the original.
unsafe impl Sync for DefaultFileDir {}
static DEFAULT_FILE_DIR: DefaultFileDir = DefaultFileDir(UnsafeCell::new([0; 0x1000]));

static DEFAULT_PORT: &[u8] = b"5060\0";
static DEFAULT_SERVICE_NAME: &[u8] = b"Digium Phone Config Server\0";
static DEFAULT_MESSAGE_CONTEXT: &[u8] = b"dpma_pjsip_message_context\0";
static EMPTY: &[u8] = b"\0";

fn cptr(s: &'static [u8]) -> *const c_char {
    s.as_ptr() as *const c_char
}

/// `ast_copy_string(dst, src, sizeof(dst))`.
fn copy(dst: &mut [c_char], src: &str) {
    let n = src.len().min(dst.len() - 1);
    for (d, s) in dst.iter_mut().zip(src.as_bytes()[..n].iter()) {
        *d = *s as c_char;
    }
    dst[n] = 0;
}

/// Build the C configuration object for `g` and make it current
/// (`config_replace` in `load_phone_config`).
pub fn publish(g: &General) {
    unsafe {
        let buf = &mut *DEFAULT_FILE_DIR.0.get();
        copy(buf, &format!("{}/digium_phones", dpma_ast::var_dir()));
    }
    let obj = ao2::alloc(size_of::<DpmaConfig>(), None) as *mut DpmaConfig;
    if obj.is_null() {
        dpma_ast::ast_log!(dpma_ast::log::LOG_ERROR, "Unable to allocate DPMA module configuration.");
        return;
    }
    // SAFETY: a fresh, zeroed allocation of the right size.
    let c = unsafe { &mut *obj };
    c.auth_flags = g.auth_flags as c_int;
    c.enable_discovery = c_int::from(g.discovery_enabled);
    c.initial_threads = g.initial_threads as c_int;
    c.max_threads = g.max_threads as c_int;
    c.delay = g.message_delay as c_int;
    copy(&mut c.password, &g.globalpin);
    copy(&mut c.mdns_addr, &g.mdns_address);
    copy(&mut c.mdns_port, g.mdns_port());
    copy(&mut c.mdns_transport, &g.mdns_transport);
    copy(&mut c.service_name, &g.service_name);
    copy(&mut c.pjsip_message_context, &g.pjsip_message_context);
    copy(&mut c.file_dir, &g.file_directory);
    copy(&mut c.firmware_package_file, &g.firmware_package_file);
    copy(&mut c.firmware_package_dir, &g.firmware_package_directory);
    copy(&mut c.server_uuid, &g.server_uuid);
    copy(&mut c.reg_addr, &g.registration_address);
    copy(&mut c.reg_port, g.registration_port());
    copy(&mut c.file_url_prefix, &g.firmware_url_prefix);
    unsafe {
        dpma_glue_exports_config_replace(obj as *mut c_void);
        ao2::cleanup(obj as *mut c_void);
    }
}

/// Drop the current configuration (`unload_phone_config`).
pub fn unpublish() {
    unsafe { dpma_glue_exports_config_replace(std::ptr::null_mut()) };
}

/// `struct dpma_config *dpma_config_get(void)`: the current configuration
/// with a reference, or NULL.
#[no_mangle]
pub extern "C" fn dpma_config_get() -> *mut DpmaConfig {
    unsafe { dpma_glue_exports_config_ref() as *mut DpmaConfig }
}

/// `void dpma_config_unref(struct dpma_config *)`.
#[no_mangle]
pub unsafe extern "C" fn dpma_config_unref(cfg: *mut DpmaConfig) {
    if !cfg.is_null() {
        ao2::ao2_ref(cfg as *mut c_void, -1);
    }
}

/// The original's pattern for the integer getters: with a NULL config,
/// use the current one (its reference is dropped at once; the holder
/// keeps it alive), or `default` without one.
unsafe fn int_field(cfg: *mut DpmaConfig, default: c_int, f: impl FnOnce(&DpmaConfig) -> c_int) -> c_int {
    let mut held = std::ptr::null_mut();
    let mut cfg = cfg;
    if cfg.is_null() {
        cfg = dpma_config_get();
        held = cfg;
        if cfg.is_null() {
            dpma_config_unref(std::ptr::null_mut());
            return default;
        }
    }
    dpma_config_unref(held);
    f(&*cfg)
}

/// `int dpma_config_auth_flags(struct dpma_config *)` (1 without config).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_auth_flags(cfg: *mut DpmaConfig) -> c_int {
    int_field(cfg, 1, |c| c.auth_flags)
}

/// `int dpma_config_enable_discovery(struct dpma_config *)` (1).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_enable_discovery(cfg: *mut DpmaConfig) -> c_int {
    int_field(cfg, 1, |c| c.enable_discovery)
}

/// `int dpma_config_initial_threads(struct dpma_config *)` (1).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_initial_threads(cfg: *mut DpmaConfig) -> c_int {
    int_field(cfg, 1, |c| c.initial_threads)
}

/// `int dpma_config_max_threads(struct dpma_config *)` (4).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_max_threads(cfg: *mut DpmaConfig) -> c_int {
    int_field(cfg, 4, |c| c.max_threads)
}

/// `int dpma_config_delay(struct dpma_config *)` (5).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_delay(cfg: *mut DpmaConfig) -> c_int {
    int_field(cfg, 5, |c| c.delay)
}

/// The address of a field of `cfg`, computed like the original (no NULL
/// check: NULL yields the field's offset).
fn field_addr(cfg: *mut DpmaConfig, offset: usize) -> *const c_char {
    (cfg as *const u8).wrapping_add(offset) as *const c_char
}

/// `const char *dpma_config_password(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_password(cfg: *mut DpmaConfig) -> *const c_char {
    field_addr(cfg, offset_of!(DpmaConfig, password))
}

/// `const char *dpma_config_mdns_addr(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_mdns_addr(cfg: *mut DpmaConfig) -> *const c_char {
    field_addr(cfg, offset_of!(DpmaConfig, mdns_addr))
}

/// A string field, or `default` when the field is empty.
unsafe fn or_default(p: *const c_char, default: &'static [u8]) -> *const c_char {
    if p.is_null() || *p == 0 {
        cptr(default)
    } else {
        p
    }
}

/// `const char *dpma_config_mdns_port(struct dpma_config *)` ("5060" when
/// empty).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_mdns_port(cfg: *mut DpmaConfig) -> *const c_char {
    or_default(field_addr(cfg, offset_of!(DpmaConfig, mdns_port)), DEFAULT_PORT)
}

/// `const char *dpma_config_mdns_transport(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_mdns_transport(cfg: *mut DpmaConfig) -> *const c_char {
    field_addr(cfg, offset_of!(DpmaConfig, mdns_transport))
}

/// `const char *dpma_config_service_name(struct dpma_config *)` ("Digium
/// Phone Config Server" when empty).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_service_name(cfg: *mut DpmaConfig) -> *const c_char {
    or_default(field_addr(cfg, offset_of!(DpmaConfig, service_name)), DEFAULT_SERVICE_NAME)
}

/// `const char *dpma_config_pjsip_message_context(struct dpma_config *)`
/// ("dpma_pjsip_message_context" when empty).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_pjsip_message_context(cfg: *mut DpmaConfig) -> *const c_char {
    or_default(field_addr(cfg, offset_of!(DpmaConfig, pjsip_message_context)), DEFAULT_MESSAGE_CONTEXT)
}

/// `const char *dpma_config_file_dir(struct dpma_config *)`: the
/// configured directory, or the default "<astvarlibdir>/digium_phones"
/// for NULL or an empty setting.
#[no_mangle]
pub unsafe extern "C" fn dpma_config_file_dir(cfg: *mut DpmaConfig) -> *const c_char {
    if !cfg.is_null() && (*cfg).file_dir[0] != 0 {
        return (*cfg).file_dir.as_ptr();
    }
    DEFAULT_FILE_DIR.0.get() as *const c_char
}

/// A string field, or "" for a NULL config.
fn or_empty(cfg: *mut DpmaConfig, offset: usize) -> *const c_char {
    if cfg.is_null() {
        cptr(EMPTY)
    } else {
        field_addr(cfg, offset)
    }
}

/// `const char *dpma_config_firmware_package_file(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_firmware_package_file(cfg: *mut DpmaConfig) -> *const c_char {
    or_empty(cfg, offset_of!(DpmaConfig, firmware_package_file))
}

/// `const char *dpma_config_firmware_package_dir(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_firmware_package_dir(cfg: *mut DpmaConfig) -> *const c_char {
    or_empty(cfg, offset_of!(DpmaConfig, firmware_package_dir))
}

/// `const char *dpma_config_server_uuid(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_server_uuid(cfg: *mut DpmaConfig) -> *const c_char {
    or_empty(cfg, offset_of!(DpmaConfig, server_uuid))
}

/// `const char *dpma_config_reg_addr(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_reg_addr(cfg: *mut DpmaConfig) -> *const c_char {
    or_empty(cfg, offset_of!(DpmaConfig, reg_addr))
}

/// `const char *dpma_config_reg_port(struct dpma_config *)` ("5060" for
/// NULL or empty).
#[no_mangle]
pub unsafe extern "C" fn dpma_config_reg_port(cfg: *mut DpmaConfig) -> *const c_char {
    if !cfg.is_null() && (*cfg).reg_port[0] != 0 {
        return (*cfg).reg_port.as_ptr();
    }
    cptr(DEFAULT_PORT)
}

/// `const char *dpma_config_file_url_prefix(struct dpma_config *)`.
#[no_mangle]
pub extern "C" fn dpma_config_file_url_prefix(cfg: *mut DpmaConfig) -> *const c_char {
    or_empty(cfg, offset_of!(DpmaConfig, file_url_prefix))
}

/// `void dpma_append_config_file_dir(char *buf, unsigned int len, const
/// char *file, struct dpma_config *cfg)`: "<file_dir>/<file>" into `buf`,
/// or just the directory when `file` is NULL or empty.  `buf` is left
/// alone when there is no configuration.
#[no_mangle]
pub unsafe extern "C" fn dpma_append_config_file_dir(
    buf: *mut c_char,
    len: c_uint,
    file: *const c_char,
    cfg: *mut DpmaConfig,
) {
    let mut held = std::ptr::null_mut();
    let mut cfg = cfg;
    if cfg.is_null() {
        cfg = dpma_config_get();
        held = cfg;
        if cfg.is_null() {
            dpma_config_unref(std::ptr::null_mut());
            return;
        }
    }
    dpma_config_unref(held);
    let dir = (*cfg).file_dir.as_ptr();
    if !file.is_null() && *file != 0 {
        libc::snprintf(buf, len as usize, c"%s/%s".as_ptr(), dir, file);
        return;
    }
    // ast_copy_string(buf, dir, len), including its behavior for len 0.
    let mut size = len as usize;
    let mut d = buf;
    let mut s = dir;
    while *s != 0 && size != 0 {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
        size -= 1;
    }
    if size == 0 {
        d = d.sub(1);
    }
    *d = 0;
}
