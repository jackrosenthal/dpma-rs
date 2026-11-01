//! phone_users.c exports used by the PJSIP helper module (H) and the rest
//! of the original export list.  `struct phone_line *` and
//! `struct phone_user *` are the ao2 handle objects of `objects.rs`.
//!
//! Prototypes (from the decompile):
//!
//! ```c
//! struct ao2_container *phone_users_get_lines(void);                 // H, no ref
//! const char *phone_users_line_get_name(struct phone_line *);       // H, == line
//! const char *phone_users_line_get_pjsip_auth(struct phone_line *); // H
//! void phone_users_line_set_delme(struct phone_line *, int);        // H
//! int  phone_users_set_line_option(const char *opt, const char *val,
//!                                  struct phone_line *);            // H
//! void phone_users_process_line(struct phone_line *);               // H
//! int  phone_users_process_phone_config(const char *trigger);       // H
//! struct phone_line *phone_line_find(const char *name);             // H, ref
//! struct phone_line *phone_line_find_authenticated(const char *name,
//!                                                  const char *secret); // ref
//! struct phone_user *phone_line_get_user(struct phone_line *);      // ref
//! struct phone_line *phone_line_create(const char *name, int external); // ref
//! int  phone_line_destroy(struct phone_line *);                     // unref, 0
//! void phone_line_link(struct phone_line *);
//! void phone_line_unlink(struct phone_line *);
//! struct phone_user *phone_user_find(const char *name);             // H, ref
//! void phone_user_token_set_last_info(struct phone_user *,
//!         const char *uri, const char *session, const char *mac);   // H
//! int  phone_users_load(const char *file);
//! int  phone_users_reload(const char *file);
//! int  phone_users_unload(void);
//! int  phone_users_load_tests(void);    // returns 0
//! int  phone_users_unload_tests(void);  // returns 0
//! extern const char *phone_line_transport_option[4]; // "", ";transport=udp", ...
//! extern const char *phone_line_transport_string[4]; // "udp", "udp", "tcp", "tls"
//! extern const char *phone_line_transport_type[4];   // "", "udp", "tcp", "tls"
//! ```

use super::objects::{self, LineObj, UserObj};
use crate::users::{self, options, Line};
use dpma_ast::ao2;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

/// A table of C strings (the transport tables).
#[repr(transparent)]
pub struct CStrTable(pub [*const c_char; 4]);
// SAFETY: the table and its strings are immutable statics.
unsafe impl Sync for CStrTable {}

macro_rules! cs {
    ($s:literal) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

/// `phone_line_transport_option`, indexed by transport (unset, udp, tcp, tls).
#[no_mangle]
pub static phone_line_transport_option: CStrTable =
    CStrTable([cs!(""), cs!(";transport=udp"), cs!(";transport=tcp"), cs!(";transport=tls")]);

/// `phone_line_transport_string`: unset means udp.
#[no_mangle]
pub static phone_line_transport_string: CStrTable = CStrTable([cs!("udp"), cs!("udp"), cs!("tcp"), cs!("tls")]);

/// `phone_line_transport_type`: "" when unset.
#[no_mangle]
pub static phone_line_transport_type: CStrTable = CStrTable([cs!(""), cs!("udp"), cs!("tcp"), cs!("tls")]);

unsafe fn opt_str<'a>(p: *const c_char) -> std::borrow::Cow<'a, str> {
    if p.is_null() {
        "".into()
    } else {
        CStr::from_ptr(p).to_string_lossy()
    }
}

/// `struct ao2_container *phone_users_get_lines(void)` (H): the lines
/// container, without a reference.
#[no_mangle]
pub extern "C" fn phone_users_get_lines() -> *mut c_void {
    objects::lines_container() as *mut c_void
}

/// `const char *phone_users_line_get_name(struct phone_line *)` (H): the
/// line object itself, which starts with the name.
#[no_mangle]
pub extern "C" fn phone_users_line_get_name(line: *mut LineObj) -> *const c_char {
    line as *const c_char
}

/// `const char *phone_users_line_get_pjsip_auth(struct phone_line *)` (H):
/// never NULL ("" when unset).
#[no_mangle]
pub unsafe extern "C" fn phone_users_line_get_pjsip_auth(line: *mut LineObj) -> *const c_char {
    (*line).pjsip_auth_ptr()
}

/// `void phone_users_line_set_delme(struct phone_line *, int)` (H).
#[no_mangle]
pub unsafe extern "C" fn phone_users_line_set_delme(line: *mut LineObj, delme: c_int) {
    dpma_ast::guard((), || {
        (*line).with_line(|l| l.delme = delme & 1 != 0);
    })
}

/// `int phone_users_set_line_option(const char *opt, const char *val,
/// struct phone_line *)` (H): 0, or -1 for an unknown option or an
/// invalid number.  A NULL line only validates the option name.
#[no_mangle]
pub unsafe extern "C" fn phone_users_set_line_option(opt: *const c_char, val: *const c_char, line: *mut LineObj) -> c_int {
    dpma_ast::guard(-1, || {
        let opt = opt_str(opt);
        let val = opt_str(val);
        if line.is_null() {
            let mut scratch = Line::default();
            return if options::set_line_option(&mut scratch, &opt, &val).is_ok() { 0 } else { -1 };
        }
        match (*line).with_line(|l| options::set_line_option(l, &opt, &val)) {
            Some(Err(())) => -1,
            Some(Ok(())) => 0,
            // The registry no longer has the line: validate the name only.
            None => {
                let mut scratch = Line::default();
                if options::set_line_option(&mut scratch, &opt, &val).is_ok() { 0 } else { -1 }
            }
        }
    })
}

/// `void phone_users_process_line(struct phone_line *)` (H): apply the
/// settings of the line's own sections in voicemail.conf, users.conf
/// (app_voicemail), and res_digium_phone.conf again (`process_line_dp`).
/// As in the original, each mailbox is set with its line looked up by name
/// and locked (`set_mailbox`), and the res_digium_phone.conf sections are
/// applied with this line locked; no two line locks are held at once.
#[no_mangle]
pub unsafe extern "C" fn phone_users_process_line(line: *mut LineObj) {
    if line.is_null() {
        return;
    }
    let name = (*line).key().to_string();
    let mailboxes = dpma_ast::guard(Vec::new(), || users::load::line_mailboxes(&name));
    for (target, mailbox) in mailboxes {
        let t = dpma_ast::cstr(&target);
        let obj = phone_line_find(t.as_ptr());
        if obj.is_null() {
            continue;
        }
        ao2::lock(obj as *mut c_void);
        dpma_ast::guard((), || {
            (*obj).with_line(|l| options::set_line_option(l, "mailbox", &mailbox));
        });
        ao2::unlock(obj as *mut c_void);
        ao2::cleanup(obj as *mut c_void);
    }
    ao2::lock(line as *mut c_void);
    dpma_ast::guard((), || {
        (*line).with_line(users::load::apply_line_sections);
    });
    ao2::unlock(line as *mut c_void);
}

/// `int phone_users_process_phone_config(const char *trigger)` (H):
/// reprocess everything; -1 when res_digium_phone.conf is not loaded.
#[no_mangle]
pub unsafe extern "C" fn phone_users_process_phone_config(trigger: *const c_char) -> c_int {
    let trigger = opt_str(trigger).into_owned();
    dpma_ast::guard(-1, || if users::load::process(&trigger).is_ok() { 0 } else { -1 })
}

/// `struct phone_line *phone_line_find(const char *name)` (H): the line
/// with a reference, or NULL (also for a NULL or empty name).
#[no_mangle]
pub unsafe extern "C" fn phone_line_find(name: *const c_char) -> *mut LineObj {
    let c = objects::lines_container();
    if c.is_null() || name.is_null() || *name == 0 {
        return std::ptr::null_mut();
    }
    ao2::find_key(c, name) as *mut LineObj
}

/// `struct phone_line *phone_line_find_authenticated(const char *name,
/// const char *secret)`: the line (with a reference) if its secret
/// matches `secret`; both empty also matches.
#[no_mangle]
pub unsafe extern "C" fn phone_line_find_authenticated(name: *const c_char, secret: *const c_char) -> *mut LineObj {
    if name.is_null() || *name == 0 {
        return std::ptr::null_mut();
    }
    let line = phone_line_find(name);
    if line.is_null() {
        return line;
    }
    ao2::lock(line as *mut c_void);
    let given = opt_str(secret).into_owned();
    let ok = dpma_ast::guard(false, || (*line).with_line(|l| l.secret == given).unwrap_or(given.is_empty()));
    ao2::unlock(line as *mut c_void);
    if !ok {
        ao2::cleanup(line as *mut c_void);
        return std::ptr::null_mut();
    }
    line
}

/// `struct phone_user *phone_line_get_user(struct phone_line *)`: the first
/// phone (in container order) with this line, with a reference, or NULL.
#[no_mangle]
pub unsafe extern "C" fn phone_line_get_user(line: *mut LineObj) -> *mut UserObj {
    let users_c = objects::users_container();
    if users_c.is_null() || line.is_null() {
        return std::ptr::null_mut();
    }
    let name = opt_str(line as *const c_char).into_owned();
    let phone = dpma_ast::guard(None, || users::runtime::phone_for_line(&name));
    match phone {
        Some(p) => {
            let c = dpma_ast::cstr(&p);
            ao2::find_key(users_c, c.as_ptr()) as *mut UserObj
        }
        None => std::ptr::null_mut(),
    }
}

/// `struct phone_line *phone_line_create(const char *name, int external)`:
/// a new line object (one reference) that is not linked yet.  Internal
/// lines get an initial CustomPresence state.
#[no_mangle]
pub unsafe extern "C" fn phone_line_create(name: *const c_char, external: c_int) -> *mut LineObj {
    let name = opt_str(name).into_owned();
    dpma_ast::guard(std::ptr::null_mut(), || {
        let line = objects::new_line(&name, "", Some(Line::new(&name, external & 1 != 0)));
        if !line.is_null() && external == 0 {
            options::init_custom_presence(&name);
        }
        line
    })
}

/// `int phone_line_destroy(struct phone_line *)`: drop a reference; 0.
#[no_mangle]
pub unsafe extern "C" fn phone_line_destroy(line: *mut LineObj) -> c_int {
    ao2::ao2_ref(line as *mut c_void, -1);
    0
}

/// `void phone_line_link(struct phone_line *)`: add the line to the
/// configuration (and the lines container).
#[no_mangle]
pub unsafe extern "C" fn phone_line_link(line: *mut LineObj) {
    if !line.is_null() {
        dpma_ast::guard((), || objects::link_line(line));
    }
}

/// `void phone_line_unlink(struct phone_line *)`: remove the line from the
/// configuration (and the lines container).
#[no_mangle]
pub unsafe extern "C" fn phone_line_unlink(line: *mut LineObj) {
    if !line.is_null() {
        dpma_ast::guard((), || objects::unlink_line(line));
    }
}

/// `struct phone_user *phone_user_find(const char *name)` (H): the phone
/// with a reference, or NULL.
#[no_mangle]
pub unsafe extern "C" fn phone_user_find(name: *const c_char) -> *mut UserObj {
    let c = objects::users_container();
    if c.is_null() || name.is_null() || *name == 0 {
        return std::ptr::null_mut();
    }
    ao2::find_key(c, name) as *mut UserObj
}

/// `void phone_user_token_set_last_info(struct phone_user *, const char
/// *uri, const char *session, const char *mac)` (H): record where the
/// phone was last seen (NULL session or mac: unchanged).
#[no_mangle]
pub unsafe extern "C" fn phone_user_token_set_last_info(
    user: *mut UserObj,
    uri: *const c_char,
    session: *const c_char,
    mac: *const c_char,
) {
    if user.is_null() {
        return;
    }
    let name = (*user).key().to_string();
    let uri = opt_str(uri).into_owned();
    let session = (!session.is_null()).then(|| opt_str(session).into_owned());
    let mac = (!mac.is_null()).then(|| opt_str(mac).into_owned());
    dpma_ast::guard((), || {
        #[cfg(feature = "devtest")]
        super::devtest::record_last_info(&name, &uri, session.as_deref(), mac.as_deref(), (*user).is_linked());
        if (*user).is_linked() {
            users::runtime::set_last_info(&name, &uri, session.as_deref(), mac.as_deref());
        }
    })
}

/// `int phone_users_load(const char *file)`.
#[no_mangle]
pub unsafe extern "C" fn phone_users_load(file: *const c_char) -> c_int {
    let file = opt_str(file).into_owned();
    dpma_ast::guard(-1, || {
        let _ = users::load::load(&file);
        0
    })
}

/// `int phone_users_reload(const char *file)`.
#[no_mangle]
pub unsafe extern "C" fn phone_users_reload(file: *const c_char) -> c_int {
    let file = opt_str(file).into_owned();
    dpma_ast::guard(-1, || {
        let _ = users::load::reload(&file);
        0
    })
}

/// `int phone_users_unload(void)`.
#[no_mangle]
pub extern "C" fn phone_users_unload() -> c_int {
    dpma_ast::guard(0, || {
        users::load::unload();
        0
    })
}

/// `int phone_users_load_tests(void)`: no tests in this build; 0.
#[no_mangle]
pub extern "C" fn phone_users_load_tests() -> c_int {
    0
}

/// `int phone_users_unload_tests(void)`: 0.
#[no_mangle]
pub extern "C" fn phone_users_unload_tests() -> c_int {
    0
}
