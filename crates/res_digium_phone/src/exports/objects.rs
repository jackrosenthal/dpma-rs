//! The astobj2 objects behind `struct phone_line *` and
//! `struct phone_user *`, and the two containers holding them.
//!
//! The phone users configuration lives in `users::Registry`; the objects
//! here are handles that name a registry line or phone.  Like the
//! original's objects they start with the NUL-terminated name (128 bytes,
//! `phone_users_line_get_name` returns the object itself), are locked and
//! reference counted with ao2, and live in hash containers of 257 buckets
//! hashed and compared case-insensitively by name, so containers iterate
//! in the same order as the registry's maps.
//!
//! `sync` keeps the containers in step with the registry: it is called
//! before the C config handlers run and after every processing pass.  A
//! line object that is not the registry's (made by `phone_line_create`
//! and not linked yet, unlinked, or swept by a reload) carries its own
//! copy of the line's settings, so changes made through it never reach
//! the live configuration, as with the original's unlinked objects.
//!
//! Locking: a handle's state mutex may be held while taking the registry
//! lock, never the other way round, and no ao2 lock is ever taken while
//! holding the registry lock (C callers hold line locks while calling
//! back into the exports).
//!
//! Line locks: C callers (the PJSIP helper's sorcery observers, on their
//! own threads) update a line with several export calls while holding the
//! line object's ao2 lock, as the original module's own code does.  Code
//! that reads or writes lines where the original takes the line's lock
//! takes it too, through `lock_lines`, `lock_phone_lines`, or
//! `lock_all_lines`, so it never sees a line half updated.  Rules: take
//! line locks before the registry lock (never while holding it), find
//! every object before locking any (a thread holding line locks must not
//! wait for the lines container's lock: `ao2_callback` holds it while the
//! helper's callback locks lines), and lock in address order (the guards
//! do both).

use crate::users::{self, Line};
use dpma_ast::ao2::{self, Container};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Size of the name at the start of every object (the original's
/// `char name[0x80]`).
pub const NAME_LEN: usize = 0x80;
/// Buckets of the original's containers.
const BUCKETS: i32 = 257;

/// `struct phone_line`.
#[repr(C)]
pub struct LineObj {
    name: [c_char; NAME_LEN],
    /// The registry's name for the line (the C name may be truncated).
    key: String,
    /// `phone_users_line_get_pjsip_auth`: never NULL.  Earlier values are
    /// kept in `LineState::retired` until the object goes away so that
    /// pointers handed out stay valid.
    pjsip_auth: AtomicPtr<c_char>,
    state: Mutex<LineState>,
}

struct LineState {
    /// The line's own settings while the object is not the registry's;
    /// None while it is (linked).
    detached: Option<Line>,
    retired: Vec<CString>,
}

/// `struct phone_user`.
#[repr(C)]
pub struct UserObj {
    name: [c_char; NAME_LEN],
    key: String,
    /// Whether the object is the registry's (in the users container).
    linked: AtomicBool,
}

static LINES: AtomicPtr<Container> = AtomicPtr::new(std::ptr::null_mut());
static USERS: AtomicPtr<Container> = AtomicPtr::new(std::ptr::null_mut());
/// Serializes `sync` and the link/unlink exports.
static SYNC: Mutex<()> = Mutex::new(());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The lines container (`phone_users_get_lines`), NULL when not loaded.
pub fn lines_container() -> *mut Container {
    LINES.load(Ordering::SeqCst)
}

/// The phone users container, NULL when not loaded.
pub fn users_container() -> *mut Container {
    USERS.load(Ordering::SeqCst)
}

/// Create (or replace) both containers (`phone_users_load`).
pub fn create_containers() {
    destroy_containers();
    let _g = lock(&SYNC);
    LINES.store(ao2::named_container(BUCKETS), Ordering::SeqCst);
    USERS.store(ao2::named_container(BUCKETS), Ordering::SeqCst);
}

/// Drop both containers (`phone_users_unload`).  Objects that C code
/// still holds survive, detached.
pub fn destroy_containers() {
    let _g = lock(&SYNC);
    for (i, c) in [&LINES, &USERS].into_iter().enumerate() {
        let old = c.swap(std::ptr::null_mut(), Ordering::SeqCst);
        if old.is_null() {
            continue;
        }
        unsafe {
            for o in ao2::collect(old) {
                if i == 0 {
                    detach_line(o as *mut LineObj, None);
                } else {
                    (*(o as *mut UserObj)).linked.store(false, Ordering::SeqCst);
                }
                ao2::cleanup(o);
            }
            ao2::cleanup(old as *mut c_void);
        }
    }
}

fn c_name(name: &str) -> [c_char; NAME_LEN] {
    // ast_copy_string(obj->name, name, sizeof(obj->name))
    let mut out = [0 as c_char; NAME_LEN];
    for (d, s) in out.iter_mut().zip(name.bytes().take(NAME_LEN - 1)) {
        *d = s as c_char;
    }
    out
}

unsafe extern "C" fn line_destructor(obj: *mut c_void) {
    let l = obj as *mut LineObj;
    let p = (*l).pjsip_auth.swap(std::ptr::null_mut(), Ordering::SeqCst);
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
    std::ptr::drop_in_place(l);
}

unsafe extern "C" fn user_destructor(obj: *mut c_void) {
    std::ptr::drop_in_place(obj as *mut UserObj);
}

/// A new line object (one reference), detached with `line` as its
/// settings, or attached (None).
pub fn new_line(key: &str, pjsip_auth: &str, detached: Option<Line>) -> *mut LineObj {
    let obj = ao2::alloc(std::mem::size_of::<LineObj>(), Some(line_destructor)) as *mut LineObj;
    if obj.is_null() {
        return obj;
    }
    let auth = dpma_ast::cstr(pjsip_auth).into_raw();
    unsafe {
        std::ptr::write(
            obj,
            LineObj {
                name: c_name(key),
                key: key.to_string(),
                pjsip_auth: AtomicPtr::new(auth),
                state: Mutex::new(LineState { detached, retired: Vec::new() }),
            },
        );
    }
    obj
}

fn new_user(key: &str) -> *mut UserObj {
    let obj = ao2::alloc(std::mem::size_of::<UserObj>(), Some(user_destructor)) as *mut UserObj;
    if obj.is_null() {
        return obj;
    }
    unsafe {
        std::ptr::write(obj, UserObj { name: c_name(key), key: key.to_string(), linked: AtomicBool::new(true) });
    }
    obj
}

impl LineObj {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn pjsip_auth_ptr(&self) -> *const c_char {
        self.pjsip_auth.load(Ordering::SeqCst)
    }

    /// Update the cached `pjsip_auth` string if it changed.
    fn refresh_auth(&self, st: &mut LineState, value: &str) {
        let cur = self.pjsip_auth.load(Ordering::SeqCst);
        let same = !cur.is_null() && unsafe { std::ffi::CStr::from_ptr(cur) }.to_bytes() == value.as_bytes();
        if same {
            return;
        }
        let new = dpma_ast::cstr(value).into_raw();
        let old = self.pjsip_auth.swap(new, Ordering::SeqCst);
        if !old.is_null() {
            st.retired.push(unsafe { CString::from_raw(old) });
        }
    }

    /// Run `f` on the line's settings: the registry's line while the object
    /// is linked (None if the registry no longer has it), else its own copy.
    pub fn with_line<R>(&self, f: impl FnOnce(&mut Line) -> R) -> Option<R> {
        let mut st = lock(&self.state);
        let (r, auth) = if let Some(l) = st.detached.as_mut() {
            let r = f(l);
            (r, l.pjsip_auth.clone())
        } else {
            let mut g = users::write();
            let l = g.as_mut()?.lines.get_mut(&self.key)?;
            let r = f(l);
            (r, l.pjsip_auth.clone())
        };
        self.refresh_auth(&mut st, &auth);
        Some(r)
    }

    /// Whether the object is the registry's line.
    pub fn is_linked(&self) -> bool {
        lock(&self.state).detached.is_none()
    }

    fn take_detached(&self) -> Option<Line> {
        lock(&self.state).detached.take()
    }
}

impl UserObj {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn is_linked(&self) -> bool {
        self.linked.load(Ordering::SeqCst)
    }
}

/// Mark a line object as no longer the registry's, keeping `last` (its
/// last settings) as its own.
unsafe fn detach_line(obj: *mut LineObj, last: Option<Line>) {
    let o = &*obj;
    let mut st = lock(&o.state);
    if st.detached.is_none() {
        let line = last.unwrap_or_else(|| Line::new(&o.key, false));
        let auth = line.pjsip_auth.clone();
        st.detached = Some(line);
        o.refresh_auth(&mut st, &auth);
    }
}

/// Bring both containers in step with the registry: link objects for new
/// lines and phones, unlink those the registry no longer has (`swept`
/// holds the settings of lines just removed), and refresh the cached
/// `pjsip_auth` strings.  Must be called without the registry lock.
pub fn sync(swept: Vec<Line>) {
    let _g = lock(&SYNC);
    let lines_c = lines_container();
    let users_c = users_container();
    if lines_c.is_null() || users_c.is_null() {
        return;
    }
    // Snapshot the registry (lower-cased name -> (name, pjsip_auth)).
    let (lines, phones): (Vec<(String, String)>, Vec<String>) = {
        let g = users::read();
        let Some(reg) = g.as_ref() else { return };
        (
            reg.lines.values().map(|l| (l.name.clone(), l.pjsip_auth.clone())).collect(),
            reg.phones.values().map(|p| p.name.clone()).collect(),
        )
    };
    let mut swept: HashMap<String, Line> = swept.into_iter().map(|l| (l.name.to_ascii_lowercase(), l)).collect();

    unsafe {
        // ---- lines ----
        let want: HashMap<String, &str> = lines.iter().map(|(n, a)| (n.to_ascii_lowercase(), a.as_str())).collect();
        let mut have = std::collections::HashSet::new();
        for o in ao2::collect(lines_c) {
            let obj = o as *mut LineObj;
            let k = (*obj).key.to_ascii_lowercase();
            match want.get(&k) {
                Some(auth) if have.insert(k.clone()) => {
                    let mut st = lock(&(*obj).state);
                    (*obj).refresh_auth(&mut st, auth);
                }
                _ => {
                    ao2::unlink(lines_c, o);
                    detach_line(obj, swept.remove(&k));
                }
            }
            ao2::cleanup(o);
        }
        for (name, auth) in &lines {
            if have.contains(&name.to_ascii_lowercase()) {
                continue;
            }
            let obj = new_line(name, auth, None);
            if !obj.is_null() {
                ao2::link(lines_c, obj as *mut c_void);
                ao2::cleanup(obj as *mut c_void);
            }
        }

        // ---- phones ----
        let want: std::collections::HashSet<String> = phones.iter().map(|n| n.to_ascii_lowercase()).collect();
        let mut have = std::collections::HashSet::new();
        for o in ao2::collect(users_c) {
            let obj = o as *mut UserObj;
            let k = (*obj).key.to_ascii_lowercase();
            if !(want.contains(&k) && have.insert(k)) {
                ao2::unlink(users_c, o);
                (*obj).linked.store(false, Ordering::SeqCst);
            }
            ao2::cleanup(o);
        }
        for name in &phones {
            if have.contains(&name.to_ascii_lowercase()) {
                continue;
            }
            let obj = new_user(name);
            if !obj.is_null() {
                ao2::link(users_c, obj as *mut c_void);
                ao2::cleanup(obj as *mut c_void);
            }
        }
    }
}

/// Line objects locked by `lock_lines`, `lock_phone_lines`, or
/// `lock_all_lines` (each with a reference); unlocked and released when
/// dropped.
pub struct LineLocks(Vec<*mut c_void>);

impl Drop for LineLocks {
    fn drop(&mut self) {
        for &o in self.0.iter().rev() {
            unsafe {
                ao2::unlock(o);
                ao2::cleanup(o);
            }
        }
    }
}

/// Lock `objs` (each with a reference, duplicates allowed) in address
/// order.
fn lock_objects(mut objs: Vec<*mut c_void>) -> LineLocks {
    objs.sort_unstable_by_key(|&o| o as usize);
    let mut unique: Vec<*mut c_void> = Vec::with_capacity(objs.len());
    for o in objs {
        if unique.last() == Some(&o) {
            unsafe { ao2::cleanup(o) };
        } else {
            unique.push(o);
        }
    }
    for &o in &unique {
        unsafe { ao2::lock(o) };
    }
    LineLocks(unique)
}

/// Lock the objects of the lines named `names` (those that have one) for a
/// consistent read or update of those lines; see "Line locks" above.  Must
/// be called without the registry lock.
pub fn lock_lines<'a>(names: impl IntoIterator<Item = &'a str>) -> LineLocks {
    let c = lines_container();
    let mut objs = Vec::new();
    if !c.is_null() {
        for name in names {
            let key = dpma_ast::cstr(name);
            let o = unsafe { ao2::find_key(c, key.as_ptr()) };
            if !o.is_null() {
                objs.push(o);
            }
        }
    }
    lock_objects(objs)
}

/// Lock the objects of every line of `phone` (`lock_lines`).
pub fn lock_phone_lines(phone: &str) -> LineLocks {
    let names: Vec<String> = {
        let g = users::read();
        g.as_ref()
            .and_then(|reg| reg.phones.get(phone))
            .map(|p| p.lines.iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default()
    };
    lock_lines(names.iter().map(String::as_str))
}

/// Lock every line object (`lock_lines`).
pub fn lock_all_lines() -> LineLocks {
    lock_objects(unsafe { ao2::collect(lines_container()) })
}

/// `phone_line_link`: make a detached line object the registry's line
/// (replacing any line of that name) and link it.
pub unsafe fn link_line(obj: *mut LineObj) {
    let _g = lock(&SYNC);
    let c = lines_container();
    if c.is_null() {
        return;
    }
    let o = &*obj;
    if let Some(line) = o.take_detached() {
        if let Some(reg) = users::write().as_mut() {
            reg.lines.insert(&o.key, line);
        }
    }
    // A registry line of the same name has an object already: replace it.
    let old = ao2::find_key(c, o.name.as_ptr());
    if !old.is_null() {
        if old != obj as *mut c_void {
            ao2::unlink(c, old);
            detach_line(old as *mut LineObj, None);
        }
        ao2::cleanup(old);
    }
    ao2::link(c, obj as *mut c_void);
}

/// `phone_line_unlink`: take the line out of the registry (the object
/// keeps its settings) and out of the container.
pub unsafe fn unlink_line(obj: *mut LineObj) {
    let _g = lock(&SYNC);
    let o = &*obj;
    if o.is_linked() {
        let line = users::write().as_mut().and_then(|reg| reg.lines.remove(&o.key));
        detach_line(obj, line);
    }
    let c = lines_container();
    if !c.is_null() {
        ao2::unlink(c, obj as *mut c_void);
    }
}
