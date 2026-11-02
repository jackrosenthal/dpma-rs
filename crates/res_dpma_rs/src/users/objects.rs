//! The astobj2 objects behind the official DPMA's `struct phone_line *` and
//! `struct phone_user *`, and the two containers holding them.
//!
//! The phone users configuration lives in `users::Registry`; the objects
//! here are handles that name a registry line or phone.  Like the
//! official DPMA's objects they start with the NUL-terminated name (128
//! bytes), are locked and reference counted with ao2, and live in hash
//! containers of 257 buckets hashed and compared case-insensitively by
//! name, so containers iterate in the same order as the registry's maps.
//! The PJSIP side (`crate::pjsip`) works on lines through them as the
//! official DPMA's helper module does: it finds lines by name, walks the
//! lines container, and updates a line under its lock.
//!
//! `sync` keeps the containers in step with the registry: it is called
//! before the PJSIP lines pass runs and after every processing pass.  A
//! line object that is no longer the registry's (unlinked, or swept by a
//! reload, while somebody still holds it) carries its own copy of the
//! line's settings, so changes made through it never reach the live
//! configuration, as with the official DPMA's unlinked objects.
//!
//! Locking: a handle's state mutex may be held while taking the registry
//! lock, never the other way round, and no ao2 lock is ever taken while
//! holding the registry lock (the PJSIP side holds line locks while it
//! updates lines).
//!
//! Line locks: the PJSIP side's sorcery observers (on their own threads)
//! update a line with several calls while holding the line object's ao2
//! lock, as the official DPMA's own code does.  Code that reads or
//! writes lines where the official DPMA takes the line's lock takes it too,
//! through `lock_lines`, `lock_phone_lines`, or `lock_all_lines`, so it
//! never sees a line half updated.  Rules: take line locks before the
//! registry lock (never while holding it), find every object before
//! locking any (a thread holding line locks must not wait for the lines
//! container's lock: `ao2_callback` holds it while the PJSIP lines pass
//! locks lines), and lock in address order (the guards do both).

use crate::users::{self, options, Line};
use dpma_ast::ao2::{self, Container};
use std::collections::HashMap;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Size of the name at the start of every object (the official DPMA's
/// `char name[0x80]`).
pub const NAME_LEN: usize = 0x80;
/// Buckets of the official DPMA's containers.
const BUCKETS: u32 = 257;

/// `struct phone_line`.
#[repr(C)]
pub struct LineObj {
    /// The key of the containers (cut to 127 bytes).
    name: [c_char; NAME_LEN],
    /// The registry's name for the line.
    key: Vec<u8>,
    state: Mutex<LineState>,
}

struct LineState {
    /// The line's own settings while the object is not the registry's;
    /// None while it is (linked).
    detached: Option<Line>,
    /// `phone_users_line_get_pjsip_auth`: the line's `pjsip_auth` as of
    /// the last change through this object or the last `sync`.
    pjsip_auth: Vec<u8>,
}

/// `struct phone_user`.
#[repr(C)]
pub struct UserObj {
    name: [c_char; NAME_LEN],
    key: Vec<u8>,
    /// Whether the object is the registry's (in the users container).
    linked: AtomicBool,
}

static LINES: AtomicPtr<Container> = AtomicPtr::new(std::ptr::null_mut());
static USERS: AtomicPtr<Container> = AtomicPtr::new(std::ptr::null_mut());
/// Serializes `sync`.
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

fn c_name(name: &[u8]) -> [c_char; NAME_LEN] {
    // ast_copy_string(obj->name, name, sizeof(obj->name))
    let mut out = [0 as c_char; NAME_LEN];
    for (d, &s) in out.iter_mut().zip(dpma_ast::dpma_bytes::c_view(name).iter().take(NAME_LEN - 1)) {
        *d = s as c_char;
    }
    out
}

unsafe extern "C" fn line_destructor(obj: *mut c_void) {
    // SAFETY: the object was initialized by `new_line`; this is its last
    // reference.
    std::ptr::drop_in_place(obj as *mut LineObj);
}

unsafe extern "C" fn user_destructor(obj: *mut c_void) {
    // SAFETY: as in `line_destructor`.
    std::ptr::drop_in_place(obj as *mut UserObj);
}

/// A new line object (one reference) for the registry's line `key`.
fn new_line(key: &[u8], pjsip_auth: &[u8]) -> *mut LineObj {
    let obj = ao2::alloc(std::mem::size_of::<LineObj>(), Some(line_destructor)) as *mut LineObj;
    if obj.is_null() {
        return obj;
    }
    // SAFETY: a fresh allocation of the right size, initialized here.
    unsafe {
        std::ptr::write(
            obj,
            LineObj {
                name: c_name(key),
                key: key.to_vec(),
                state: Mutex::new(LineState { detached: None, pjsip_auth: pjsip_auth.to_vec() }),
            },
        );
    }
    obj
}

fn new_user(key: &[u8]) -> *mut UserObj {
    let obj = ao2::alloc(std::mem::size_of::<UserObj>(), Some(user_destructor)) as *mut UserObj;
    if obj.is_null() {
        return obj;
    }
    // SAFETY: as in `new_line`.
    unsafe {
        std::ptr::write(obj, UserObj { name: c_name(key), key: key.to_vec(), linked: AtomicBool::new(true) });
    }
    obj
}

impl LineObj {
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The container key: the name as the official DPMA's object holds it
    /// (`phone_users_line_get_name`).
    pub fn name(&self) -> &std::ffi::CStr {
        // SAFETY: `c_name` always leaves a NUL in the buffer.
        unsafe { std::ffi::CStr::from_ptr(self.name.as_ptr()) }
    }

    /// `phone_users_line_get_pjsip_auth`.
    pub fn pjsip_auth(&self) -> Vec<u8> {
        lock(&self.state).pjsip_auth.clone()
    }

    /// Update the cached `pjsip_auth` string.
    fn refresh_auth(st: &mut LineState, value: &[u8]) {
        if st.pjsip_auth != value {
            st.pjsip_auth = value.to_vec();
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
        LineObj::refresh_auth(&mut st, &auth);
        Some(r)
    }

    /// Whether the object is the registry's line.
    pub fn is_linked(&self) -> bool {
        lock(&self.state).detached.is_none()
    }

    /// `phone_users_line_set_delme`.
    pub fn set_delme(&self, delme: bool) {
        self.with_line(|l| l.delme = delme);
    }

    /// `phone_users_set_line_option(option, value, line)`: Err for an
    /// unknown option or an invalid number.
    pub fn set_option(&self, option: &[u8], value: &[u8]) -> Result<(), ()> {
        match self.with_line(|l| options::set_line_option(l, option, value)) {
            Some(r) => r,
            // The registry no longer has the line: validate the name only.
            None => options::set_line_option(&mut Line::default(), option, value),
        }
    }

    /// `ao2_lock` on the object, released when the guard is dropped.
    pub fn lock(&self) -> ObjLock<'_> {
        let p = self as *const LineObj as *mut c_void;
        // SAFETY: a live ao2 object (the caller holds a reference).
        unsafe { ao2::lock(p) };
        ObjLock(p, std::marker::PhantomData)
    }
}

/// An ao2 lock on an object (see `LineObj::lock`).
pub struct ObjLock<'a>(*mut c_void, std::marker::PhantomData<&'a LineObj>);

impl Drop for ObjLock<'_> {
    fn drop(&mut self) {
        // SAFETY: locked by `LineObj::lock` on this thread.
        unsafe { ao2::unlock(self.0) };
    }
}

impl UserObj {
    pub fn key(&self) -> &[u8] {
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
        LineObj::refresh_auth(&mut st, &auth);
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
    // Snapshot the registry: (name, pjsip_auth) of each line, and the
    // phone names.
    type Snapshot = (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>);
    let (lines, phones): Snapshot = {
        let g = users::read();
        let Some(reg) = g.as_ref() else { return };
        (
            reg.lines.values().map(|l| (l.name.clone(), l.pjsip_auth.clone())).collect(),
            reg.phones.values().map(|p| p.name.clone()).collect(),
        )
    };
    let mut swept: HashMap<Vec<u8>, Line> = swept.into_iter().map(|l| (l.name.to_ascii_lowercase(), l)).collect();

    unsafe {
        // ---- lines ----
        let want: HashMap<Vec<u8>, &[u8]> = lines.iter().map(|(n, a)| (n.to_ascii_lowercase(), a.as_slice())).collect();
        let mut have = std::collections::HashSet::new();
        for o in ao2::collect(lines_c) {
            let obj = o as *mut LineObj;
            let k = (*obj).key.to_ascii_lowercase();
            match want.get(&k) {
                Some(auth) if have.insert(k.clone()) => {
                    let mut st = lock(&(*obj).state);
                    LineObj::refresh_auth(&mut st, auth);
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
            let obj = new_line(name, auth);
            if !obj.is_null() {
                ao2::link(lines_c, obj as *mut c_void);
                ao2::cleanup(obj as *mut c_void);
            }
        }

        // ---- phones ----
        let want: std::collections::HashSet<Vec<u8>> = phones.iter().map(|n| n.to_ascii_lowercase()).collect();
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
pub fn lock_lines<'a>(names: impl IntoIterator<Item = &'a [u8]>) -> LineLocks {
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
pub fn lock_phone_lines(phone: &[u8]) -> LineLocks {
    let names: Vec<Vec<u8>> = {
        let g = users::read();
        g.as_ref()
            .and_then(|reg| reg.phones.get(phone))
            .map(|p| p.lines.iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default()
    };
    lock_lines(names.iter().map(Vec::as_slice))
}

/// Lock every line object (`lock_lines`).
pub fn lock_all_lines() -> LineLocks {
    lock_objects(unsafe { ao2::collect(lines_container()) })
}

/// A line object with a reference (dropped with the handle).
pub struct LineRef(*mut LineObj);

// SAFETY: the object is reference counted and locks its own state.
unsafe impl Send for LineRef {}

impl std::ops::Deref for LineRef {
    type Target = LineObj;
    fn deref(&self) -> &LineObj {
        // SAFETY: we hold a reference.
        unsafe { &*self.0 }
    }
}

impl Drop for LineRef {
    fn drop(&mut self) {
        // SAFETY: the reference this handle owns.
        unsafe { ao2::cleanup(self.0) };
    }
}

/// `phone_line_find(name)`: the line object named `name` (the container
/// key, case insensitive), or None (also for an empty name).
pub fn find_line(name: &std::ffi::CStr) -> Option<LineRef> {
    let c = lines_container();
    if c.is_null() || name.is_empty() {
        return None;
    }
    // SAFETY: a live container of named objects; a found object comes with
    // a reference.
    let o = unsafe { ao2::find_key(c, name.as_ptr()) } as *mut LineObj;
    (!o.is_null()).then_some(LineRef(o))
}

/// Every line object, in container order.
pub fn all_lines() -> Vec<LineRef> {
    // SAFETY: each object comes with a reference.
    unsafe { ao2::collect(lines_container()) }.into_iter().map(|o| LineRef(o as *mut LineObj)).collect()
}

/// `ao2_callback(lines, OBJ_NODATA | OBJ_MULTIPLE, cb, NULL)` on the lines
/// container: call `cb` with every line object, with the container locked
/// (nothing when the container does not exist).
///
/// # Safety
/// `cb` must take its object argument as a `LineObj` (it is called with
/// the container's own reference).
pub unsafe fn callback_all_lines(cb: ao2::CallbackFn) {
    let c = lines_container();
    if !c.is_null() {
        ao2::callback_all(c, cb, std::ptr::null_mut());
    }
}

/// `phone_users_process_line(line)`: apply the settings of the line's
/// own sections in voicemail.conf, users.conf (app_voicemail), and
/// res_digium_phone.conf again (`process_line_dp`).  As in the official
/// DPMA, each mailbox is set with its line looked up by name and locked
/// (`set_mailbox`), and the res_digium_phone.conf sections are applied
/// with this line locked; no two line locks are held at once.
pub fn process_line(line: &LineObj) {
    for (target, mailbox) in users::load::line_mailboxes(&line.key) {
        let Some(obj) = find_line(&dpma_ast::cstr(&target)) else {
            continue;
        };
        let _locked = obj.lock();
        obj.with_line(|l| options::set_line_option(l, b"mailbox", &mailbox));
    }
    let _locked = line.lock();
    line.with_line(users::load::apply_line_sections);
}

/// A phone object with a reference (dropped with the handle).
pub struct UserRef(*mut UserObj);

impl std::ops::Deref for UserRef {
    type Target = UserObj;
    fn deref(&self) -> &UserObj {
        // SAFETY: we hold a reference.
        unsafe { &*self.0 }
    }
}

impl Drop for UserRef {
    fn drop(&mut self) {
        // SAFETY: the reference this handle owns.
        unsafe { ao2::cleanup(self.0) };
    }
}

/// `phone_user_find(name)`: the phone object, or None (also for an empty
/// name).
pub fn find_user(name: &std::ffi::CStr) -> Option<UserRef> {
    let c = users_container();
    if c.is_null() || name.is_empty() {
        return None;
    }
    // SAFETY: as in `find_line`.
    let o = unsafe { ao2::find_key(c, name.as_ptr()) } as *mut UserObj;
    (!o.is_null()).then_some(UserRef(o))
}

impl UserObj {
    /// `phone_user_token_set_last_info(user, uri, session, mac)`: record
    /// where the phone was last seen (None: unchanged); nothing for a
    /// phone that is no longer configured.
    pub fn set_last_info(&self, uri: &[u8], session: Option<&[u8]>, mac: Option<&[u8]>) {
        #[cfg(feature = "devtest")]
        crate::pjsip::devtest::record_last_info(&self.key, uri, session, mac, self.is_linked());
        if self.is_linked() {
            users::runtime::set_last_info(&self.key, uri, session, mac);
        }
    }
}
