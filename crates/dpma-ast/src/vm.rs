//! Voicemail API (`ast_vm_*`): mailbox snapshots, move, remove, forward,
//! playback, and folder names.  The calls go to whichever voicemail provider is
//! registered (normally app_voicemail); without one they fail, as in C.
//!
//! Strings are passed as bytes: the callers work on fixed-size C buffers
//! and message ids that need not be UTF-8.  A string is cut at its first
//! NUL byte, as C would see it.

use crate::sys;
use crate::types::AstChannel;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

/// `ast_vm_msg_play_cb`: plays `playfile` (a path without extension) of a
/// message `duration` seconds long on `chan`.
pub type MsgPlayCb = unsafe extern "C" fn(chan: *mut AstChannel, playfile: *const c_char, duration: c_int);

/// `enum ast_vm_snapshot_sort_val`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Id = sys::AST_VM_SNAPSHOT_SORT_BY_ID as isize,
    Time = sys::AST_VM_SNAPSHOT_SORT_BY_TIME as isize,
}

/// One message of a snapshot (`struct ast_vm_msg_snapshot`), copied.
#[derive(Debug, Clone, Default)]
pub struct MsgSnapshot {
    pub msg_id: Vec<u8>,
    pub callerid: Vec<u8>,
    pub callerchan: Vec<u8>,
    pub exten: Vec<u8>,
    pub origdate: Vec<u8>,
    pub origtime: Vec<u8>,
    pub duration: Vec<u8>,
    pub folder_name: Vec<u8>,
    pub flag: Vec<u8>,
    pub msg_number: u32,
}

/// A mailbox snapshot (`struct ast_vm_mailbox_snapshot`), copied: one list
/// of messages per folder index, in the provider's order.
#[derive(Debug, Clone, Default)]
pub struct MailboxSnapshot {
    pub total_msg_num: i32,
    pub folders: Vec<Vec<MsgSnapshot>>,
}

/// A C string of `s` up to its first NUL byte.
pub fn c_bytes(s: &[u8]) -> CString {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    CString::new(&s[..end]).unwrap_or_default()
}

fn opt_c(s: Option<&[u8]>) -> Option<CString> {
    s.map(c_bytes)
}

fn opt_ptr(c: &Option<CString>) -> *const c_char {
    c.as_ref().map_or(ptr::null(), |c| c.as_ptr())
}

unsafe fn bytes_of(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        Vec::new()
    } else {
        CStr::from_ptr(p).to_bytes().to_vec()
    }
}

/// `ast_vm_mailbox_snapshot_create`: copy the snapshot and destroy it.
/// None when the provider fails (unknown mailbox or folder, no provider).
pub fn mailbox_snapshot_create(
    mailbox: &[u8],
    context: Option<&[u8]>,
    folder: Option<&[u8]>,
    descending: bool,
    sort: SortBy,
    combine_inbox_and_old: bool,
) -> Option<MailboxSnapshot> {
    let mailbox = c_bytes(mailbox);
    let context = opt_c(context);
    let folder = opt_c(folder);
    // SAFETY: the snapshot is walked (folder lists of message snapshots,
    // AST_LIST links) while it is owned here, copied, and destroyed.
    unsafe {
        let raw = sys::ast_vm_mailbox_snapshot_create(
            mailbox.as_ptr(),
            opt_ptr(&context),
            opt_ptr(&folder),
            descending as c_int,
            sort as sys::ast_vm_snapshot_sort_val,
            combine_inbox_and_old as c_int,
        );
        if raw.is_null() {
            return None;
        }
        let snapshot = &*raw;
        let count = snapshot.folders.max(0) as usize;
        let mut folders = Vec::with_capacity(count);
        for i in 0..count {
            let mut list = Vec::new();
            let mut m = if snapshot.snapshots.is_null() { ptr::null_mut() } else { (*snapshot.snapshots.add(i)).first };
            while !m.is_null() {
                let msg = &*m;
                list.push(MsgSnapshot {
                    msg_id: bytes_of(msg.msg_id),
                    callerid: bytes_of(msg.callerid),
                    callerchan: bytes_of(msg.callerchan),
                    exten: bytes_of(msg.exten),
                    origdate: bytes_of(msg.origdate),
                    origtime: bytes_of(msg.origtime),
                    duration: bytes_of(msg.duration),
                    folder_name: bytes_of(msg.folder_name),
                    flag: bytes_of(msg.flag),
                    msg_number: msg.msg_number,
                });
                m = msg.msg.next;
            }
            folders.push(list);
        }
        let total_msg_num = snapshot.total_msg_num;
        sys::ast_vm_mailbox_snapshot_destroy(raw);
        Some(MailboxSnapshot { total_msg_num, folders })
    }
}

/// Owned C strings and the pointer array the `ast_vm_msg_*` calls take.
struct CArray {
    _owned: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

impl CArray {
    fn new<T: AsRef<[u8]>>(items: &[T]) -> CArray {
        let owned: Vec<CString> = items.iter().map(|s| c_bytes(s.as_ref())).collect();
        let ptrs = owned.iter().map(|c| c.as_ptr()).collect();
        CArray { _owned: owned, ptrs }
    }
}

/// `ast_vm_msg_move`: move `ids` from `oldfolder` to `newfolder`.
/// Returns the provider's result (negative on failure).
pub fn msg_move<T: AsRef<[u8]>>(
    mailbox: &[u8],
    context: Option<&[u8]>,
    oldfolder: &[u8],
    ids: &[T],
    newfolder: &[u8],
) -> i32 {
    let (mailbox, context) = (c_bytes(mailbox), opt_c(context));
    let (oldfolder, newfolder) = (c_bytes(oldfolder), c_bytes(newfolder));
    let ids = CArray::new(ids);
    unsafe {
        sys::ast_vm_msg_move(
            mailbox.as_ptr(),
            opt_ptr(&context),
            ids.ptrs.len(),
            oldfolder.as_ptr(),
            ids.ptrs.as_ptr() as *mut *const c_char,
            newfolder.as_ptr(),
        )
    }
}

/// `ast_vm_msg_remove`: remove `ids` from `folder`.  Returns the
/// provider's result (nonzero on failure).
pub fn msg_remove<T: AsRef<[u8]>>(mailbox: &[u8], context: Option<&[u8]>, folder: &[u8], ids: &[T]) -> i32 {
    let (mailbox, context, folder) = (c_bytes(mailbox), opt_c(context), c_bytes(folder));
    let ids = CArray::new(ids);
    unsafe { sys::ast_vm_msg_remove(mailbox.as_ptr(), opt_ptr(&context), ids.ptrs.len(), folder.as_ptr(), ids.ptrs.as_ptr() as *mut *const c_char) }
}

/// `ast_vm_msg_forward`: copy `ids` from a folder of one mailbox to a
/// folder of another (`delete_old` removes the originals).  Returns the
/// provider's result (negative on failure).
#[allow(clippy::too_many_arguments)]
pub fn msg_forward<T: AsRef<[u8]>>(
    from_mailbox: &[u8],
    from_context: Option<&[u8]>,
    from_folder: &[u8],
    to_mailbox: &[u8],
    to_context: Option<&[u8]>,
    to_folder: &[u8],
    ids: &[T],
    delete_old: bool,
) -> i32 {
    let (fm, fc, ff) = (c_bytes(from_mailbox), opt_c(from_context), c_bytes(from_folder));
    let (tm, tc, tf) = (c_bytes(to_mailbox), opt_c(to_context), c_bytes(to_folder));
    let ids = CArray::new(ids);
    unsafe {
        sys::ast_vm_msg_forward(
            fm.as_ptr(),
            opt_ptr(&fc),
            ff.as_ptr(),
            tm.as_ptr(),
            opt_ptr(&tc),
            tf.as_ptr(),
            ids.ptrs.len(),
            ids.ptrs.as_ptr() as *mut *const c_char,
            delete_old as c_int,
        )
    }
}

/// `ast_vm_index_to_foldername`: the provider's name for folder `id`.
pub fn index_to_foldername(id: i32) -> Option<Vec<u8>> {
    unsafe {
        let p = sys::ast_vm_index_to_foldername(id as c_int);
        if p.is_null() {
            None
        } else {
            Some(CStr::from_ptr(p).to_bytes().to_vec())
        }
    }
}

/// `ast_vm_msg_play`: play message `msg_num` (a message id) of `folder`
/// in `mailbox@context` on `chan`, through `cb`.  Returns 0 on success.
///
/// # Safety
/// `chan` must be a live channel the caller is running on.
pub unsafe fn msg_play(
    chan: *mut AstChannel,
    mailbox: &[u8],
    context: Option<&[u8]>,
    folder: &[u8],
    msg_num: &[u8],
    cb: MsgPlayCb,
) -> i32 {
    let (mailbox, context) = (c_bytes(mailbox), opt_c(context));
    let (folder, msg_num) = (c_bytes(folder), c_bytes(msg_num));
    sys::ast_vm_msg_play(chan, mailbox.as_ptr(), opt_ptr(&context), folder.as_ptr(), msg_num.as_ptr(), Some(cb))
}
