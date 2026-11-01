//! Voicemail API (`ast_vm_*`): mailbox snapshots, move, remove, forward,
//! playback, and folder names.  The calls go to whichever voicemail provider is
//! registered (normally app_voicemail); without one they fail, as in C.
//!
//! Strings are passed as bytes: the callers work on fixed-size C buffers
//! and message ids that need not be UTF-8.  A string is cut at its first
//! NUL byte, as C would see it.  The snapshot walk is in `glue/vm.c`.

use crate::types::AstChannel;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

/// `ast_vm_msg_play_cb`: plays `playfile` (a path without extension) of a
/// message `duration` seconds long on `chan`.
pub type MsgPlayCb = unsafe extern "C" fn(chan: *mut AstChannel, playfile: *const c_char, duration: c_int);

/// Opaque `struct ast_vm_mailbox_snapshot`.
#[repr(C)]
struct RawMailboxSnapshot {
    _private: [u8; 0],
}

/// Opaque `struct ast_vm_msg_snapshot`.
#[repr(C)]
struct RawMsgSnapshot {
    _private: [u8; 0],
}

extern "C" {
    fn ast_vm_mailbox_snapshot_create(
        mailbox: *const c_char,
        context: *const c_char,
        folder: *const c_char,
        descending: c_int,
        sort_val: c_int,
        combine_inbox_and_old: c_int,
    ) -> *mut RawMailboxSnapshot;
    fn ast_vm_mailbox_snapshot_destroy(snapshot: *mut RawMailboxSnapshot) -> *mut RawMailboxSnapshot;
    fn ast_vm_msg_move(
        mailbox: *const c_char,
        context: *const c_char,
        num_msgs: usize,
        oldfolder: *const c_char,
        old_msg_ids: *const *const c_char,
        newfolder: *const c_char,
    ) -> c_int;
    fn ast_vm_msg_remove(
        mailbox: *const c_char,
        context: *const c_char,
        num_msgs: usize,
        folder: *const c_char,
        msgs: *const *const c_char,
    ) -> c_int;
    fn ast_vm_msg_forward(
        from_mailbox: *const c_char,
        from_context: *const c_char,
        from_folder: *const c_char,
        to_mailbox: *const c_char,
        to_context: *const c_char,
        to_folder: *const c_char,
        num_msgs: usize,
        msg_ids: *const *const c_char,
        delete_old: c_int,
    ) -> c_int;
    fn ast_vm_index_to_foldername(id: c_int) -> *const c_char;
    fn ast_vm_msg_play(
        chan: *mut AstChannel,
        mailbox: *const c_char,
        context: *const c_char,
        folder: *const c_char,
        msg_num: *const c_char,
        cb: Option<MsgPlayCb>,
    ) -> c_int;

    fn dpma_glue_vm_snapshot_total(snapshot: *const RawMailboxSnapshot) -> c_int;
    fn dpma_glue_vm_snapshot_folders(snapshot: *const RawMailboxSnapshot) -> c_int;
    fn dpma_glue_vm_snapshot_first(snapshot: *const RawMailboxSnapshot, index: c_int) -> *const RawMsgSnapshot;
    fn dpma_glue_vm_msg_next(msg: *const RawMsgSnapshot) -> *const RawMsgSnapshot;
    fn dpma_glue_vm_msg_fields(msg: *const RawMsgSnapshot, fields: *mut *const c_char) -> c_uint;
}

/// `enum ast_vm_snapshot_sort_val`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Id = 0,
    Time = 1,
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
    unsafe {
        let raw = ast_vm_mailbox_snapshot_create(
            mailbox.as_ptr(),
            opt_ptr(&context),
            opt_ptr(&folder),
            descending as c_int,
            sort as c_int,
            combine_inbox_and_old as c_int,
        );
        if raw.is_null() {
            return None;
        }
        let total_msg_num = dpma_glue_vm_snapshot_total(raw);
        let count = dpma_glue_vm_snapshot_folders(raw).max(0);
        let mut folders = Vec::with_capacity(count as usize);
        for i in 0..count {
            let mut list = Vec::new();
            let mut m = dpma_glue_vm_snapshot_first(raw, i);
            while !m.is_null() {
                let mut f: [*const c_char; 9] = [ptr::null(); 9];
                let msg_number = dpma_glue_vm_msg_fields(m, f.as_mut_ptr());
                list.push(MsgSnapshot {
                    msg_id: bytes_of(f[0]),
                    callerid: bytes_of(f[1]),
                    callerchan: bytes_of(f[2]),
                    exten: bytes_of(f[3]),
                    origdate: bytes_of(f[4]),
                    origtime: bytes_of(f[5]),
                    duration: bytes_of(f[6]),
                    folder_name: bytes_of(f[7]),
                    flag: bytes_of(f[8]),
                    msg_number,
                });
                m = dpma_glue_vm_msg_next(m);
            }
            folders.push(list);
        }
        ast_vm_mailbox_snapshot_destroy(raw);
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
        ast_vm_msg_move(
            mailbox.as_ptr(),
            opt_ptr(&context),
            ids.ptrs.len(),
            oldfolder.as_ptr(),
            ids.ptrs.as_ptr(),
            newfolder.as_ptr(),
        )
    }
}

/// `ast_vm_msg_remove`: remove `ids` from `folder`.  Returns the
/// provider's result (nonzero on failure).
pub fn msg_remove<T: AsRef<[u8]>>(mailbox: &[u8], context: Option<&[u8]>, folder: &[u8], ids: &[T]) -> i32 {
    let (mailbox, context, folder) = (c_bytes(mailbox), opt_c(context), c_bytes(folder));
    let ids = CArray::new(ids);
    unsafe { ast_vm_msg_remove(mailbox.as_ptr(), opt_ptr(&context), ids.ptrs.len(), folder.as_ptr(), ids.ptrs.as_ptr()) }
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
        ast_vm_msg_forward(
            fm.as_ptr(),
            opt_ptr(&fc),
            ff.as_ptr(),
            tm.as_ptr(),
            opt_ptr(&tc),
            tf.as_ptr(),
            ids.ptrs.len(),
            ids.ptrs.as_ptr(),
            delete_old as c_int,
        )
    }
}

/// `ast_vm_index_to_foldername`: the provider's name for folder `id`.
pub fn index_to_foldername(id: i32) -> Option<Vec<u8>> {
    unsafe {
        let p = ast_vm_index_to_foldername(id as c_int);
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
    ast_vm_msg_play(chan, mailbox.as_ptr(), opt_ptr(&context), folder.as_ptr(), msg_num.as_ptr(), Some(cb))
}
