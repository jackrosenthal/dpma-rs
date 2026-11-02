//! The scenarios, one per part, in order.

use std::time::Duration;

use anyhow::{anyhow, Result};
use bstr::ByteSlice;
use dpma_tests::harness::ConfFile;
use dpma_tests::sipua::{Answer, UaEvent, Uas, UasConfig};
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde_json::{json, Value};

use crate::model::{de, getlist_doc, inbox_ids, snapshot};
use crate::Vm;

const ORIGDATE: &str = "Sat Jan  1 12:00:00 AM UTC 2022";

/// The result of a method that only succeeds.
fn success() -> Value {
    json!({"success": {}})
}

/// The getList document with the default paging and order.
fn getlist(vm: &Vm, mbox: &str, folder: &str, shown: &str) -> (String, Vec<(String, String)>) {
    getlist_doc(&vm.spool, mbox, folder, shown, 50, 1, false, false)
}

fn first<T: Clone>(v: &[T], what: &str) -> Result<T> {
    v.first().cloned().ok_or_else(|| anyhow!("no {what}"))
}

/// A message made from the one left through `VoiceMail()`: mailbox,
/// folder, number, the extension and context `VoiceMail()` would have run
/// in, the flag, and the caller id.
type MsgCopy<'a> = (&'a str, &'a str, u32, &'a str, &'a str, &'a str, &'a [u8]);

/// Empties the test mailboxes and leaves the messages.  The first is left
/// through `VoiceMail()`; the others are copies of it, with the fields
/// that `VoiceMail()` would have written for them, each a second later
/// than the one before.
pub fn messages(vm: &mut Vm) -> Result<()> {
    for b in ["default/1001", "default/1002", "default/1003", "other/2001"] {
        vm.spool.remove(b);
    }
    let leave = "dpma-vm-leave";
    vm.leave("1001", "\"Alice Caller\" <2005551212>", leave, None)?;
    let src = first(&vm.spool.all("default/1001"), "message left")?;
    let t0: u64 = src.get("origtime").parse()?;
    let copies: [MsgCopy; 5] = [
        ("default/1001", "INBOX", 1, "1001", leave, "", b"2125551234"),
        (
            "default/1001",
            "Urgent",
            0,
            "1001",
            "dpma-vm-urgent",
            "Urgent",
            b"\"Bob Urgent\" <3035550000>",
        ),
        (
            "default/1001",
            "INBOX",
            2,
            "1001",
            leave,
            "",
            b"\"Carol\" <4045550000>",
        ),
        (
            "default/1002",
            "INBOX",
            0,
            "1002",
            leave,
            "",
            b"\"Dave\" <5055550000>",
        ),
        (
            "other/2001",
            "INBOX",
            0,
            "o2001",
            leave,
            "",
            b"\"Eve\" <6065550000>",
        ),
    ];
    for (i, (mbox, folder, num, exten, context, flag, cid)) in copies.into_iter().enumerate() {
        let n = i as u64 + 1;
        let origmailbox = exten.trim_start_matches('o');
        let callerchan = format!("Local/{exten}@{context}-{:08x};2", 0x100 + n);
        vm.spool.copy_msg(
            "default/1001",
            &src,
            mbox,
            folder,
            num,
            &[
                ("origmailbox", origmailbox.as_bytes()),
                ("context", context.as_bytes()),
                ("exten", exten.as_bytes()),
                ("callerchan", callerchan.as_bytes()),
                ("callerid", cid),
                ("origtime", (t0 + n).to_string().as_bytes()),
                ("msg_id", format!("{}-{:08x}", t0 + n, 0x100 + n).as_bytes()),
                ("flag", flag.as_bytes()),
            ],
        )?;
    }
    // Unusual caller ids, in Friends (the order of the list is by number).
    let friends: [(&str, &[u8]); 6] = [
        ("1640995200-0000f001", b"Name Only <7075550000>"),
        ("1640995201-0000f002", b"\"Unclosed <123>"),
        ("1640995202-0000f003", b"\"\""),
        ("1640995203-0000f004", b"\"Q\" 555"),
        ("1640995204-0000f005", b"<8085550000>"),
        ("1640995205-0000f006", b""),
    ];
    for (i, (id, cid)) in friends.iter().enumerate() {
        let n = i as u32;
        vm.spool.craft(
            "default/1001",
            "Friends",
            n,
            id,
            cid,
            1640995200 + u64::from(n),
            ORIGDATE,
        )?;
    }
    // A caller id that is not UTF-8 (jansson refuses it).
    vm.spool.craft(
        "default/1001",
        "Cust3",
        0,
        "1640995300-0000c301",
        b"\"Ren\xe9\" <100>",
        1640995300,
        ORIGDATE,
    )?;
    Ok(())
}

pub fn folder_list(vm: &mut Vm) -> Result<()> {
    // Translated names; Old and Urgent count in INBOX; Recordings is Cust5.
    let names = [
        ("INBOX", 0),
        ("Work", 2),
        ("Family", 3),
        ("Friends", 4),
        ("Recordings", 9),
    ];
    let snap = snapshot(&vm.spool, "default/1001", None, false, false);
    let folders: Vec<Value> = names
        .iter()
        .map(|(n, i)| json!({"name": de(n), "count": snap[*i].len().to_string()}))
        .collect();
    vm.expect_ok(
        "getFolderList translated",
        "vmphone",
        "getFolderList",
        json!({"account_id": "1001"}),
        json!({"folders": {"folder": folders}}),
    )?;
    let snap = snapshot(&vm.spool, "default/1002", None, false, false);
    let folders: Vec<Value> = names
        .iter()
        .map(|(n, i)| json!({"name": n, "count": snap[*i].len().to_string()}))
        .collect();
    vm.expect_ok(
        "getFolderList plain",
        "vmphone2",
        "getFolderList",
        json!({"account_id": "1002"}),
        json!({"folders": {"folder": folders}}),
    )?;
    let folders: Vec<Value> = names
        .iter()
        .map(|(n, i)| json!({"name": n, "count": if *i == 0 { "1" } else { "0" }}))
        .collect();
    vm.expect_ok(
        "getFolderList other context",
        "vmphone3",
        "getFolderList",
        json!({"account_id": "2001"}),
        json!({"folders": {"folder": folders}}),
    )?;
    let m = "getFolderList";
    vm.expect_error(
        "getFolderList no account_id",
        "vmphone",
        m,
        json!({}),
        10011,
        "account_id",
    )?;
    vm.expect_error(
        "getFolderList account_id not a string",
        "vmphone",
        m,
        json!({"account_id": 1001}),
        10011,
        "account_id",
    )?;
    vm.expect_error(
        "getFolderList params not an object",
        "vmphone",
        m,
        json!(["1001"]),
        10011,
        "account_id",
    )?;
    let nobox = "must have line with mailbox";
    vm.expect_error(
        "getFolderList line of another phone",
        "vmphone",
        m,
        json!({"account_id": "1002"}),
        27168,
        nobox,
    )?;
    vm.expect_error(
        "getFolderList line without mailbox",
        "vmphone",
        m,
        json!({"account_id": "1003"}),
        27168,
        nobox,
    )?;
    vm.expect_error(
        "getFolderList external line",
        "vmphone",
        m,
        json!({"account_id": "ext1"}),
        27168,
        nobox,
    )?;
    vm.expect_error(
        "getFolderList unknown phone",
        "nosuchphone",
        m,
        json!({"account_id": "1001"}),
        27168,
        nobox,
    )?;
    vm.expect_error(
        "getFolderList mailbox unknown to app_voicemail",
        "ghostphone",
        m,
        json!({"account_id": "1005"}),
        64125,
        "could not create snapshot of 1005@default",
    )?;
    Ok(())
}

pub fn get_list(vm: &mut Vm) -> Result<()> {
    let m = "getList";
    let (want, ids) = getlist(vm, "default/1001", "INBOX", "Posteingang");
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "Posteingang"}),
    )?;
    vm.c().same("getList INBOX via translated name", body, want);
    let tr = vm.trackers("vmphone")?;
    vm.c().same("getList trackers", tr, Some(ids));

    let (want, _) = getlist(vm, "default/1001", "INBOX", "Posteingang");
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "INBOX"}),
    )?;
    vm.c()
        .same("getList INBOX shows translated folder", body, want);

    let (want, _) = getlist_doc(
        &vm.spool,
        "default/1001",
        "INBOX",
        "Posteingang",
        50,
        1,
        true,
        true,
    );
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "INBOX", "sort_order": "desc", "sort_field": "DATE"}),
    )?;
    vm.c().same("getList INBOX newest first", body, want);

    let (want, _) = getlist_doc(
        &vm.spool,
        "default/1001",
        "INBOX",
        "Posteingang",
        50,
        1,
        true,
        false,
    );
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "INBOX", "sort_order": "DESC"}),
    )?;
    vm.c().same("getList INBOX by id descending", body, want);

    let (want, ids) = getlist_doc(
        &vm.spool,
        "default/1001",
        "INBOX",
        "Posteingang",
        3,
        2,
        false,
        false,
    );
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "INBOX", "items_per_page": 3, "page_number": " 2xyz"}),
    )?;
    vm.c().same("getList page 2 of 3 per page", body, want);
    let tr = vm.trackers("vmphone")?;
    vm.c()
        .same("getList trackers hold only the page", tr, Some(ids));

    let (want, _) = getlist_doc(
        &vm.spool,
        "default/1001",
        "INBOX",
        "Posteingang",
        2,
        1,
        false,
        false,
    );
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "INBOX", "items_per_page": 2, "page_number": 2}),
    )?;
    vm.c()
        .same("getList integer page_number is ignored", body, want);

    let (want, _) = getlist_doc(
        &vm.spool,
        "default/1001",
        "INBOX",
        "Posteingang",
        -1,
        3,
        false,
        false,
    );
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "INBOX", "items_per_page": -1, "page_number": "3"}),
    )?;
    vm.c().same("getList negative items_per_page", body, want);

    let (want, _) = getlist(vm, "default/1001", "Friends", "Friends");
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "Friends"}),
    )?;
    vm.c().same("getList caller id forms", body, want);

    let (want, _) = getlist(vm, "default/1001", "Recordings", "Aufnahmen");
    let (_, body) = vm.call(
        "vmphone",
        m,
        &json!({"account_id": "1001", "folder": "Aufnahmen"}),
    )?;
    vm.c()
        .same("getList Recordings (empty) via translation", body, want);

    let (_, body) = vm.call(
        "vmphone2",
        m,
        &json!({"account_id": "1002", "folder": "INBOX"}),
    )?;
    let (want, _) = getlist(vm, "default/1002", "INBOX", "INBOX");
    vm.c().same("getList without translation", body, want);

    vm.expect_error(
        "getList bad folder",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder": "Bogus"}),
        64125,
        "could not create snapshot of 1001@default Bogus",
    )?;
    vm.expect_error(
        "getList Recordings maps to Cust5 in the error",
        "ghostphone",
        m,
        json!({"account_id": "1005", "folder": "Recordings"}),
        64125,
        "could not create snapshot of 1005@default Cust5",
    )?;
    vm.expect_error(
        "getList non-UTF-8 caller id",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder": "Cust3"}),
        10002,
        "message_entry",
    )?;
    vm.expect_error(
        "getList no account_id",
        "vmphone",
        m,
        json!({"folder": "INBOX"}),
        10011,
        "account_id",
    )?;
    vm.expect_error(
        "getList no mailbox",
        "nomboxphone",
        m,
        json!({"account_id": "1004", "folder": "INBOX"}),
        27168,
        "must have line with mailbox",
    )?;
    // Deviations (the official DPMA crashes): no folder, zero
    // items_per_page.
    vm.expect_error(
        "getList no folder (deviation)",
        "vmphone",
        m,
        json!({"account_id": "1001"}),
        10011,
        "folder",
    )?;
    vm.expect_error(
        "getList items_per_page 0 (deviation)",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder": "INBOX", "items_per_page": 0}),
        10011,
        "items_per_page",
    )?;
    vm.expect_error(
        "getList items_per_page string (deviation)",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder": "INBOX", "items_per_page": "10"}),
        10011,
        "items_per_page",
    )?;
    Ok(())
}

/// Whether `id` is in a folder of a mailbox.
fn in_folder(vm: &Vm, mbox: &str, folder: &str, id: &str) -> bool {
    vm.spool.folder_ids(mbox, folder).iter().any(|x| x == id)
}

pub fn mark(vm: &mut Vm) -> Result<()> {
    let b = "default/1001";
    vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "INBOX"}),
    )?;
    let msgs = inbox_ids(&vm.spool, b);
    let plain: Vec<_> = msgs.iter().filter(|x| x.2 == "INBOX").cloned().collect();
    let urgent = first(
        &msgs
            .iter()
            .filter(|x| x.2 == "Urgent")
            .cloned()
            .collect::<Vec<_>>(),
        "urgent message",
    )?;
    let first_ = first(&plain, "INBOX message")?;

    vm.expect_ok(
        "markRead",
        "vmphone",
        "markRead",
        json!({"account_id": "1001", "message_ids": [first_.0, 7, null]}),
        success(),
    )?;
    let ok = in_folder(vm, b, "Old", &first_.1);
    vm.c().same("markRead moved the message to Old", ok, true);
    let tr = vm.tracker("vmphone", &first_.0)?;
    vm.c()
        .same("markRead updated the tracker", tr, Some("Old".into()));
    vm.expect_ok(
        "markRead again (already Old)",
        "vmphone",
        "markRead",
        json!({"account_id": "1001", "message_ids": [first_.0]}),
        success(),
    )?;
    vm.expect_ok(
        "markUnread",
        "vmphone",
        "markUnread",
        json!({"account_id": "1001", "message_ids": [first_.0]}),
        success(),
    )?;
    let ok = in_folder(vm, b, "INBOX", &first_.1);
    vm.c().same("markUnread moved it back", ok, true);
    let tr = vm.tracker("vmphone", &first_.0)?;
    vm.c()
        .same("markUnread updated the tracker", tr, Some("INBOX".into()));

    vm.expect_ok(
        "markRead an Urgent message",
        "vmphone",
        "markRead",
        json!({"account_id": "1001", "message_ids": [urgent.0]}),
        success(),
    )?;
    let ok = in_folder(vm, b, "Old", &urgent.1);
    vm.c().same("Urgent message is now Old", ok, true);

    // An id with the translated folder name: tracker made from a snapshot.
    let second = plain
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow!("no second INBOX message"))?;
    let alias = format!("Posteingang-{}", second.1);
    vm.expect_ok(
        "markRead with a translated folder in the id",
        "vmphone",
        "markRead",
        json!({"account_id": "1001", "message_ids": [alias]}),
        success(),
    )?;
    let ok = in_folder(vm, b, "Old", &second.1);
    vm.c().same("translated id moved", ok, true);
    let tr = vm.tracker("vmphone", &alias)?;
    vm.c()
        .same("tracker for the translated id", tr, Some("Old".into()));
    vm.expect_ok(
        "markUnread with a translated folder in the id",
        "vmphone",
        "markUnread",
        json!({"account_id": "1001", "message_ids": [alias]}),
        success(),
    )?;

    let friends = first(&vm.spool.folder_ids(b, "Friends"), "Friends message")?;
    let mark = vm.log_mark();
    vm.expect_ok(
        "markRead on Friends is refused but succeeds",
        "vmphone",
        "markRead",
        json!({"account_id": "1001", "message_ids": [format!("Friends-{friends}")]}),
        success(),
    )?;
    let want = "Attempted to mark read/unread on Friends folder";
    let log = vm.log_since(mark, want);
    vm.c().contains("markRead on Friends logs", &log, &[want]);
    let ok = in_folder(vm, b, "Friends", &friends);
    vm.c().same("Friends message not moved", ok, true);

    let m = "markRead";
    vm.expect_error(
        "markRead unknown message",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_ids": ["INBOX-1-2"]}),
        10002,
        "failed to find message",
    )?;
    let third = plain
        .get(2)
        .cloned()
        .ok_or_else(|| anyhow!("no third INBOX message"))?;
    vm.expect_error(
        "markRead lower-case folder does not match",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_ids": [format!("inbox-{}", third.1)]}),
        10002,
        "failed to find message",
    )?;
    vm.expect_error(
        "markRead id without dash",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_ids": ["INBOX"]}),
        10011,
        "message id",
    )?;
    vm.expect_error(
        "markRead id ending in dash",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_ids": ["INBOX-"]}),
        10011,
        "message id",
    )?;
    vm.expect_error(
        "markRead empty list",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_ids": []}),
        10011,
        "total_msgs",
    )?;
    vm.expect_error(
        "markRead string instead of list",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_ids": first_.0}),
        10011,
        "total_msgs",
    )?;
    vm.expect_error(
        "markRead no message_ids",
        "vmphone",
        m,
        json!({"account_id": "1001"}),
        10011,
        "message_ids",
    )?;
    vm.expect_error(
        "markUnread no account_id",
        "vmphone",
        "markUnread",
        json!({"message_ids": []}),
        10011,
        "account_id",
    )?;
    vm.expect_error(
        "markRead null message_ids, no line",
        "nomboxphone",
        m,
        json!({"account_id": "1004", "message_ids": null}),
        27168,
        "must have line with mailbox",
    )?;
    Ok(())
}

/// A move response: each id with its old id.
fn moved(ids: &[String]) -> Value {
    let msgs: Vec<Value> = ids.iter().map(|i| json!({"id": i, "old_id": i})).collect();
    json!({"messages": {"message": msgs}})
}

pub fn move_(vm: &mut Vm) -> Result<()> {
    let b = "default/1001";
    let m = "move";
    vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "INBOX"}),
    )?;
    let msgs: Vec<_> = inbox_ids(&vm.spool, b)
        .into_iter()
        .filter(|x| x.2 == "INBOX")
        .collect();
    if msgs.len() < 2 {
        return Err(anyhow!("fewer than 2 INBOX messages"));
    }
    let (a, bb) = (msgs[0].clone(), msgs[1].clone());
    // Two messages to Work (translated as Arbeit).  The response ids come
    // from the official DPMA's reused buffer: the first gets the folder of
    // the last id parsed, the rest "(null)".
    vm.expect_ok(
        "move two to Arbeit",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "Posteingang", "folder_to": "Arbeit",
               "message_ids": [a.0, bb.0]}),
        json!({"messages": {"message": [
            {"id": format!("INBOX-{}", a.1), "old_id": format!("INBOX-{}", a.1)},
            {"id": format!("(null)-{}", bb.1), "old_id": format!("(null)-{}", bb.1)}]}}),
    )?;
    let mut work = vm.spool.folder_ids(b, "Work");
    work.sort();
    let mut want = vec![a.1.clone(), bb.1.clone()];
    want.sort();
    vm.c().same("move: both in Work", work, want);
    let tr = vm.tracker("vmphone", &a.0)?;
    vm.c()
        .same("move leaves trackers alone", tr, Some("INBOX".into()));

    // Stale trackers: the same ids now fail to move from INBOX.
    let mark = vm.log_mark();
    vm.expect_error(
        "move with stale trackers",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX", "folder_to": "Family", "message_ids": [a.0]}),
        10011,
        "could not move message",
    )?;
    let want = "Could not move msgs from INBOX to Family";
    let log = vm.log_since(mark, want);
    vm.c().contains("move failure logs", &log, &[want]);

    // getList of Work, then move one to Recordings (Cust5).
    vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "Arbeit"}),
    )?;
    vm.expect_ok(
        "move to Recordings",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "Work", "folder_to": "Recordings",
               "message_ids": [format!("Work-{}", a.1)]}),
        moved(&[format!("Work-{}", a.1)]),
    )?;
    let ok = in_folder(vm, b, "Cust5", &a.1);
    vm.c().same("move: in Cust5", ok, true);
    let (_, body) = vm.call("vmphone", "getFolderList", &json!({"account_id": "1001"}))?;
    let ok = body.contains(r#"{"name":"Aufnahmen","count":"1"}"#);
    vm.c().same("getFolderList counts the recording", ok, true);
    let (want, _) = getlist(vm, b, "Recordings", "Aufnahmen");
    let (_, body) = vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "Aufnahmen"}),
    )?;
    vm.c().same("getList Recordings", body, want);
    // "Recordings" is not a folder name, so the rebuilt id gets "(null)".
    vm.expect_ok(
        "move Recordings back to INBOX",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "Aufnahmen", "folder_to": "INBOX",
               "message_ids": [format!("Recordings-{}", a.1)]}),
        moved(&[format!("(null)-{}", a.1)]),
    )?;
    vm.expect_ok(
        "move Work back to INBOX",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "Work", "folder_to": "INBOX",
               "message_ids": [format!("Work-{}", bb.1)]}),
        moved(&[format!("Work-{}", bb.1)]),
    )?;
    let work = vm.spool.folder_ids(b, "Work");
    vm.c()
        .same("move: Work empty again", work, Vec::<String>::new());

    vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "INBOX"}),
    )?;
    let c = first(
        &inbox_ids(&vm.spool, b)
            .into_iter()
            .filter(|x| x.2 == "INBOX")
            .collect::<Vec<_>>(),
        "INBOX message",
    )?;
    vm.expect_error(
        "move to an unknown folder",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX", "folder_to": "Bogus", "message_ids": [c.0]}),
        10011,
        "could not move message",
    )?;
    let mark = vm.log_mark();
    vm.expect_error(
        "move id without dash",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": ["xyz"]}),
        10011,
        "id decode",
    )?;
    let want = "ERROR decoding message id xyz";
    let log = vm.log_since(mark, want);
    vm.c().contains("move decode error logs", &log, &[want]);
    vm.expect_error(
        "move unknown message",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": ["Work-1-2"]}),
        10002,
        "failed to find message",
    )?;
    vm.expect_error(
        "move no folder_from",
        "vmphone",
        m,
        json!({"account_id": "1001"}),
        10011,
        "folder_from",
    )?;
    vm.expect_error(
        "move no folder_to",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX"}),
        10011,
        "folder_to",
    )?;
    vm.expect_error(
        "move no message_ids",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work"}),
        10011,
        "message_ids",
    )?;
    vm.expect_error(
        "move empty list",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": []}),
        10011,
        "total_msgs",
    )?;
    vm.expect_error(
        "move line of another phone",
        "vmphone",
        m,
        json!({"account_id": "1002", "folder_from": "INBOX", "folder_to": "Work", "message_ids": []}),
        27168,
        "must have line with mailbox",
    )?;
    vm.expect_ok(
        "move list of non-strings",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": [1, {}]}),
        json!({"messages": {"message": []}}),
    )?;
    Ok(())
}

pub fn forward(vm: &mut Vm) -> Result<()> {
    let m = "forward";
    vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "INBOX"}),
    )?;
    let src = first(
        &inbox_ids(&vm.spool, "default/1001")
            .into_iter()
            .filter(|x| x.2 == "INBOX")
            .collect::<Vec<_>>(),
        "INBOX message",
    )?;
    let before = vm.spool.folder_ids("default/1002", "INBOX").len();
    vm.expect_ok(
        "forward to another phone's line",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "1002", "folder": "INBOX", "message_ids": [src.0]}),
        success(),
    )?;
    let after = vm
        .spool
        .read("default/1002")
        .remove("INBOX")
        .unwrap_or_default();
    vm.c()
        .same("forward: copy in 1002", after.len(), before + 1);
    let ok = in_folder(vm, "default/1001", "INBOX", &src.1);
    vm.c().same("forward: original stays", ok, true);
    let copy = after.last().map(|m| m.get("callerid").to_string());
    let orig = vm
        .spool
        .read("default/1001")
        .remove("INBOX")
        .unwrap_or_default()
        .into_iter()
        .rev()
        .find(|m| m.msg_id() == src.1)
        .map(|m| m.get("callerid").to_string());
    vm.c().same("forward: copy has the caller id", copy, orig);
    vm.expect_ok(
        "forward across contexts",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "2001", "folder": "x", "message_ids": [src.0]}),
        success(),
    )?;
    let n = vm.spool.folder_ids("other/2001", "INBOX").len();
    vm.c().same("forward: copy in other/2001", n, 2);
    vm.expect_error(
        "forward to a line without mailbox",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "1003", "folder": "INBOX", "message_ids": [src.0]}),
        27168,
        "to_mailbox",
    )?;
    vm.expect_error(
        "forward to an unknown line",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "nosuch", "folder": "INBOX", "message_ids": [src.0]}),
        27168,
        "to_mailbox",
    )?;
    let mark = vm.log_mark();
    vm.expect_error(
        "forward to a mailbox app_voicemail does not know",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "1005", "folder": "INBOX", "message_ids": [src.0]}),
        10011,
        "could not forward message",
    )?;
    let want = "Could not forward msgs from 1001@default to 1005@default";
    let log = vm.log_since(mark, want);
    vm.c().contains("forward failure logs", &log, &[want]);
    vm.expect_error(
        "forward from a line of another phone",
        "vmphone",
        m,
        json!({"account_from": "1002", "account_to": "1001", "folder": "INBOX", "message_ids": []}),
        27168,
        "must have line with mailbox",
    )?;
    vm.expect_error(
        "forward no account_from",
        "vmphone",
        m,
        json!({}),
        10011,
        "account_from",
    )?;
    vm.expect_error(
        "forward no account_to",
        "vmphone",
        m,
        json!({"account_from": "1001"}),
        10011,
        "account_to",
    )?;
    vm.expect_error(
        "forward no folder",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "1002"}),
        10011,
        "folder",
    )?;
    vm.expect_error(
        "forward no message_ids",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "1002", "folder": "INBOX"}),
        10011,
        "message_ids",
    )?;
    vm.expect_error(
        "forward bad id",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "1002", "folder": "INBOX", "message_ids": ["-"]}),
        10011,
        "message id",
    )?;
    vm.expect_error(
        "forward empty list",
        "vmphone",
        m,
        json!({"account_from": "1001", "account_to": "1002", "folder": "INBOX", "message_ids": []}),
        10011,
        "total_msgs",
    )?;
    Ok(())
}

pub fn remove(vm: &mut Vm) -> Result<()> {
    let m = "remove";
    vm.call(
        "vmphone2",
        "getList",
        &json!({"account_id": "1002", "folder": "INBOX"}),
    )?;
    let ids = inbox_ids(&vm.spool, "default/1002");
    let id0 = first(&ids, "INBOX message of 1002")?;
    vm.expect_ok(
        "remove",
        "vmphone2",
        m,
        json!({"account_id": "1002", "folder": "INBOX", "message_ids": [id0.0]}),
        success(),
    )?;
    let gone = in_folder(vm, "default/1002", "INBOX", &id0.1);
    vm.c().same("remove: gone from the spool", gone, false);
    let nums: Vec<u32> = vm
        .spool
        .read("default/1002")
        .remove("INBOX")
        .unwrap_or_default()
        .iter()
        .map(|m| m.number)
        .collect();
    let want: Vec<u32> = (0..ids.len() as u32 - 1).collect();
    vm.c().same("remove: messages renumbered", nums, want);
    vm.expect_error(
        "remove again (stale tracker)",
        "vmphone2",
        m,
        json!({"account_id": "1002", "folder": "INBOX", "message_ids": [id0.0]}),
        10011,
        "could not remove message",
    )?;
    vm.expect_error(
        "remove unknown",
        "vmphone2",
        m,
        json!({"account_id": "1002", "folder": "INBOX", "message_ids": ["INBOX-9-9"]}),
        10002,
        "failed to find message",
    )?;
    vm.expect_error(
        "remove no folder",
        "vmphone2",
        m,
        json!({"account_id": "1002", "message_ids": []}),
        10011,
        "folder",
    )?;
    vm.expect_error(
        "remove no message_ids",
        "vmphone2",
        m,
        json!({"account_id": "1002", "folder": "INBOX"}),
        10011,
        "message_ids",
    )?;
    vm.expect_error(
        "remove empty list",
        "vmphone2",
        m,
        json!({"account_id": "1002", "folder": "INBOX", "message_ids": []}),
        10011,
        "total_msgs",
    )?;
    vm.expect_error(
        "remove bad id",
        "vmphone2",
        m,
        json!({"account_id": "1002", "folder": "INBOX", "message_ids": ["INBOX-"]}),
        10011,
        "message id",
    )?;
    vm.expect_error(
        "remove no account_id",
        "vmphone2",
        m,
        json!({}),
        10011,
        "account_id",
    )?;
    // Remove from Friends by id only (the folder parameter is only logged).
    let f = vm.spool.folder_ids("default/1001", "Friends");
    let last = f
        .last()
        .cloned()
        .ok_or_else(|| anyhow!("no Friends message"))?;
    vm.expect_ok(
        "remove ignores the folder parameter",
        "vmphone",
        m,
        json!({"account_id": "1001", "folder": "Familie", "message_ids": [format!("Friends-{last}")]}),
        success(),
    )?;
    let still = in_folder(vm, "default/1001", "Friends", &last);
    vm.c().same("remove: Friends message gone", still, false);
    Ok(())
}

/// Starts the test phone (endpoint 1001) for `secs` seconds and waits for
/// its registration; returns it and its first event (`registered`).
fn run_uas(vm: &Vm, secs: u64, answer: Answer, dtmf: &str) -> Result<(Uas, String)> {
    let mut cfg = UasConfig::new("1001", "secret1001", Duration::from_secs(secs));
    cfg.answer = answer;
    cfg.dtmf = dtmf.into();
    let mut uas = Uas::spawn("127.0.0.1", vm.inst().sip_port, cfg)?;
    let first = match uas.next(Duration::from_secs(15)) {
        Some(e) if e.is_registered() => "registered".to_string(),
        Some(e) => format!("{e:?}"),
        None => "(nothing)".into(),
    };
    Ok((uas, first))
}

/// The lines for DTMF keys sent and INFOs received.
fn key_lines(events: &[UaEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            UaEvent::Dtmf(k) => Some(format!("dtmf {k}")),
            UaEvent::Info(m) => Some(format!(
                "info X-Event-Name={} body={}",
                m.get_str("X-Event-Name").unwrap_or_else(|| "-".into()),
                m.body.to_str_lossy()
            )),
            _ => None,
        })
        .collect()
}

pub fn play(vm: &mut Vm) -> Result<()> {
    let m = "play";
    vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "INBOX"}),
    )?;
    let msg = first(
        &inbox_ids(&vm.spool, "default/1001")
            .into_iter()
            .filter(|x| x.2 == "INBOX")
            .collect::<Vec<_>>(),
        "INBOX message",
    )?;
    vm.cli("core set verbose 3")?; // for file.c's "Playing" line
    let (mut uas, first_) = run_uas(vm, 10, Answer::All, "#*")?;
    vm.c().same("UAS registered", first_.as_str(), "registered");
    let mark = vm.log_mark();
    vm.expect_ok(
        "play",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_id": msg.0}),
        success(),
    )?;
    // The message plays to its end, then the call is hung up.
    uas.wait_for(Duration::from_secs(10), |e| matches!(e, UaEvent::Bye(_)));
    let events = uas.stop();
    vm.cli("core set verbose 0")?;
    let invite = events.iter().any(|e| {
        matches!(e, UaEvent::Invite(_, m, _)
            if m.get("X-Event-Name").is_some_and(|v| v == "digium.incomingCall.voicemail"))
    });
    vm.c()
        .same("play: INVITE carries the event header", invite, true);
    let answered = events
        .iter()
        .any(|e| matches!(e, UaEvent::Invite(_, _, "answered")));
    let bye = events.iter().any(|e| matches!(e, UaEvent::Bye(_)));
    vm.c().same(
        "play: answered, then hung up",
        [answered, bye],
        [true, true],
    );
    let playing = format!("Playing '{}/default/1001/INBOX/msg", vm.spool.dir.display());
    let log = vm.log_since(mark, &playing);
    // DigiumVoicemailPlayback plays the message with # and * as fast
    // forward and rewind, and reports each new position with an INFO.
    vm.c().lacks(
        "play: DigiumVoicemailPlayback runs on answer",
        &log,
        &["Could not find application (DigiumVoicemailPlayback)"],
    );
    vm.c().contains("play: plays the message", &log, &[playing]);
    let keys = key_lines(&events);
    let dtmf: Vec<&str> = keys
        .iter()
        .filter(|x| x.starts_with("dtmf "))
        .map(String::as_str)
        .collect();
    vm.c().same(
        "play: fast forward and rewind keys sent",
        dtmf,
        vec!["dtmf #", "dtmf *"],
    );
    let re = Regex::new(
        r"\Ainfo X-Event-Name=digium\.voicemail\.play\.location\.change body=\{'location':\d+\}\z",
    )
    .expect("regex");
    let infos: Vec<bool> = keys
        .iter()
        .filter(|x| x.starts_with("info "))
        .map(|x| re.is_match(x))
        .collect();
    vm.c().check_with(
        "play: a location INFO for each key",
        infos == [true, true],
        || format!("got:  {infos:?}\nwant: [true, true]\nlines: {keys:?}"),
    );

    let (uas, _) = run_uas(vm, 10, Answer::Reject, "")?;
    let mark = vm.log_mark();
    vm.expect_ok(
        "play, phone busy",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_id": msg.0}),
        success(),
    )?;
    let want = format!(
        "for DigiumVoicemailPlayback,1001@default,INBOX,{} was not answered",
        msg.1
    );
    let log = vm.log_since(mark, &want);
    uas.stop();
    vm.c()
        .contains("play, busy: logged as not answered", &log, &[want]);

    let mark = vm.log_mark();
    vm.expect_error(
        "play, phone not registered",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_id": msg.0}),
        10012,
        "channel could not run",
    )?;
    let want = "Failed dialing to PJSIP/1001 (prerun)";
    let log = vm.log_since(mark, want);
    vm.c().contains("play prerun failure logs", &log, &[want]);
    vm.expect_error(
        "play Recordings id is not mapped",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_id": format!("Recordings-{}", msg.1)}),
        10002,
        "failed to find message",
    )?;
    vm.expect_error(
        "play bad id",
        "vmphone",
        m,
        json!({"account_id": "1001", "message_id": "INBOX"}),
        10011,
        "msg_id_decode",
    )?;
    vm.expect_error(
        "play no message_id",
        "vmphone",
        m,
        json!({"account_id": "1001"}),
        10011,
        "message_id",
    )?;
    vm.expect_error(
        "play no account_id",
        "vmphone",
        m,
        json!({}),
        10011,
        "account_id",
    )?;
    vm.expect_error(
        "play not own line",
        "vmphone",
        m,
        json!({"account_id": "1002", "message_id": msg.0}),
        27168,
        "must have line with mailbox",
    )?;
    Ok(())
}

pub fn tracker_lifecycle(vm: &mut Vm) -> Result<()> {
    vm.call(
        "vmphone3",
        "getList",
        &json!({"account_id": "2001", "folder": "INBOX"}),
    )?;
    let tr = vm.trackers("vmphone3")?;
    vm.c().same(
        "vmphone3 has trackers",
        tr.as_ref().is_some_and(|t| t.len() == 2),
        true,
    );
    let conf = ConfFile::new(&vm.inst().conf("res_digium_phone.conf"));
    let backup = conf.backup()?;
    let text = conf.read()?;
    let re = BytesRegex::new(
        r"\n; A mailbox in another voicemail context\.\n\[vmphone3\]\n(?:[^\[\n].*\n)*",
    )
    .expect("regex");
    conf.write(re.replace_all(&text, &b"\n"[..]))?;
    let result = (|| -> Result<()> {
        vm.cli("module reload res_dpma_rs.so")?;
        let tr = vm.trackers("vmphone3")?;
        vm.c().same("tracker removed with its phone", tr, None);
        let tr = vm.trackers("vmphone")?;
        vm.c().same("other trackers kept", tr.is_some(), true);
        Ok(())
    })();
    backup.restore()?;
    vm.cli("module reload res_dpma_rs.so")?;
    result?;
    vm.cli("dpmadev vm forget vmphone")?;
    let tr = vm.trackers("vmphone")?;
    vm.c().same("dpmadev vm forget", tr, None);
    // A new session for the phone (phone_user_token_set_last_info,
    // through a TokenRequest after a new handshake) drops its trackers.
    vm.start_phone()?;
    vm.call(
        "vmphone",
        "getList",
        &json!({"account_id": "1001", "folder": "INBOX"}),
    )?;
    let tr = vm.trackers("vmphone")?;
    vm.c()
        .same("trackers before a new session", tr.is_some(), true);
    vm.start_phone()?;
    let tr = vm.trackers("vmphone")?;
    vm.c()
        .same("a new session drops the phone's trackers", tr, None);
    Ok(())
}

/// 55 messages: getList pages of 50; the first page also as the phone
/// asks for it (a reply of many chunks).
pub fn big_list(vm: &mut Vm) -> Result<()> {
    let result = (|| -> Result<()> {
        for i in 0..55u32 {
            vm.spool.craft(
                "default/1001",
                "Cust2",
                i,
                &format!("1641000000-0000b{i:03}"),
                format!("\"Big {i}\" <{}>", 9000 + i).as_bytes(),
                1641000000 + u64::from(i),
                ORIGDATE,
            )?;
        }
        for page in [1, 2] {
            let (want, ids) = getlist_doc(
                &vm.spool,
                "default/1001",
                "Cust2",
                "Cust2",
                50,
                page,
                false,
                false,
            );
            let (_, body) = vm.call(
                "vmphone",
                "getList",
                &json!({"account_id": "1001", "folder": "Cust2", "page_number": page.to_string()}),
            )?;
            vm.c()
                .same(format!("getList 55 messages, page {page}"), body, want);
            let tr = vm.trackers("vmphone")?;
            vm.c().same(
                format!("getList 55 messages, page {page} trackers"),
                tr,
                Some(ids),
            );
        }
        let (want, _) = getlist_doc(
            &vm.spool,
            "default/1001",
            "Cust2",
            "Cust2",
            50,
            1,
            false,
            false,
        );
        let (body, chunks) = vm.call_phone(
            "getList",
            &json!({"account_id": "1001", "folder": "Cust2", "page_number": "1"}),
        )?;
        vm.c()
            .same("getList 55 messages, page 1 through the phone", body, want);
        vm.c().check(
            "getList 55 messages, page 1 through the phone: many chunks",
            chunks > 10,
            format!("{chunks} chunks"),
        );
        Ok(())
    })();
    vm.spool.remove("default/1001/Cust2");
    result
}
