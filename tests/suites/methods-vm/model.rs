//! A model of the decompile: the documents the official DPMA builds from
//! the spool (app_voicemail's mailbox snapshots, getList's caller id
//! parsing and paging), and the response documents.

use std::cmp::Ordering;

use dpma_tests::harness::fixtures;
use dpma_tests::util::json_compact;
use serde_json::{json, Value};

use crate::spool::{Msg, Spool};

/// The method name prefix.
pub const VM: &str = "switchvox.users.voicemail.";

/// app_voicemail's folders, in snapshot order.
pub const FOLDERS: [&str; 12] = [
    "INBOX", "Old", "Work", "Family", "Friends", "Cust1", "Cust2", "Cust3", "Cust4", "Cust5",
    "Deleted", "Urgent",
];

/// The folder name a message id gets for each of [`FOLDERS`].
pub const CANONICAL: [&str; 12] = [
    "INBOX", "INBOX", "Work", "Family", "Friends", "Cust1", "Cust2", "Cust3", "Cust4", "Cust5",
    "Deleted", "INBOX",
];

/// The `de_DE` translation of the test configuration.
pub fn de(name: &str) -> &str {
    match name {
        "INBOX" => "Posteingang",
        "Work" => "Arbeit",
        "Family" => "Familie",
        "Recordings" => "Aufnahmen",
        n => n,
    }
}

/// A successful response document.
pub fn ok_doc(method: &str, result: Value) -> String {
    json_compact(&json!({"response": {"method": format!("{VM}{method}"), "result": result}}))
}

/// An error response document.
pub fn err_doc(method: &str, code: u32, detail: &str) -> String {
    fixtures::json_error(&format!("{VM}{method}"), code, detail)
}

/// A message in a snapshot.
#[derive(Clone, Debug)]
pub struct SnapMsg {
    /// The folder it was found in.
    pub folder_name: String,
    /// The message.
    pub msg: Msg,
}

/// app_voicemail's `vm_mailbox_snapshot_create` (folders combined): 12
/// lists of messages.  `folder` must be one of [`FOLDERS`].
pub fn snapshot(
    spool: &Spool,
    mbox: &str,
    folder: Option<&str>,
    descending: bool,
    by_time: bool,
) -> Vec<Vec<SnapMsg>> {
    let combine = true;
    let sp = spool.read(mbox);
    let mut lists: Vec<Vec<SnapMsg>> = vec![Vec::new(); FOLDERS.len()];
    let only = folder.map(|f| {
        FOLDERS
            .iter()
            .position(|x| *x == f)
            .expect("a folder of FOLDERS")
    });
    for (i, name) in FOLDERS.iter().enumerate() {
        let wanted = match only {
            None => true,
            Some(o) => o == i || (o == 0 && combine && (i == 1 || i == 11)),
        };
        if !wanted {
            continue;
        }
        let idx = if combine && (i == 1 || i == 11) { 0 } else { i };
        for m in sp.get(*name).into_iter().flatten() {
            let msg = SnapMsg {
                folder_name: name.to_string(),
                msg: m.clone(),
            };
            let lst = &mut lists[idx];
            if !by_time {
                if descending {
                    lst.insert(0, msg);
                } else {
                    lst.push(msg);
                }
                continue;
            }
            // The origtimes compare as text, as the official DPMA does.
            let pos = lst.iter().position(|cur| {
                let val = msg.msg.get("origtime").cmp(cur.msg.get("origtime"));
                (descending && val != Ordering::Less) || (!descending && val != Ordering::Greater)
            });
            match pos {
                Some(j) => lst.insert(j, msg),
                None => lst.push(msg),
            }
        }
    }
    lists
}

/// getList's caller id parsing: (number, name).
pub fn parse_callerid(cid: &str) -> (String, String) {
    let cid: String = cid.chars().take(255).collect();
    let (name, rest) = match cid.find('"') {
        None => (String::new(), Some(cid.clone())),
        Some(q) => {
            let after = &cid[q + 1..];
            match after.find('"') {
                Some(q2) => (after[..q2].to_string(), Some(after[q2 + 1..].to_string())),
                None => (after.to_string(), None),
            }
        }
    };
    let mut num = rest.unwrap_or_default();
    if !num.is_empty() {
        if let Some(lt) = num.find('<') {
            num = num[lt + 1..].to_string();
        }
        if let Some(gt) = num.rfind('>') {
            num.truncate(gt);
        }
    }
    (num, name)
}

/// The folder name a message id gets (case-insensitive lookup).
pub fn canonical(name: &str) -> Option<&'static str> {
    FOLDERS
        .iter()
        .position(|f| f.eq_ignore_ascii_case(name))
        .map(|i| CANONICAL[i])
}

/// The getList document for `folder` (shown as `shown`) and the message
/// trackers it leaves: (id, folder).
#[allow(clippy::too_many_arguments)]
pub fn getlist_doc(
    spool: &Spool,
    mbox: &str,
    folder: &str,
    shown: &str,
    per_page: i64,
    page: i64,
    descending: bool,
    by_time: bool,
) -> (String, Vec<(String, String)>) {
    let f = if folder == "Recordings" {
        "Cust5"
    } else {
        folder
    };
    let lists = snapshot(spool, mbox, Some(f), descending, by_time);
    let total = lists.iter().map(Vec::len).sum::<usize>() as i64;
    let (mut on_page, mut cur) = (0i64, 1i64);
    let mut msgs = Vec::new();
    let mut ids = Vec::new();
    for m in lists.iter().flatten() {
        if on_page < per_page {
            on_page += 1;
        } else {
            cur += 1;
            on_page = 1;
        }
        if cur != page {
            continue;
        }
        let mid = format!(
            "{}-{}",
            canonical(&m.folder_name).unwrap_or("(null)"),
            m.msg.get("msg_id")
        );
        let cid = m.msg.get("callerid");
        let (num, name) = parse_callerid(cid);
        let read = if ["inbox", "urgent"].contains(&m.folder_name.to_lowercase().as_str()) {
            "No"
        } else {
            "Yes"
        };
        msgs.push(json!({
            "id": mid, "caller_id": cid, "caller_id_number": num, "caller_id_name": name,
            "date": m.msg.get("origdate"), "date_UTC": m.msg.get("origdate"),
            "duration": m.msg.get("duration"), "read": read,
        }));
        ids.push((mid, m.folder_name.clone()));
    }
    // Python's int(total / per_page): truncated toward zero.
    let pages = total / per_page + 1;
    let result = json!({"messages": {
        "folder": shown, "page_number": page.to_string(), "total_pages": pages.to_string(),
        "items_per_page": per_page.to_string(), "total_items": total.to_string(), "message": msgs,
    }});
    (ok_doc("getList", result), ids)
}

/// The combined INBOX of a mailbox by number: (id as getList shows it,
/// msg_id, real folder).
pub fn inbox_ids(spool: &Spool, mbox: &str) -> Vec<(String, String, String)> {
    snapshot(spool, mbox, Some("INBOX"), false, false)
        .swap_remove(0)
        .into_iter()
        .map(|m| {
            let id = m.msg.msg_id();
            (format!("INBOX-{id}"), id, m.folder_name)
        })
        .collect()
}
