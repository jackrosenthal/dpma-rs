//! The built-in phone methods (phone_method_internal_api.c): the table at
//! 0x5bcec0 registered by `phone_method_internal_load` (FUN_00186920) and
//! removed by `phone_method_internal_cleanup` (FUN_00186840).
//!
//! The table and load order match the original.  The handlers live in
//! `voicemail.rs` (voicemail), `calls.rs` (queues, parking, recording,
//! phonebook, and echo), and `presence.rs` (presence).

pub mod calls;
pub mod presence;
pub mod voicemail;

use crate::method::{self, JsonMethod, XmlMethod};

struct Entry {
    name: &'static str,
    xml: Option<XmlMethod>,
    json: Option<JsonMethod>,
}

const fn json(name: &'static str, f: JsonMethod) -> Entry {
    Entry { name, xml: None, json: Some(f) }
}

/// The original table, in order.
const TABLE: &[Entry] = &[
    json("switchvox.users.presence.getInfo", presence::get_info),
    json("switchvox.users.presence.update", presence::update),
    json("switchvox.users.presence.options.getList", presence::options_get_list),
    json("switchvox.users.parkingLots.getList", calls::parking_lots_get_list),
    json("switchvox.users.voicemail.getList", voicemail::get_list),
    json("switchvox.users.voicemail.getFolderList", voicemail::get_folder_list),
    json("switchvox.users.voicemail.move", voicemail::move_message),
    json("switchvox.users.voicemail.remove", voicemail::remove),
    json("switchvox.users.voicemail.forward", voicemail::forward),
    json("switchvox.users.voicemail.markRead", voicemail::mark_read),
    json("switchvox.users.voicemail.markUnread", voicemail::mark_unread),
    json("switchvox.users.voicemail.play", voicemail::play),
    Entry {
        name: "switchvox.users.currentCalls.startRecording",
        xml: Some(calls::start_recording_xml),
        json: Some(calls::start_recording_json),
    },
    Entry {
        name: "switchvox.users.currentCalls.stopRecording",
        xml: Some(calls::stop_recording_xml),
        json: Some(calls::stop_recording_json),
    },
    json("switchvox.users.callQueues.getList", calls::queues_get_list),
    json("switchvox.users.callQueues.getTodaysStatus", calls::queues_get_todays_status),
    json("switchvox.users.callQueues.login", calls::queue_login),
    json("switchvox.users.callQueues.logout", calls::queue_logout),
    json("switchvox.users.callQueues.pause", calls::queue_pause),
    json("switchvox.users.callQueues.resume", calls::queue_resume),
    json("switchvox.users.phonebooks.entries.add", calls::phonebook_entries_add),
    json("test.dpma.api.echo", calls::echo),
];

/// `phone_method_internal_load`: per-area setup, then the registrations.
pub fn load() -> Result<(), ()> {
    voicemail::load()?;
    if calls::load().is_err() {
        voicemail::unload();
        return Err(());
    }
    for e in TABLE {
        if let Some(f) = e.xml {
            let _ = method::register_xml(e.name, f);
        }
        if let Some(f) = e.json {
            let _ = method::register_json(e.name, f);
        }
    }
    Ok(())
}

/// `phone_method_internal_cleanup`.
pub fn unload() {
    for e in TABLE {
        if e.xml.is_some() {
            method::unregister_xml(e.name);
        }
        if e.json.is_some() {
            method::unregister_json(e.name);
        }
    }
    calls::unload();
    voicemail::unload();
}
