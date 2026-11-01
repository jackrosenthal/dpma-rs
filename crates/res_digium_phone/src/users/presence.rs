//! Per-user presence options and current presence (phone_users.c
//! `phone_presence_*` 0x160740..0x1610e0, `phone_pres_destroy_cb`
//! 0x151fb0, `phone_presence_user_application_sync` 0x1648d0).
//!
//! Every phone has a list of presence options (the original's ao2 hash
//! container at +0x8e8, 57 buckets keyed by the option id): the states a
//! user can pick on the phone, each with an optional sub-state.
//! `set_user_defaults` installs the six standard states; the first
//! `user_application_sync` that finds one of the phone's status
//! applications replaces them with the states of the phone's status
//! applications and updates the send-486 mask (see `Phone::send486_custom`).
//! The phone's current presence is the `CustomPresence:<first line>`
//! state.

use super::*;
use dpma_ast::presence as ast_presence;

/// Buckets of the original's option container; iteration follows them.
const BUCKETS: u32 = 57;

/// `owner` of an option added by a user (never used in 3.6.13).
pub const OWNER_USER: i32 = 0;
/// `owner` of the default options and of the status applications' options.
pub const OWNER_SYSTEM: i32 = 1;

/// One presence option (`struct phone_presence_option`, 0x18 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceOption {
    /// Presence state (`dpma_ast::presence`) (+0x00).
    pub state: i32,
    /// `OWNER_USER` or `OWNER_SYSTEM` (+0x04).
    pub owner: i32,
    /// Sub-state (+0x08); None for an option without one, which the CLI
    /// shows differently from an empty one.
    pub subtype: Option<String>,
    /// Option id, from 1 (+0x10); the container key.
    pub id: i32,
}

impl PresenceOption {
    /// The owner's name in `presence.options.getList` (table at 0x5bd1a8).
    pub fn owner_name(&self) -> &'static str {
        if self.owner == OWNER_USER {
            "user"
        } else {
            "system"
        }
    }
}

/// The options in container order: by bucket (`id % 57`), then in
/// insertion order within a bucket.
pub fn ordered(options: &[PresenceOption]) -> Vec<PresenceOption> {
    let mut v = options.to_vec();
    v.sort_by_key(|o| o.id.unsigned_abs() % BUCKETS);
    v
}

/// `phone_presence_option_add` (0x1609b0): add an option with the lowest
/// unused id; returns the id.
pub fn option_add(options: &mut Vec<PresenceOption>, state: i32, owner: i32, subtype: Option<&str>) -> i32 {
    let count = options.len() as i32;
    let mut id = 1;
    loop {
        if !options.iter().any(|o| o.id == id) {
            break;
        }
        let more = id <= count;
        id += 1;
        if !more {
            break;
        }
    }
    options.push(PresenceOption { state, owner, subtype: subtype.map(str::to_string), id });
    id
}

/// The options `set_user_defaults` installs (after
/// `phone_presence_option_remove_all`): available, unavailable, away, xa,
/// chat, and dnd, owned by the system, ids 1 to 6.
pub fn default_options() -> Vec<PresenceOption> {
    let mut v = Vec::new();
    for state in [
        ast_presence::AVAILABLE,
        ast_presence::UNAVAILABLE,
        ast_presence::AWAY,
        ast_presence::XA,
        ast_presence::CHAT,
        ast_presence::DND,
    ] {
        option_add(&mut v, state, OWNER_SYSTEM, None);
    }
    v
}

/// The body of `phone_presence_user_application_sync` for `phone`, with
/// `list` as its application list.
///
/// Runs only while the phone is not synchronized yet (`send486_custom`
/// clear).  The first status application found (not marked for deletion)
/// sets the flag and removes every option; each status application then
/// adds its state and one option per sub-state, and sets (`send486=yes`)
/// or clears (`send486=no`) its state in the send-486 mask.  An
/// application that does not exist is logged.
///
/// `set_user_defaults` runs this with the phone's previous application
/// list while every application is marked for deletion, so then it only
/// logs the missing ones (the original's behavior, kept).
pub fn sync_applications(apps: &NamedMap<Application>, phone: &mut Phone, list: &[String]) {
    if phone.send486_custom {
        return;
    }
    for name in list {
        let Some(app) = apps.get(name) else {
            dpma_ast::dpma_log!("Failed to find application '{}'", name);
            continue;
        };
        let Some(AppKind::Status(st)) = app.kind.as_ref() else { continue };
        if app.delme {
            continue;
        }
        if !phone.send486_custom {
            phone.send486_custom = true;
            phone.presence_options.clear();
        }
        let bit = 1u32 << (st.status as u32 & 0x1f);
        match st.send486 {
            Send486::Yes => phone.send486_mask |= bit,
            Send486::No => phone.send486_mask &= !bit,
            Send486::NotSet => {}
        }
        // FUN_00160bb0: the state, then one option per sub-state.
        option_add(&mut phone.presence_options, st.status, OWNER_SYSTEM, None);
        for sub in &st.substatuses {
            option_add(&mut phone.presence_options, st.status, OWNER_SYSTEM, Some(sub));
        }
    }
}

/// `phone_presence_user_application_sync`: refresh the presence options
/// of phone `phone` from its status applications (see
/// `sync_applications`).
pub fn user_application_sync(phone: &str) {
    let mut g = write();
    let Some(reg) = g.as_mut() else { return };
    let Registry { phones, applications, .. } = reg;
    let Some(p) = phones.get_mut(phone) else { return };
    let list = p.applications.clone();
    sync_applications(applications, p, &list);
}

/// The presence provider of a phone: `CustomPresence:<first line slot>`
/// (empty when the phone has no lines, as in the original).
fn provider(p: &Phone) -> String {
    format!("CustomPresence:{}", p.lines.first().map_or("", |l| l.name.as_str()))
}

/// The option matching `state` and `subtype` (absent and empty are the
/// same), in container order.
fn matching(options: &[PresenceOption], state: i32, subtype: Option<&str>) -> Option<PresenceOption> {
    let cur = subtype.unwrap_or("");
    ordered(options).into_iter().find(|o| o.state == state && o.subtype.as_deref().unwrap_or("") == cur)
}

/// The current presence of a phone (`phone_presence_get_current`
/// 0x1610e0): the option matching the phone's `CustomPresence` state and
/// sub-state (None when no option matches), and the presence message.
/// None when the phone does not exist.
pub fn get_current(phone: &str) -> Option<(Option<PresenceOption>, Option<String>)> {
    let (provider, options) = {
        let g = read();
        let p = g.as_ref()?.phones.get(phone)?;
        (provider(p), p.presence_options.clone())
    };
    let (state, subtype, message) = ast_presence::query(&provider);
    Some((matching(&options, state, subtype.as_deref()), message))
}

/// The phone's options in container order (None when the phone does not
/// exist).
pub fn options(phone: &str) -> Option<Vec<PresenceOption>> {
    let g = read();
    Some(ordered(&g.as_ref()?.phones.get(phone)?.presence_options))
}

/// `phone_presence_update` (0x160ce0): set the phone's presence to option
/// `id` with `message`, i.e., set
/// `PRESENCE_STATE(CustomPresence:<first line>)` to
/// `<state>,<sub-state>,<message>` (at most 511 characters).  Err when the
/// phone or the option does not exist.
pub fn update(phone: &str, id: i32, message: Option<&str>) -> Result<(), ()> {
    let (var, value) = {
        let g = read();
        let p = g.as_ref().and_then(|r| r.phones.get(phone)).ok_or(())?;
        let o = p.presence_options.iter().find(|o| o.id == id).ok_or(())?;
        let var = crate::util::truncate(&format!("PRESENCE_STATE({})", provider(p)), 0x200);
        let value = format!(
            "{},{},{}",
            ast_presence::state2str(o.state),
            o.subtype.as_deref().unwrap_or(""),
            message.unwrap_or("")
        );
        (var, crate::util::truncate(&value, 0x200))
    };
    // The original sets it while holding the phone's lock; the setter
    // raises a presence change, so it is done without the registry lock.
    dpma_ast::pbx::set_global(&var, &value);
    Ok(())
}

/// The status listing of `digium_phones show status`: synchronize the
/// options, then each option in container order with the current one
/// marked.  None when the phone does not exist.
pub fn status_lines(phone: &str) -> Option<Vec<String>> {
    user_application_sync(phone);
    let (current, _) = get_current(phone)?;
    let options = options(phone)?;
    Some(
        options
            .iter()
            .map(|o| {
                format!(
                    "{}{}: {} {} {}\n",
                    if current.as_ref().is_some_and(|c| c.id == o.id) { "(*) " } else { "    " },
                    o.id,
                    ast_presence::state2str(o.state),
                    if o.subtype.is_some() { "-" } else { "" },
                    o.subtype.as_deref().unwrap_or("")
                )
            })
            .collect(),
    )
}
