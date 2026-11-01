//! The session container and the module's session life cycle
//! (`phone_msg_load` FUN_00150440, `phone_msg_unload` FUN_001510f0,
//! `phone_msg_reload` FUN_00150420, `phone_msg_session_alloc` FUN_0014b450,
//! `phone_msg_session_find` FUN_00149d60, `phone_msg_session_find_by_mac`
//! FUN_00149e30, `phone_msg_session_mark_*` FUN_0014c160 FUN_0014c230
//! FUN_0014c310, `phone_msg_session_invalidate` FUN_0014c390, and the
//! global auth flags FUN_00149f00).
//!
//! The original verifies phone certificates against three CA certificates
//! embedded in the binary (`load_castore`); here they come from the
//! user-supplied `phone_ca_file`, and the AppServer certificate sent in
//! every HandshakeResponse from `appserver_certificate` (both read at load
//! and again at reload).  Unlike the original, which fails to load when its
//! CA store cannot be built, a missing or unreadable file is logged and the
//! module loads; handshakes then fail.

use super::{now, Session, DB_FAMILY};
use crate::util::NamedMap;
use dpma_ast::cli::CliGroup;
use dpma_ast::{bformat, db, dpma_log};
use dpma_proto::cert::{CaStore, ClientInfo};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Buckets of the original's session container (`ao2_container_alloc_hash`
/// with 0x101 buckets, case-insensitive djb2 of the id); listings follow
/// its order.
const BUCKETS: u32 = 0x101;

/// The session container (0x5f4e40); None while not loaded.
static SESSIONS: Mutex<Option<NamedMap<Arc<Session>>>> = Mutex::new(None);

/// The global auth flags (0x5eeda0), copied into every new session.
static GLOBAL_AUTH_FLAGS: AtomicU32 = AtomicU32::new(crate::config::auth::USER);

/// `digium_phones show sessions` (registered by `phone_msg_load`).
static CLI: Mutex<Option<CliGroup>> = Mutex::new(None);

/// Trust material read from the configured files.
pub(crate) struct Trust {
    /// `phone_ca_file` (the original's `castore`).
    pub ca: Option<CaStore>,
    /// `appserver_certificate`: appended to every HandshakeResponse.
    pub appserver_pem: Vec<u8>,
}

static TRUST: RwLock<Option<Trust>> = RwLock::new(None);

/// Run `f` with the trust material (None when not loaded).
pub(crate) fn with_trust<R>(f: impl FnOnce(Option<&Trust>) -> R) -> R {
    let g = TRUST.read().unwrap_or_else(|e| e.into_inner());
    f(g.as_ref())
}

/// Read `phone_ca_file` and `appserver_certificate`.  Problems are logged;
/// what could be read is kept.
fn load_trust() -> Trust {
    let g = crate::config::get();
    let ca = match std::fs::read(crate::util::path(&g.phone_ca_file)) {
        Ok(pem) => match CaStore::from_pem(&pem) {
            Ok(s) => Some(s),
            Err(e) => {
                dpma_log!("Error creating castore from '{}': {}", g.phone_ca_file, e.message());
                None
            }
        },
        Err(e) => {
            dpma_log!("Error creating castore: cannot read phone_ca_file '{}': {}", g.phone_ca_file, e);
            None
        }
    };
    let appserver_pem = match std::fs::read(crate::util::path(&g.appserver_certificate)) {
        Ok(pem) => pem,
        Err(e) => {
            dpma_log!("Cannot read appserver_certificate '{}': {}", g.appserver_certificate, e);
            Vec::new()
        }
    };
    Trust { ca, appserver_pem }
}

/// `phone_msg_load` (FUN_00150440): load the CA store, create the
/// containers, set the global auth flags, register `digium_phones show
/// sessions`, restore sessions from AstDB, then `transport::load()`.
pub fn load(_config_file: &[u8]) -> Result<(), ()> {
    let g = crate::config::get();
    crate::config::check_trust_material(&g);
    *TRUST.write().unwrap_or_else(|e| e.into_inner()) = Some(load_trust());
    super::incoming::reset();
    *SESSIONS.lock().unwrap_or_else(|e| e.into_inner()) = Some(NamedMap::new(BUCKETS));
    set_global_auth_flags(g.auth_flags);
    *CLI.lock().unwrap_or_else(|e| e.into_inner()) = Some(CliGroup::register(&super::cli::commands()));
    super::persist::restore_all();
    crate::transport::load()
}

/// `phone_msg_reload` (FUN_00150420): refresh the global auth flags.  The
/// trust material is read again too (the original's is built in); what
/// cannot be read keeps its previous value.
pub fn reload(_config_file: &[u8]) -> Result<(), ()> {
    set_global_auth_flags(crate::config::get().auth_flags);
    if TRUST.read().unwrap_or_else(|e| e.into_inner()).is_some() {
        let new = load_trust();
        let mut g = TRUST.write().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = g.as_mut() {
            if new.ca.is_some() {
                old.ca = new.ca;
            }
            if !new.appserver_pem.is_empty() {
                old.appserver_pem = new.appserver_pem;
            }
        }
    }
    Ok(())
}

/// `phone_msg_unload` (FUN_001510f0): unregister `digium_phones show
/// sessions`, stop the transport (`network_handler_destroy`), drop the
/// containers, then destroy the dialplan routing and the CA store.
pub fn unload() {
    CLI.lock().unwrap_or_else(|e| e.into_inner()).take();
    crate::transport::unload();
    super::incoming::reset();
    let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(sessions);
    crate::transport::destroy_routing();
    TRUST.write().unwrap_or_else(|e| e.into_inner()).take();
}

/// `phone_msg_session_find` (FUN_00149d60): the session with id `id`
/// (case insensitive; the id is cut to 127 bytes first).
pub fn find(id: &[u8]) -> Option<Arc<Session>> {
    let id = crate::util::truncate(id, 0x80);
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).as_ref()?.get(&id).cloned()
}

/// `phone_msg_session_find_by_mac` (FUN_00149e30): the first session (in
/// container order) whose MAC equals `mac`, ignoring case.
pub fn find_by_mac(mac: &[u8]) -> Option<Arc<Session>> {
    all().into_iter().find(|s| {
        let st = s.lock();
        !st.mac.is_empty() && st.mac.eq_ignore_ascii_case(mac)
    })
}

/// Every session, in the original container's iteration order.
pub fn all() -> Vec<Arc<Session>> {
    SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default()
}

/// Link a new session into the container (`ao2_link`).
fn link(s: &Arc<Session>) {
    if let Some(m) = SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        m.insert(&s.id, s.clone());
    }
}

/// Unlink `s` (only that very session, not another with the same id).
fn unlink(s: &Arc<Session>) {
    let mut g = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(m) = g.as_mut() {
        if m.get(&s.id).is_some_and(|x| Arc::ptr_eq(x, s)) {
            m.remove(&s.id);
        }
    }
}

/// `phone_msg_session_mark_authenticated` (FUN_0014c230): set
/// authenticated (clearing inactive), replace the response URI when
/// `response_uri` is not empty, and save the session to AstDB.
pub fn mark_authenticated(s: &Arc<Session>, response_uri: Option<&[u8]>) {
    {
        let mut st = s.lock();
        st.authenticated = true;
        st.inactive = false;
        if let Some(uri) = response_uri.filter(|u| !u.is_empty()) {
            st.response_uri = uri.to_vec();
        }
    }
    super::persist::update_db_info(s);
}

/// `phone_msg_session_mark_inactive` (FUN_0014c310): set inactive and
/// delete the AstDB entry.
pub fn mark_inactive(s: &Arc<Session>) {
    s.lock().inactive = true;
    db::del(DB_FAMILY, &s.id);
}

/// `phone_msg_session_mark_unconfigured_by_mac` (FUN_0014c160): clear the
/// configured flag of the MAC's session and save it when it was set.
pub fn mark_unconfigured_by_mac(mac: &[u8]) {
    let Some(s) = find_by_mac(mac) else { return };
    let changed = {
        let mut st = s.lock();
        std::mem::replace(&mut st.configured, false)
    };
    if changed {
        super::persist::update_db_info(&s);
    }
}

/// `phone_msg_session_invalidate` (FUN_0014c390): delete the AstDB entry
/// and drop the session from the container.
pub fn invalidate(s: &Arc<Session>) {
    db::del(DB_FAMILY, &s.id);
    unlink(s);
}

/// `phone_msg_set_global_auth_flags` (FUN_00149f00).
pub fn set_global_auth_flags(flags: u32) {
    GLOBAL_AUTH_FLAGS.store(flags, Ordering::SeqCst);
}

/// `phone_msg_get_global_auth_flags`.
pub fn global_auth_flags() -> u32 {
    GLOBAL_AUTH_FLAGS.load(Ordering::SeqCst)
}

/// The session id the original generates: `"%d%ld"` of the djb2 hash
/// (`h * 33 ^ c`, seed 5381, masked to 31 bits) of `"%ld%s"` (time,
/// contact; at most 127 bytes) and `ast_random()`.
fn new_session_id(time: i64, contact: &[u8]) -> Vec<u8> {
    let seed = crate::util::truncate(&bformat!("{}{}", time, contact), 0x80);
    let mut h: u32 = 5381;
    for &b in &seed {
        h = h.wrapping_mul(33) ^ u32::from(b);
    }
    let id = bformat!("{}{}", h & 0x7fff_ffff, dpma_ast::util::random());
    crate::util::truncate(&id, 0x80)
}

/// What `phone_msg_session_alloc` gets.
pub(crate) struct NewSession<'a> {
    pub mac: Option<&'a [u8]>,
    pub contact: &'a [u8],
    pub response_uri: &'a [u8],
    /// The certificate PEM from the Handshake body (or AstDB).
    pub client_cert: &'a [u8],
    /// A restored session's id; None generates one.
    pub id: Option<&'a [u8]>,
    pub user_agent: Option<&'a [u8]>,
    pub origination_network: Option<&'a [u8]>,
}

/// `phone_msg_session_alloc` (FUN_0014b450) as both of the original's
/// callers use it: create a session, verify the phone certificate(s)
/// (`session_verify_cert`, which logs its own failures), and link it into
/// the container.  None on failure.
pub(crate) fn alloc(n: &NewSession) -> Option<Arc<Session>> {
    let time = now();
    if n.client_cert.is_empty() {
        dpma_log!("No client certificate was provided");
        return None;
    }
    let Some(ua) = n.user_agent else {
        // ast_strdup(NULL) fails.
        dpma_log!("User Agent allocation failed");
        return None;
    };
    let id = match n.id.filter(|i| !i.is_empty()) {
        Some(i) => crate::util::truncate(i, 0x80),
        None => new_session_id(time, n.contact),
    };
    let mac = n.mac.filter(|m| !m.is_empty());
    let verified = {
        let info = ClientInfo { contact: n.contact, mac, user_agent: ua };
        with_trust(|t| match t.and_then(|t| t.ca.as_ref()) {
            Some(store) => dpma_proto::cert::verify_client_chain(store, n.client_cert, &info).ok(),
            None => {
                dpma_log!(
                    "<{}>: Client cert failed to verify: no phone CA certificates are loaded (phone_ca_file)",
                    n.contact
                );
                None
            }
        })
    }?;
    let s = Arc::new(Session::new(&id));
    {
        let mut st = s.lock();
        st.mac = mac.unwrap_or(b"").to_vec();
        st.contact = n.contact.to_vec();
        st.response_uri = n.response_uri.to_vec();
        st.user_agent = ua.to_vec();
        st.origination_network = n.origination_network.unwrap_or(b"").to_vec();
        st.auth_flags = global_auth_flags();
        st.created = time;
        st.last_activity = time;
        st.intermediate_serial = verified.intermediate_serial;
        st.public_key = verified.public_key;
        st.certificate = Some(verified.certificate);
        st.client_cert_pem = n.client_cert.to_vec();
    }
    link(&s);
    Some(s)
}

#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

    fn session_arg(a: &CliArgs, i: usize) -> Option<Arc<Session>> {
        let s = find(a.argv.get(i)?);
        if s.is_none() {
            a.out(bformat!("No session '{}'\n", a.argv[i]));
        }
        s
    }

    /// dpmadev session mark <id> authenticated|inactive|unconfigured|configured
    fn mark(a: &CliArgs) -> CliResult {
        if a.argc() != 5 {
            return CliResult::ShowUsage;
        }
        let Some(s) = session_arg(a, 3) else { return CliResult::Failure };
        match a.argv[4].as_slice() {
            b"authenticated" => mark_authenticated(&s, None),
            b"inactive" => mark_inactive(&s),
            b"unconfigured" => mark_unconfigured_by_mac(&s.mac()),
            b"configured" => {
                s.lock().configured = true;
                super::persist::update_db_info(&s);
            }
            _ => return CliResult::ShowUsage,
        }
        a.out(bformat!("Session {} marked {}\n", s.id, a.argv[4]));
        CliResult::Success
    }

    /// dpmadev session idle <id> <seconds>: pretend the session has been
    /// idle that long, and let the next read prune at once.
    fn idle(a: &CliArgs) -> CliResult {
        if a.argc() != 5 {
            return CliResult::ShowUsage;
        }
        let Some(s) = session_arg(a, 3) else { return CliResult::Failure };
        let Ok(secs) = crate::util::parse::<i64>(&a.argv[4]) else { return CliResult::ShowUsage };
        s.lock().last_activity = now() - secs;
        super::incoming::force_prune();
        a.out(bformat!("Session {} last activity set {} s ago\n", s.id, secs));
        CliResult::Success
    }

    /// dpmadev session event <id> <event> <length>|<text...>
    fn event(a: &CliArgs) -> CliResult {
        if a.argc() < 6 {
            return CliResult::ShowUsage;
        }
        let Some(s) = session_arg(a, 3) else { return CliResult::Failure };
        let body = match (a.argc(), crate::util::parse::<usize>(&a.argv[5])) {
            (6, Ok(n)) => {
                let mut b = b"<config>".to_vec();
                let filler = b"0123456789abcdefghijklmnopqrstuvwxyz";
                while b.len() + 9 < n {
                    let take = (n - 9 - b.len()).min(filler.len());
                b.extend_from_slice(&filler[..take]);
                }
                b.extend_from_slice(b"</config>");
                b
            }
            _ => a.argv[5..].join(&b" "[..]),
        };
        let res = super::outgoing::send_event(&s, &a.argv[4], &body);
        a.out(bformat!(
            "send_event {} ({} bytes): {}\n",
            a.argv[4],
            body.len(),
            match res {
                Ok(()) => b"ok".to_vec(),
                Err(e) => e,
            }
        ));
        CliResult::Success
    }

    /// dpmadev session restore: restore AstDB sessions now.
    fn restore(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        super::persist::restore_all();
        a.out(bformat!("{} session(s)\n", all().len()));
        CliResult::Success
    }

    /// dpmadev session prune: prune at the next read.
    fn prune(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        super::incoming::force_prune();
        a.out("The next read prunes idle sessions and transactions\n");
        CliResult::Success
    }

    vec![
        CliCommand {
            command: "dpmadev session mark",
            summary: "Change a session's flags",
            usage: "Usage: dpmadev session mark <id> authenticated|inactive|unconfigured|configured\n",
            exec: mark,
            complete: None,
        },
        CliCommand {
            command: "dpmadev session idle",
            summary: "Backdate a session's last activity",
            usage: "Usage: dpmadev session idle <id> <seconds>\n       Sets the last activity <seconds> ago; the next read prunes.\n",
            exec: idle,
            complete: None,
        },
        CliCommand {
            command: "dpmadev session event",
            summary: "Send an event to a session's phone",
            usage: "Usage: dpmadev session event <id> <event> <length>|<text...>\n       With a number, the body is a <config> document of that length.\n",
            exec: event,
            complete: None,
        },
        CliCommand {
            command: "dpmadev session restore",
            summary: "Restore sessions from AstDB",
            usage: "Usage: dpmadev session restore\n",
            exec: restore,
            complete: None,
        },
        CliCommand {
            command: "dpmadev session prune",
            summary: "Prune idle sessions at the next read",
            usage: "Usage: dpmadev session prune\n",
            exec: prune,
            complete: None,
        },
    ]
}
