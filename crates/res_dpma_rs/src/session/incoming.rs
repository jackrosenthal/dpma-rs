//! Incoming messages (FUN_0014f280: `incoming_build_transaction`,
//! `validate_message`, `find_transaction`, `transaction_alloc`,
//! `incoming_add_msg`, `prune_inactive`; `incoming_check_finalize`
//! FUN_0014a000; `validate_session` FUN_0014ed90).
//!
//! Every message read from the transport is checked (a request other than
//! Handshake, Echo, or Preconfig needs a known session that validates;
//! unencrypted AsteriskRequests and UserlistResponses with a body are
//! dropped) and added to the transaction `"<ID>-<MAC>"`
//! (`dpma_proto::message::Transactions`).  When the transaction is complete
//! `dpma_proto::message::Collector::decode` reassembles and decrypts it with
//! the session's common password.

use super::{now, or_null, user_agent_of, Session, Transaction};
use dpma_ast::dpma_bytes::ByteSlice;
use dpma_ast::msg::Msg;
use dpma_ast::{bformat, dpma_debug, dpma_log};
use dpma_proto::framing;
use dpma_proto::message::{Message, Sender, Transactions, INCOMING};
use dpma_proto::{headers as h, types};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

/// Unauthenticated sessions idle longer than this are pruned (0x77).
const UNAUTHENTICATED_IDLE: i64 = 0x77;
/// Authenticated but inactive sessions idle longer than this are pruned
/// (0x3b).
const INACTIVE_IDLE: i64 = 0x3b;
/// Incomplete transactions older than this are dropped (0x28).
const TRANSACTION_AGE: i64 = 0x28;
/// Pruning runs when more than this many seconds have passed (5).
const PRUNE_INTERVAL: i64 = 5;

/// The incomplete transactions (0x5f4e48), each with the session it is for
/// and the SIP message of each part.
static PENDING: Mutex<Transactions<Option<Arc<Session>>, Msg>> =
    Mutex::new(Transactions::new(Sender::Phone));

/// When sessions and transactions were last pruned (0x5ee008).
static LAST_PRUNE: AtomicI64 = AtomicI64::new(0);

/// Drop every incomplete transaction (load and unload).
pub(crate) fn reset() {
    let pending = PENDING.lock().unwrap_or_else(|e| e.into_inner()).clear();
    drop(pending);
    LAST_PRUNE.store(0, Ordering::SeqCst);
}

/// Make the next [`next_transaction`] prune (test hooks).
#[cfg(feature = "devtest")]
pub(crate) fn force_prune() {
    LAST_PRUNE.store(0, Ordering::SeqCst);
}

/// Make every incomplete transaction `secs` older and the next
/// [`next_transaction`] prune (test hooks); how many there are.
#[cfg(feature = "devtest")]
pub(crate) fn backdate_pending(secs: i64) -> usize {
    let mut g = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    g.age(secs);
    force_prune();
    g.len()
}

/// `prune_inactive`: invalidate idle sessions (authenticated active
/// sessions are kept) and drop stale transactions.
fn prune_inactive() {
    let t = now();
    if t - LAST_PRUNE.load(Ordering::SeqCst) <= PRUNE_INTERVAL {
        return;
    }
    LAST_PRUNE.store(t, Ordering::SeqCst);
    for s in super::store::all() {
        let doomed = {
            let st = s.lock();
            let idle = t - st.last_activity;
            if st.authenticated && !st.inactive {
                None
            } else if !st.authenticated {
                (idle > UNAUTHENTICATED_IDLE).then(|| {
                    bformat!(
                        "Pruning unauthenticated session for device at '{}' due to inactivity.",
                        st.contact
                    )
                })
            } else {
                (idle > INACTIVE_IDLE).then(|| {
                    bformat!(
                        "Pruning session for device at '{}' due to inactivity.",
                        st.contact
                    )
                })
            }
        };
        if let Some(msg) = doomed {
            dpma_log!("{}", msg);
            super::store::invalidate(&s);
        }
    }
    let gone = PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .prune(t, TRANSACTION_AGE);
    drop(gone);
}

/// `validate_session` (FUN_0014ed90): the message must come from the
/// session's MAC and contact; otherwise the phone is answered "Session
/// Timeout".  Learns the user agent (once) and the origination network,
/// saving the session when either changes.
fn validate_session(m: &Msg, s: &Arc<Session>) -> bool {
    let mac = m.get_var(h::MAC_ADDRESS);
    let mut st = s.lock();
    let contact = match m.get_var(h::CONTACT).filter(|c| !c.is_empty()) {
        Some(c) => c,
        None => match m.get_var(h::FROM).filter(|c| !c.is_empty()) {
            Some(c) => c,
            None => {
                dpma_log!(
                    "Message from {} dropped because of missing contact or from header",
                    st.response_uri
                );
                return false;
            }
        },
    };
    if let Some(mac) = mac.as_deref() {
        if !st.mac.is_empty() && !mac.eq_ignore_ascii_case(&st.mac) {
            dpma_log!(
                "Responded to {} with session timeout due to mac mismatch",
                st.response_uri
            );
            drop(st);
            let _ = super::outgoing::send_timeout(m, s);
            return false;
        }
    }
    let contact = dpma_proto::uri::get_in_brackets(&contact);
    if dpma_proto::uri::sip_uri_cmp(&contact, &st.contact) != 0 {
        let (session_addr, _) = dpma_proto::uri::phone_utils_parse_uri(&st.response_uri);
        let (contact_addr, _) = dpma_proto::uri::phone_utils_parse_uri(&contact);
        if session_addr != contact_addr {
            dpma_log!(
                "Responded to {} with session timeout due to contact '{}' does not match session '{}'",
                st.response_uri,
                contact,
                st.contact
            );
            drop(st);
            let _ = super::outgoing::send_timeout(m, s);
            return false;
        }
    }
    let mut changed = false;
    if st.user_agent.is_empty() {
        if let Some(ua) = user_agent_of(m) {
            st.user_agent = ua;
            st.last_activity = now();
            changed = true;
        }
    }
    if let Some(net) = m.get_var(h::ORIGINATION_NETWORK) {
        if net != st.origination_network {
            st.origination_network = net;
            changed = true;
        }
    }
    drop(st);
    if changed {
        super::persist::update_db_info(s);
    }
    true
}

/// Why `validate_message` refuses a message; None when it is valid.
fn validate_message(m: &Msg) -> Option<&'static str> {
    let no_salt = m.get_var(h::MESSAGE_SALT).is_none_or(|s| s.is_empty());
    let no_body = m.body().is_none_or(|b| b.is_empty());
    let request = m.get_var(h::REQUEST_TYPE).filter(|r| !r.is_empty());
    let response = m.get_var(h::RESPONSE_TYPE);
    if request.is_none() && response.as_deref().is_none_or(<[u8]>::is_empty) {
        return Some("Message dropped due to lack of response or request type.");
    }
    if no_salt {
        if request
            .as_deref()
            .is_some_and(|r| r.eq_ignore_ascii_case(types::ASTERISK_REQUEST.as_bytes()))
            && !no_body
        {
            return Some("AsteriskRequest dropped due to lack of encryption.");
        }
        if response
            .as_deref()
            .is_some_and(|r| r.eq_ignore_ascii_case(b"UserlistResponse"))
            && !no_body
        {
            return Some("UserlistResponse dropped due to lack of encryption.");
        }
    }
    None
}

/// `incoming_check_finalize` (FUN_0014a000): build the transaction from
/// its parts.  None when decryption fails (the transaction is dropped).
fn finalize(
    session: Option<Arc<Session>>,
    parts: dpma_proto::message::Collector<Msg>,
) -> Option<Transaction> {
    let password = session.as_ref().map(|s| s.lock().common_password.clone());
    let inc = match parts.decode(Sender::Phone, password.as_deref()) {
        Ok(inc) => inc,
        Err(e) => {
            dpma_log!("{}", e.message());
            return None;
        }
    };
    let first = parts.into_metas().remove(0);
    let var = |name: &str| first.get_var(name);
    let has_id = inc.first.header(h::APPSERVER_ID).is_some();
    let mut tx = Transaction {
        key: if has_id {
            framing::transaction_key(&inc.id, Some(&inc.mac))
        } else {
            Vec::new()
        },
        app_server_id: inc.id,
        session,
        request_type: inc.request_type,
        response_type: inc.response_type,
        username: inc.username,
        mac: inc.mac,
        full_contact: inc.full_contact,
        password: inc.password,
        config_password: inc.config_password,
        config_token: inc.config_token,
        origination_network: inc.origination_network,
        body: inc.body,
        ..Default::default()
    };
    if inc.first.header(h::RESPONSE_URI).is_some() {
        tx.response_uri = framing::response_uri(
            &inc.response_uri,
            var(h::PJSIP_TRANSPORT).as_deref(),
            framing::RESPONSE_URI_BUF,
        );
    }
    if let Some(ua) = user_agent_of(&first) {
        tx.model = phone_model(&ua).unwrap_or_default();
        tx.user_agent = ua;
    }
    if let Some((host, port)) = var(h::TO).and_then(|to| dpma_proto::uri::to_host_port(&to)) {
        tx.to_host = host;
        tx.to_port = port.unwrap_or_default();
    }
    tx.first_msg = Some(first);
    dpma_debug!(
        3,
        "Receive fm {} '{}' body length = {}",
        tx.response_uri,
        tx.request_type,
        tx.body.len()
    );
    Some(tx)
}

/// `phone_utils_get_model`: the second word of a user agent whose first
/// word is a prefix of "sangoma p" or "digium" (case insensitive).
fn phone_model(ua: &[u8]) -> Option<Vec<u8>> {
    let (first, rest) = ua.split_once_str(" ")?;
    let prefix_of =
        |w: &[u8]| w.len() >= first.len() && w[..first.len()].eq_ignore_ascii_case(first);
    if !prefix_of(b"sangoma p") && !prefix_of(b"digium") {
        return None;
    }
    Some(rest.split(|&c| c == b' ').next().unwrap_or(b"").to_vec())
}

/// `incoming_build_transaction` for one message: Some(transaction) when it
/// completed one.
fn build(m: Msg) -> Option<Transaction> {
    let id = m.get_var(h::APPSERVER_ID);
    let session_id = m.get_var(h::SESSION).filter(|s| !s.is_empty());
    let request = m.get_var(h::REQUEST_TYPE);
    let needs_session = request.as_deref().is_none_or(types::needs_session);
    let mut session = None;
    if needs_session {
        let Some(session_id) = session_id else {
            dpma_log!(
                "Message '{}' dropped because of lacking session id",
                or_null(request.as_deref())
            );
            return None;
        };
        match super::store::find(&session_id) {
            None => {
                let uri = framing::response_uri(
                    or_null(m.get_var(h::RESPONSE_URI).as_deref()),
                    m.get_var(h::PJSIP_TRANSPORT).as_deref(),
                    framing::HANDSHAKE_REQUIRED_URI_BUF,
                );
                dpma_log!(
                    "Message '{}' inactive session '{}', sending handshake required response.",
                    or_null(request.as_deref()),
                    session_id
                );
                let net = m.get_var(h::ORIGINATION_NETWORK).unwrap_or_default();
                super::outgoing::send_handshake_required(
                    id.as_deref().unwrap_or(b""),
                    &uri,
                    None,
                    b"",
                    b"",
                    &net,
                );
                return None;
            }
            Some(s) => {
                if !validate_session(&m, &s) {
                    dpma_log!(
                        "Message '{}' dropped, session '{}' did not validate.",
                        or_null(request.as_deref()),
                        session_id
                    );
                    return None;
                }
                session = Some(s);
            }
        }
    }
    if let Some(why) = validate_message(&m) {
        dpma_log!("{}", why);
        dpma_log!(
            "Message '{}' dropped, message is not valid.",
            or_null(request.as_deref())
        );
        return None;
    }
    let message = Message::collect(INCOMING, |n| m.get_var(n), m.body().unwrap_or_default());
    let (session, parts) =
        PENDING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add(message, m, now(), session)?;
    finalize(session, parts)
}

/// `incoming_build_transaction` (FUN_0014f280): prune idle sessions and
/// transactions, expire auth incidents, then read
/// messages (each read waiting up to `timeout_ms`) until one completes a
/// transaction.  Returns None as soon as a read returns nothing (a timeout
/// or a wake from `transport::wake_reader`).
pub fn next_transaction(timeout_ms: i32) -> Option<Arc<Transaction>> {
    prune_inactive();
    crate::auth::expire_problems();
    loop {
        let m = crate::transport::read_msg(timeout_ms)?;
        if let Some(tx) = build(m) {
            return Some(Arc::new(tx));
        }
    }
}
