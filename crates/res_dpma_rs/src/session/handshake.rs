//! The Handshake request.
//!
//! A phone sends its certificate(s) in the body.  The server drops any
//! other session of the same MAC, creates a session (verifying the
//! certificates), generates the 40-byte common password, and answers with
//! a HandshakeResponse: the common password RSA-encrypted to the phone's
//! key in `X-Digium-AppServer-Password`, the AppServer certificate in the
//! body, and the authentication requirement headers.  A failed
//! verification gets no answer, only an auth incident.

use super::store::{self, alloc, NewSession};
use super::{user_agent_of, Outgoing, Session, Transaction};
use crate::config::auth;
use dpma_ast::dpma_log;
use dpma_proto::headers as h;
use std::sync::Arc;

/// `prune_session_by_mac`: drop every other session of `mac`.
fn prune_session_by_mac(mac: &[u8]) {
    for s in store::all() {
        let contact = {
            let st = s.lock();
            if st.mac.is_empty() || !st.mac.eq_ignore_ascii_case(mac) {
                continue;
            }
            st.contact.clone()
        };
        dpma_log!(
            "Pruning old session for '{}' on new handshake from mac '{}'.",
            contact,
            mac
        );
        store::invalidate(&s);
    }
}

/// `phone_msg_set_common_password` (FUN_0014bb00): generate the session's
/// common password and put it, RSA-encrypted to the phone's key and base64
/// encoded, in `out.password`.
pub(crate) fn set_common_password(out: &mut Outgoing, session: &Arc<Session>) -> Result<(), ()> {
    let mut st = session.lock();
    if st.certificate.is_none() {
        dpma_log!("Client cert is missing from session");
        return Err(());
    }
    let Some(key) = st.public_key.clone() else {
        dpma_log!("failed to get pkey during common password generation");
        return Err(());
    };
    if key.rsa().is_none() {
        dpma_log!("failed to get rsa during common password generation");
        return Err(());
    }
    let password = dpma_proto::crypto::new_common_password().map_err(|_| ())?;
    st.common_password = password.clone();
    // RSA_public_encrypt's -1 on failure becomes an empty base64 string.
    out.password = dpma_proto::crypto::encrypt_common_password(&key, &password)
        .unwrap_or_default()
        .into_bytes();
    Ok(())
}

/// `set_auth_requirements` (FUN_00149710): the HandshakeResponse's
/// `Userlist-Auth-Requirements` and `Token-Auth-Requirements`.
pub(crate) fn set_auth_requirements(out: &mut Outgoing, flags: u32) {
    out.userlist_auth_requirements = if flags & auth::USER == 0 {
        "disabled"
    } else if flags & auth::USERLIST_GLOBALPIN != 0 {
        "configpass"
    } else {
        "none"
    }
    .into();
    let mut list: Vec<&str> = Vec::new();
    if flags & auth::MAC != 0 {
        list.push("mac");
    }
    if flags & auth::USER != 0 {
        list.push("user");
    }
    if flags & auth::PIN != 0 {
        list.push("pass");
    }
    if flags & auth::GLOBALPIN != 0 {
        list.push("configpass");
    }
    out.token_auth_requirements = if list.is_empty() {
        "user".into()
    } else {
        list.join(",").into_bytes()
    };
}

/// Request handler for "Handshake" (`handle_request_handshake`,
/// FUN_0014dbe0).
pub fn handle_handshake(tx: Arc<Transaction>) -> i32 {
    let Some(msg) = tx.first_msg.as_ref() else {
        return 0;
    };
    let mac = msg.get_var(h::MAC_ADDRESS);
    let user_agent = user_agent_of(msg);
    let origination_network = msg.get_var(h::ORIGINATION_NETWORK);
    let contact = match msg.get_var(h::CONTACT).filter(|c| !c.is_empty()) {
        Some(c) => c,
        None => match msg.get_var(h::FROM).filter(|c| !c.is_empty()) {
            Some(c) => c,
            None => {
                dpma_log!("Message dropped because of missing contact or from header");
                return 0;
            }
        },
    };
    let contact = dpma_proto::uri::get_in_brackets(&contact);
    if let Some(mac) = mac.as_deref().filter(|m| !m.is_empty()) {
        prune_session_by_mac(mac);
    }

    // Deviation (port plan section 8, item 12): Asterisk 24 strips the
    // trailing CR/LF of every MESSAGE body chunk, so restore the line
    // breaks lost at PEM boundaries before the certificates are read.
    let client_cert = dpma_proto::cert::restore_pem_newlines(&tx.body);
    let Some(session) = alloc(&NewSession {
        mac: mac.as_deref(),
        contact: &contact,
        response_uri: &tx.response_uri,
        client_cert: &client_cert,
        id: None,
        user_agent: user_agent.as_deref(),
        origination_network: origination_network.as_deref(),
    }) else {
        dpma_log!("Session could not be created due to invalid credentials");
        crate::auth::issue_alert(&tx, "invalid credentials");
        return 0;
    };

    let mut guard = tx.outgoing.lock().unwrap_or_else(|e| e.into_inner());
    let Some(out) = guard.as_mut() else {
        drop(guard);
        store::invalidate(&session);
        dpma_log!("Session could not be created due to no outgoing buffer");
        return 0;
    };
    if set_common_password(out, &session).is_err() {
        dpma_log!("Error generating common pass during handshake");
        *guard = None;
        drop(guard);
        store::invalidate(&session);
        return 0;
    }
    // The official DPMA appends its built-in AppServer certificate here.
    store::with_trust(|t| {
        if let Some(t) = t {
            out.append(&t.appserver_pem);
        }
    });
    let flags = session.auth_flags();
    set_auth_requirements(out, flags);
    let _ = super::outgoing::send(out, &session);
    *guard = None;
    0
}
