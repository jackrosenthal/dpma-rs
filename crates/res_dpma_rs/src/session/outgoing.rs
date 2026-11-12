//! Outgoing messages.
//!
//! `dpma_proto::message::Outgoing::encode` builds the MESSAGEs (every one
//! but a HandshakeResponse encrypted with the session's common password and
//! a fresh salt); each is sent as its own `ast_msg` through the
//! `digium_phone_module` extension, `message_delay` ms apart.  The
//! session's lock is held for the whole send.

use super::{now, Outgoing, Session, Transaction};
use crate::transport;
use dpma_ast::msg::Msg;
use dpma_ast::{dpma_debug, dpma_log};
use dpma_proto::message::SendContext;
use dpma_proto::{framing, headers as h};
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Send `out` to the phone of `session` (or log that there is none), as
/// `phone_msg_outgoing_send` does when called with a NULL session.
pub fn send_maybe(out: &Outgoing, session: Option<&Arc<Session>>) -> Result<(), ()> {
    match session {
        Some(s) => send(out, s),
        None => {
            if out.message_type().is_some() {
                dpma_log!("Outgoing message not sent due to missing session");
            } else {
                dpma_log!("Outgoing message is not request, response, or event type");
            }
            dpma_log!("error sending phone msg, session id {}", "NULL");
            Err(())
        }
    }
}

/// `phone_msg_outgoing_send` (FUN_0014c6b0): send `out` to the phone of
/// `session`.
pub fn send(out: &Outgoing, session: &Arc<Session>) -> Result<(), ()> {
    let Some(type_name) = out.message_type() else {
        dpma_log!("Outgoing message is not request, response, or event type");
        dpma_log!("error sending phone msg, session id {}", session.id);
        return Err(());
    };
    let mut st = session.lock();
    let messages = out.encode(&SendContext {
        password: &st.common_password,
        session_id: &session.id,
        origination_network: &st.origination_network,
        chain_certificate: st.intermediate_serial != 0,
    });
    let messages = match messages {
        Ok(m) => m,
        Err(e) => {
            dpma_log!("{}", e.message());
            dpma_log!("error sending phone msg, session id {}", session.id);
            return Err(());
        }
    };
    if out.error == 0 {
        dpma_debug!(
            3,
            "Sending to {} '{}' body length {}",
            out.response_uri,
            type_name,
            out.body.len()
        );
    } else {
        dpma_debug!(
            3,
            "Sending to {} '{}' ERROR={} body length {}",
            out.response_uri,
            type_name,
            out.error,
            out.body.len()
        );
    }
    let delay = crate::config::get().message_delay;
    let n = messages.len();
    for (i, message) in messages.iter().enumerate() {
        let Some(mut m) = transport::new_outgoing(&out.response_uri) else {
            dpma_log!("error sending phone msg, session id {}", session.id);
            return Err(());
        };
        let mut ok = m.set_exten(transport::SEND_EXTEN);
        for (name, value) in &message.headers {
            ok &= m.set_var(name, value);
        }
        ok &= m.set_body(&message.body);
        if !ok {
            drop(m);
            dpma_log!("Outgoing message failure res={}", -1);
            dpma_log!("error sending phone msg, session id {}", session.id);
            return Err(());
        }
        if transport::write_msg(m).is_err() {
            dpma_log!(
                "Sending to {} '{}' had failure writing message",
                out.response_uri,
                type_name
            );
        }
        if i + 1 != n {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(delay)));
        }
    }
    st.last_activity = now();
    Ok(())
}

/// `phone_msg_send_and_destroy` (FUN_0014e590): apply the transaction's
/// configured / unconfigured requests to the session (saving it when that
/// changes it), then send the transaction's outgoing message with its
/// session.
pub fn send_and_destroy(tx: &Arc<Transaction>) {
    let Some(session) = tx.session.as_ref() else {
        dpma_log!("Transaction missing session");
        return;
    };
    let changed = {
        let mut st = session.lock();
        let mut changed = false;
        if tx.configured.load(Ordering::SeqCst) && !st.configured {
            st.configured = true;
            changed = true;
        }
        if tx.unconfigured.load(Ordering::SeqCst) && st.configured {
            st.configured = false;
            changed = true;
        }
        changed
    };
    if changed {
        super::persist::update_db_info(session);
    }
    let out = tx.outgoing.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(out) = out.as_ref() {
        let _ = send(out, session);
    }
}

/// `phone_msg_send_timeout` (FUN_0014e7e0): answer `msg`, whose session
/// failed validation, with "Session Timeout" (-398) in the response type
/// of its request type.
///
/// Deviation: the reply goes over the transport of the request it
/// answers, `;transport=<PJSIP_TRANSPORT>` appended to the Response-URI
/// as for a transaction's replies.  The
/// official DPMA uses the raw Response-URI, so over TCP it answers over
/// UDP.  The URI is not truncated (the official DPMA keeps it in a string
/// field).
pub fn send_timeout(msg: &Msg, session: &Arc<Session>) -> Result<(), ()> {
    let uri = msg.get_var(h::RESPONSE_URI).unwrap_or_default();
    let full_contact = msg.get_var(h::RESPONSE_FULLCONTACT).unwrap_or_default();
    let request_type = msg.get_var(h::REQUEST_TYPE).unwrap_or_default();
    let id = msg.get_var(h::APPSERVER_ID).unwrap_or_default();
    if uri.is_empty() || request_type.is_empty() {
        return Err(());
    }
    let Some(response_type) = dpma_proto::types::response_type_for(&request_type) else {
        return Err(());
    };
    let uri = framing::response_uri(&uri, msg.get_var(h::PJSIP_TRANSPORT).as_deref(), usize::MAX);
    let out = Outgoing {
        error: dpma_proto::errors::msg::SESSION_TIMEOUT,
        response_uri: uri,
        full_contact,
        id,
        response_type: response_type.into(),
        ..Default::default()
    };
    let _ = send(&out, session);
    Ok(())
}

/// `phone_msg_send_event` (FUN_0014e030): send an event with `body` to the
/// session's phone.  `digium.assignment.update` goes out as the official
/// DPMA sends it: no event name, ID `bootcReset`, and Error-ID -398.  The
/// error text matches the official DPMA's error buffer.
pub fn send_event(session: &Arc<Session>, event: &[u8], body: &[u8]) -> Result<(), &'static str> {
    let mut out = Outgoing::new();
    {
        let st = session.lock();
        if st.response_uri.is_empty() {
            dpma_log!("Unable to send event to '{}' with no uri", st.mac);
            return Err("URI not available to send event");
        }
        out.response_uri = st.response_uri.clone();
    }
    if event == dpma_proto::types::events::ASSIGNMENT_UPDATE.as_bytes() {
        out.id = "bootcReset".into();
        out.error = dpma_proto::errors::msg::SESSION_TIMEOUT;
    } else {
        out.event_name = event.to_vec();
    }
    out.append(body);
    let _ = send(&out, session);
    Ok(())
}

/// FUN_0014bf10 (`phone_msg_outgoing_send_handshake_error`): reply
/// `HandshakeResponse` with Error-ID -398, unencrypted and unchunked, to a
/// message for an unknown session, so the phone handshakes again.
pub fn send_handshake_required(
    id: &[u8],
    response_uri: &[u8],
    session: Option<&Arc<Session>>,
    salt: &[u8],
    body: &[u8],
    origination_network: &[u8],
) {
    let Some(mut m) = transport::new_outgoing(response_uri) else {
        return;
    };
    m.set_exten(transport::SEND_EXTEN);
    m.set_var(h::RESPONSE_TYPE, "HandshakeResponse");
    m.set_var(h::ERROR_ID, "-398");
    if !response_uri.is_empty() {
        m.set_var(h::RESPONSE_URI, response_uri);
    }
    if let Some(s) = session {
        if !s.id.is_empty() {
            m.set_var(h::SESSION, &s.id);
        }
    }
    if !origination_network.is_empty() {
        m.set_var(h::ORIGINATION_NETWORK, origination_network);
    } else if let Some(s) = session {
        let net = s.lock().origination_network.clone();
        if !net.is_empty() {
            m.set_var(h::ORIGINATION_NETWORK, &net);
        }
    }
    if !salt.is_empty() {
        m.set_var(h::MESSAGE_SALT, salt);
    }
    if !body.is_empty() {
        m.set_body(body);
    }
    if !id.is_empty() {
        m.set_var(h::APPSERVER_ID, id);
    }
    if transport::write_msg(m).is_ok() {
        dpma_debug!(
            3,
            "Sending to {} '{}' ERROR={}",
            response_uri,
            "HandshakeResponse",
            "-398"
        );
    } else {
        dpma_log!(
            "Sending to {} '{}' ERROR={} had failure writing message",
            response_uri,
            "HandshakeResponse",
            "-398"
        );
    }
}
