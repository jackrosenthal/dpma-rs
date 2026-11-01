//! Outgoing messages: `phone_msg_outgoing_send` (FUN_0014c6b0),
//! `phone_msg_send_and_destroy` (FUN_0014e590), `phone_msg_send_timeout`
//! (FUN_0014e7e0), `phone_msg_send_event` (FUN_0014e030), and the
//! handshake error reply (`phone_msg_outgoing_send_handshake_error`,
//! FUN_0014bf10).
//!
//! Every message but a HandshakeResponse is encrypted with the session's
//! common password and a fresh salt; the body is split into chunks (see
//! `dpma_proto::framing`), each sent as its own `ast_msg` through the
//! `digium_phone_module` extension, `message_delay` ms apart.  The
//! session's lock is held for the whole send.

use super::{now, Outgoing, Session, Transaction};
use crate::transport;
use dpma_ast::msg::Msg;
use dpma_ast::{dpma_debug, dpma_log};
use dpma_proto::crypto::{self, Encryptor, SALT_LEN};
use dpma_proto::{framing, headers as h};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

/// The request id counter (0x5e8060): 1..100000, advanced once per send.
static COUNTER: AtomicI32 = AtomicI32::new(0);

fn next_counter() -> i32 {
    let mut cur = COUNTER.load(Ordering::Relaxed);
    loop {
        let next = if cur + 1 > 100000 { 1 } else { cur + 1 };
        match COUNTER.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(c) => cur = c,
        }
    }
}

/// Encrypt a header field with the message's salt
/// (`send_encrypt_hdr_helper`, 0x515-byte buffer).
fn encrypt_header(plain: &[u8], password: &[u8], salt: &[u8; SALT_LEN]) -> Vec<u8> {
    super::persist::encrypt_helper(plain, password, salt, crypto::CIPHERTEXT_B64_BUF)
}

/// Send `out` to the phone of `session` (or log that there is none), as
/// `phone_msg_outgoing_send` does when called with a NULL session.
pub fn send_maybe(out: &Outgoing, session: Option<&Arc<Session>>) -> Result<(), ()> {
    match session {
        Some(s) => send(out, s),
        None => {
            if message_type(out).is_some() {
                dpma_log!("Outgoing message not sent due to missing session");
            } else {
                dpma_log!("Outgoing message is not request, response, or event type");
            }
            dpma_log!("error sending phone msg, session id {}", "NULL");
            Err(())
        }
    }
}

/// The type the original logs: the response type, else the request type,
/// else the event name, else "Error" for an error reply.
fn message_type(out: &Outgoing) -> Option<&[u8]> {
    [&out.response_type, &out.request_type, &out.event_name]
        .into_iter()
        .find(|t| !t.is_empty())
        .map(|t| t.as_slice())
        .or((out.error != 0).then_some(b"Error"))
}

/// `phone_msg_outgoing_send` (FUN_0014c6b0): send `out` to the phone of
/// `session`: chunking, encryption, and headers.
pub fn send(out: &Outgoing, session: &Arc<Session>) -> Result<(), ()> {
    let Some(type_name) = message_type(out) else {
        dpma_log!("Outgoing message is not request, response, or event type");
        dpma_log!("error sending phone msg, session id {}", session.id);
        return Err(());
    };
    let mut st = session.lock();
    let counter = next_counter();

    let handshake = out.response_type.eq_ignore_ascii_case(b"HandshakeResponse");
    let (encrypted, handshake_version, salt) = if handshake {
        (false, (st.intermediate_serial != 0).then_some("1"), None)
    } else {
        // FUN_00151840 logs its own failure; the salt is used regardless.
        (true, None, Some(crypto::new_salt().unwrap_or([0; SALT_LEN])))
    };
    let salt_hex = salt.as_ref().map(crypto::salt_to_hex).unwrap_or_default();

    let mut body = out.body.clone();
    let error_id = if out.error != 0 {
        body.extend_from_slice(framing::error_body(out.error).as_bytes());
        out.error.to_string().into_bytes()
    } else {
        Vec::new()
    };
    let limit = framing::chunk_limit(encrypted, framing::is_tcp(&out.response_uri));
    if body.is_empty() {
        body.extend_from_slice(framing::EMPTY_BODY.as_bytes());
    }

    // Header fields encrypted with this message's salt (encrypted messages
    // only).
    let (enc_password, enc_token) = match salt.as_ref() {
        Some(salt) => (
            (!out.encrypted_password.is_empty())
                .then(|| encrypt_header(&out.encrypted_password, &st.common_password, salt)),
            (!out.config_token.is_empty()).then(|| encrypt_header(&out.config_token, &st.common_password, salt)),
        ),
        None => (None, None),
    };

    if error_id.is_empty() {
        dpma_debug!(3, "Sending to {} '{}' body length {}", out.response_uri, type_name, body.len());
    } else {
        dpma_debug!(3, "Sending to {} '{}' ERROR={} body length {}", out.response_uri, type_name, out.error, body.len());
    }

    let prefix = if !out.event_name.is_empty() || !error_id.is_empty() { framing::COMMAND_PREFIX } else { "" };
    let chunks = framing::split(&body, prefix, limit, handshake);
    let mut encryptor = match salt.as_ref() {
        Some(salt) => match Encryptor::new(&st.common_password, salt) {
            Ok(e) => Some(e),
            Err(_) => {
                dpma_log!("Call to init_encryption failed");
                None
            }
        },
        None => None,
    };
    let delay = crate::config::get().message_delay;

    let n = chunks.len();
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i + 1 == n;
        let Some(mut m) = transport::new_outgoing(&out.response_uri) else {
            dpma_log!("error sending phone msg, session id {}", session.id);
            return Err(());
        };
        let mut ok = m.set_exten(transport::SEND_EXTEN);
        let mut set = |name: &str, value: &[u8]| ok &= m.set_var(name, value);
        if !out.response_type.is_empty() {
            set(h::RESPONSE_TYPE, &out.response_type);
        } else if !out.request_type.is_empty() {
            set(h::REQUEST_TYPE, &out.request_type);
        }
        if let Some(v) = handshake_version {
            set(h::HANDSHAKE_VERSION, v.as_bytes());
        }
        for (name, value) in [
            (h::USERNAME, &out.username),
            (h::RESPONSE_URI, &out.response_uri),
            (h::RESPONSE_FULLCONTACT, &out.full_contact),
            (h::TOKEN_AUTH_REQUIREMENTS, &out.token_auth_requirements),
            (h::USERLIST_AUTH_REQUIREMENTS, &out.userlist_auth_requirements),
            (h::PASSWORD, &out.password),
            (h::EVENT_NAME, &out.event_name),
            (h::SESSION, &session.id),
            (h::ORIGINATION_NETWORK, &st.origination_network),
            (h::HTTP_STATUS, &out.http_status),
            (h::MD5, &out.md5),
            (h::ERROR_ID, &error_id),
        ] {
            if !value.is_empty() {
                set(name, value);
            }
        }
        if let Some(v) = &enc_password {
            set(h::PASSWORD, v);
        }
        if let Some(v) = &enc_token {
            set(h::CONFIG_TOKEN, v);
        }

        // The body: plaintext, or this chunk's part of the CBC stream (the
        // last one with the padding), base64 encoded on its own.
        if encrypted {
            let text = match encryptor.as_mut().map(|e| e.update(&chunk.plain)) {
                Some(Ok(mut c)) => {
                    if !last {
                        crypto::base64_encode_max(&c, crypto::CIPHERTEXT_B64_BUF)
                    } else if let Some(Ok(f)) = encryptor.take().map(Encryptor::finish) {
                        c.extend(f);
                        crypto::base64_encode_max(&c, crypto::CIPHERTEXT_B64_BUF)
                    } else {
                        dpma_log!("Call to encrypt_final returned failure");
                        String::new()
                    }
                }
                _ => {
                    dpma_log!("Call to encrypt_data returned failure");
                    String::new()
                }
            };
            ok &= m.set_body(&text);
        } else {
            ok &= m.set_body(&chunk.plain);
        }
        if !salt_hex.is_empty() {
            ok &= m.set_var(h::MESSAGE_SALT, &salt_hex);
        }
        if let Some(seq) = chunk.sequence {
            m.set_var(h::MESSAGE_SEQUENCE, seq.to_string());
        }
        if chunk.finished {
            m.set_var(h::MESSAGE_FINISHED, "1");
        }
        if !out.id.is_empty() {
            m.set_var(h::APPSERVER_ID, &out.id);
        } else if !out.request_type.is_empty() {
            m.set_var(h::APPSERVER_ID, counter.to_string());
        }
        if !ok {
            drop(m);
            dpma_log!("Outgoing message failure res={}", -1);
            dpma_log!("error sending phone msg, session id {}", session.id);
            return Err(());
        }
        if transport::write_msg(m).is_err() {
            dpma_log!("Sending to {} '{}' had failure writing message", out.response_uri, type_name);
        }
        if !last {
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
/// Deviation (port plan section 8, item 11): the reply goes over the
/// transport of the request it answers, `;transport=<PJSIP_TRANSPORT>`
/// appended to the Response-URI as for a transaction's replies.  The
/// original uses the raw Response-URI, so over TCP it answers over UDP.
/// The URI is not truncated (the original keeps it in a string field).
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
/// session's phone.  `digium.assignment.update` goes out as the original
/// sends it: no event name, ID `bootcReset`, and Error-ID -398.  The error
/// text matches the original's error buffer.
pub fn send_event(session: &Arc<Session>, event: &[u8], body: &[u8]) -> Result<(), Vec<u8>> {
    let mut out = Outgoing::new();
    {
        let st = session.lock();
        if st.response_uri.is_empty() {
            dpma_log!("Unable to send event to '{}' with no uri", st.mac);
            return Err("URI not available to send event".into());
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
    let Some(mut m) = transport::new_outgoing(response_uri) else { return };
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
        dpma_debug!(3, "Sending to {} '{}' ERROR={}", response_uri, "HandshakeResponse", "-398");
    } else {
        dpma_log!("Sending to {} '{}' ERROR={} had failure writing message", response_uri, "HandshakeResponse", "-398");
    }
}
