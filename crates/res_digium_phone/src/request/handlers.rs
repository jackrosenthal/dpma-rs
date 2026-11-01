//! The request handlers (phone_request.c), registered by
//! `phone_request_load` (FUN_00177610) in this order: Echo, Handshake
//! (`session::handshake`), HTTPRequest, AsteriskRequest, UserlistRequest,
//! TokenRequest, ConfigRequest, FileRequest, VerifyRequest, PingRequest.
//!
//! Owner: P12 "request-handlers" (wave 3); `handle_echo` and `handle_ping`
//! by P7 "session" (wave 2).  The registration list below matches the
//! original's.

use super::register_handler;
use crate::session::Transaction;
use std::sync::Arc;

/// `phone_request_load`.
pub fn load() -> Result<(), ()> {
    use dpma_proto::types::*;
    let mut res = Ok(());
    let table: [(&'static str, Option<&'static str>, bool, super::Handler); 10] = [
        (ECHO, None, false, handle_echo),
        (HANDSHAKE, Some("HandshakeResponse"), false, crate::session::handshake::handle_handshake),
        (HTTP_REQUEST, Some("HTTPResponse"), true, handle_http_or_asterisk),
        (ASTERISK_REQUEST, Some("AsteriskResponse"), true, handle_http_or_asterisk),
        (USERLIST_REQUEST, Some("UserlistResponse"), true, handle_userlist),
        (TOKEN_REQUEST, Some("TokenResponse"), true, handle_token),
        (CONFIG_REQUEST, Some("ConfigResponse"), true, handle_config),
        (FILE_REQUEST, Some("FileResponse"), true, handle_file),
        (VERIFY_REQUEST, Some("VerifyResponse"), true, handle_verify),
        (PING_REQUEST, Some("PingResponse"), true, handle_ping),
    ];
    for (req, resp, session, h) in table {
        if register_handler(req, resp, session, h).is_err() {
            res = Err(());
        }
    }
    if res.is_err() {
        dpma_ast::ast_log!(dpma_ast::log::LOG_ERROR, "DPMA: Unable to load all phone request handlers");
    }
    res
}

/// `handle_request_echo` (FUN_001764f0): answer directly (not through the
/// session layer, so unencrypted and in one message) with an EchoResponse
/// carrying Error-ID 0, the request's ID and origination network, and its
/// body.  (Implemented by P7 so the stack can be tested end to end.)
pub fn handle_echo(tx: Arc<Transaction>) -> i32 {
    use dpma_proto::headers as h;
    let var = |name: &str| tx.first_msg.as_ref().and_then(|m| m.get_var(name));
    let uri = var(h::RESPONSE_URI);
    let Some(m) = crate::transport::new_outgoing(uri.as_deref().unwrap_or("")) else {
        dpma_ast::ast_log!(dpma_ast::log::LOG_ERROR, "Unable to allocate msg");
        return 0;
    };
    m.set_exten(crate::transport::SEND_EXTEN);
    m.set_var(h::RESPONSE_TYPE, "EchoResponse");
    m.set_var(h::ERROR_ID, "0");
    if let Some(uri) = uri.filter(|u| !u.is_empty()) {
        let uri = dpma_proto::framing::response_uri(
            &uri,
            var(h::PJSIP_TRANSPORT).as_deref(),
            dpma_proto::framing::RESPONSE_URI_BUF,
        );
        m.set_var(h::RESPONSE_URI, &uri);
    }
    if let Some(id) = var(h::APPSERVER_ID).filter(|i| !i.is_empty()) {
        m.set_var(h::APPSERVER_ID, &id);
    }
    if let Some(net) = var(h::ORIGINATION_NETWORK).filter(|n| !n.is_empty()) {
        m.set_var(h::ORIGINATION_NETWORK, &net);
    }
    m.set_body_bytes(&tx.body_bytes);
    let _ = crate::transport::write_msg(m);
    0
}

/// `handle_request_asterisk` / `handle_request_xml` / `handle_request_json`
/// (FUN_00176a60), including AMI forwarding (`__handle_request_ami`).
pub fn handle_http_or_asterisk(_tx: Arc<Transaction>) -> i32 {
    0
}

/// `handle_request_userlist` (FUN_001762c0).
pub fn handle_userlist(_tx: Arc<Transaction>) -> i32 {
    0
}

/// `handle_request_token` (FUN_00175d50).
pub fn handle_token(_tx: Arc<Transaction>) -> i32 {
    0
}

/// `handle_request_config` (FUN_00175be0).
pub fn handle_config(_tx: Arc<Transaction>) -> i32 {
    0
}

/// `handle_request_file` (FUN_001758f0).
pub fn handle_file(_tx: Arc<Transaction>) -> i32 {
    0
}

/// `handle_request_verify` (FUN_00176750).
pub fn handle_verify(_tx: Arc<Transaction>) -> i32 {
    0
}

/// `handle_request_ping` (FUN_001758e0): send the (empty) PingResponse.
/// (Implemented by P7 so the stack can be tested end to end.)
pub fn handle_ping(tx: Arc<Transaction>) -> i32 {
    crate::session::send_and_destroy(&tx);
    0
}
