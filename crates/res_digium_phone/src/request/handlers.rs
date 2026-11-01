//! The request handlers (phone_request.c), registered by
//! `phone_request_load` (FUN_00177610) in this order: Echo, Handshake
//! (`session::handshake`), HTTPRequest, AsteriskRequest, UserlistRequest,
//! TokenRequest, ConfigRequest, FileRequest, VerifyRequest, PingRequest.
//!
//! Owner: P12 "request-handlers" (wave 3).  The registration list below is
//! final; only the handler bodies are to be written.

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

/// `handle_request_echo` (FUN_001764f0).
pub fn handle_echo(_tx: Arc<Transaction>) -> i32 {
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

/// `handle_request_ping` (FUN_001758e0).
pub fn handle_ping(_tx: Arc<Transaction>) -> i32 {
    0
}
