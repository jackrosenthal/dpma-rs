//! Request dispatch (dpma_request.c): the request-type handler table, the
//! `DPMA_request` and `DPMA_extended` thread pools, and the XML/JSON error
//! responses.
//!
//! Owner: P3 "request" (wave 1).  `handlers.rs` is owned by P12
//! "request-handlers" (wave 3).

pub mod handlers;

use crate::session::Transaction;
use std::sync::Arc;

/// A request-type handler (`request_register_handler`); runs on the
/// `DPMA_request` pool.  The transaction's `outgoing` is allocated (and
/// its response type, URI, full contact, and id filled in) before the
/// handler runs when the registration has a response type.
pub type Handler = fn(tx: Arc<Transaction>) -> i32;

/// `request_load` (FUN_00189890): create the handler table, register the
/// request handlers (`handlers::load`, i.e., `phone_request_load`), and
/// create the thread pools (initial and maximum sizes from
/// `transaction_initial_threads` / `transaction_max_threads`, idle timeout
/// 60 s, auto increment 1).
pub fn load() -> Result<(), ()> {
    handlers::load()
}

/// `request_unload` (FUN_00189820).
pub fn unload() {}

/// `request_register_handler` (FUN_00188bf0).
pub fn register_handler(
    _request_type: &'static str,
    _response_type: Option<&'static str>,
    _requires_session: bool,
    _handler: Handler,
) -> Result<(), ()> {
    Ok(())
}

/// `request_handle_incoming` (FUN_00188d20): look up the handler, check
/// the session requirement, allocate the outgoing message, and push the
/// handler onto the request pool.
pub fn handle_incoming(_tx: Arc<Transaction>) -> Result<(), ()> {
    Err(())
}

/// `request_extended_task_push` (FUN_00188b30): run `task` on the
/// `DPMA_extended` pool (long-running work such as dialing a phone).
pub fn push_extended(_task: Box<dyn FnOnce() + Send + 'static>) -> Result<(), ()> {
    Err(())
}

/// `create_error_response_xml` (FUN_00189280): append the XML error
/// document for `code` (method "NA" when empty).
pub fn error_response_xml(_out: &mut String, _method: &str, _code: i32) {}

/// `create_error_response_json` (FUN_00189450): append the JSON error
/// document; the message is "<code text>: <detail>".
pub fn error_response_json(_out: &mut String, _method: &str, _code: i32, _detail: &str) {}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
