//! Phone method registries (phone_method.c).
//!
//! Three case-insensitive registries keyed by method name:
//!
//! * XML methods (container at 0x5f4e68),
//! * JSON methods (0x5f4e58), and
//! * AMI methods (0x5f4e60): names registered by AMI clients with
//!   `DPMAMessageRegister`; requests for them are forwarded to AMI as
//!   `DPMAMessage` events.
//!
//! Registering an XML or JSON method removes an AMI registration of the
//! same name (and vice versa for JSON, see `__phone_method_register`).
//!
//! Owner: P3 "request" (wave 1).

use crate::session::Transaction;
use std::sync::Arc;

/// Context of one method invocation.
pub struct MethodCall {
    /// Name of the authenticated phone (`[phone]` section) making the
    /// request.
    pub phone: String,
    /// Method name as requested.
    pub method: String,
    /// The transaction, when invoked for a phone request (None from test
    /// hooks).
    pub tx: Option<Arc<Transaction>>,
}

/// An XML method: `params` is the `<parameters>` element as XML text;
/// the response document is appended to `out`.  Returns 0 or a request
/// error code (`dpma_proto::errors::request`).
pub type XmlMethod = fn(call: &MethodCall, params: &str, out: &mut String) -> i32;

/// A JSON method: `params` is the request's `"parameters"` value.
pub type JsonMethod = fn(call: &MethodCall, params: &serde_json::Value, out: &mut String) -> i32;

/// `phone_method_load` (FUN_00178c10).
pub fn load() -> Result<(), ()> {
    Ok(())
}

/// `phone_method_unload` (FUN_00178dd0).
pub fn unload() {}

pub fn register_xml(_name: &str, _f: XmlMethod) -> Result<(), ()> {
    Ok(())
}

pub fn register_json(_name: &str, _f: JsonMethod) -> Result<(), ()> {
    Ok(())
}

/// Register a name handled by AMI (`DPMAMessageRegister`).
pub fn register_ami(_name: &str) -> Result<(), ()> {
    Ok(())
}

pub fn unregister_xml(_name: &str) {}

pub fn unregister_json(_name: &str) {}

pub fn unregister_ami(_name: &str) {}

pub fn find_xml(_name: &str) -> Option<XmlMethod> {
    None
}

pub fn find_json(_name: &str) -> Option<JsonMethod> {
    None
}

pub fn is_ami(_name: &str) -> bool {
    false
}

/// Test hooks (feature "devtest"), e.g., invoking a JSON method for a
/// phone from the CLI.
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
