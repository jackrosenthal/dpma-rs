//! Call-related methods: queues, parking lots, recording, phonebook, and
//! the echo test method, plus the AMI hook helper (`amihook_action`) and
//! the parked-call Stasis router (phone_method_internal_api.c).
//!
//! Owner: P10 "methods-calls" (wave 2).

use crate::method::MethodCall;
use serde_json::Value;

/// Parking topic forwarding and the parked-call router (FUN_00186920
/// part; `handle_parked_call_message` FUN_0017b130).
pub fn load() -> Result<(), ()> {
    Ok(())
}

pub fn unload() {}

/// switchvox.users.parkingLots.getList (FUN_00181040, `user_can_read_parkinglot`).
pub fn parking_lots_get_list(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_xml_recording_start` (FUN_0017c910).
pub fn start_recording_xml(_c: &MethodCall, _p: &str, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_recording_start` (FUN_0017f730).
pub fn start_recording_json(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_xml_recording_stop` (FUN_0017c3d0).
pub fn stop_recording_xml(_c: &MethodCall, _p: &str, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_recording_stop` (FUN_0017e0e0).
pub fn stop_recording_json(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_queue_getlist` (FUN_00180960).
pub fn queues_get_list(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_queue_gettodaysstatus` (FUN_0017fbb0).
pub fn queues_get_todays_status(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_queue_login` (FUN_0017f030).
pub fn queue_login(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// callQueues.logout (FUN_0017e990).
pub fn queue_logout(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// callQueues.pause (FUN_0017cd80 → `queue_pause_member` FUN_0017c070).
pub fn queue_pause(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// callQueues.resume (FUN_0017c7b0 → FUN_0017c070).
pub fn queue_resume(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// phonebooks.entries.add (FUN_0017e4a0).
pub fn phonebook_entries_add(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// test.dpma.api.echo (FUN_0017c340): `{"response":{"method":M,"result":PARAMS}}`.
pub fn echo(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
