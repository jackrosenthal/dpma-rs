//! Voicemail methods and the voicemail message trackers
//! (phone_method_internal_api.c: `vm_*`, `handle_request_json_vm_*`,
//! `mark_read_unread_helper_json`, `dial_phone_event_app`).
//!
//! Owner: P9 "methods-vm" (wave 2).

use crate::method::MethodCall;
use serde_json::Value;

/// Create the phone-user tracker container (FUN_00186920 part).
pub fn load() -> Result<(), ()> {
    Ok(())
}

pub fn unload() {}

/// `handle_request_json_vm_getlist` (FUN_001859c0).
pub fn get_list(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// FUN_0017d8d0 (getFolderList).
pub fn get_folder_list(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_vm_move` (FUN_00184200).
pub fn move_message(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_vm_remove` (FUN_00183500).
pub fn remove(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_vm_forward` (FUN_00182660).
pub fn forward(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// markRead (FUN_001859b0 → `mark_read_unread_helper_json` FUN_001850e0).
pub fn mark_read(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// markUnread (FUN_001859a0 → FUN_001850e0).
pub fn mark_unread(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// `handle_request_json_vm_play` (FUN_00181d40).
pub fn play(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
