//! Presence methods (phone_method_internal_api.c): getInfo
//! (FUN_0017d0e0), update (FUN_0017cf20), options.getList
//! (`handle_request_json_presence_getlist` FUN_0017dd50).  They use the
//! presence store in `users::presence`.
//!
//! Owner: P8 "users-runtime" (wave 2).

use crate::method::MethodCall;
use serde_json::Value;

pub fn get_info(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

pub fn update(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}

pub fn options_get_list(_c: &MethodCall, _p: &Value, _out: &mut String) -> i32 {
    dpma_proto::errors::request::METHOD_NOT_FOUND
}
