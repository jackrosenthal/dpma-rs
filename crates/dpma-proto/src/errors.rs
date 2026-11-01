//! Error codes and texts.
//!
//! Two independent sets exist in the original:
//!
//! * message errors, sent as `X-Digium-AppServer-Error-ID: <code>` with a
//!   `<error msg="..." />` body by `phone_msg_outgoing_send` (table at
//!   0x5bcce8), and
//! * request (method) errors, sent inside XML or JSON responses to
//!   AsteriskRequest / HTTPRequest (`create_error_response_xml`
//!   0x189280, `create_error_response_json` 0x189450).

/// Message error codes (`outgoing->error`).
pub mod msg {
    pub const UNKNOWN: i32 = -1;
    pub const FILE_NOT_FOUND: i32 = -98;
    pub const INVALID_TOKEN: i32 = -192;
    pub const USER_NOT_FOUND: i32 = -195;
    pub const INVALID_CONFIG_PASSWORD: i32 = -198;
    pub const INVALID_PASSWORD: i32 = -199;
    pub const CREDENTIALS_NOT_PROVIDED: i32 = -200;
    pub const SESSION_TIMEOUT: i32 = -398;
    pub const INVALID_CERTIFICATE: i32 = -400;
}

/// Text for a message error code, exactly as the original sends it
/// (including its spelling mistakes).
pub fn msg_error_text(code: i32) -> &'static str {
    match code {
        msg::UNKNOWN => "An Unknown Error has occurred",
        msg::FILE_NOT_FOUND => "The file requested was not found",
        msg::INVALID_TOKEN => "User Config token presented is invalid",
        msg::USER_NOT_FOUND => "Specfied user not found",
        msg::INVALID_CONFIG_PASSWORD => "An Invalid configuration password was provided",
        msg::INVALID_PASSWORD => "An invalid password was provided",
        msg::CREDENTIALS_NOT_PROVIDED => "The requested credentials where not provided",
        msg::SESSION_TIMEOUT => "Session Timeout",
        msg::INVALID_CERTIFICATE => "Invalid Certificate",
        _ => "Unknown error",
    }
}

/// Request (method) error codes.
pub mod request {
    pub const EMPTY: i32 = 10001;
    pub const PARSE: i32 = 10002;
    pub const MISSING_METHOD: i32 = 10003;
    pub const METHOD_NOT_FOUND: i32 = 10005;
    pub const PARAMS_NOT_FOUND: i32 = 10011;
    pub const PHONE_EVENT_APP_FAILED: i32 = 10012;
    pub const PHONEBOOK_ENTRY_EXISTS: i32 = 15688;
    pub const NOT_PERMITTED: i32 = 27168;
    pub const PRESENCE_ACCOUNT_MISMATCH: i32 = 42013;
    pub const INVALID_PHONEBOOK_ID: i32 = 51141;
    pub const INVALID_MAILBOX_FOLDER: i32 = 64125;
    pub const INVALID_PRESENCE: i32 = 90039;
    pub const AUTH_FAILED: i32 = 99999;
}

/// Text for a request error code.
pub fn request_error_text(code: i32) -> &'static str {
    match code {
        request::EMPTY => "Your request was empty",
        request::PARSE => "Error parsing request",
        request::MISSING_METHOD => "Missing method name",
        request::METHOD_NOT_FOUND => "Method not found",
        request::PARAMS_NOT_FOUND => "Parameters not found",
        request::PHONE_EVENT_APP_FAILED => "Call to phone event application failed to complete",
        request::PHONEBOOK_ENTRY_EXISTS => "Phonebook entry already exists",
        request::NOT_PERMITTED => "Your account is not permitted to run this action",
        request::PRESENCE_ACCOUNT_MISMATCH => "The account id does not match the owners presence option",
        request::INVALID_PHONEBOOK_ID => "Invalid phonebook_id",
        request::INVALID_MAILBOX_FOLDER => "Invalid mailbox folder",
        request::INVALID_PRESENCE => "Invalid presence",
        request::AUTH_FAILED => "Authentication failed for this request",
        _ => "error msg unknown",
    }
}
