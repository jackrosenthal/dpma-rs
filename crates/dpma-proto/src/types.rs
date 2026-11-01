//! Request and response types (`X-Digium-AppServer-RequestType` /
//! `X-Digium-AppServer-ResponseType`).

pub const HANDSHAKE: &str = "Handshake";
pub const ECHO: &str = "Echo";
/// Accepted without a session by `validate_message`; no handler is
/// registered for it in 3.6.13.
pub const PRECONFIG: &str = "Preconfig";
pub const HTTP_REQUEST: &str = "HTTPRequest";
pub const ASTERISK_REQUEST: &str = "AsteriskRequest";
pub const USERLIST_REQUEST: &str = "UserlistRequest";
pub const TOKEN_REQUEST: &str = "TokenRequest";
pub const CONFIG_REQUEST: &str = "ConfigRequest";
pub const FILE_REQUEST: &str = "FileRequest";
pub const VERIFY_REQUEST: &str = "VerifyRequest";
pub const PING_REQUEST: &str = "PingRequest";

/// (request type, response type, requires session), in the order
/// `phone_request_load` registers them.
pub const REQUESTS: &[(&str, &str, bool)] = &[
    (ECHO, "EchoResponse", false),
    (HANDSHAKE, "HandshakeResponse", false),
    (HTTP_REQUEST, "HTTPResponse", true),
    (ASTERISK_REQUEST, "AsteriskResponse", true),
    (USERLIST_REQUEST, "UserlistResponse", true),
    (TOKEN_REQUEST, "TokenResponse", true),
    (CONFIG_REQUEST, "ConfigResponse", true),
    (FILE_REQUEST, "FileResponse", true),
    (VERIFY_REQUEST, "VerifyResponse", true),
    (PING_REQUEST, "PingResponse", true),
];

/// The response type that answers `request` (case insensitive), as used by
/// `phone_msg_send_timeout`.
pub fn response_type_for(request: &str) -> Option<&'static str> {
    REQUESTS
        .iter()
        .find(|(r, _, _)| r.eq_ignore_ascii_case(request))
        .map(|(_, resp, _)| *resp)
}

/// Event names sent in `X-Event-Name` / `X-Event-Type`.
pub mod events {
    pub const CONFIG_UPDATE: &str = "digium.config.update";
    pub const ASSIGNMENT_UPDATE: &str = "digium.assignment.update";
    pub const VOICEMAIL_PLAY_LOCATION: &str = "digium.voicemail.play.location.change";
    pub const START_RECORDING_SUCCESS: &str = "digium.startRecording.success";
    pub const STOP_RECORDING_SUCCESS: &str = "digium.stopRecording.success";
}
