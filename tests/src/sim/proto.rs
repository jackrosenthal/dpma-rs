//! Protocol constants and the documents of the request types.

/// The prefix of the AppServer headers.
pub const P: &str = "X-Digium-AppServer-";
/// Transaction id chosen by the sender, echoed in the reply.
pub const H_ID: &str = "X-Digium-AppServer-ID";
/// Session id.
pub const H_SESSION: &str = "X-Digium-AppServer-Session";
/// Request type.
pub const H_REQUEST_TYPE: &str = "X-Digium-AppServer-RequestType";
/// Response type.
pub const H_RESPONSE_TYPE: &str = "X-Digium-AppServer-ResponseType";
/// The phone's MAC address.
pub const H_MAC: &str = "X-Digium-AppServer-MACAddress";
/// 16 hex digits; present when the message is encrypted.
pub const H_SALT: &str = "X-Digium-AppServer-Message-Salt";
/// Chunk number from 0.
pub const H_SEQUENCE: &str = "X-Digium-AppServer-Message-Sequence";
/// `1` on the last chunk.
pub const H_FINISHED: &str = "X-Digium-AppServer-Message-Finished";
/// User password (encrypted), or the RSA-encrypted common password of a
/// HandshakeResponse.
pub const H_PASSWORD: &str = "X-Digium-AppServer-Password";
/// Configuration password (encrypted).
pub const H_CONFIG_PASSWORD: &str = "X-Digium-AppServer-ConfigPassword";
/// Configuration token (encrypted).
pub const H_CONFIG_TOKEN: &str = "X-Digium-AppServer-Config-Token";
/// User (phone) name.
pub const H_USERNAME: &str = "X-Digium-AppServer-Username";
/// Message error code.
pub const H_ERROR: &str = "X-Digium-AppServer-Error-ID";
/// `1` when the phone used the certificate-chain form.
pub const H_HANDSHAKE_VERSION: &str = "X-Digium-AppServer-Handshake-Version";
/// Event name of server-to-phone events.
pub const H_EVENT: &str = "X-Event-Name";
/// Origination network.
pub const H_ORIGINATION: &str = "X-Origination-Network";

/// Request types that need no session (`validate_message`).
pub const NO_SESSION_TYPES: [&str; 3] = ["handshake", "echo", "preconfig"];

/// Whether requests of this type carry a session.
pub fn needs_session(request_type: &str) -> bool {
    !NO_SESSION_TYPES.contains(&request_type.to_ascii_lowercase().as_str())
}

/// The response type the server answers a request type with.
pub fn response_for(request_type: &str) -> Option<&'static str> {
    Some(match request_type {
        "Echo" => "EchoResponse",
        "Handshake" => "HandshakeResponse",
        "HTTPRequest" => "HTTPResponse",
        "AsteriskRequest" => "AsteriskResponse",
        "UserlistRequest" => "UserlistResponse",
        "TokenRequest" => "TokenResponse",
        "ConfigRequest" => "ConfigResponse",
        "FileRequest" => "FileResponse",
        "VerifyRequest" => "VerifyResponse",
        "PingRequest" => "PingResponse",
        _ => return None,
    })
}

/// The server prefixes every chunk of events and error replies with this.
pub const COMMAND_PREFIX: &[u8] = b"Command: ";

/// The texts of the server's `<error msg=... />` bodies for message error
/// codes (`X-Digium-AppServer-Error-ID`; the official DPMA's table at
/// 0x5bcce8).  Other codes print "Unknown error".
pub fn msg_error_text(code: i32) -> &'static str {
    match code {
        -1 => "An Unknown Error has occurred",
        -98 => "The file requested was not found",
        -192 => "User Config token presented is invalid",
        -195 => "Specfied user not found",
        -198 => "An Invalid configuration password was provided",
        -199 => "An invalid password was provided",
        -200 => "The requested credentials where not provided",
        -398 => "Session Timeout",
        -400 => "Invalid Certificate",
        _ => "Unknown error",
    }
}

/// The body `phone_msg_outgoing_send` appends for a non-zero error.
pub fn error_body(code: i32) -> String {
    format!("<error msg=\"{}\" />", msg_error_text(code))
}

/// The credentials line of an AsteriskRequest or HTTPRequest body.
pub fn digest_auth_line(auth: &[u8]) -> Vec<u8> {
    let mut v = b"X-Digium-AppServer-Digest-Auth=".to_vec();
    v.extend_from_slice(auth);
    v.extend_from_slice(b"\r\n");
    v
}

/// The format of an AsteriskRequest method call document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocFormat {
    /// `{"request": {"method": ..., "parameters": ...}}`
    Json,
    /// `<request method="..."><parameters>...</parameters></request>`
    Xml,
}

/// A JSON method call document: `{"request": {"method": M, "parameters":
/// P}}` (no parameters when `params` is `None`).
pub fn method_request_json(method: &str, params: Option<&serde_json::Value>) -> String {
    let mut req = serde_json::Map::new();
    req.insert("method".into(), serde_json::Value::String(method.into()));
    if let Some(p) = params {
        req.insert("parameters".into(), p.clone());
    }
    let mut doc = serde_json::Map::new();
    doc.insert("request".into(), serde_json::Value::Object(req));
    crate::util::json_python(&serde_json::Value::Object(doc))
}

/// An XML method call document; `params` is an XML fragment.
pub fn method_request_xml(method: &str, params: &str) -> String {
    format!("<request method=\"{method}\"><parameters>{params}</parameters></request>")
}
