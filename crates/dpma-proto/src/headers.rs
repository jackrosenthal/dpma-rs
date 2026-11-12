//! Message variable (SIP header) names used by the protocol.
//!
//! Incoming SIP MESSAGE headers arrive as `ast_msg` variables; outgoing
//! variables become SIP headers (see `ast_msg_set_var`).

/// The start of the names of the protocol's own headers.
pub const PREFIX: &str = "X-Digium-AppServer-";
pub const APPSERVER_ID: &str = "X-Digium-AppServer-ID";
pub const SESSION: &str = "X-Digium-AppServer-Session";
pub const REQUEST_TYPE: &str = "X-Digium-AppServer-RequestType";
pub const RESPONSE_TYPE: &str = "X-Digium-AppServer-ResponseType";
pub const RESPONSE_URI: &str = "X-Digium-AppServer-Response-URI";
pub const RESPONSE_FULLCONTACT: &str = "X-Digium-AppServer-Response-FullContact";
pub const MAC_ADDRESS: &str = "X-Digium-AppServer-MACAddress";
pub const MESSAGE_SALT: &str = "X-Digium-AppServer-Message-Salt";
pub const MESSAGE_SEQUENCE: &str = "X-Digium-AppServer-Message-Sequence";
pub const MESSAGE_FINISHED: &str = "X-Digium-AppServer-Message-Finished";
pub const PASSWORD: &str = "X-Digium-AppServer-Password";
pub const CONFIG_PASSWORD: &str = "X-Digium-AppServer-ConfigPassword";
pub const CONFIG_TOKEN: &str = "X-Digium-AppServer-Config-Token";
pub const USERNAME: &str = "X-Digium-AppServer-Username";
pub const ERROR_ID: &str = "X-Digium-AppServer-Error-ID";
pub const HANDSHAKE_VERSION: &str = "X-Digium-AppServer-Handshake-Version";
pub const TOKEN_AUTH_REQUIREMENTS: &str = "X-Digium-AppServer-Token-Auth-Requirements";
pub const USERLIST_AUTH_REQUIREMENTS: &str = "X-Digium-AppServer-Userlist-Auth-Requirements";
pub const HTTP_STATUS: &str = "X-Digium-AppServer-HTTP-Status";
pub const MD5: &str = "X-Digium-AppServer-MD5";
pub const EVENT_NAME: &str = "X-Event-Name";
pub const EVENT_TYPE: &str = "X-Event-Type";
pub const ORIGINATION_NETWORK: &str = "X-Origination-Network";
pub const DIGIUM_USER_AGENT: &str = "X-Digium-User-Agent";
pub const USER_AGENT: &str = "User-Agent";
pub const CONTACT: &str = "Contact";
pub const FROM: &str = "From";
pub const TO: &str = "To";
/// Set by res_pjsip_messaging on incoming messages.
pub const PJSIP_TRANSPORT: &str = "PJSIP_TRANSPORT";
pub const PJSIP_RECVADDR: &str = "PJSIP_RECVADDR";
pub const PJSIP_FULLCONTACT: &str = "PJSIP_FULLCONTACT";
/// Marker inside an AsteriskRequest body carrying the user credentials.
pub const DIGEST_AUTH_MARKER: &str = "X-Digium-AppServer-Digest-Auth=";
