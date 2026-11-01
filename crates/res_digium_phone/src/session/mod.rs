//! Phone sessions and messaging (phone_message.c).
//!
//! A *session* is created by a successful Handshake: it remembers the
//! phone's contact, MAC, user agent, certificate key, and the common
//! password that encrypts everything after the handshake.  A
//! *transaction* is one complete incoming request (possibly reassembled
//! from several SIP MESSAGEs); handlers answer it by filling in its
//! [`Outgoing`] and calling [`outgoing::send_and_destroy`].
//!
//! The types below are the starting cross-package interface; other
//! packages read them.  Changes are fine; mention them in the hand-off.
//!
//! Owner: P7 "session" (wave 2).

pub mod ami;
pub mod cli;
pub mod handshake;
pub mod incoming;
pub mod outgoing;
pub mod persist;
pub mod store;

pub use incoming::next_transaction;
pub use outgoing::{send, send_and_destroy, send_event};
pub use store::{find, find_by_mac, invalidate, load, mark_authenticated, mark_inactive, reload, unload};

use dpma_ast::msg::Msg;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// AstDB family holding persisted sessions.
pub const DB_FAMILY: &str = "DigiumPhoneSessions";

/// Mutable session state (`struct phone_session`, 0xe60 bytes).
#[derive(Default)]
pub struct SessionState {
    /// Contact URI from the handshake (+0xdf8).
    pub contact: String,
    /// MAC address (+0xe00).
    pub mac: String,
    /// User agent (+0xe08).
    pub user_agent: String,
    /// Client certificate (or, for restored sessions, public key) PEM
    /// (+0xe10).
    pub client_cert_pem: String,
    /// The phone's public key (+0xe18 / +0xe28).
    pub public_key: Option<openssl::pkey::PKey<openssl::pkey::Public>>,
    /// Intermediate certificate serial, 0 for legacy certificates (+0xe20).
    pub intermediate_serial: i64,
    /// Authentication flags (`config::auth`) in force for this session
    /// (+0xe30).
    pub auth_flags: u32,
    /// Flag bit 0 (+0xe34).
    pub authenticated: bool,
    /// Flag bit 1.
    pub inactive: bool,
    /// Flag bit 2: a ConfigRequest was answered.
    pub configured: bool,
    /// Creation time, seconds since the epoch (+0xe38).
    pub created: i64,
    /// Last activity, seconds since the epoch (+0xe40).
    pub last_activity: i64,
    /// Configuration password (+0xe48; never set by 3.6.13).
    pub config_password: String,
    /// Where to send messages for this phone (+0xe50).
    pub response_uri: String,
    /// `X-Origination-Network` (+0xe58).
    pub origination_network: String,
    /// The 40-byte common password (+0x8, length at +0x808).
    pub common_password: Vec<u8>,
}

/// A phone session.  Looked up by `id` (`X-Digium-AppServer-Session`).
pub struct Session {
    /// Session id (+0xd78): `"%d%ld"` of a djb2 hash of time+contact and
    /// `ast_random()`, unless restored.
    pub id: String,
    pub state: Mutex<SessionState>,
}

impl Session {
    pub fn new(id: &str) -> Session {
        Session { id: id.to_string(), state: Mutex::new(SessionState::default()) }
    }
}

/// An outgoing message being built (`phone_msg_outgoing_alloc`, 0xc0
/// bytes).  Exactly one of `request_type`, `response_type`, or
/// `event_name` (or a non-zero `error`) must be set.
#[derive(Debug, Default, Clone)]
pub struct Outgoing {
    pub body: Vec<u8>,
    /// Message error code (`dpma_proto::errors::msg`); non-zero replaces
    /// the body with `<error msg="..." />` and sets Error-ID.
    pub error: i32,
    pub request_type: String,
    pub response_type: String,
    pub response_uri: String,
    pub full_contact: String,
    pub userlist_auth_requirements: String,
    pub token_auth_requirements: String,
    /// Sent encrypted in `X-Digium-AppServer-Config-Token`.
    pub config_token: String,
    pub username: String,
    /// Sent verbatim in `X-Digium-AppServer-Password` (the RSA-encrypted
    /// common password in a HandshakeResponse).
    pub password: String,
    /// Sent encrypted in `X-Digium-AppServer-Password`.
    pub encrypted_password: String,
    /// Overrides `X-Digium-AppServer-ID` (requests get a counter).
    pub id: String,
    /// `X-Event-Name`; also selects the "Command: " body prefix.
    pub event_name: String,
    pub http_status: String,
    pub md5: String,
}

impl Outgoing {
    pub fn new() -> Outgoing {
        Outgoing::default()
    }

    /// `phone_msg_body_append` (FUN_0014c650).
    pub fn append(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    pub fn append_str(&mut self, s: &str) {
        self.body.extend_from_slice(s.as_bytes());
    }
}

/// One complete incoming request (`struct transaction`, 0x168 bytes).
/// Immutable once built, except for `outgoing` and `configured`.
pub struct Transaction {
    /// Container key: `"<X-Digium-AppServer-ID>-<MAC or unknown>"`.
    pub key: String,
    /// `X-Digium-AppServer-ID`.
    pub app_server_id: String,
    pub request_type: String,
    pub response_type: String,
    /// `X-Digium-AppServer-Response-URI` plus `;transport=<PJSIP_TRANSPORT>`.
    pub response_uri: String,
    pub full_contact: String,
    pub username: String,
    pub mac: String,
    pub user_agent: String,
    /// Decrypted `X-Digium-AppServer-Password`.
    pub password: String,
    /// Decrypted `X-Digium-AppServer-ConfigPassword`.
    pub config_password: String,
    /// Decrypted `X-Digium-AppServer-Config-Token`.
    pub config_token: String,
    /// User part of the `To` URI.
    pub to_user: String,
    pub origination_network: String,
    /// Reassembled (and decrypted) body.
    pub body: String,
    /// The first message of the transaction, for any other variable.
    pub first_msg: Option<Msg>,
    pub session: Option<Arc<Session>>,
    /// The reply being built; allocated by `request::handle_incoming`.
    pub outgoing: Mutex<Option<Outgoing>>,
    /// Set by the ConfigRequest handler (+0x160).
    pub configured: AtomicBool,
}

impl Transaction {
    /// The value of message variable `name` from the first message.
    pub fn var(&self, name: &str) -> Option<String> {
        self.first_msg.as_ref().and_then(|m| m.var(name))
    }
}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    Vec::new()
}
