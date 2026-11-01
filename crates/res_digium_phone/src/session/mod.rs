//! Phone sessions and messaging (phone_message.c).
//!
//! A *session* is created by a successful Handshake: it remembers the
//! phone's contact, MAC, user agent, certificate, and the common password
//! that encrypts everything after the handshake.  A *transaction* is one
//! complete incoming request (possibly reassembled from several SIP
//! MESSAGEs); handlers answer it by filling in its [`Outgoing`] and calling
//! [`outgoing::send_and_destroy`].
//!
//! | File | Original |
//! |---|---|
//! | `store.rs` | the session container, `phone_msg_session_alloc`, `phone_msg_session_find*`, `phone_msg_session_mark_*`, `phone_msg_session_invalidate`, the global auth flags, `phone_msg_load`, `phone_msg_unload`, the trust material (`load_castore`) |
//! | `incoming.rs` | `incoming_build_transaction`, `validate_message`, `validate_session`, `incoming_add_msg`, `incoming_check_finalize`, `prune_inactive` |
//! | `outgoing.rs` | `phone_msg_outgoing_send`, `phone_msg_send_and_destroy`, `phone_msg_send_timeout`, `phone_msg_send_event`, `phone_msg_outgoing_send_handshake_error` |
//! | `handshake.rs` | `handle_request_handshake`, `prune_session_by_mac`, `phone_msg_set_common_password`, `set_auth_requirements` |
//! | `persist.rs` | `phone_session_update_db_info`, `phone_session_db_restore_entry` |
//! | `cli.rs`, `ami.rs` | `digium_phones show sessions`, `DPMAShowPhones` |

pub mod ami;
pub mod cli;
pub mod handshake;
pub mod incoming;
pub mod outgoing;
pub mod persist;
pub mod store;

pub use incoming::next_transaction;
pub use outgoing::{send, send_and_destroy, send_event, send_handshake_required, send_maybe, send_timeout};
pub use store::{
    all, find, find_by_mac, global_auth_flags, invalidate, load, mark_authenticated, mark_inactive,
    mark_unconfigured_by_mac, reload, set_global_auth_flags, unload,
};

use dpma_ast::msg::Msg;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};

/// AstDB family holding persisted sessions.
pub const DB_FAMILY: &str = "DigiumPhoneSessions";

/// Mutable session state (`struct phone_session`, 0xe60 bytes).  Empty
/// strings stand for the original's NULL pointers.
#[derive(Default)]
pub struct SessionState {
    /// Contact URI from the handshake, without brackets (+0xdf8).
    pub contact: String,
    /// MAC address (+0xe00); empty when the handshake had none.
    pub mac: String,
    /// User agent (+0xe08).
    pub user_agent: String,
    /// The certificate PEM the phone sent in its Handshake body, stored in
    /// AstDB and verified again on restore (+0xe10).
    pub client_cert_pem: String,
    /// The verified phone certificate (+0xe18).
    pub certificate: Option<X509>,
    /// Its public key; None when OpenSSL could not decode it.
    pub public_key: Option<PKey<Public>>,
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
    /// Last activity, seconds since the epoch (+0xe40): set when the user
    /// agent is first learned and after every successful send.
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
/// The state's lock is held for the whole of an outgoing send, as the
/// original holds the session's ao2 lock.
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

    /// Lock the state (a poisoned lock is still usable).
    pub fn lock(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `phone_msg_session_get_auth_flags` (FUN_00149f90).
    pub fn auth_flags(&self) -> u32 {
        self.lock().auth_flags
    }

    /// `phone_msg_session_get_uri` (FUN_00149fb0).
    pub fn response_uri(&self) -> String {
        self.lock().response_uri.clone()
    }

    /// `phone_msg_session_get_config_password` (FUN_00149f70).
    pub fn config_password(&self) -> String {
        self.lock().config_password.clone()
    }

    /// The session's MAC address ("" when none).
    pub fn mac(&self) -> String {
        self.lock().mac.clone()
    }
}

/// An outgoing message being built (`phone_msg_outgoing_alloc`, 0xc0
/// bytes).  One of `request_type`, `response_type`, or `event_name` (or a
/// non-zero `error`) must be set.
#[derive(Debug, Default, Clone)]
pub struct Outgoing {
    /// +0x00.
    pub body: Vec<u8>,
    /// Message error code (`dpma_proto::errors::msg`, +0x08); non-zero
    /// appends `<error msg="..." />` to the body, sets Error-ID, and
    /// prefixes every chunk with "Command: ".
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
/// Immutable once built, except for `outgoing`, `configured`, and
/// `unconfigured`.
#[derive(Default)]
pub struct Transaction {
    /// Container key: `"<X-Digium-AppServer-ID>-<MAC or unknown>"`.
    pub key: String,
    /// `X-Digium-AppServer-ID` ([1]).
    pub app_server_id: String,
    /// [2].
    pub request_type: String,
    /// [3].
    pub response_type: String,
    /// `X-Digium-AppServer-Response-URI` plus `;transport=<PJSIP_TRANSPORT>`
    /// when that variable exists, cut to 78 bytes ([4]).
    pub response_uri: String,
    /// `X-Digium-AppServer-Response-FullContact` ([5]; Asterisk 24 never
    /// sets PJSIP_FULLCONTACT, so this is empty).
    pub full_contact: String,
    /// [6].
    pub username: String,
    /// [7].
    pub mac: String,
    /// The user agent (`X-Digium-User-Agent`, else `User-Agent`).  Not a
    /// field of the original's transaction; handlers there read it from
    /// the message.
    pub user_agent: String,
    /// Decrypted `X-Digium-AppServer-Password` ([8]).
    pub password: String,
    /// Decrypted `X-Digium-AppServer-ConfigPassword` ([9]).
    pub config_password: String,
    /// Decrypted `X-Digium-AppServer-Config-Token` ([10]).
    pub config_token: String,
    /// Host of the `To` URI ([11]; see `dpma_proto::uri::to_host_port`).
    pub to_host: String,
    /// Port of the `To` URI ([12]).
    pub to_port: String,
    /// Phone model from the user agent (`phone_utils_get_model`, [13]).
    pub model: String,
    /// `X-Origination-Network` of the first message (not a field of the
    /// original's transaction).
    pub origination_network: String,
    /// Reassembled (and decrypted) body, as text.
    pub body: String,
    /// The same body's exact bytes.
    pub body_bytes: Vec<u8>,
    /// The first message of the transaction, for any other variable (+0xa8).
    pub first_msg: Option<Msg>,
    /// +0x150.
    pub session: Option<Arc<Session>>,
    /// The reply being built (+0xc8); allocated by
    /// `request::handle_incoming`.
    pub outgoing: Mutex<Option<Outgoing>>,
    /// Set by the ConfigRequest (and token) handlers (+0x160): the session
    /// becomes configured when the reply is sent.
    pub configured: AtomicBool,
    /// Set by the UserlistRequest handler (+0x164): the session becomes
    /// unconfigured when the reply is sent.
    pub unconfigured: AtomicBool,
}

impl Transaction {
    /// The value of message variable `name` from the first message.
    pub fn var(&self, name: &str) -> Option<String> {
        self.first_msg.as_ref().and_then(|m| m.var(name))
    }
}

/// Seconds since the epoch (`time(NULL)`).
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `phone_msg_get_user_agent` (FUN_00149fc0): `X-Digium-User-Agent` when
/// present and not empty, else `User-Agent` (possibly absent).
pub(crate) fn user_agent_of(m: &Msg) -> Option<String> {
    match m.get_var(dpma_proto::headers::DIGIUM_USER_AGENT) {
        Some(ua) if !ua.is_empty() => Some(ua),
        _ => m.get_var(dpma_proto::headers::USER_AGENT),
    }
}

/// `%s` of a C string that may be NULL.
pub(crate) fn or_null(s: Option<&str>) -> &str {
    s.unwrap_or("(null)")
}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    store::devtest_commands()
}
