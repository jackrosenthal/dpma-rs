//! A phone's side of a session with a server: what it keeps from the
//! handshake and the requests built from that.

use rsa::RsaPrivateKey;

use crate::message::{Incoming, Message, Request};
use crate::{crypto, types, ProtoError, Result};

/// What a phone knows of its session: the session id and common password
/// from the HandshakeResponse, and the configuration token of the last
/// TokenResponse.
#[derive(Debug, Clone, Default)]
pub struct Session {
    mac: Vec<u8>,
    session_id: Vec<u8>,
    password: Vec<u8>,
    handshake_version: Vec<u8>,
    config_token: Vec<u8>,
}

fn non_empty(v: &[u8]) -> Option<&[u8]> {
    (!v.is_empty()).then_some(v)
}

impl Session {
    /// The session of the phone with this MAC address, before its
    /// handshake.
    pub fn new(mac: impl Into<Vec<u8>>) -> Session {
        Session {
            mac: mac.into(),
            ..Default::default()
        }
    }

    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    pub fn session_id(&self) -> Option<&[u8]> {
        non_empty(&self.session_id)
    }

    /// The common password that encrypts everything but a handshake.
    pub fn common_password(&self) -> Option<&[u8]> {
        non_empty(&self.password)
    }

    /// `Handshake-Version` of the HandshakeResponse.
    pub fn handshake_version(&self) -> Option<&[u8]> {
        non_empty(&self.handshake_version)
    }

    pub fn config_token(&self) -> Option<&[u8]> {
        non_empty(&self.config_token)
    }

    /// Continue a session that was saved earlier.
    pub fn resume(&mut self, session_id: impl Into<Vec<u8>>, common_password: impl Into<Vec<u8>>) {
        self.session_id = session_id.into();
        self.password = common_password.into();
    }

    /// Keep `token` for the requests that need a configuration token.
    pub fn set_config_token(&mut self, token: impl Into<Vec<u8>>) {
        self.config_token = token.into();
    }

    /// Forget the session, the password, and the token (as a reboot does).
    pub fn forget(&mut self) {
        self.session_id.clear();
        self.password.clear();
        self.handshake_version.clear();
        self.config_token.clear();
    }

    /// The Handshake request, whose body is the phone's `certificates`.
    pub fn handshake(&self, certificates: Vec<u8>) -> Request {
        Request {
            request_type: types::HANDSHAKE.into(),
            mac: self.mac.clone(),
            body: certificates,
            ..Default::default()
        }
    }

    /// A request of `request_type`: with the session id when the type needs
    /// one, and the configuration token for the types that carry it.
    pub fn request(&self, request_type: &str, body: Vec<u8>) -> Request {
        let carries_token = [types::CONFIG_REQUEST, types::VERIFY_REQUEST]
            .iter()
            .any(|t| t.eq_ignore_ascii_case(request_type));
        Request {
            request_type: request_type.into(),
            mac: self.mac.clone(),
            session_id: if types::needs_session(request_type) {
                self.session_id.clone()
            } else {
                Vec::new()
            },
            config_token: if carries_token {
                self.config_token.clone()
            } else {
                Vec::new()
            },
            body,
            ..Default::default()
        }
    }

    /// Whether a request of this type is encrypted: it needs a session, and
    /// there is a common password.
    pub fn encrypts(&self, request_type: &str) -> bool {
        types::needs_session(request_type) && self.common_password().is_some()
    }

    /// The MESSAGEs of `request`, encrypted when [`Session::encrypts`].
    pub fn encode(&self, request: &Request, chunk_len: usize) -> Result<Vec<Message>> {
        let password = self
            .encrypts(&request.request_type)
            .then_some(self.password.as_slice());
        request.encode(password, chunk_len)
    }

    /// Take the session from a HandshakeResponse: its session id, and the
    /// common password, which it carries encrypted to the phone's key.  The
    /// AppServer certificate in its body is not checked here; see
    /// [`crate::cert::verify_appserver_certificate`].
    pub fn accept_handshake_response(
        &mut self,
        response: &Incoming,
        private_key: &RsaPrivateKey,
    ) -> Result<()> {
        let invalid = |what: &str| Err(ProtoError::Invalid(what.into()));
        if !response
            .response_type
            .eq_ignore_ascii_case(b"HandshakeResponse")
        {
            return invalid("expected a HandshakeResponse");
        }
        if response.error != 0 {
            return invalid(&format!("the handshake failed: error {}", response.error));
        }
        if response.encrypted {
            return invalid("the HandshakeResponse is encrypted");
        }
        if response.password.is_empty() {
            return invalid("the HandshakeResponse has no password");
        }
        if response.session_id.is_empty() {
            return invalid("the HandshakeResponse has no session");
        }
        self.password = crypto::decrypt_common_password(private_key, &response.password)?;
        self.session_id = response.session_id.clone();
        self.handshake_version = response.handshake_version.clone();
        self.config_token.clear();
        Ok(())
    }
}
