//! The simulator's phone identity, minted the way the phones mint theirs
//! (by [`dpma_proto::cert::PhoneIdentity`]).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use dpma_proto::cert::PhoneIdentity;
use rsa::RsaPrivateKey;

use super::phone::Form;

/// A phone's identity, and its legacy one for the chain form.
#[derive(Clone)]
pub struct Identity {
    phone: PhoneIdentity,
    legacy: PhoneIdentity,
}

impl Identity {
    /// The Handshake body of `form`.
    pub fn body(&self, form: Form) -> Vec<u8> {
        match form {
            Form::Legacy => self.phone.legacy_body(),
            Form::Chain => self.phone.chain_body(&self.legacy),
        }
    }

    /// The private key of the phone's certificate.
    pub fn key(&self) -> RsaPrivateKey {
        self.phone.private_key.clone()
    }
}

/// The identity of the phone with `mac` (minted on first use; real phones
/// mint theirs once and keep it).
pub fn identity(mac: &str) -> Result<Identity> {
    static IDENTITIES: OnceLock<Mutex<HashMap<String, Identity>>> = OnceLock::new();
    let mut map = IDENTITIES.get_or_init(Default::default).lock().unwrap();
    if let Some(id) = map.get(mac) {
        return Ok(id.clone());
    }
    let id = Identity {
        phone: PhoneIdentity::generate().context("minting the identity")?,
        legacy: PhoneIdentity::generate().context("minting the identity")?,
    };
    map.insert(mac.to_string(), id.clone());
    Ok(id)
}
