//! Session persistence in AstDB family `DigiumPhoneSessions`
//! (`phone_session_update_db_info` FUN_00149250,
//! `phone_session_db_restore_entry` in FUN_00150440).
//!
//! An entry is keyed by the session id; its value is
//!
//! ```text
//! mac=%s;auth_flags=%d;data=%s;data_len=%d;ran=%s;contact=%s;uri=%s;cfgd=%d;ua=%s;client_cert=%s;origination_network=%s
//! ```
//!
//! where `data` is the common password encrypted (AES-128-CBC, key and IV
//! from `EVP_BytesToKey` of a storage passphrase and the random salt `ran`,
//! base64), `contact`, `uri`, and `ua` are base64, `cfgd` is the configured
//! flag as a one-bit signed bit field (-1 or 0), and `client_cert` is the
//! certificate PEM the phone sent in its handshake.  Inactive sessions are
//! not saved.
//!
//! The storage passphrase is the one embedded in the official DPMA, so
//! sessions saved by the official DPMA restore here.
//!
//! Restoring verifies the stored certificate again exactly as a handshake
//! does (both of the official DPMA's callers of `phone_msg_session_alloc`
//! pass 0 for its "load an RSA public key instead" argument), links the
//! session as authenticated but inactive (so it is pruned unless a phone
//! user's `last_session_id` re-activates it), and deletes its AstDB
//! entry until the session is saved again.

use super::store::{alloc, NewSession};
use super::{Session, DB_FAMILY};
use dpma_ast::dpma_bytes::ByteSlice;
use dpma_ast::{bformat, db, dpma_log};
use dpma_proto::crypto;
use std::sync::{Arc, Mutex};

/// The official DPMA's storage passphrase for the common passwords in
/// AstDB, embedded in its binary.
const DB_PASSPHRASE: &[u8] = b"1sInnalILansfPOEIdi)0-294923kjashdkjwe][";

/// `db_crypto_mutex`: serializes saving and restoring.
static DB_CRYPTO: Mutex<()> = Mutex::new(());

/// `send_encrypt_hdr_helper` into a buffer of `size` bytes, with the
/// official DPMA's messages; "" on failure.
pub(crate) fn encrypt_helper(
    plain: &[u8],
    password: &[u8],
    salt: &[u8; crypto::SALT_LEN],
    size: usize,
) -> Vec<u8> {
    let fail = |msg: &str| {
        dpma_log!("{}", msg);
        Vec::new()
    };
    let Ok(mut enc) = crypto::Encryptor::new(password, salt) else {
        return fail("Call to init_encryption failed");
    };
    let Ok(mut cipher) = enc.update(plain) else {
        return fail("Call to encrypt_data returned failure");
    };
    match enc.finish() {
        Ok(last) => cipher.extend(last),
        Err(_) => return fail("Call to encrypt_final returned failure"),
    }
    crypto::base64_encode_max(&cipher, size).into_bytes()
}

/// `phone_session_update_db_info` (FUN_00149250): write the session's
/// AstDB entry, unless it is inactive.
pub fn update_db_info(s: &Arc<Session>) {
    let value = {
        let st = s.lock();
        if st.inactive {
            return;
        }
        let _db = DB_CRYPTO.lock().unwrap_or_else(|e| e.into_inner());
        let salt = crypto::new_salt().unwrap_or([0; crypto::SALT_LEN]);
        let data = encrypt_helper(&st.common_password, DB_PASSPHRASE, &salt, 0x100);
        bformat!(
            "mac={};auth_flags={};data={};data_len={};ran={};contact={};uri={};cfgd={};ua={};client_cert={};origination_network={}",
            st.mac,
            st.auth_flags as i32,
            data,
            st.common_password.len(),
            crypto::salt_to_hex(&salt),
            crypto::base64_encode_max(&st.contact, 0x200),
            crypto::base64_encode_max(&st.response_uri, 0x200),
            -i32::from(st.configured),
            crypto::base64_encode_max(&st.user_agent, 0x200),
            st.client_cert_pem,
            st.origination_network
        )
    };
    db::put(DB_FAMILY, &s.id, &value);
}

/// The value after `name=` (first occurrence anywhere in the entry, as the
/// official DPMA's `strstr` finds it), up to the next `;`.
fn field<'a>(value: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let start = value.find(name)? + name.len();
    let rest = &value[start..];
    Some(rest.split(|&c| c == b';').next().unwrap_or(b""))
}

/// `strtol(s, NULL, 10)` as an int.
fn strtol(s: &[u8]) -> i32 {
    dpma_proto::framing::parse_sequence(s)
}

/// `ast_base64decode` of a field into a buffer of its length plus one,
/// read as a C string.
fn b64_text(s: &[u8]) -> Vec<u8> {
    let bytes = crypto::base64_decode_max(s, s.len());
    crypto::c_str(&bytes).to_vec()
}

/// `phone_session_db_restore_entry`: restore one AstDB entry.
fn restore_entry(key: &[u8], value: &[u8]) {
    let Some(slash) = key.rfind_byte(b'/') else {
        return;
    };
    let id = &key[slash + 1..];
    let get = |n: &str| field(value, n);
    let (Some(contact), Some(data), Some(ran), Some(data_len)) =
        (get("contact="), get("data="), get("ran="), get("data_len="))
    else {
        return;
    };
    if contact.is_empty() || data.is_empty() || ran.is_empty() || data_len.is_empty() {
        return;
    }
    let data_len = strtol(data_len);
    let cfgd = get("cfgd=")
        .filter(|v| !v.is_empty())
        .map(strtol)
        .unwrap_or(0);
    let auth_flags = get("auth_flags=")
        .filter(|v| !v.is_empty())
        .map(strtol)
        .unwrap_or(0);
    let mac = get("mac=");
    let uri = b64_text(get("uri=").unwrap_or(b""));
    let ua = b64_text(get("ua=").unwrap_or(b""));
    let contact = b64_text(contact);
    let client_cert = get("client_cert=").unwrap_or(b"");
    let origination_network = get("origination_network=");

    let password = {
        let _db = DB_CRYPTO.lock().unwrap_or_else(|e| e.into_inner());
        crypto::decrypt_field_limited(DB_PASSPHRASE, ran, data, data.len() + 1)
    };
    // A corrupt entry nearly always fails the padding check; the length
    // check catches the rest.
    let password = match password {
        Ok(p) if usize::try_from(data_len).is_ok_and(|n| n == p.len()) => p,
        _ => {
            dpma_log!("Call to decrypt_msg_field failed");
            // Deviation: the official DPMA keeps the entry (and fails on it
            // at every load); it is dropped here so the phone simply
            // handshakes again.
            db::del(DB_FAMILY, id);
            return;
        }
    };

    let Some(s) = alloc(&NewSession {
        mac,
        contact: &contact,
        response_uri: &uri,
        client_cert,
        id: Some(id),
        user_agent: Some(&ua),
        origination_network,
    }) else {
        return;
    };
    {
        let mut st = s.lock();
        st.auth_flags = auth_flags as u32;
        st.authenticated = true;
        st.inactive = true;
        st.configured = cfgd & 1 != 0;
        st.common_password = password;
        db::del(DB_FAMILY, &s.id);
    }
}

/// Restore every session found in AstDB (the restore loop of
/// `phone_msg_load`).
pub fn restore_all() {
    for (key, value) in db::tree(DB_FAMILY) {
        restore_entry(&key, &value);
    }
}
