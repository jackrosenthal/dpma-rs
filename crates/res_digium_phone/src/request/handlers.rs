//! The request handlers (phone_request.c), registered by
//! `phone_request_load` (FUN_00177610) in this order: Echo, Handshake
//! (`session::handshake`), HTTPRequest, AsteriskRequest, UserlistRequest,
//! TokenRequest, ConfigRequest, FileRequest, VerifyRequest, PingRequest.

use super::{error_response_json, error_response_xml, register_handler};
use crate::method::{self, MethodCall};
use crate::session::{Outgoing, Transaction};
use crate::users;
use dpma_ast::{astxml, dpma_debug, dpma_log, json};
use dpma_proto::errors;
use std::io::Read;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// `phone_request_load`.
pub fn load() -> Result<(), ()> {
    use dpma_proto::types::*;
    let mut res = Ok(());
    let table: [(&'static str, Option<&'static str>, bool, super::Handler); 10] = [
        (ECHO, None, false, handle_echo),
        (HANDSHAKE, Some("HandshakeResponse"), false, crate::session::handshake::handle_handshake),
        (HTTP_REQUEST, Some("HTTPResponse"), true, handle_http_or_asterisk),
        (ASTERISK_REQUEST, Some("AsteriskResponse"), true, handle_http_or_asterisk),
        (USERLIST_REQUEST, Some("UserlistResponse"), true, handle_userlist),
        (TOKEN_REQUEST, Some("TokenResponse"), true, handle_token),
        (CONFIG_REQUEST, Some("ConfigResponse"), true, handle_config),
        (FILE_REQUEST, Some("FileResponse"), true, handle_file),
        (VERIFY_REQUEST, Some("VerifyResponse"), true, handle_verify),
        (PING_REQUEST, Some("PingResponse"), true, handle_ping),
    ];
    for (req, resp, session, h) in table {
        if register_handler(req, resp, session, h).is_err() {
            res = Err(());
        }
    }
    if res.is_err() {
        dpma_ast::ast_log!(dpma_ast::log::LOG_ERROR, "DPMA: Unable to load all phone request handlers");
    }
    res
}

/// `handle_request_echo` (FUN_001764f0): answer directly (not through the
/// session layer, so unencrypted and in one message) with an EchoResponse
/// carrying Error-ID 0, the request's ID and origination network, and its
/// body.
pub fn handle_echo(tx: Arc<Transaction>) -> i32 {
    use dpma_proto::headers as h;
    let var = |name: &str| tx.first_msg.as_ref().and_then(|m| m.get_var(name));
    let uri = var(h::RESPONSE_URI);
    let Some(mut m) = crate::transport::new_outgoing(uri.as_deref().unwrap_or("")) else {
        dpma_ast::ast_log!(dpma_ast::log::LOG_ERROR, "Unable to allocate msg");
        return 0;
    };
    m.set_exten(crate::transport::SEND_EXTEN);
    m.set_var(h::RESPONSE_TYPE, "EchoResponse");
    m.set_var(h::ERROR_ID, "0");
    if let Some(uri) = uri.filter(|u| !u.is_empty()) {
        let uri = dpma_proto::framing::response_uri(
            &uri,
            var(h::PJSIP_TRANSPORT).as_deref(),
            dpma_proto::framing::RESPONSE_URI_BUF,
        );
        m.set_var(h::RESPONSE_URI, &uri);
    }
    if let Some(id) = var(h::APPSERVER_ID).filter(|i| !i.is_empty()) {
        m.set_var(h::APPSERVER_ID, &id);
    }
    if let Some(net) = var(h::ORIGINATION_NETWORK).filter(|n| !n.is_empty()) {
        m.set_var(h::ORIGINATION_NETWORK, &net);
    }
    m.set_body_bytes(&tx.body_bytes);
    let _ = crate::transport::write_msg(m);
    0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run `f` on the transaction's reply (allocated by
/// `request::handle_incoming`), if it has one.
fn with_out(tx: &Transaction, f: impl FnOnce(&mut Outgoing)) {
    let mut g = tx.outgoing.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(o) = g.as_mut() {
        f(o);
    }
}

/// Set the reply's message error (`X-Digium-AppServer-Error-ID`, with
/// `<error msg="..." />` appended to the body when it is sent).
fn set_error(tx: &Transaction, code: i32) {
    with_out(tx, |o| o.error = code);
}

/// `phone_msg_body_append` on the reply.
fn append(tx: &Transaction, data: &[u8]) {
    with_out(tx, |o| o.append(data));
}

/// `phone_msg_session_get_id` (FUN_00149fa0) of the transaction's session.
fn session_id(tx: &Transaction) -> String {
    tx.session.as_ref().map(|s| s.id.clone()).unwrap_or_default()
}

/// `phone_msg_session_get_auth_flags` (FUN_00149f90), as the original's
/// signed int (the handlers reject negative flags as an invalid session).
fn session_auth_flags(tx: &Transaction) -> i32 {
    tx.session.as_ref().map_or(0, |s| s.auth_flags() as i32)
}

/// `dpma_config_password(dpma_config_get())`: the global pin as the
/// exported configuration object holds it (at most 255 bytes).
fn config_password() -> String {
    crate::util::truncate(&crate::config::get().globalpin, 0x100)
}

/// Size of the original's path buffers.
const PATH_BUF: usize = 0x1000;

/// `dpma_append_config_file_dir(buf, 0x1000, file, NULL)`: `file` inside
/// the file directory (`"%s/%s"`), or the directory itself when `file` is
/// empty.
fn config_file_dir(file: &str) -> String {
    let dir = crate::util::truncate(&crate::config::get().file_directory, PATH_BUF);
    if file.is_empty() {
        dir
    } else {
        crate::util::truncate(&format!("{}/{}", dir, file), PATH_BUF)
    }
}

/// The transaction's body as the original's handlers see it: a C string,
/// so it ends at the first NUL.
fn body_cstr(tx: &Transaction) -> &[u8] {
    let b = &tx.body_bytes;
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `strstr` on bytes.
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The C string starting at `pos` of `b` (up to the next NUL).
fn cstr_at(b: &[u8], pos: usize) -> &[u8] {
    let s = &b[pos.min(b.len())..];
    &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
}

/// `ast_skip_blanks` and `ast_trim_blanks` (bytes 1 to 32 are blanks).
fn strip_blanks(s: &str) -> &str {
    s.trim_start_matches(|c: char| ('\u{1}'..='\u{20}').contains(&c))
        .trim_end_matches(|c: char| c <= '\u{20}')
}

// ---------------------------------------------------------------------------
// FileRequest
// ---------------------------------------------------------------------------

/// The body answering `file://null`.
const NULL_CONTACTS: &str = "<contacts group_name=\"null\" editable=\"0\" />\n";

/// `handle_request_file` (FUN_001758f0): the body names a file as
/// `file://<name>` (up to the end of the line).  `default` is the default
/// contacts document (every phone with a primary line), `null` an empty
/// contacts list, and anything else a file inside `file_directory`, sent
/// as it is.  A body without `file://` or a file that cannot be opened is
/// answered with error -98 (File Not Found).
///
/// The name is not checked: as in the original, `..` reaches files outside
/// `file_directory`.
pub fn handle_file(tx: Arc<Transaction>) -> i32 {
    file_reply(&tx);
    crate::session::send_and_destroy(&tx);
    0
}

fn file_reply(tx: &Transaction) {
    let body = body_cstr(tx);
    let Some(pos) = find_bytes(body, b"file://") else {
        set_error(tx, errors::msg::FILE_NOT_FOUND);
        return;
    };
    // strsep(&p, "\r\n")
    let rest = &body[pos + 7..];
    let name = &rest[..rest.iter().position(|&c| c == b'\r' || c == b'\n').unwrap_or(rest.len())];
    let name = String::from_utf8_lossy(name);
    if name.eq_ignore_ascii_case("default") {
        let mut buf = String::with_capacity(0x400);
        crate::users::contacts::default_contacts_xml(&mut buf);
        append(tx, buf.as_bytes());
        return;
    }
    if name.eq_ignore_ascii_case("null") {
        append(tx, NULL_CONTACTS.as_bytes());
        return;
    }
    let path = config_file_dir(&name);
    if path.is_empty() {
        dpma_log!("File request with null filename");
        set_error(tx, errors::msg::FILE_NOT_FOUND);
        return;
    }
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            dpma_log!("Failed to open file {}", path);
            set_error(tx, errors::msg::FILE_NOT_FOUND);
            return;
        }
    };
    // fread in 2047-byte pieces until the end of the file or an error (a
    // directory opens but reads nothing); every byte is kept.
    let mut chunk = [0u8; 0x7ff];
    loop {
        match f.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => append(tx, &chunk[..n]),
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigRequest and VerifyRequest
// ---------------------------------------------------------------------------

/// `standard_phone_user_find_by_token` for the transaction's
/// `Config-Token`, MAC, session, and Response-URI.
fn phone_for_token(tx: &Transaction) -> Option<String> {
    users::runtime::find_by_token(&tx.config_token, &tx.mac, &session_id(tx), &tx.response_uri, &config_password())
        .phone
}

/// `handle_request_config` (FUN_00175be0): the configuration document of
/// the phone the `Config-Token` belongs to (built for the model in the
/// request's user agent); error -192 (Invalid Token) when the token does
/// not match.  A successful answer marks the session configured.
pub fn handle_config(tx: Arc<Transaction>) -> i32 {
    match phone_for_token(&tx) {
        None => set_error(&tx, errors::msg::INVALID_TOKEN),
        Some(phone) => {
            // The original builds the document in an ast_str of 0x400
            // bytes; get_config reproduces that buffer's behavior.
            let mut buf = String::with_capacity(crate::users::build_config::INITIAL_BUF);
            let dir = config_file_dir("");
            let _ = crate::users::build_config::get_config(&phone, &mut buf, &dir, &tx.model);
            append(&tx, buf.as_bytes());
            tx.configured.store(true, Ordering::SeqCst);
        }
    }
    crate::session::send_and_destroy(&tx);
    0
}

/// `handle_request_verify` (FUN_00176750): check the `Config-Token`; error
/// -192 (Invalid Token) when it is missing or does not match.  The session
/// is marked configured whenever a token was presented, even one that
/// does not match (as in the original).
pub fn handle_verify(tx: Arc<Transaction>) -> i32 {
    if tx.config_token.is_empty() {
        dpma_log!("Verify request with null token");
        set_error(&tx, errors::msg::INVALID_TOKEN);
        crate::session::send_and_destroy(&tx);
        return 0;
    }
    if phone_for_token(&tx).is_none() {
        set_error(&tx, errors::msg::INVALID_TOKEN);
    }
    tx.configured.store(true, Ordering::SeqCst);
    crate::session::send_and_destroy(&tx);
    0
}

// ---------------------------------------------------------------------------
// TokenRequest
// ---------------------------------------------------------------------------

/// Size of the original's buffer for the phone name.
const NAME_BUF: usize = 0x80;

/// `handle_request_token` (FUN_00175d50): issue a configuration token.
///
/// The phone is selected by `phone_username_for_token` from the
/// `Username` (a primary line's name or extension, or a phone name) or,
/// without one, the MAC.  Then every check the session's authentication
/// flags require must pass:
///
/// - GLOBALPIN: the `ConfigPassword` is the global pin, or the phone's
///   `group_pin`;
/// - MAC: the request's MAC is the phone's `mac`;
/// - PIN: the `Password` is the phone's `pin`.
///
/// A failed GLOBALPIN check is answered with -198 (Invalid Config
/// Password), any other failure (no such phone, MAC or pin mismatch)
/// with -195 (User Not Found).  On success the token goes back in
/// `Config-Token`, the phone's last MAC, URI, and session are updated, and
/// the session is marked configured.
pub fn handle_token(tx: Arc<Transaction>) -> i32 {
    token_reply(&tx);
    crate::session::send_and_destroy(&tx);
    0
}

fn token_reply(tx: &Transaction) {
    use crate::config::auth;
    let flags = session_auth_flags(tx);
    if flags < 0 {
        set_error(tx, errors::msg::USER_NOT_FOUND);
        dpma_log!("Token request with invalid session id ");
        return;
    }
    if tx.mac.is_empty() && tx.username.is_empty() {
        set_error(tx, errors::msg::USER_NOT_FOUND);
        dpma_log!("The MAC and USERNAME headers are required in a token request. ");
        return;
    }
    let Some(name) = users::runtime::username_for_token(&tx.username, &tx.mac) else {
        set_error(tx, errors::msg::USER_NOT_FOUND);
        return;
    };
    let name = crate::util::truncate(&name, NAME_BUF);
    let flags = flags as u32;
    let global_pin = config_password();

    // The original runs these lookups in a tangle of branches; each check
    // is a pure lookup, so only their results matter: a configpass failure
    // wins over the others.
    let configpass_ok = flags & auth::GLOBALPIN == 0
        || (!global_pin.is_empty() && tx.config_password == global_pin)
        || users::runtime::find_w_grouppin(&name, &tx.config_password).is_some();
    let mac_ok = flags & auth::MAC == 0 || users::runtime::find_w_mac(&name, &tx.mac).is_some();
    let pin_ok = flags & auth::PIN == 0 || users::runtime::find_authenticated(&name, &tx.password).is_some();
    if !configpass_ok {
        set_error(tx, errors::msg::INVALID_CONFIG_PASSWORD);
        return;
    }
    if !(mac_ok && pin_ok) {
        set_error(tx, errors::msg::USER_NOT_FOUND);
        return;
    }
    match users::runtime::config_token_build(&name, &tx.mac, &session_id(tx), &tx.response_uri, &global_pin) {
        Some(token) => {
            with_out(tx, |o| o.config_token = token);
            tx.configured.store(true, Ordering::SeqCst);
        }
        None => set_error(tx, errors::msg::USER_NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// UserlistRequest
// ---------------------------------------------------------------------------

/// `handle_request_userlist` (FUN_001762c0): the user list as JSON
/// (`users::userlist::build_userlist_json`).  With USERLIST_GLOBALPIN in
/// the session's flags and a `ConfigPassword` other than the global pin,
/// only the phones whose `group_pin` is that password are listed.  An
/// empty list is answered with -198 (Invalid Config Password) and records
/// an auth incident.  The session becomes unconfigured either way.
pub fn handle_userlist(tx: Arc<Transaction>) -> i32 {
    userlist_reply(&tx);
    crate::session::send_and_destroy(&tx);
    0
}

fn userlist_reply(tx: &Transaction) {
    let flags = session_auth_flags(tx);
    if flags < 0 {
        set_error(tx, errors::msg::USER_NOT_FOUND);
        dpma_log!("Userlist request with invalid session id ");
        return;
    }
    let differs = tx.config_password != config_password();
    let filter = differs && (flags as u32) & crate::config::auth::USERLIST_GLOBALPIN != 0;
    let mut buf = String::with_capacity(0x400);
    match crate::users::userlist::build_userlist_json(&mut buf, filter, &tx.config_password) {
        Ok(n) if n >= 1 => append(tx, buf.as_bytes()),
        _ => {
            set_error(tx, errors::msg::INVALID_CONFIG_PASSWORD);
            crate::auth::issue_alert(tx, "invalid config pass");
            dpma_log!("Userlist request with invalid config password, or no users configured.");
        }
    }
    tx.unconfigured.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// AsteriskRequest and HTTPRequest
// ---------------------------------------------------------------------------

/// `FUN_00176900`: the phone that `user:secret` authenticates (both parts
/// stripped of blanks; no colon means no secret): the phone named `user`
/// with pin `secret`, else the first phone with the line named `user`
/// whose secret is `secret`.
fn authenticate(credentials: &str) -> Option<String> {
    let (user, secret) = match credentials.find(':') {
        Some(i) => (&credentials[..i], strip_blanks(&credentials[i + 1..])),
        // The original passes NULL, which matches only an empty pin or
        // secret (and crashes on a set one); "" does the same without the
        // crash.
        None => (credentials, ""),
    };
    if user.is_empty() {
        return None;
    }
    let user = strip_blanks(user);
    if let Some(phone) = users::runtime::find_authenticated(user, secret) {
        return Some(phone);
    }
    let line = users::runtime::line_find_authenticated(user, secret)?;
    users::runtime::phone_for_line(&line)
}

/// A request handed to AMI (`ami::messages::raise_event` was called): the
/// reply waits for `DPMAMessageResponse`.
struct Forwarded {
    method: String,
}

/// `handle_request_asterisk` (FUN_00176a60), registered for both
/// AsteriskRequest and HTTPRequest.
///
/// The body carries the credentials on a line
/// `X-Digium-AppServer-Digest-Auth=<user>:<secret>` and the request as
/// XML (`<request method="M"><parameters>...</parameters></request>`) or
/// JSON (`{"request": {"method": M, "parameters": ...}}`).  The method
/// runs for the authenticated phone (`authenticate`); a method that is
/// not built in but registered by AMI raises a `DPMAMessage` event and
/// the reply waits for `DPMAMessageResponse` (`ami::messages`).
///
/// The reply body is `HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n`
/// followed, when there is one, by the method's response (or an XML or
/// JSON request error) and `\r\n\r\n`.
pub fn handle_http_or_asterisk(tx: Arc<Transaction>) -> i32 {
    append(&tx, crate::ami::messages::HTTP_PREAMBLE.as_bytes());
    // The original's response buffer (ast_str_create(0x400)).
    let mut buf = String::with_capacity(0x400);
    let forwarded = asterisk_request(&tx, &mut buf);
    if !buf.is_empty() {
        buf.push_str("\r\n\r\n");
        append(&tx, buf.as_bytes());
    }
    match forwarded {
        Some(f) => queue_for_ami(&tx, f),
        None => crate::session::send_and_destroy(&tx),
    }
    0
}

/// Keep the reply until AMI answers (`ami::messages::queue_request`: the
/// original schedules the expiry, then links the queued message).  When
/// that fails, the reply is sent at once with just the HTTP header.
fn queue_for_ami(tx: &Arc<Transaction>, f: Forwarded) {
    if crate::ami::messages::queue_request(tx, &f.method).is_err() {
        crate::session::send_and_destroy(tx);
    }
}

/// Authenticate and run the request; the response (or error) goes to
/// `buf`.  Some when the request was forwarded to AMI.
fn asterisk_request(tx: &Arc<Transaction>, buf: &mut String) -> Option<Forwarded> {
    use dpma_proto::errors::request as rq;
    let mut body = body_cstr(tx).to_vec();
    let marker = dpma_proto::headers::DIGEST_AUTH_MARKER.as_bytes();
    let Some(auth) = find_bytes(&body, marker) else {
        dpma_log!("No auth credentials found in phone msg");
        error_response_json(buf, "", rq::PARSE, "missing authentication credentials");
        return None;
    };
    let (start, is_xml) = match find_bytes(&body, b"<request method") {
        Some(p) => (p, true),
        None => match find_bytes(&body, b"{\"request\":") {
            Some(p) => (p, false),
            None => {
                dpma_log!("No xml request body found in phone msg:");
                error_response_json(buf, "", rq::PARSE, "empty json body");
                return None;
            }
        },
    };

    // The credentials run to the end of their line, without trailing
    // blanks.  The original cuts the body in place to get them (a NUL at
    // the marker, at the line break, and over the trailing blanks), and
    // the request text then ends at the first of those cuts after it.
    body[auth] = 0;
    let cred_start = auth + marker.len();
    let mut cred_end = match body[cred_start..].iter().position(|&c| c == b'\r' || c == b'\n') {
        Some(i) => {
            body[cred_start + i] = 0;
            cred_start + i
        }
        None => body.len(),
    };
    while cred_end > cred_start && body[cred_end - 1] < 0x21 {
        cred_end -= 1;
        body[cred_end] = 0;
    }
    let credentials = String::from_utf8_lossy(&body[cred_start..cred_end]).into_owned();
    let Some(phone) = authenticate(&credentials) else {
        dpma_log!("Authentication failed for user credentials: {}", credentials);
        error_response_json(buf, "", rq::AUTH_FAILED, &format!("authentication failed for {}", credentials));
        return None;
    };
    let text = cstr_at(&body, start);
    if is_xml {
        xml_request(tx, &phone, text, buf)
    } else {
        json_request(tx, &phone, text, buf)
    }
}

/// `handle_request_xml` (inlined in FUN_00176a60).
fn xml_request(tx: &Arc<Transaction>, phone: &str, text: &[u8], buf: &mut String) -> Option<Forwarded> {
    use dpma_proto::errors::request as rq;
    let Some(doc) = astxml::Doc::read_memory(text) else {
        error_response_xml(buf, "", rq::PARSE);
        return None;
    };
    let Some(root) = doc.root().filter(|r| !r.name().is_empty()) else {
        error_response_xml(buf, "", rq::PARSE);
        return None;
    };
    let name = root.name();
    // The original copies the attribute without checking it (a request
    // without one crashes it); a missing one is treated as empty here.
    let method = root.attribute("method").unwrap_or_default();
    dpma_debug!(3, "Asterisk {} method '{}' is using XML body", name, method);
    if !name.eq_ignore_ascii_case("request") {
        return None;
    }
    let code = 'code: {
        let Some(children) = root.children() else { break 'code rq::EMPTY };
        if method.is_empty() {
            break 'code rq::MISSING_METHOD;
        }
        let Some(params) = children.find_element("parameters", None) else {
            break 'code rq::PARAMS_NOT_FOUND;
        };
        if let Some(f) = method::find_xml(&method) {
            // Methods get the <parameters> element as markup.
            let markup = doc.node_markup(&params).unwrap_or_default();
            let call = MethodCall { phone: phone.to_string(), method: method.clone(), tx: Some(tx.clone()) };
            f(&call, &markup, buf);
            if !buf.is_empty() {
                return None;
            }
            break 'code rq::PARSE;
        }
        if method::is_ami(&method) {
            let text = params.text();
            crate::ami::messages::raise_event(&tx.key, &method, "XML", text.as_deref().unwrap_or("(null)"));
            return Some(Forwarded { method });
        }
        rq::METHOD_NOT_FOUND
    };
    error_response_xml(buf, &method, code);
    None
}

/// `handle_request_json` (inlined in FUN_00176a60).  The request is parsed
/// with Asterisk's JSON library (jansson), as the original does, so the
/// same documents are accepted and AMI sees the same parameter text;
/// methods get the parameters as a `serde_json::Value`.
fn json_request(tx: &Arc<Transaction>, phone: &str, text: &[u8], buf: &mut String) -> Option<Forwarded> {
    use dpma_proto::errors::request as rq;
    let Some(doc) = json::Json::load(text) else {
        error_response_json(buf, "", rq::PARSE, "json body");
        return None;
    };
    let Some(request) = doc.get("request").filter(|r| r.kind() == json::OBJECT) else {
        error_response_json(buf, "", rq::PARSE, "no request in body");
        return None;
    };
    let Some(method) = request.get("method").filter(|m| m.kind() == json::STRING).map(|m| m.string()) else {
        error_response_json(buf, "", rq::PARSE, "no method in body");
        return None;
    };
    buf.clear();
    let Some(params) = request.get("parameters") else {
        error_response_json(buf, &method, rq::EMPTY, "request contains no parameters");
        return None;
    };
    if let Some(f) = method::find_json(&method) {
        // jansson accepted the document; serde_json reads the same one.
        let value = serde_json::from_slice::<serde_json::Value>(text)
            .ok()
            .and_then(|mut v| v.get_mut("request")?.get_mut("parameters").map(serde_json::Value::take))
            .unwrap_or(serde_json::Value::Null);
        let call = MethodCall { phone: phone.to_string(), method: method.clone(), tx: Some(tx.clone()) };
        f(&call, &value, buf);
        if buf.is_empty() {
            error_response_json(buf, &method, rq::PARSE, "empty response body");
        }
        return None;
    }
    if method::is_ami(&method) {
        // ast_json_dump_string fails for parameters that are not an object
        // or an array; then no event is raised, but the request still
        // waits for an answer.
        if let Some(params) = params.dump() {
            crate::ami::messages::raise_event(&tx.key, &method, "JSON", &params);
        }
        return Some(Forwarded { method });
    }
    // The original passes the method name as the printf format of the
    // detail.
    error_response_json(buf, &method, rq::METHOD_NOT_FOUND, &method);
    None
}

/// `handle_request_ping` (FUN_001758e0): send the (empty) PingResponse.
pub fn handle_ping(tx: Arc<Transaction>) -> i32 {
    crate::session::send_and_destroy(&tx);
    0
}
