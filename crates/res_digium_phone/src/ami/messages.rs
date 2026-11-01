//! DPMAMessageSend / DPMAMessageRegister / DPMAMessageResponse, the
//! queued AMI-forwarded requests, and the AMI scheduler (phone_ami.c
//! 0x174980..0x175750; phone_request.c 0x175840..0x1758c0, 0x176490, and
//! the AMI part of 0x176a60).
//! (`DPMALicenseStatus`, FUN_00174d20, is intentionally not ported.)
//!
//! AMI clients register method names with `DPMAMessageRegister`.  When a
//! phone calls such a method in an AsteriskRequest or HTTPRequest (and no
//! XML or JSON method of that name exists), the request handler raises a
//! `DPMAMessage` event ([`raise_event`]) and queues the transaction's reply
//! under the transaction key ([`queue_request`]).  `DPMAMessageResponse`
//! with that key as `RequestID` completes the reply and sends it to the
//! phone's session.
//!
//! Each queued request also gets an expiry entry 300 s out in the AMI
//! scheduler context.  As in the original, nothing services that context:
//! it is created with `ast_sched_context_create` and never given a thread
//! (`ast_sched_start_thread`) or run (`ast_sched_runq`), so the expiry never
//! fires and a request that is never answered stays queued until unload.
//! (`dpmadev ami runq` runs the due entries by hand.)

use super::AmiAction;
use crate::session::{self, Outgoing, Transaction};
use dpma_ast::manager::{self, Request};
use dpma_ast::sched::Context;
use dpma_ast::{dpma_debug, dpma_log};
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

/// Delay of `sched_expire_queued` (FUN_001758c0 schedules after 300000 ms).
pub const QUEUED_EXPIRY_MS: i32 = 300_000;

/// The `DPMAMessage` event's category: EVENT_FLAG_AGENT ("agent").
const DPMA_MESSAGE_CATEGORY: i32 = manager::AUTH_AGENT;

/// The body `handle_request_asterisk` starts every reply with.  A queued
/// reply carries it (and nothing else the handler adds) until
/// `DPMAMessageResponse` appends the response document.
pub const HTTP_PREAMBLE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n";

/// A phone request forwarded to AMI as a `DPMAMessage` event, waiting for
/// `DPMAMessageResponse` (`struct queued_msg`, 0x28 bytes; destroyed by
/// `destroy_queued_msg`, FUN_00175650).
pub struct QueuedMsg {
    /// The transaction key, `"<AppServer-ID>-<MAC>"`: the event's
    /// `RequestID` and the container key (case insensitive) (+0x00).
    pub request_id: String,
    /// The method as the phone requested it (+0x08).
    pub method: String,
    /// Id of the session the request came in on; the reply goes to the
    /// session found under this id when it is answered (+0x10).
    pub session_id: String,
    /// The transaction's reply, taken from the transaction (+0x18).
    pub outgoing: Option<Outgoing>,
    /// The expiry's scheduler entry, or -1 (+0x20).
    pub sched_id: i32,
    /// Identifies this entry to the expiry callback (the original passes
    /// the object itself as the callback data).
    token: usize,
}

impl QueuedMsg {
    pub fn new(request_id: &str, method: &str, session_id: &str, outgoing: Option<Outgoing>) -> QueuedMsg {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        QueuedMsg {
            request_id: request_id.to_string(),
            method: method.to_string(),
            session_id: session_id.to_string(),
            outgoing,
            sched_id: -1,
            token: NEXT.fetch_add(1, Ordering::Relaxed),
        }
    }
}

/// The queued message container (0x5f4e50): None while not initialized.
/// Kept in insertion order, so a lookup finds the oldest of several
/// entries with the same key, as the original's hash container does.
static QUEUE: Mutex<Option<Vec<QueuedMsg>>> = Mutex::new(None);

/// The AMI scheduler context (0x5eef30).
static SCHED: RwLock<Option<Context>> = RwLock::new(None);

fn queue() -> MutexGuard<'static, Option<Vec<QueuedMsg>>> {
    QUEUE.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Scheduler (phone_request.c)
// ---------------------------------------------------------------------------

/// FUN_00175880: create the scheduler context ("Failed to create ami
/// schedule context" on error, logged by the caller).  No thread is
/// started, as in the original.
pub fn sched_create() -> Result<(), ()> {
    let ctx = Context::create().ok_or(())?;
    *SCHED.write().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
    Ok(())
}

/// FUN_001758a0: destroy the scheduler context; pending expiries are
/// dropped without running.
pub fn sched_destroy() {
    let ctx = SCHED.write().unwrap_or_else(|e| e.into_inner()).take();
    drop(ctx);
}

/// FUN_001758c0: schedule `sched_expire_queued` for `msg` in
/// [`QUEUED_EXPIRY_MS`] and record the entry in `msg.sched_id`.  Err (with
/// `sched_id` -1) when that fails.
pub fn schedule_expiry(msg: &mut QueuedMsg) -> Result<(), ()> {
    msg.sched_id = match SCHED.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(ctx) => ctx.add(QUEUED_EXPIRY_MS, sched_expire_queued, msg.token),
        None => -1,
    };
    if msg.sched_id == -1 {
        Err(())
    } else {
        Ok(())
    }
}

/// `ast_sched_del` of an entry's expiry, if it has one.
fn cancel_expiry(sched_id: i32) {
    if sched_id == -1 {
        return;
    }
    if let Some(ctx) = SCHED.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        ctx.del(sched_id);
    }
}

/// `sched_expire_queued` (FUN_00176490): drop a request nobody answered.
/// Returns 0 (not rescheduled).
unsafe extern "C" fn sched_expire_queued(data: *const c_void) -> c_int {
    dpma_ast::guard(0, || {
        if let Some(msg) = unlink_token(data as usize) {
            dpma_log!("No response to request ({}), expired.", msg.request_id);
        }
        0
    })
}

// ---------------------------------------------------------------------------
// The queued message container (phone_ami.c)
// ---------------------------------------------------------------------------

/// `phone_ami_queued_msg_container_initialize` (FUN_001755b0).
pub fn queue_init() -> Result<(), ()> {
    *queue() = Some(Vec::new());
    Ok(())
}

/// `phone_ami_queued_msg_container_dispose` (FUN_00175610): drop every
/// queued request (their replies are never sent).
pub fn queue_dispose() {
    let q = queue().take();
    drop(q);
}

/// `phone_ami_queued_msg_link` (FUN_001756d0).  Err when the container
/// does not exist.
pub fn queue_link(msg: QueuedMsg) -> Result<(), ()> {
    match queue().as_mut() {
        Some(q) => {
            q.push(msg);
            Ok(())
        }
        None => Err(()),
    }
}

/// Find (`queued_msg_find`, FUN_00174bc0) and unlink the oldest queued
/// request with this RequestID (case insensitive).
pub fn queue_unlink(request_id: &str) -> Option<QueuedMsg> {
    let mut g = queue();
    let q = g.as_mut()?;
    let i = q.iter().position(|m| m.request_id.eq_ignore_ascii_case(request_id))?;
    Some(q.remove(i))
}

/// `phone_ami_queued_msg_unlink` (FUN_00175710) of one particular entry.
fn unlink_token(token: usize) -> Option<QueuedMsg> {
    let mut g = queue();
    let q = g.as_mut()?;
    let i = q.iter().position(|m| m.token == token)?;
    Some(q.remove(i))
}

// ---------------------------------------------------------------------------
// The request side (phone_request.c, handle_request_asterisk)
// ---------------------------------------------------------------------------

/// `__handle_request_ami` (phone_request.c line 0x192): raise the
/// `DPMAMessage` event (category "agent") for a request to an
/// AMI-registered method.  `request_id` is the transaction key, `format`
/// "XML" or "JSON", and `params` the request's parameters: for XML the
/// text content of the `<parameters>` element (`ast_xml_get_text`), for
/// JSON the compact dump of the `"parameters"` value.
pub fn raise_event(request_id: &str, method: &str, format: &str, params: &str) {
    manager::event_at(
        DPMA_MESSAGE_CATEGORY,
        "DPMAMessage",
        "phone_request.c",
        0x192,
        "__handle_request_ami",
        &format!("RequestID: {}\r\nMethod: {}\r\nFormat: {}\r\nParameters: {}\r\n", request_id, method, format, params),
    );
}

/// The end of `handle_request_asterisk` (FUN_00176a60) after an AMI
/// forward: move the transaction's reply into a queued request keyed by
/// the transaction key, schedule its expiry, and link it.  The handler
/// must not send the reply when this succeeds; on Err the reply is left in
/// the transaction for the handler to send (`send_and_destroy`), as the
/// original does when the expiry cannot be scheduled.
pub fn queue_request(tx: &Arc<Transaction>, method: &str) -> Result<(), ()> {
    let session_id = tx.session.as_ref().map(|s| s.id.clone()).unwrap_or_default();
    let outgoing = tx.outgoing.lock().unwrap_or_else(|e| e.into_inner()).take();
    let mut msg = QueuedMsg::new(&tx.key, method, &session_id, outgoing);
    if schedule_expiry(&mut msg).is_ok() {
        let sched_id = msg.sched_id;
        let mut g = queue();
        if let Some(q) = g.as_mut() {
            q.push(msg);
            dpma_debug!(3, "Queued AMI request '{}' (expiry {})", tx.key, sched_id);
            return Ok(());
        }
        drop(g);
        // No container (unloading): undo the expiry.
        cancel_expiry(sched_id);
    }
    // The original drops the queued message when the expiry cannot be
    // scheduled, freeing the reply it shares with the transaction, and
    // then sends the transaction; here the reply is put back so that the
    // caller sends it intact.
    *tx.outgoing.lock().unwrap_or_else(|e| e.into_inner()) = msg.outgoing.take();
    Err(())
}

// ---------------------------------------------------------------------------
// AMI actions (phone_ami.c)
// ---------------------------------------------------------------------------

/// `snprintf(idtext, 0x100, "ActionID: %s\r\n", id)` when the request has
/// a non-empty ActionID, else "".
fn action_id_text(r: &Request) -> Vec<u8> {
    let id = r.header_bytes("ActionID");
    if id.is_empty() {
        return Vec::new();
    }
    let mut t = b"ActionID: ".to_vec();
    t.extend_from_slice(&id);
    t.extend_from_slice(b"\r\n");
    t.truncate(0xff);
    t
}

/// `astman_append(s, "Response: %s\r\n%s\r\n", ...)`: every action here
/// answers with exactly this (no `Message` header).
fn reply(r: &Request, ok: bool, idtext: &[u8]) {
    let mut t = format!("Response: {}\r\n", if ok { "Success" } else { "Failure" }).into_bytes();
    t.extend_from_slice(idtext);
    t.extend_from_slice(b"\r\n");
    r.append_bytes(&t);
}

/// `action_dpma_message_send` (FUN_00174a00): send event `Method` with
/// body `Message` to phone `PhoneName` (`phone_user_send_event`).
fn action_message_send(r: &Request) -> i32 {
    let method = r.header("Method");
    let message = r.header("Message");
    let phone = r.header("PhoneName");
    let idtext = action_id_text(r);
    // phone_user_find: no phone for an empty name.
    let found = !phone.is_empty() && crate::users::read().as_ref().is_some_and(|reg| reg.phones.contains(&phone));
    let ok = if !found {
        dpma_log!("Phone '{}' could not be found.", phone);
        false
    } else if method.is_empty() {
        dpma_log!("Message not supplied.");
        false
    } else {
        crate::users::runtime::send_event(&phone, &method, &message).is_ok()
    };
    reply(r, ok, &idtext);
    0
}

/// `DPMAMessageRegister` (FUN_00174c50): forward requests for `Method` to
/// AMI from now on (`__phone_method_register` in the AMI registry).
fn action_message_register(r: &Request) -> i32 {
    let method = r.header("Method");
    let idtext = action_id_text(r);
    let ok = !method.is_empty() && crate::method::register_ami(&method).is_ok();
    reply(r, ok, &idtext);
    0
}

/// The response document `DPMAMessageResponse` appends to the queued
/// reply, or Err (the request stays queued) for a JSON response with
/// neither `Response` nor both `ErrorNum` and `ErrorMsg`, or with text
/// jansson refuses (invalid UTF-8).  Any `Format` other than JSON and XML
/// (ignoring case) gives an empty document.
fn response_document(method: &str, format: &str, response: &[u8], num: &[u8], msg: &[u8]) -> Result<Vec<u8>, ()> {
    let has_error = !num.is_empty() && !msg.is_empty();
    if format.eq_ignore_ascii_case("JSON") {
        let v = if !response.is_empty() {
            let result = std::str::from_utf8(response).map_err(|_| ())?;
            serde_json::json!({"response": {"method": method, "result": result}})
        } else if has_error {
            let message = std::str::from_utf8(msg).map_err(|_| ())?;
            // The original packs the ErrorNum string's address with "i"
            // (low 32 bits of a pointer); its value is used instead.
            let code = dpma_proto::framing::parse_sequence(&String::from_utf8_lossy(num));
            serde_json::json!({"response": {"method": method, "errors": {"error": {"code": code, "message": message}}}})
        } else {
            return Err(());
        };
        Ok(format!("\r\n\r\n{}\r\n", dpma_proto::json::dump(&v)).into_bytes())
    } else if format.eq_ignore_ascii_case("XML") {
        let mut b = format!("\r\n\r\n<response method=\"{}\">\r\n", method).into_bytes();
        if !response.is_empty() {
            b.extend_from_slice(b"<result>");
            b.extend_from_slice(response);
            b.extend_from_slice(b"</result>\r\n");
        } else if has_error {
            b.extend_from_slice(b"<errors>\r\n<error code=\"");
            b.extend_from_slice(num);
            b.extend_from_slice(b"\" message=\"");
            b.extend_from_slice(msg);
            b.extend_from_slice(b"\" />\r\n</errors>\r\n");
        }
        b.extend_from_slice(b"</response>\r\n");
        Ok(b)
    } else {
        Ok(Vec::new())
    }
}

/// Complete and send the queued request `request_id`.
fn respond(request_id: &str, format: &str, response: &[u8], num: &[u8], msg: &[u8]) -> Result<(), ()> {
    if request_id.is_empty() {
        return Err(());
    }
    let (mut queued, document) = {
        let mut g = queue();
        let q = g.as_mut().ok_or(())?;
        let i = q.iter().position(|m| m.request_id.eq_ignore_ascii_case(request_id)).ok_or(())?;
        let document = response_document(&q[i].method, format, response, num, msg)?;
        (q.remove(i), document)
    };
    // Outside the container lock: ast_sched_del waits for a running expiry.
    cancel_expiry(queued.sched_id);
    let mut out = queued.outgoing.take().unwrap_or_default();
    out.append(&document);
    let session = session::find(&queued.session_id).ok_or(())?;
    session::send(&out, &session)
}

/// `action_dpma_message_response` (FUN_00174f20): answer the queued
/// request `RequestID` with `Response` (or `ErrorNum` and `ErrorMsg`) as an
/// XML or JSON document (`Format`), and send it to the phone.
fn action_message_response(r: &Request) -> i32 {
    let request_id = r.header("RequestID");
    let format = r.header("Format");
    let response = r.header_bytes("Response");
    let num = r.header_bytes("ErrorNum");
    let msg = r.header_bytes("ErrorMsg");
    let idtext = action_id_text(r);
    let ok = respond(&request_id, &format, &response, &num, &msg).is_ok();
    reply(r, ok, &idtext);
    0
}

/// Actions contributed to `ami::register_actions` (all with authority
/// "call", as FUN_00175750 registers them).
pub fn actions() -> Vec<AmiAction> {
    vec![
        AmiAction { name: "DPMAMessageRegister", authority: manager::AUTH_CALL, handler: action_message_register },
        AmiAction { name: "DPMAMessageResponse", authority: manager::AUTH_CALL, handler: action_message_response },
        AmiAction { name: "DPMAMessageSend", authority: manager::AUTH_CALL, handler: action_message_send },
    ]
}

// ---------------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------------

#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

    /// dpmadev ami queue: list the queued requests.
    fn list(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        let g = queue();
        let Some(q) = g.as_ref() else {
            a.out("No queued message container\n");
            return CliResult::Success;
        };
        for m in q {
            let (kind, len) = match m.outgoing.as_ref() {
                Some(o) => (o.response_type.as_str(), o.body.len()),
                None => ("(none)", 0),
            };
            a.out(&format!(
                "RequestID: {}  Method: {}  Session: {}  SchedID: {}  Reply: {} ({} bytes)\n",
                m.request_id, m.method, m.session_id, m.sched_id, kind, len
            ));
        }
        a.out(&format!("{} queued\n", q.len()));
        CliResult::Success
    }

    /// dpmadev ami runq: run the scheduler entries that are due.
    fn runq(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        let n = SCHED.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|c| c.runq());
        match n {
            Some(n) => a.out(&format!("{} scheduled entries ran\n", n)),
            None => a.out("No scheduler context\n"),
        }
        CliResult::Success
    }

    /// dpmadev ami forward <session> <uri> <id> <XML|JSON> <method> [params...]:
    /// what handle_request_asterisk does for an AMI-registered method, for a
    /// synthetic AsteriskRequest with AppServer-ID <id> on <session> whose
    /// reply goes to <uri>.
    fn forward(a: &CliArgs) -> CliResult {
        if a.argc() < 8 {
            return CliResult::ShowUsage;
        }
        let Some(s) = session::find(&a.argv[3]) else {
            a.out(&format!("No session '{}'\n", a.argv[3]));
            return CliResult::Failure;
        };
        let (uri, id, format, method) = (&a.argv[4], &a.argv[5], &a.argv[6], &a.argv[7]);
        let params = a.argv[8..].join(" ");
        if !crate::method::is_ami(method) {
            a.out(&format!("'{}' is not registered by AMI\n", method));
            return CliResult::Failure;
        }
        let mac = s.mac();
        let mut out = Outgoing::new();
        out.response_uri = uri.clone();
        out.id = id.clone();
        out.response_type = "AsteriskResponse".into();
        out.append_str(HTTP_PREAMBLE);
        let tx = Arc::new(Transaction {
            key: format!("{}-{}", id, if mac.is_empty() { "unknown" } else { mac.as_str() }),
            app_server_id: id.clone(),
            request_type: "AsteriskRequest".into(),
            response_uri: uri.clone(),
            mac,
            session: Some(s),
            outgoing: Mutex::new(Some(out)),
            ..Default::default()
        });
        raise_event(&tx.key, method, &format.to_ascii_uppercase(), &params);
        match queue_request(&tx, method) {
            Ok(()) => a.out(&format!("Queued {}\n", tx.key)),
            Err(()) => {
                session::send_and_destroy(&tx);
                a.out(&format!("Not queued; sent {}\n", tx.key));
            }
        }
        CliResult::Success
    }

    vec![
        CliCommand {
            command: "dpmadev ami queue",
            summary: "List the requests queued for DPMAMessageResponse",
            usage: "Usage: dpmadev ami queue\n",
            exec: list,
            complete: None,
        },
        CliCommand {
            command: "dpmadev ami runq",
            summary: "Run the due AMI scheduler entries (expiries)",
            usage: "Usage: dpmadev ami runq\n       Nothing runs the AMI scheduler otherwise (as in the original).\n",
            exec: runq,
            complete: None,
        },
        CliCommand {
            command: "dpmadev ami forward",
            summary: "Forward a synthetic request to AMI",
            usage: "Usage: dpmadev ami forward <session> <uri> <id> <XML|JSON> <method> [params...]\n       Raises DPMAMessage and queues an AsteriskResponse for <session>, sent to <uri>.\n",
            exec: forward,
            complete: None,
        },
    ]
}
