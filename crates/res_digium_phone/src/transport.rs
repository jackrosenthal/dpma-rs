//! Message transport between phones and the module
//! (phone_network_handler2.c, plus the dialplan routing and outgoing
//! message construction from phone_message.c).
//!
//! Phones send SIP MESSAGE requests.  res_pjsip delivers them to the
//! dialplan context `pjsip_message_context` (via the endpoint identifier
//! helper module), whose `proxy` extension, built here, records the
//! response address and hands them to the `digium_phone` message
//! technology with `MessageSend(digium_phone:blah)`.  The technology
//! callback queues them; the phone_main thread reads them with
//! [`read_msg`].  Replies are `ast_msg`s queued into the same context at
//! extension `digium_phone_module`, which sends them back with
//! `MessageSend(${TMP_RESPONSE_URI},proxy)`.
//!
//! The original also builds the same routing for chan_sip (sip.conf's
//! `outofcall_message_context`, `SIP_RECVADDR`); chan_sip is not
//! supported here, so only the PJSIP routing exists.

use crate::config::General;
use dpma_ast::msg::{self, Msg};
use dpma_ast::{dpma_debug, dpma_log, pbx};
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Registrar of the routing contexts and their extensions.
pub const REGISTRAR: &str = "digium_phone_module";
/// Message technology name.
pub const MSG_TECH: &str = "digium_phone";
/// Extension that sends replies.
pub const SEND_EXTEN: &str = "digium_phone_module";
/// Extension that receives phone messages.
pub const PROXY_EXTEN: &str = "proxy";

/// Message variable carrying the address replies go to.
const VAR_RESPONSE_URI: &str = "X-Digium-AppServer-Response-URI";
/// Message variable carrying the phone's full contact.
const VAR_RESPONSE_FULLCONTACT: &str = "X-Digium-AppServer-Response-FullContact";

/// The read queue (the original's `read_queue` list plus its alert pipe).
struct ReadQueue {
    msgs: VecDeque<Msg>,
    /// Set by [`wake_reader`]; makes the next [`read_msg`] return None.
    wake: bool,
}

static QUEUE: Mutex<ReadQueue> = Mutex::new(ReadQueue { msgs: VecDeque::new(), wake: false });
static QUEUE_CV: Condvar = Condvar::new();

fn queue() -> std::sync::MutexGuard<'static, ReadQueue> {
    QUEUE.lock().unwrap_or_else(|e| e.into_inner())
}

/// `receive_msg` (FUN_00147c70): the technology's `msg_send` callback.
/// Takes a reference to the message (done by the caller) and queues it
/// for [`read_msg`].
fn receive_msg(m: Msg, _to: &str, _from: &str) -> i32 {
    queue().msgs.push_back(m);
    QUEUE_CV.notify_one();
    0
}

/// Drop every queued message.
fn drain_queue() {
    // Release the messages outside the lock.
    let msgs = std::mem::take(&mut queue().msgs);
    drop(msgs);
}

/// `phone_network_handler2` init (FUN_00148040): register the message
/// technology and create the read queue.  Called at the end of
/// `session::load` (as the original does from `phone_msg_load`).
pub fn load() -> Result<(), ()> {
    {
        // The module's statics can outlive an unload (a Rust library is
        // not always unmapped), so start from a clean queue.
        let mut q = queue();
        q.wake = false;
    }
    drain_queue();
    if !msg::tech_register(receive_msg) {
        unload();
        return Err(());
    }
    Ok(())
}

/// `network_handler_destroy` (FUN_00147d70): unregister the technology
/// and drop queued messages.  A reader still waiting is woken (the
/// original closes the alert pipe under it).
pub fn unload() {
    msg::tech_unregister();
    drain_queue();
    wake_reader();
}

/// `phone_network_handler2_read_msg` (FUN_00147eb0): wait up to
/// `timeout_ms` (forever when negative) for the next incoming message.
/// Returns None on timeout or when woken by [`wake_reader`].
pub fn read_msg(timeout_ms: i32) -> Option<Msg> {
    let deadline = u64::try_from(timeout_ms)
        .ok()
        .map(|ms| Instant::now() + Duration::from_millis(ms));
    let mut q = queue();
    loop {
        if q.wake {
            q.wake = false;
            return None;
        }
        if let Some(m) = q.msgs.pop_front() {
            return Some(m);
        }
        q = match deadline {
            None => QUEUE_CV.wait(q).unwrap_or_else(|e| e.into_inner()),
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    return None;
                }
                QUEUE_CV.wait_timeout(q, d - now).unwrap_or_else(|e| e.into_inner()).0
            }
        };
    }
}

/// Wake a thread blocked in [`read_msg`] (used to stop phone_main).  The
/// wake is remembered until a [`read_msg`] consumes it, so it cannot be
/// lost to a race with a reader that is about to wait.
pub fn wake_reader() {
    queue().wake = true;
    QUEUE_CV.notify_all();
}

/// `phone_network_handler2_write_msg` (FUN_00147e60): queue an outgoing
/// message into the dialplan (`ast_msg_queue`).
pub fn write_msg(msg: Msg) -> Result<(), ()> {
    if msg.queue() {
        Ok(())
    } else {
        dpma_log!("message queue failed {}", -1);
        Err(())
    }
}

/// FUN_0014be60: allocate an outgoing message for `response_uri`, with
/// its context set from the URI scheme: `pjsip...` gets
/// `pjsip_message_context` (its default when the setting is empty).  None
/// for other schemes, including the original's `sip...` (chan_sip), which
/// is not supported.
pub fn new_outgoing(response_uri: &str) -> Option<Msg> {
    // The original compares prefixes (strncmp with "sip", then "pjsip").
    if !response_uri.starts_with("pjsip") {
        return None;
    }
    let mut m = Msg::alloc()?;
    m.set_context(crate::config::get().message_context());
    Some(m)
}

/// Called after every successful `config::load()` (`config_replace`):
/// when `pjsip_message_context` changed, destroy the old routing context
/// and build the new one (`msg_build_dialplan_routing(ctx, "pjsip")`).
/// As in the original, the raw setting is compared, so an explicitly
/// empty `pjsip_message_context` builds no routing.
pub fn config_changed(old: Option<&General>, new: &General) {
    if let Some(old) = old {
        if old.pjsip_message_context == new.pjsip_message_context {
            return;
        }
        if !old.pjsip_message_context.is_empty() {
            destroy_dialplan_routing(&old.pjsip_message_context);
        }
    }
    if !new.pjsip_message_context.is_empty() {
        let _ = build_dialplan_routing(&new.pjsip_message_context, "pjsip");
    }
}

/// Destroy the routing context (`phone_msg_unload`): the current
/// configuration's `pjsip_message_context`, or its default.
pub fn destroy_routing() {
    destroy_dialplan_routing(crate::config::get().message_context());
}

/// `msg_build_dialplan_routing` (FUN_00148860): create `context` and add
/// the `digium_phone_module` (send) and `proxy` (receive) extensions for
/// the channel technology `tech` ("pjsip").
fn build_dialplan_routing(context: &str, tech: &str) -> Result<(), ()> {
    dpma_debug!(5, "Build dialplan routing for {} - message context = {}", tech, context);
    if !pbx::context_create(context, REGISTRAR) {
        dpma_log!("Unable to build dialplan routing - can't find/create context {}", context);
        return Err(());
    }
    let tech_upper = tech.to_ascii_uppercase();
    let send: [(Option<&str>, &str, String); 7] = [
        (None, "Set", "MESSAGE(custom_data)=mark_all_outbound".into()),
        (None, "Set", format!("TMP_RESPONSE_URI=${{MESSAGE_DATA({})}}", VAR_RESPONSE_URI)),
        (
            None,
            "Set",
            format!("MESSAGE_DATA(Request-URI)=${{MESSAGE_DATA({})}}", VAR_RESPONSE_FULLCONTACT),
        ),
        (None, "Set", format!("MESSAGE_DATA({})=", VAR_RESPONSE_URI)),
        (None, "Set", format!("MESSAGE_DATA({})=", VAR_RESPONSE_FULLCONTACT)),
        (None, "MessageSend", format!("${{TMP_RESPONSE_URI}},{}", PROXY_EXTEN)),
        (None, "Hangup", String::new()),
    ];
    let proxy: [(Option<&str>, &str, String); 5] = [
        (None, "Set", "MESSAGE(custom_data)=mark_all_outbound".into()),
        (
            Some("recvaddr"),
            "Set",
            format!("MESSAGE_DATA({})={}:${{MESSAGE_DATA({}_RECVADDR)}}", VAR_RESPONSE_URI, tech, tech_upper),
        ),
        (
            Some("fullcontact"),
            "Set",
            format!("MESSAGE_DATA({})=${{MESSAGE_DATA({}_FULLCONTACT)}}", VAR_RESPONSE_FULLCONTACT, tech_upper),
        ),
        (Some("send"), "MessageSend", format!("{}:blah", MSG_TECH)),
        (None, "Hangup", String::new()),
    ];
    for (exten, steps) in [(SEND_EXTEN, &send[..]), (PROXY_EXTEN, &proxy[..])] {
        for (i, (label, app, data)) in steps.iter().enumerate() {
            let data = (!data.is_empty()).then_some(data.as_str());
            // The original ignores the results.
            pbx::add_extension(context, true, exten, i as i32 + 1, *label, None, app, data, REGISTRAR);
        }
    }
    Ok(())
}

/// `msg_destroy_dialplan_routing` (FUN_0014ff30): remove what this module
/// added to `context` (and the context itself when that leaves it empty).
fn destroy_dialplan_routing(context: &str) {
    if !pbx::context_exists(context) {
        return;
    }
    dpma_debug!(5, "Destroy dialplan routing - message context = {}", context);
    pbx::context_destroy(context, REGISTRAR);
}

/// Test hooks (feature "devtest"): pop a queued message and print it, or
/// send one to a URI through the dialplan.
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn read(a: &CliArgs) -> CliResult {
        if a.argc() != 4 {
            return CliResult::ShowUsage;
        }
        let Ok(ms) = a.argv[3].parse::<i32>() else {
            return CliResult::ShowUsage;
        };
        let Some(m) = read_msg(ms) else {
            a.out("No message\n");
            return CliResult::Success;
        };
        let mut out = format!("Refcount: {}\n", m.refcount());
        for (what, v) in [("To", m.to()), ("From", m.from()), ("Tech", m.tech()), ("Endpoint", m.endpoint())] {
            out.push_str(&format!("{}: {}\n", what, v.unwrap_or_default()));
        }
        out.push_str("Variables:\n");
        for v in m.vars() {
            out.push_str(&format!("  {}{}: {}\n", if v.outbound { "" } else { "(received) " }, v.name, v.value));
        }
        out.push_str(&format!("Body:\n{}\n", m.body().unwrap_or_default()));
        a.out(&out);
        CliResult::Success
    }

    fn send(a: &CliArgs) -> CliResult {
        static ID: AtomicU32 = AtomicU32::new(0);
        if a.argc() < 5 {
            return CliResult::ShowUsage;
        }
        let uri = &a.argv[3];
        let ty = &a.argv[4];
        let body = a.argv[5..].join(" ");
        let Some(mut m) = new_outgoing(uri) else {
            a.out(&format!("Cannot create a message for '{}'\n", uri));
            return CliResult::Failure;
        };
        m.set_exten(SEND_EXTEN);
        m.set_var(VAR_RESPONSE_URI, uri);
        let type_var = if ty.ends_with("Response") {
            "X-Digium-AppServer-ResponseType"
        } else {
            "X-Digium-AppServer-RequestType"
        };
        m.set_var(type_var, ty);
        let id = ID.fetch_add(1, Ordering::Relaxed) % 100000 + 1;
        m.set_var("X-Digium-AppServer-ID", &id.to_string());
        if !body.is_empty() {
            m.set_body(&body);
        }
        if write_msg(m).is_ok() {
            a.out(&format!("Queued {} (ID {}) to {}\n", ty, id, uri));
            CliResult::Success
        } else {
            a.out("Queueing failed\n");
            CliResult::Failure
        }
    }

    fn stats(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        let mut counts = std::collections::BTreeMap::new();
        let q = queue();
        for m in &q.msgs {
            *counts.entry(m.refcount()).or_insert(0usize) += 1;
        }
        let n = q.msgs.len();
        drop(q);
        let by_ref: Vec<String> = counts.iter().map(|(r, c)| format!("{} with refcount {}", c, r)).collect();
        a.out(&format!("{} queued message(s){}{}\n", n, if n > 0 { ": " } else { "" }, by_ref.join(", ")));
        CliResult::Success
    }

    fn wake(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        wake_reader();
        CliResult::Success
    }

    vec![
        CliCommand {
            command: "dpmadev transport queue",
            summary: "Show the incoming message queue",
            usage: "Usage: dpmadev transport queue\n       Count the queued incoming messages by reference count.\n",
            exec: stats,
            complete: None,
        },
        CliCommand {
            command: "dpmadev transport wake",
            summary: "Wake a blocked message reader",
            usage: "Usage: dpmadev transport wake\n       Make the next (or a blocked) message read return without a message.\n",
            exec: wake,
            complete: None,
        },
        CliCommand {
            command: "dpmadev transport read",
            summary: "Pop a queued phone message",
            usage: "Usage: dpmadev transport read <ms>\n       Wait up to <ms> milliseconds (forever if negative) for a message\n       from the digium_phone message technology and print it.\n",
            exec: read,
            complete: None,
        },
        CliCommand {
            command: "dpmadev transport send",
            summary: "Send a phone message",
            usage: "Usage: dpmadev transport send <uri> <type> [<body>]\n       Queue a message of request (or, for types ending in \"Response\",\n       response) type <type> for <uri> (e.g., pjsip:127.0.0.1:5070)\n       through the digium_phone_module extension.\n",
            exec: send,
            complete: None,
        },
    ]
}
