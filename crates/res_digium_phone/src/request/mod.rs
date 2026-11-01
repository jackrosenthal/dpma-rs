//! Request dispatch (dpma_request.c): the request-type handler table, the
//! `DPMA_request` and `DPMA_extended` thread pools, and the XML/JSON error
//! responses.
//!
//! Owner: P3 "request" (wave 1).  `handlers.rs` is owned by P12
//! "request-handlers" (wave 3).

pub mod handlers;

use crate::session::{Outgoing, Transaction};
use dpma_ast::log::LOG_ERROR;
use dpma_ast::threadpool::{Options, Origin, ThreadPool};
use dpma_ast::{ast_log, dpma_log};
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

/// A request-type handler (`request_register_handler`); runs on the
/// `DPMA_request` pool.  The transaction's `outgoing` is allocated (and
/// its response type, URI, full contact, and id filled in) before the
/// handler runs when the registration has a response type.  The return
/// value is ignored (as the taskprocessor ignores it in the original).
pub type Handler = fn(tx: Arc<Transaction>) -> i32;

/// One entry of the handler table (32 bytes in the original).
#[derive(Clone, Copy)]
struct Registration {
    request_type: &'static str,
    response_type: Option<&'static str>,
    requires_session: bool,
    handler: Handler,
}

/// The handler table (0x5f4e80), searched in registration order.
static HANDLERS: RwLock<Vec<Registration>> = RwLock::new(Vec::new());

/// The `DPMA_request` pool (0x5eff78).
static REQUEST_POOL: RwLock<Option<ThreadPool>> = RwLock::new(None);

/// The `DPMA_extended` pool (0x5eff70).
static EXTENDED_POOL: RwLock<Option<ThreadPool>> = RwLock::new(None);

const REQUEST_POOL_NAME: &str = "DPMA_request";
const EXTENDED_POOL_NAME: &str = "DPMA_extended";

/// Fixed part of the pools' options (0x5e95e0): version 1, idle timeout
/// 60 s, auto increment 1.  The sizes come from the configuration.
const IDLE_TIMEOUT: i32 = 60;
const AUTO_INCREMENT: i32 = 1;

/// `request_load` (FUN_00189890): create the handler table, register the
/// request handlers (`handlers::load`, i.e., `phone_request_load`), and
/// create the thread pools (initial and maximum sizes from
/// `transaction_initial_threads` / `transaction_max_threads`, idle timeout
/// 60 s, auto increment 1).  Does nothing when already loaded.
pub fn load() -> Result<(), ()> {
    if REQUEST_POOL.read().unwrap().is_some() {
        return Ok(());
    }
    {
        let mut h = HANDLERS.write().unwrap();
        h.clear();
        h.reserve(10);
    }
    if handlers::load().is_err() {
        unload();
        return Err(());
    }

    let g = crate::config::get();
    let opts = Options {
        idle_timeout: IDLE_TIMEOUT,
        auto_increment: AUTO_INCREMENT,
        initial_size: g.initial_threads.min(i32::MAX as u32) as i32,
        max_size: g.max_threads.min(i32::MAX as u32) as i32,
    };
    let Some(request) = ThreadPool::create(REQUEST_POOL_NAME, &opts) else {
        ast_log!(LOG_ERROR, "DPMA: Unable to create request threadpool");
        unload();
        return Err(());
    };
    *REQUEST_POOL.write().unwrap() = Some(request);
    let Some(extended) = ThreadPool::create(EXTENDED_POOL_NAME, &opts) else {
        ast_log!(LOG_ERROR, "DPMA: Unable to create extended threadpool");
        unload();
        return Err(());
    };
    *EXTENDED_POOL.write().unwrap() = Some(extended);
    Ok(())
}

/// `request_unload` (FUN_00189820): drop the handler table and shut down
/// the extended pool, then the request pool.  Each shutdown waits for the
/// pool's running tasks; queued tasks are discarded.
pub fn unload() {
    HANDLERS.write().unwrap().clear();
    // Take each pool out before shutting it down so that tasks still
    // running can fail their pushes instead of blocking on the lock.
    let extended = EXTENDED_POOL.write().unwrap().take();
    drop(extended);
    let request = REQUEST_POOL.write().unwrap().take();
    drop(request);
}

/// True while the thread pools exist.
pub fn is_loaded() -> bool {
    REQUEST_POOL.read().unwrap().is_some()
}

/// `request_register_handler` (FUN_00188bf0): append to the handler table.
/// A request type registered twice is answered by the first registration.
pub fn register_handler(
    request_type: &'static str,
    response_type: Option<&'static str>,
    requires_session: bool,
    handler: Handler,
) -> Result<(), ()> {
    HANDLERS.write().unwrap().push(Registration { request_type, response_type, requires_session, handler });
    Ok(())
}

/// `request_handle_incoming` (FUN_00188d20): look up the handler, check
/// the session requirement, allocate the outgoing message, and push the
/// handler onto the request pool (`request_task_push`).
pub fn handle_incoming(tx: Arc<Transaction>) -> Result<(), ()> {
    if tx.request_type.is_empty() {
        dpma_log!("Received request with no type");
        return Err(());
    }
    let reg = HANDLERS
        .read()
        .unwrap()
        .iter()
        .find(|r| r.request_type.eq_ignore_ascii_case(&tx.request_type))
        .copied();
    let Some(reg) = reg else {
        dpma_log!("Received request with unknown type '{}'", tx.request_type);
        return Err(());
    };
    if reg.requires_session && tx.session.is_none() {
        dpma_log!("Request '{}' requires session", tx.request_type);
        return Err(());
    }
    if let Some(response_type) = reg.response_type.filter(|r| !r.is_empty()) {
        let mut out = Outgoing::new();
        if !tx.response_uri.is_empty() {
            out.response_uri = tx.response_uri.clone();
        }
        if !tx.full_contact.is_empty() {
            out.full_contact = tx.full_contact.clone();
        }
        if !tx.app_server_id.is_empty() {
            out.id = tx.app_server_id.clone();
        }
        out.response_type = response_type.to_string();
        *tx.outgoing.lock().unwrap() = Some(out);
    }

    let handler = reg.handler;
    let task: dpma_ast::threadpool::Task = Box::new(move || {
        handler(tx);
    });
    let origin = Origin { file: "dpma_request.c", line: 0x19, function: "request_task_push" };
    let pushed = match REQUEST_POOL.read().unwrap().as_ref() {
        Some(pool) => pool.push(task, origin).is_ok(),
        None => false,
    };
    if !pushed {
        ast_log!(LOG_ERROR, "DPMA: Failed to push task to request threadpool.");
        return Err(());
    }
    Ok(())
}

/// `request_extended_task_push` (FUN_00188b30): run `task` on the
/// `DPMA_extended` pool (long-running work such as dialing a phone).  On
/// failure the task is dropped unrun.
pub fn push_extended(task: Box<dyn FnOnce() + Send + 'static>) -> Result<(), ()> {
    let origin = Origin { file: "dpma_request.c", line: 0x29, function: "request_extended_task_push" };
    let pushed = match EXTENDED_POOL.read().unwrap().as_ref() {
        Some(pool) => pool.push(task, origin).is_ok(),
        None => false,
    };
    if !pushed {
        ast_log!(LOG_ERROR, "DPMA: Failed to push task to extended threadpool.");
        return Err(());
    }
    Ok(())
}

/// The method name used in error documents: "NA" when empty.
fn method_or_na(method: &str) -> &str {
    if method.is_empty() {
        "NA"
    } else {
        method
    }
}

/// `create_error_response_xml` (FUN_00189280): REPLACE the contents of
/// `out` with the XML error document for `code` (method "NA" when empty):
///
/// ```text
/// <response method="M">\r\n<errors>\r\n<error code="C" message="T" />\r\n</errors>\r\n</response>\r\n
/// ```
///
/// The original starts with `ast_str_set`, so anything already in the
/// buffer is discarded.  Neither the method nor the text is XML-escaped.
pub fn error_response_xml(out: &mut String, method: &str, code: i32) {
    out.clear();
    let _ = write!(
        out,
        "<response method=\"{}\">\r\n<errors>\r\n<error code=\"{}\" message=\"{}\" />\r\n</errors>\r\n</response>\r\n",
        method_or_na(method),
        code,
        dpma_proto::errors::request_error_text(code)
    );
}

/// `create_error_response_json` (FUN_00189450): REPLACE the contents of
/// `out` with the compact JSON error document
///
/// ```text
/// {"response":{"method":"M","errors":{"error":{"code":C,"message":"T: D "}}}}
/// ```
///
/// where T is the code's text and D is `detail` (the original's printf
/// format and arguments, already formatted here).  The original appends
/// a single space after the detail, so the message ends with one.  The
/// method is "NA" when empty.
pub fn error_response_json(out: &mut String, method: &str, code: i32, detail: &str) {
    let message = format!("{}: {} ", dpma_proto::errors::request_error_text(code), detail);
    let doc = serde_json::json!({
        "response": {
            "method": method_or_na(method),
            "errors": {"error": {"code": code, "message": message}},
        }
    });
    *out = dpma_proto::json::dump(&doc);
}

#[cfg(feature = "devtest")]
mod devtest {
    use super::*;
    use crate::session::Session;
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    static NEXT_ID: AtomicU32 = AtomicU32::new(1);

    /// A synthetic transaction as session::next_transaction would build it.
    pub fn synthetic(request_type: &str, response_type: &str, session: Option<&str>) -> Transaction {
        let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let id = format!("dpmadev-{}", n);
        let mac = "000fd3dead01".to_string();
        Transaction {
            key: format!("{}-{}", id, mac),
            app_server_id: id,
            request_type: request_type.to_string(),
            response_type: response_type.to_string(),
            response_uri: "pjsip:127.0.0.1:5060;transport=udp".into(),
            full_contact: "sip:dpmadev@127.0.0.1:5060".into(),
            mac,
            user_agent: "Digium D65 2_9_17 dpmadev".into(),
            session: session.map(|s| Arc::new(Session::new(s))),
            ..Default::default()
        }
    }

    fn arg_or_empty(s: &str) -> &str {
        if s == "-" {
            ""
        } else {
            s
        }
    }

    /// dpmadev request <type> [<session>|-] [<response type>]
    fn request_cmd(a: &CliArgs) -> CliResult {
        if !(3..=5).contains(&a.argc()) {
            return CliResult::ShowUsage;
        }
        let request_type = arg_or_empty(&a.argv[2]);
        let session = a.argv.get(3).map(|s| arg_or_empty(s)).filter(|s| !s.is_empty());
        let response_type = a.argv.get(4).map(|s| arg_or_empty(s)).unwrap_or("");
        let tx = Arc::new(synthetic(request_type, response_type, session));
        let probe = tx.clone();
        let res = crate::phone_main::dispatch(tx);
        a.out(&format!(
            "Transaction {} type '{}' session {}: {}\n",
            probe.key,
            probe.request_type,
            session.unwrap_or("(none)"),
            match res {
                Some(Ok(())) => "dispatched to DPMA_request",
                Some(Err(())) => "rejected",
                None => "response logged, not dispatched",
            }
        ));
        if res == Some(Ok(())) {
            // The pool drops its reference when the handler returns.
            let start = Instant::now();
            while Arc::strong_count(&probe) > 1 && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(5));
            }
            a.out(&format!(
                "Handler {} after {} ms\n",
                if Arc::strong_count(&probe) > 1 { "still running" } else { "finished" },
                start.elapsed().as_millis()
            ));
        }
        match probe.outgoing.lock().unwrap().as_ref() {
            Some(o) => a.out(&format!(
                "Outgoing: response_type='{}' response_uri='{}' full_contact='{}' id='{}' body={} bytes\n",
                o.response_type,
                o.response_uri,
                o.full_contact,
                o.id,
                o.body.len()
            )),
            None => a.out("Outgoing: (none)\n"),
        }
        CliResult::Success
    }

    fn handlers_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        let h = HANDLERS.read().unwrap();
        a.out(&format!("{:<18} {:<18} {}\n", "Request", "Response", "Session"));
        for r in h.iter() {
            a.out(&format!(
                "{:<18} {:<18} {}\n",
                r.request_type,
                r.response_type.unwrap_or("(none)"),
                if r.requires_session { "yes" } else { "no" }
            ));
        }
        a.out(&format!(
            "{} handlers; pools {}\n",
            h.len(),
            if is_loaded() { "running" } else { "not created" }
        ));
        CliResult::Success
    }

    /// dpmadev request error xml|json <method|-> <code> [detail...]
    fn error_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 6 {
            return CliResult::ShowUsage;
        }
        let method = arg_or_empty(&a.argv[4]);
        let Ok(code) = a.argv[5].parse::<i32>() else {
            return CliResult::ShowUsage;
        };
        let mut out = String::from("previous contents");
        let detail = a.argv[6..].join(" ");
        let json = match a.argv[3].to_ascii_lowercase().as_str() {
            "xml" => {
                error_response_xml(&mut out, method, code);
                false
            }
            "json" => {
                error_response_json(&mut out, method, code, &detail);
                true
            }
            _ => return CliResult::ShowUsage,
        };
        a.out(&format!("{} bytes: {:?}\n", out.len(), out));
        if json {
            // Build the same document the original way (ast_json_pack and
            // ast_json_dump_string, i.e., jansson) and compare.
            let reference = jansson_error_doc(method_or_na(method), code, &format!(
                "{}: {} ",
                dpma_proto::errors::request_error_text(code),
                detail
            ));
            match reference {
                Some(r) if r == out => a.out("Identical to Asterisk's ast_json_pack/ast_json_dump_string output\n"),
                Some(r) => a.out(&format!("DIFFERS from Asterisk's output: {:?}\n", r)),
                None => a.out("Asterisk could not build the reference document\n"),
            }
        }
        CliResult::Success
    }

    fn jansson_error_doc(method: &str, code: i32, message: &str) -> Option<String> {
        use std::os::raw::{c_char, c_int, c_void};
        extern "C" {
            fn ast_json_pack(format: *const c_char, ...) -> *mut c_void;
            fn ast_json_dump_string_format(root: *mut c_void, format: c_int) -> *mut c_char;
            fn ast_json_free(p: *mut c_void);
            fn ast_json_unref(p: *mut c_void);
        }
        let c = dpma_ast::cstr;
        let (fmt, response, m, errors, error, code_k, message_k) =
            (c("{s: {s: s, s: {s: {s: i, s: s}}}}"), c("response"), c("method"), c("errors"), c("error"), c("code"), c("message"));
        let (mv, msgv) = (c(method), c(message));
        unsafe {
            let j = ast_json_pack(
                fmt.as_ptr(),
                response.as_ptr(),
                m.as_ptr(),
                mv.as_ptr(),
                errors.as_ptr(),
                error.as_ptr(),
                code_k.as_ptr(),
                code as c_int,
                message_k.as_ptr(),
                msgv.as_ptr(),
            );
            if j.is_null() {
                return None;
            }
            let s = ast_json_dump_string_format(j, 0);
            ast_json_unref(j);
            if s.is_null() {
                return None;
            }
            let r = dpma_ast::from_ptr(s);
            ast_json_free(s as *mut c_void);
            r
        }
    }

    /// dpmadev request extended <milliseconds>: run a task on DPMA_extended.
    fn extended_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 4 {
            return CliResult::ShowUsage;
        }
        let Ok(ms) = a.argv[3].parse::<u64>() else {
            return CliResult::ShowUsage;
        };
        let res = push_extended(Box::new(move || {
            std::thread::sleep(Duration::from_millis(ms));
            dpma_log!("dpmadev extended task finished after {} ms", ms);
        }));
        a.out(&format!("push_extended: {}\n", if res.is_ok() { "queued" } else { "failed" }));
        CliResult::Success
    }

    pub fn commands() -> Vec<CliCommand> {
        vec![
            CliCommand {
                command: "dpmadev request",
                summary: "Dispatch a synthetic transaction",
                usage: "Usage: dpmadev request <type>|- [<session id>|-] [<response type>]\n       Builds a transaction (\"-\" for empty) and dispatches it as phone_main does.\n",
                exec: request_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev request handlers",
                summary: "List the request handler table",
                usage: "Usage: dpmadev request handlers\n",
                exec: handlers_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev request error",
                summary: "Print an XML or JSON request error document",
                usage: "Usage: dpmadev request error xml|json <method>|- <code> [detail...]\n",
                exec: error_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev request extended",
                summary: "Run a sleeping task on the DPMA_extended pool",
                usage: "Usage: dpmadev request extended <milliseconds>\n",
                exec: extended_cmd,
                complete: None,
            },
        ]
    }
}

/// A synthetic transaction for test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub use devtest::synthetic as devtest_synthetic;

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    devtest::commands()
}
