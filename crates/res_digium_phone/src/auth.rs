//! Authentication incidents (phone_auth.c): failed handshakes and bad
//! credentials are recorded per IP address, logged, expired, and exposed
//! through `DPMAShowIncidents` / `DPMARemoveIncident`.
//!
//! An incident (`struct auth_problem`, 0x50 bytes) keeps the reason, MAC
//! address, and user agent of the first failure from an address, the times
//! of the first and the latest failure, and a count.  It expires 600 s
//! after the latest failure.  From the fifth failure on, the log line says
//! "ALERT" and `DPMAShowIncidents` reports it as blocking; nothing is
//! actually blocked, and the "alert sent" flag is never set in 3.6.13.
//!
//! Owner: P3 "request" (wave 1).

use crate::ami::AmiAction;
use crate::session::Transaction;
use dpma_ast::dpma_log;
use dpma_ast::manager::{self, Request};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Buckets of the original's ao2 hash container; listing order follows
/// the buckets, then insertion order within a bucket.
const BUCKETS: usize = 37;

/// Incidents expire this many seconds after the latest failure.
const EXPIRE_SECONDS: i64 = 600;

/// Failures from one address before it is reported as blocking.
const ALERT_COUNT: i64 = 5;

/// A `struct timeval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimeVal {
    sec: i64,
    usec: i64,
}

impl TimeVal {
    fn now() -> TimeVal {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        TimeVal { sec: d.as_secs() as i64, usec: i64::from(d.subsec_micros()) }
    }

    /// `ast_tvdiff_sec(self, start)`.
    fn diff_sec(self, start: TimeVal) -> i64 {
        let mut r = self.sec - start.sec;
        if r > 0 && self.usec < start.usec {
            r -= 1;
        } else if r < 0 && self.usec > start.usec {
            r += 1;
        }
        r
    }
}

/// `struct auth_problem`.
#[derive(Debug, Clone)]
struct Problem {
    /// Reason of the first failure (+0x00).
    reason: String,
    /// Source address, without port (+0x08); the container key.
    ip: String,
    /// MAC address of the first failure (+0x10).
    mac: String,
    /// User agent of the first failure (+0x18).
    user_agent: String,
    /// First failure (+0x20).
    first: TimeVal,
    /// Latest failure (+0x30).
    last: TimeVal,
    /// Failures so far (+0x40).
    count: i64,
    /// Never set by 3.6.13 (+0x48).
    alert_sent: bool,
}

/// The container (0x5eef38); None while the module is not loaded.
static PROBLEMS: Mutex<Option<Vec<Vec<Problem>>>> = Mutex::new(None);

/// The container's hash (FUN_00177810): djb2 (`h * 33 ^ c`, seed 5381)
/// over the address bytes, masked to 31 bits.
fn bucket(ip: &str) -> usize {
    let mut h: u32 = 5381;
    for b in ip.bytes() {
        h = h.wrapping_mul(33) ^ u32::from(b);
    }
    (h & 0x7fff_ffff) as usize % BUCKETS
}

fn find_mut<'a>(buckets: &'a mut [Vec<Problem>], ip: &str) -> Option<&'a mut Problem> {
    buckets[bucket(ip)].iter_mut().find(|p| p.ip == ip)
}

/// `phone_auth_init` (FUN_00178300).
pub fn load() -> Result<(), ()> {
    *PROBLEMS.lock().unwrap() = Some(vec![Vec::new(); BUCKETS]);
    Ok(())
}

/// `phone_auth_unload` (FUN_00178380).
pub fn unload() {
    PROBLEMS.lock().unwrap().take();
}

/// The address part of a URI as `phone_utils_parse_uri` returns it:
/// after the scheme, after any `user@`, up to the first `;`.  Empty when
/// there is no `:`.
fn uri_address(uri: &str) -> &str {
    let Some((_, rest)) = uri.split_once(':') else {
        return "";
    };
    let rest = rest.split_once('@').map_or(rest, |(_, host)| host);
    rest.split(';').next().unwrap_or("")
}

/// `phone_auth_issue_alert` (FUN_00177920): record a failure for the
/// transaction's source address.  `reason` is, e.g., "invalid credentials"
/// or "invalid config pass".
///
/// The address is the host of the first message's
/// `X-Digium-AppServer-Response-URI` (set by the dialplan from the
/// receiving address), cut at its first `:` (so an IPv6 address keeps
/// only its first group, as in the original).
pub fn issue_alert(tx: &Transaction, reason: &str) {
    let _ = record(tx, reason);
}

/// The body of `issue_alert`; Err when nothing could be recorded.
fn record(tx: &Transaction, reason: &str) -> Result<(), ()> {
    let msg = tx.first_msg.as_ref();
    let Some(uri) = msg.and_then(|m| m.get_var("X-Digium-AppServer-Response-URI")) else {
        dpma_log!("Unable to process authorization problem with no uri");
        return Err(());
    };
    // The user agent as `phone_msg_get_user_agent` (FUN_00149fc0) reads
    // it: X-Digium-User-Agent if not empty, else User-Agent (possibly
    // absent).
    let user_agent = msg.and_then(|m| m.var("X-Digium-User-Agent").or_else(|| m.get_var("User-Agent")));
    let addr = uri_address(&uri);
    if addr.is_empty() {
        dpma_log!("Failed to parse uri from authorization problem");
        return Err(());
    }
    let ip = addr.split(':').next().unwrap_or("");

    let mut g = PROBLEMS.lock().unwrap();
    let Some(buckets) = g.as_mut() else {
        dpma_log!("Failed to create auth problem record");
        return Err(());
    };
    if find_mut(buckets, ip).is_none() {
        // `auth_problem_alloc`: every field is copied with ast_strdup; a
        // missing user agent makes the copy (and the record) fail.
        let Some(user_agent) = user_agent else {
            dpma_log!("Failed to create auth problem record");
            return Err(());
        };
        let now = TimeVal::now();
        buckets[bucket(ip)].push(Problem {
            reason: reason.to_string(),
            ip: ip.to_string(),
            mac: tx.mac.clone(),
            user_agent,
            first: now,
            last: now,
            count: 0,
            alert_sent: false,
        });
    }
    let Some(p) = find_mut(buckets, ip) else {
        return Err(());
    };
    p.last = TimeVal::now();
    p.count += 1;
    dpma_log!(
        "Auth failed for ip '{}' mac '{}' reason '{}' count={}{}{}",
        ip,
        tx.mac,
        reason,
        p.count,
        if p.count >= ALERT_COUNT { " ALERT" } else { "" },
        if p.alert_sent { " SENT" } else { "" }
    );
    Ok(())
}

/// `phone_auth_expire_problems` (FUN_00177d30): drop incidents whose latest
/// failure is more than 600 s old.  Called by `session::next_transaction`
/// on every pass.
pub fn expire_problems() {
    let now = TimeVal::now();
    let mut g = PROBLEMS.lock().unwrap();
    let Some(buckets) = g.as_mut() else {
        return;
    };
    for b in buckets.iter_mut() {
        b.retain(|p| {
            let age = now.sec - p.last.sec;
            let expired = age > 0 && now.diff_sec(p.last) > EXPIRE_SECONDS;
            if expired {
                dpma_log!("Expiring auth incident for ip '{}' at count={}", p.ip, p.count);
            }
            !expired
        });
    }
}

/// "ActionID: <id>\r\n" as the original formats it into a 256-byte buffer
/// (at most 255 bytes kept), or "" when there is no ActionID.
fn action_id_text(id: &str) -> String {
    if id.is_empty() {
        return String::new();
    }
    let mut s = format!("ActionID: {}\r\n", id);
    if s.len() > 255 {
        let mut end = 255;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// `action_dpma_show_incidents` (FUN_00177e70).
fn action_show_incidents(r: &Request) -> i32 {
    let now = TimeVal::now();
    let id = r.header("ActionID");
    let idtext = action_id_text(&id);
    r.send_listack("DPMA incident list will follow", "start");
    let problems: Vec<Problem> = PROBLEMS
        .lock()
        .unwrap()
        .as_ref()
        .map(|b| b.iter().flatten().cloned().collect())
        .unwrap_or_default();
    for p in &problems {
        r.append(&format!(
            "Event: DPMAShowIncidentsList\r\n{}IPAddress: {}\r\nMAC: {}\r\nUserAgent: {}\r\nSecondsFirstIncident: {}\r\nSecondsLastIncident: {}\r\nIncidentCount: {}\r\nReason: {}\r\nBlocking: {}\r\nAlertSent: {}\r\n\r\n",
            idtext,
            p.ip,
            p.mac,
            p.user_agent,
            now.diff_sec(p.first) as i32,
            now.diff_sec(p.last) as i32,
            p.count,
            p.reason,
            // The original's string really has a leading space.
            if p.count >= ALERT_COUNT { " Yes" } else { "No" },
            if p.alert_sent { "Yes" } else { "No" },
        ));
    }
    let mut done = String::from("Event: DPMAShowIncidentsComplete\r\n");
    if !id.is_empty() {
        done.push_str(&format!("ActionID: {}\r\n", id));
    }
    done.push_str(&format!("EventList: Complete\r\nListItems: {}\r\n\r\n", problems.len()));
    r.append(&done);
    0
}

/// `action_dpma_remove_incident` (FUN_00178110).
fn action_remove_incident(r: &Request) -> i32 {
    let idtext = action_id_text(&r.header("ActionID"));
    // astman_get_header never returns NULL, so the original's "AMI remove
    // incident missing IPAddress" branch is unreachable; a missing header
    // is looked up as "".
    let ip = r.header("IPAddress");
    let removed = {
        let mut g = PROBLEMS.lock().unwrap();
        g.as_mut().and_then(|buckets| {
            let b = &mut buckets[bucket(&ip)];
            let pos = b.iter().position(|p| p.ip == ip)?;
            Some(b.remove(pos))
        })
    };
    let result = match removed {
        Some(p) => {
            dpma_log!("AMI Removed incident for ip '{}'", p.ip);
            "Success"
        }
        None => {
            dpma_log!("AMI requested removal for ip '{}' not found", ip);
            "Failure"
        }
    };
    r.append(&format!("Response: {}\r\n{}\r\n", result, idtext));
    0
}

/// AMI actions DPMAShowIncidents and DPMARemoveIncident (authority call).
pub fn ami_actions() -> Vec<AmiAction> {
    vec![
        AmiAction { name: "DPMAShowIncidents", authority: manager::AUTH_CALL, handler: action_show_incidents },
        AmiAction { name: "DPMARemoveIncident", authority: manager::AUTH_CALL, handler: action_remove_incident },
    ]
}

#[cfg(feature = "devtest")]
mod devtest {
    use super::*;
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};
    use dpma_ast::msg::Msg;
    use std::sync::Arc;

    /// dpmadev auth alert <ip[:port]>|<uri> <mac>|- <user agent>|- <reason...>
    fn alert_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 7 {
            return CliResult::ShowUsage;
        }
        let Some(msg) = Msg::alloc() else {
            a.out("Unable to allocate a message\n");
            return CliResult::Failure;
        };
        let target = &a.argv[3];
        let uri = if target.contains("sip:") { target.clone() } else { format!("pjsip:{}", target) };
        msg.set_var("X-Digium-AppServer-Response-URI", &uri);
        if a.argv[5] != "-" {
            msg.set_var("User-Agent", &a.argv[5]);
        }
        let mac = if a.argv[4] == "-" { String::new() } else { a.argv[4].clone() };
        let mut tx = crate::request::devtest_synthetic("TokenRequest", "", Some("dpmadev"));
        tx.mac = mac;
        tx.first_msg = Some(msg);
        let tx = Arc::new(tx);
        let reason = a.argv[6..].join(" ");
        let res = record(&tx, &reason);
        a.out(&format!("issue_alert(uri '{}'): {}\n", uri, if res.is_ok() { "recorded" } else { "failed" }));
        CliResult::Success
    }

    fn expire_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        expire_problems();
        a.out("Expired old incidents\n");
        CliResult::Success
    }

    /// dpmadev auth age <ip> <seconds>: move an incident's times back.
    fn age_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 5 {
            return CliResult::ShowUsage;
        }
        let Ok(secs) = a.argv[4].parse::<i64>() else {
            return CliResult::ShowUsage;
        };
        let mut g = PROBLEMS.lock().unwrap();
        let found = g.as_mut().and_then(|b| find_mut(b, &a.argv[3])).map(|p| {
            p.first.sec -= secs;
            p.last.sec -= secs;
        });
        a.out(if found.is_some() { "Aged\n" } else { "Not found\n" });
        CliResult::Success
    }

    pub fn commands() -> Vec<CliCommand> {
        vec![
            CliCommand {
                command: "dpmadev auth alert",
                summary: "Record an auth incident",
                usage: "Usage: dpmadev auth alert <ip[:port]>|<uri> <mac>|- <user agent>|- <reason...>\n       \"-\" leaves the MAC empty or the User-Agent header out.\n",
                exec: alert_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev auth expire",
                summary: "Run the auth incident expiry",
                usage: "Usage: dpmadev auth expire\n",
                exec: expire_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev auth age",
                summary: "Make an auth incident older",
                usage: "Usage: dpmadev auth age <ip> <seconds>\n",
                exec: age_cmd,
                complete: None,
            },
        ]
    }
}

/// Test hooks (feature "devtest").
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    devtest::commands()
}
