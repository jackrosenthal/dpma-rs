//! mDNS/DNS-SD announcement of the configuration server (phone_avahi.c,
//! 0x173ba0..0x174390).
//!
//! The original registers one service through libavahi-client (and so
//! needs a running avahi-daemon); this rewrite answers mDNS itself with
//! the pure-Rust `mdns-sd` responder (plan section 8, item 8), so it
//! announces with or without avahi-daemon.  What is announced is what
//! `av_create_service` (FUN_00173da0) registers:
//!
//! - instance `service_name` (default "Digium Phone Config Server") of
//!   type `_digiumproxy._udp` in domain `local`, on every interface and
//!   protocol, with port `strtol(mdns_port) & 0xffff` (default 5060);
//! - TXT `serviceType=asterisk` and, when `mdns_address` is set,
//!   `sipUrl=sip:proxy@<mdns_address>:<mdns_port>[;transport=<mdns_transport>]`
//!   (cut to 255 bytes, as the original's `snprintf` into 256 bytes);
//! - nothing when `service_discovery_enabled` is off, or when the name is
//!   empty or longer than 63 bytes (Avahi rejects such a name, and the
//!   original then announces nothing, silently).
//!
//! The lifecycle follows `avahi_start`, `avahi_reload`, and `avahi_stop`:
//! the service is announced at load, withdrawn (goodbye packets) and
//! announced again from the new configuration at every reload, and
//! withdrawn at unload.  The responder runs only while discovery is
//! enabled, so with discovery off no mDNS socket is open.  When Asterisk
//! exits without unloading its modules (`core stop now`), avahi-daemon
//! withdraws the original's service as its client goes away; here an
//! Asterisk atexit handler withdraws it.
//!
//! Differences that come with leaving Avahi (see the hand-off notes):
//!
//! - The SRV target and its address records are the responder's own host
//!   name, `<hostname>-dpma.local`, rather than avahi-daemon's
//!   `<hostname>.local`: a second responder publishing address records
//!   under avahi-daemon's host name would make avahi-daemon rename the
//!   host whenever their address lists differ (e.g., IPv6 link-local
//!   addresses, which avahi-daemon leaves out next to global ones).
//! - On a name collision `mdns-sd` picks "<name> (2)" where Avahi's
//!   `avahi_alternative_service_name` picks "<name> #2".
//! - `mdns-sd` takes the instance name as UTF-8 text, so a `service_name`
//!   that is not valid UTF-8 is announced with each invalid sequence
//!   replaced by U+FFFD.  (Avahi passes the name over D-Bus, which
//!   accepts only UTF-8; the original's behavior with such a name is not
//!   known.)  The TXT record carries `mdns_address` and `mdns_transport`
//!   as bytes.
//! - Interfaces: those that are up, multicast-capable, and not point to
//!   point.  avahi-daemon also never uses loopback interfaces; this
//!   responder uses one only if multicast is enabled on it (never the case
//!   by default), which lets the tests run on `lo` in a network namespace.

use crate::exports::config_api::{self as c, text};
use dpma_ast::dpma_log;
use mdns_sd::{IfKind, IfPredicate, ServiceDaemon, ServiceInfo, TxtProperty};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The service type (`_digiumproxy._udp` in domain `local`).
const SERVICE_TYPE: &str = "_digiumproxy._udp.local.";

/// The name `mdns-sd` gives its thread.
const DAEMON_THREAD_NAME: &str = "mDNS_daemon";

/// How long to wait for the responder to withdraw a service or to stop.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// The service `av_create_service` would register.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Announcement {
    /// The instance name's bytes.
    name: Vec<u8>,
    port: u16,
    /// The `sipUrl` TXT value, when `mdns_address` is set.
    sip_url: Option<Vec<u8>>,
}

/// The running responder and the full name of the service it announces.
struct Responder {
    daemon: ServiceDaemon,
    registered: Option<String>,
}

static STATE: Mutex<Option<Responder>> = Mutex::new(None);

/// `strtol(s, NULL, 10)`.
fn strtol(s: &[u8]) -> i64 {
    dpma_ast::dpma_bytes::c::strtol(s).0
}

/// What to announce under the current configuration (read from the C
/// configuration object, as the original does); None when discovery is
/// disabled.
fn wanted() -> Option<Announcement> {
    unsafe {
        let cfg = c::dpma_config_get();
        let res = if c::dpma_config_enable_discovery(cfg) == 0 {
            None
        } else {
            let port = match text(cfg, |p| c::dpma_config_mdns_port(p)) {
                p if p.is_empty() => crate::config::DEFAULT_PORT.into(),
                p => p,
            };
            let addr = text(cfg, |p| c::dpma_config_mdns_addr(p));
            let sip_url = (!addr.is_empty()).then(|| {
                let transport = text(cfg, |p| c::dpma_config_mdns_transport(p));
                let sep = if transport.is_empty() { "" } else { ";transport=" };
                let mut entry = dpma_ast::bformat!("sipUrl=sip:proxy@{}:{}{}{}", addr, port, sep, transport);
                entry.truncate(255);
                entry.split_off("sipUrl=".len())
            });
            let name = match text(cfg, |p| c::dpma_config_service_name(p)) {
                n if n.is_empty() => crate::config::DEFAULT_SERVICE_NAME.into(),
                n => n,
            };
            Some(Announcement { name, port: (strtol(&port) & 0xffff) as u16, sip_url })
        };
        c::dpma_config_unref(cfg);
        res
    }
}

/// The host label (the system host name up to its first dot).
fn host_label() -> String {
    let mut buf = [0u8; 256];
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut c_char, buf.len() - 1) } == 0;
    let name = if ok {
        CStr::from_bytes_until_nul(&buf).map(|c| c.to_string_lossy().into_owned()).unwrap_or_default()
    } else {
        String::new()
    };
    let mut label = name.split('.').next().unwrap_or("").to_string();
    if label.is_empty() {
        label = "localhost".into();
    }
    // Leave room for the suffix in a 63-byte DNS label.
    while label.len() > 58 {
        label.pop();
    }
    label
}

/// The responder's own host name (see the module documentation).
fn host_name() -> String {
    format!("{}-dpma.local.", host_label())
}

/// True when interface `name` is up for multicast (`IFF_MULTICAST`).
fn multicast_capable(name: &str) -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let mut req: libc::ifreq = std::mem::zeroed();
        for (d, s) in req.ifr_name.iter_mut().zip(name.bytes().take(libc::IFNAMSIZ - 1)) {
            *d = s as c_char;
        }
        let ok = libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut req) == 0;
        libc::close(fd);
        ok && (libc::c_int::from(req.ifr_ifru.ifru_flags) & libc::IFF_MULTICAST) != 0
    }
}

/// Start a responder on the multicast-capable interfaces.
fn new_daemon() -> Option<ServiceDaemon> {
    let daemon = ServiceDaemon::new().ok()?;
    let _ = daemon.disable_interface(IfKind::All);
    let _ = daemon.enable_interface(IfKind::Predicate(IfPredicate::new(|i| multicast_capable(&i.name))));
    Some(daemon)
}

/// The DNS-SD service for `a`; None when Avahi would refuse it (an empty
/// name or one longer than 63 bytes).
fn service_info(a: &Announcement) -> Option<ServiceInfo> {
    if a.name.is_empty() || a.name.len() > 63 {
        return None;
    }
    let mut txt = vec![TxtProperty::from(("serviceType", "asterisk"))];
    if let Some(url) = &a.sip_url {
        txt.push(TxtProperty::from(("sipUrl", url.as_slice())));
    }
    let name = String::from_utf8_lossy(&a.name);
    let info = ServiceInfo::new(SERVICE_TYPE, &name, &host_name(), (), a.port, txt).ok()?;
    Some(info.enable_addr_auto())
}

/// Withdraw the announced service, if any (`avahi_entry_group_reset`
/// and `avahi_entry_group_free`): the responder sends goodbye packets.
fn withdraw(r: &mut Responder) {
    if let Some(fullname) = r.registered.take() {
        if let Ok(rx) = r.daemon.unregister(&fullname) {
            let _ = rx.recv_timeout(REPLY_TIMEOUT);
        }
    }
}

/// Wait (briefly) until the responder's thread has finished, so that no
/// thread runs this module's code once it is unloaded.
fn wait_daemon_thread_exit() {
    let deadline = Instant::now() + REPLY_TIMEOUT;
    while Instant::now() < deadline {
        let running =
            std::fs::read_dir("/proc/self/task").into_iter().flatten().flatten().any(|t| {
                std::fs::read_to_string(t.path().join("comm")).is_ok_and(|n| n.trim_end() == DAEMON_THREAD_NAME)
            });
        if !running {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Stop the responder; it withdraws its service first.
fn shut_down(r: Responder, wait_exit: bool) {
    if let Ok(rx) = r.daemon.shutdown() {
        let _ = rx.recv_timeout(REPLY_TIMEOUT);
    }
    if wait_exit {
        wait_daemon_thread_exit();
    }
}

/// Announce the service of the current configuration (`av_create_service`
/// once the client runs); with discovery disabled, stop the responder.
fn publish(state: &mut Option<Responder>) {
    let Some(a) = wanted() else {
        if let Some(r) = state.take() {
            shut_down(r, false);
        }
        return;
    };
    if state.is_none() {
        match new_daemon() {
            Some(daemon) => *state = Some(Responder { daemon, registered: None }),
            None => {
                dpma_log!("Could not create Avahi client.");
                return;
            }
        }
    }
    let Some(r) = state.as_mut() else { return };
    let Some(info) = service_info(&a) else { return };
    let fullname = info.get_fullname().to_string();
    match r.daemon.register(info) {
        Ok(()) => r.registered = Some(fullname),
        Err(_) => dpma_log!("Could not create Avahi group"),
    }
}

/// Withdraw the service when Asterisk exits without unloading modules.
extern "C" fn exit_handler() {
    dpma_ast::guard((), || {
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut r) = state.take() {
            withdraw(&mut r);
            shut_down(r, false);
        }
    })
}

/// `avahi_start` (FUN_00174170): announce the service if discovery is
/// enabled.
pub fn start() {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    dpma_ast::util::register_atexit(exit_handler);
    if state.is_some() {
        return;
    }
    publish(&mut state);
}

/// `avahi_stop` (FUN_001742f0): withdraw the service and stop the
/// responder.
pub fn stop() {
    dpma_ast::util::unregister_atexit(exit_handler);
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut r) = state.take() {
        withdraw(&mut r);
        shut_down(r, true);
    }
}

/// `avahi_reload` (FUN_00174390): withdraw the service and announce the
/// one of the reloaded configuration.
pub fn reload() {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = state.as_mut() {
        withdraw(r);
    }
    publish(&mut state);
}
