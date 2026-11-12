//! The phone simulator: a Digium phone playing against an Asterisk
//! instance over SIP MESSAGE (UDP or TCP), for the test suites.
//!
//! The protocol is [`dpma_proto`]'s: requests are encoded with
//! [`dpma_proto::message::Request`], and what the server sends is decoded
//! with [`dpma_proto::message::Collector`].  The simulator adds the SIP, the
//! bookkeeping of a session, and ways to send what a correct phone would not
//! (see [`chunking`] and the options of [`Phone`]).
//!
//! ```no_run
//! use dpma_tests::sim::{Options, Phone};
//! # fn main() -> anyhow::Result<()> {
//! let phone = Phone::start(Options::default())?;
//! let ex = phone.handshake().send()?;
//! assert!(ex.ok(), "{:?}", ex);
//! let ex = phone.get_token().user("simphone").config_password("344486").send()?;
//! let ex = phone.config().send()?;
//! println!("{}", ex.reply.unwrap().body);
//! let ev = phone.next_event(std::time::Duration::from_secs(30), Some("digium.config.update"));
//! # Ok(()) }
//! ```
//!
//! Against an instance, the simulator needs the simulator's test
//! configuration in it ([`crate::harness::fixtures::sim_setup`]; see
//! [`crate::harness::fixtures::SIM_CONF`] for the test phones).  The phone
//! mints its identity as the phones do, with the provisioning CA key
//! ([`dpma_proto::cert::PhoneIdentity`]), so the module trusts it with no
//! setup.
//!
//! The simulator sends every request to `sip:proxy@<server>:<port>`
//! (what real phones use as `config_server_url`) from one socket, and
//! answers every MESSAGE it receives with 200 OK.  The server replies to
//! the address the request came from (`PJSIP_RECVADDR`), so replies
//! arrive on the same socket; over TCP they come back on the same
//! connection (see [`transport`] for the "Session Timeout" reply).  Every
//! MESSAGE has `Content-Type: text/plain` (res_pjsip_messaging refuses one
//! without it, even with an empty body), and res_pjsip_messaging keeps at
//! most 1023 bytes of a body, so keep the chunk size below that.

mod certs;
pub mod chunking;
mod phone;
mod reply;
pub mod transport;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use chunking::ChunkStyle;
pub use phone::{Form, Options, Phone, RequestBuilder, SessionChoice};
pub use reply::{Exchange, Reply};

pub use crate::sip::Transport;

/// The simulator's default MAC address (the test phone `simphone`).
pub const DEFAULT_MAC: &str = "000fd3000001";
/// The simulator's default user agent.
pub const DEFAULT_UA: &str = "Digium D65 2_9_17";

/// Where the simulator's diagnostics go, and how many of them.
///
/// Level 0 messages are printed unless the verbosity is negative, level 1
/// with `-v` (a SIP summary), level 2 with `-vv` (full SIP messages).
#[derive(Clone)]
pub struct Logger {
    verbose: i32,
    sink: Sink,
}

/// Where a [`Logger`] writes.
type Sink = Arc<dyn Fn(&[u8]) + Send + Sync>;

impl Logger {
    /// A logger that writes to `output` up to `verbose`.
    pub fn new(verbose: i32, output: &Output) -> Logger {
        let sink: Sink = match output {
            Output::Stdout => Arc::new(|t: &[u8]| {
                use std::io::Write;
                let mut o = std::io::stdout().lock();
                let _ = o.write_all(t);
                let _ = o.write_all(b"\n");
                let _ = o.flush();
            }),
            Output::Quiet => Arc::new(|_: &[u8]| {}),
            Output::Capture(buf) => {
                let buf = buf.clone();
                Arc::new(move |t: &[u8]| {
                    let mut b = buf.lock().unwrap();
                    b.extend_from_slice(t);
                    b.push(b'\n');
                })
            }
        };
        Logger { verbose, sink }
    }

    /// Writes `text` when the verbosity is at least `level`.
    pub fn log(&self, level: i32, text: &str) {
        if self.verbose >= level {
            (self.sink)(text.as_bytes());
        }
    }

    /// Writes `text` regardless of the verbosity.
    pub fn print(&self, text: &[u8]) {
        (self.sink)(text);
    }

    /// The verbosity.
    pub fn verbose(&self) -> i32 {
        self.verbose
    }
}

/// A buffer that collects a phone's output ([`Output::Capture`]).
pub type Captured = Arc<Mutex<Vec<u8>>>;

/// Where a phone writes its diagnostics and descriptions.
#[derive(Clone, Default)]
pub enum Output {
    /// Standard output (the default).
    #[default]
    Stdout,
    /// Nowhere.
    Quiet,
    /// Into a buffer, one line per message.
    Capture(Captured),
}

impl Output {
    /// A new capture buffer and the output that fills it.
    pub fn capture() -> (Output, Captured) {
        let buf = Captured::default();
        (Output::Capture(buf.clone()), buf)
    }
}

/// The repository root (the parent of this crate's directory).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// The default reply timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
