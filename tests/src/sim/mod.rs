//! The phone simulator: the phone side of the DPMA AppServer protocol
//! over SIP MESSAGE (UDP or TCP).
//!
//! It plays a Digium phone against an Asterisk instance: handshake with a
//! certificate of the test PKI (legacy or chain form), AES-128-CBC
//! encryption, chunking and reassembly, every request type, and events.
//! It is written from the decompile of the original module (the phone
//! side of `phone_message.c`, `phone_crypto.c`, and `phone_request.c`)
//! and is deliberately independent of the module's own crates (no
//! dpma-proto, no OpenSSL), so that it cross-checks them: see
//! [`selftest`] and the vectors in `tests/data/vectors.json`.
//!
//! ```no_run
//! use dpma_tests::sim::{Options, Phone};
//! # fn main() -> anyhow::Result<()> {
//! let phone = Phone::start(Options::for_slot(5))?;
//! let ex = phone.handshake().send()?;
//! assert!(ex.ok(), "{:?}", ex);
//! let ex = phone.get_token().user("simphone").config_password("344486").send()?;
//! let ex = phone.config().send()?;
//! println!("{}", ex.reply.unwrap().body);
//! let ev = phone.next_event(std::time::Duration::from_secs(30), Some("digium.config.update"));
//! # Ok(()) }
//! ```
//!
//! Text is bytes from end to end: bodies, header values, the user agent,
//! user names, and passwords go on the wire exactly as given, and replies
//! keep the bytes they arrived with.

pub mod crypto;
pub mod framing;
mod phone;
pub mod pki;
pub mod proto;
mod reply;
pub mod selftest;
pub mod transport;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use framing::ChunkStyle;
pub use phone::{ami_port_for, sip_port_for, Form, Options, Phone, RequestBuilder, SessionChoice};
pub use reply::{Added, Exchange, Reassembler, Reply};

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

    /// Writes `text` (raw bytes) regardless of the verbosity.
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

/// The default test PKI directory: `$DPMA_PKI` if set, else
/// `dev/sim/pki` in the repository (generated, not committed), the
/// default of the Python tools (`tests/sim/mkpki.py`, `dpma_sim.py`) too,
/// so that both share one PKI.
pub fn default_pki_dir() -> PathBuf {
    match std::env::var_os("DPMA_PKI") {
        Some(p) => PathBuf::from(p),
        None => repo_root().join("dev").join("sim").join("pki"),
    }
}

/// The default reply timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
