//! The phone simulator: the phone side of the DPMA AppServer protocol
//! over SIP MESSAGE (UDP or TCP).
//!
//! It plays a Digium phone against an Asterisk instance.  It is written
//! from the decompile of the official DPMA and is deliberately
//! independent of the module's own crates (it shares only the RustCrypto
//! primitive crates), so that it cross-checks them: see [`selftest`] and
//! the vectors in `tests/data/vectors.json`.
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
//! Against an instance, the simulator needs the test PKI's trust material
//! and the simulator's test configuration in it
//! ([`crate::harness::fixtures::sim_setup`]; see
//! [`crate::harness::fixtures::SIM_CONF`] for the test phones).
//!
//! # Protocol details
//!
//! The simulator sends every request to `sip:proxy@<server>:<port>`
//! (what real phones use as `config_server_url`) from one socket, and
//! answers every MESSAGE it receives with 200 OK.  The server replies to
//! the address the request came from (`PJSIP_RECVADDR`), so replies
//! arrive on the same socket; over TCP they come back on the same
//! connection (see [`transport`] for the "Session Timeout" reply).
//!
//! Phone to server:
//!
//! - Every chunk carries `RequestType`, `ID` (a counter starting at a
//!   random value, so that a restarted simulator does not collide with an
//!   incomplete transaction the server keeps for 40 s under
//!   `"<ID>-<MAC>"`), `MACAddress`, `Session` (except for Handshake, Echo,
//!   and Preconfig), `Message-Sequence` (0, 1, ...), and on the last chunk
//!   `Message-Finished: 1`; and always `Content-Type: text/plain`
//!   (res_pjsip_messaging refuses a MESSAGE without it, even with an empty
//!   body).
//! - After the handshake everything but Echo is encrypted: a new 8-byte
//!   salt per request (`Message-Salt`, 16 uppercase hex digits); key and
//!   IV from `EVP_BytesToKey(aes-128-cbc, SHA-1, salt, common password,
//!   1)`; `Password`, `ConfigPassword`, and `Config-Token` each encrypted
//!   as their own CBC stream with that key and IV.
//! - Encrypted bodies ([`ChunkStyle::Split`], the default): the whole body
//!   is encrypted and base64 encoded, and the text is split into chunks.
//!   The server concatenates the chunk bodies and decodes them once with
//!   `ast_base64decode`, which stops at the first `=`, so this is the form
//!   it can reassemble.  [`ChunkStyle::Stream`] sends the way the server
//!   itself sends.
//! - Plaintext chunks never end in CR or LF (except the last one, and
//!   with `pem_cuts`): res_pjsip_messaging strips trailing CR and LF from
//!   every MESSAGE body, so a line break at a chunk boundary would be
//!   lost.  It also keeps at most 1023 bytes of a body, so keep the chunk
//!   size at or below 1022 bytes of wire body.
//!
//! Server to phone ([`Reassembler`], [`Reply`]):
//!
//! - Chunks are grouped by transaction id, salt, and type (events carry
//!   no `X-Digium-AppServer-ID`), ordered by `Message-Sequence`, and
//!   complete when the chunk with `Message-Finished` is in and none is
//!   missing, or at once when a chunk has no sequence (a single-chunk
//!   HandshakeResponse).
//! - Encrypted replies: each chunk's body is base64 decoded on its own,
//!   the ciphertexts are concatenated and decrypted as one stream, and
//!   `Password` and `Config-Token` are decrypted with the same salt.
//! - HandshakeResponse: unencrypted; `X-Digium-AppServer-Password` is the
//!   40-byte common password, RSA PKCS#1 v1.5 encrypted to the key of the
//!   last certificate of the handshake body; the body is the AppServer
//!   certificate, which the simulator checks against the test AppServer
//!   CA.
//! - Events and error replies have `Command: ` at the start of every
//!   chunk's plaintext (inside the encryption); a reply's payload has
//!   them removed.

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
pub use phone::{Form, Options, Phone, RequestBuilder, SessionChoice};
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

/// The default test PKI directory: `$DPMA_PKI` if set (each `cargo xtask`
/// run sets it to a temporary directory), else `dpma-sim-pki` in the
/// system's temporary directory.
pub fn default_pki_dir() -> PathBuf {
    match std::env::var_os("DPMA_PKI") {
        Some(p) => PathBuf::from(p),
        None => std::env::temp_dir().join("dpma-sim-pki"),
    }
}

/// The default reply timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
