//! Test support for dpma-rs: everything needed to test `res_dpma_rs.so`
//! in a private Asterisk instance without Digium phones, and the test
//! suites themselves.
//!
//! # Modules
//!
//! | Module | What it is |
//! |---|---|
//! | [`sim`] | The phone simulator: SIP transport, handshake (legacy and chain forms), encryption, chunking and reassembly, every request type, events, and a self-test.  Independent of the module's crates (it shares only the RustCrypto primitive crates, not dpma-proto), so it cross-checks them. |
//! | [`mkpki`] | The test PKI: phone CAs and certificates, negative variants, and the AppServer certificate; installs the trust material into an instance. |
//! | [`ami`] | An AMI client that keeps every message's raw bytes. |
//! | [`asterisk`] | The pinned Asterisk releases and the private instances: the instance manager behind `cargo xtask instance` and [`harness::Instance`]. |
//! | [`sipua`] | A minimal SIP user agent for test phones: REGISTER with digest authentication, MESSAGE, SUBSCRIBE, and a UAS that answers or rejects calls, sends DTMF INFOs, and records INFOs and NOTIFYs. |
//! | [`mdns`] | An mDNS browser (legacy unicast queries) and listener. |
//! | [`netns`] | A private network namespace a suite runs itself in (`unshare -rn`). |
//! | [`harness`] | Shared by the suites: the instance and its CLI (control socket), checks, the log, configuration editing, the suite runner, and fixtures. |
//! | [`sip`] | SIP messages as bytes (parsing and encoding). |
//! | [`util`] | JSON text as the test documents write it, waiting with timeouts. |
//! | [`ari`] | An ARI (Asterisk REST Interface) HTTP client, for push configuration. |
//! | [`diff`] | Unified line diffs for check details. |
//! | [`xml`] | XML well-formedness. |
//!
//! # Binaries
//!
//! - `dpma-sim`: the simulator from the command line (`dpma-sim --help`).
//! - `dpma-mkpki`: makes and installs the test PKI, or checks that its
//!   certificates verify as the module's rules expect.
//! - `dpma-ami`: sends an AMI action and prints the response and events.
//!
//! # Suites
//!
//! Each suite is a test target in `tests/suites/` that runs against a
//! private instance (`DPMA_SLOT`, see [`asterisk`]) with a devtest build
//! of the module:
//!
//! ```text
//! export DPMA_SLOT=<n> ASTERISK_SOURCE_DIR=$PWD/dev/asterisk-builds/24.0.0-rc4/src
//! cargo build -p res_dpma_rs --features devtest
//! cargo test -p dpma-tests --test session -- --ignored
//! ```
//!
//! A suite prepares the instance itself (fresh configuration, its setup,
//! the module installed, Asterisk restarted), then runs its parts; see
//! [`harness::Suite`] for the arguments.  `cargo xtask test` runs the
//! suites one after another (see `tests/README.md`).  A plain `cargo test` runs the
//! unit tests (including the simulator's self-test against a throwaway
//! PKI) and skips the suites.
//!
//! # Bytes
//!
//! Text is bytes from end to end: SIP header values, bodies, AMI fields,
//! CLI output, and configuration files are `Vec<u8>` or
//! [`bstr::BString`], so text that is not UTF-8 (Latin-1 in the raw-bytes
//! tests) goes out and comes back unchanged.

#![warn(missing_docs)]

pub mod ami;
pub mod ari;
pub mod asterisk;
pub mod diff;
pub mod harness;
pub mod mdns;
pub mod mkpki;
pub mod netns;
pub mod sim;
pub mod sip;
pub mod sipua;
pub mod util;
pub mod xml;
