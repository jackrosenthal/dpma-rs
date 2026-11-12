//! Test support for dpma-rs: everything needed to test `res_dpma_rs.so`
//! in the Asterisk of the test container without Digium phones, and the
//! test suites themselves.
//!
//! # Suites
//!
//! Each suite is a test target in `tests/suites/` that runs inside the
//! test container, against its Asterisk ([`harness::Instance`]) with a
//! devtest build of the module (see `tests/README.md`):
//!
//! ```text
//! cargo xtask test [--asterisk VERSION] [SUITE... | all]
//! ```
//!
//! Inside, each suite runs as `cargo test -p dpma-tests --test <suite> --
//! --ignored`: it prepares the instance itself, then runs its parts; see
//! [`harness::Suite`] for the arguments.  A plain `cargo test` runs the
//! unit tests and skips the suites.
//!
//! # Bytes
//!
//! Text is bytes from end to end (`Vec<u8>` or [`bstr::BString`]), so
//! text that is not UTF-8 goes out and comes back unchanged.

#![warn(missing_docs)]

pub mod ami;
pub mod ari;
pub mod diff;
pub mod harness;
pub mod mdns;
pub mod sim;
pub mod sip;
pub mod sipua;
pub mod util;
pub mod xml;
