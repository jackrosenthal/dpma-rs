//! The phone_main thread (res_digium_phone.c: `phone_main`,
//! `start_DPMA_thread`, `stop_DPMA_thread`).
//!
//! Waits until Asterisk is fully booted, logs "Digium Phone Module
//! Started" at verbose 2, then loops: `session::next_transaction(10000)`;
//! a transaction with a response type is logged as "Received response of
//! unknown type"; anything else goes to `request::handle_incoming`.
//!
//! Owner: P3 "request" (wave 1).

/// Start the thread if it is not running.
pub fn start() -> Result<(), ()> {
    Ok(())
}

/// Stop the thread and wait for it.
pub fn stop() {}

pub fn is_running() -> bool {
    false
}
