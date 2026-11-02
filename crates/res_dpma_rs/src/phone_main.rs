//! The phone_main thread (res_digium_phone.c: `phone_main` FUN_001461e0,
//! `start_DPMA_thread`, `stop_DPMA_thread`).
//!
//! Waits until Asterisk is fully booted, logs "Digium Phone Module
//! Started" (to the DPMA level, when the system verbosity is at least 2),
//! then loops: `session::next_transaction(10000)`; a transaction with a
//! response type is logged as "Received response of unknown type"; anything
//! else goes to `request::handle_incoming`.
//!
//! The original stops the thread with `pthread_cancel` (it has a
//! `pthread_testcancel` after every transaction) plus a signal to break the
//! wait.  Here a stop flag is checked instead, and `transport::wake_reader`
//! interrupts a blocked `next_transaction`.

use crate::session::Transaction;
use dpma_ast::dpma_log;
use dpma_ast::threadpool;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long `next_transaction` waits for a message (ms).
const READ_TIMEOUT_MS: i32 = 10000;

/// The `core show threads` name `ast_pthread_create_stack` gives the
/// original's thread (created at res_digium_phone.c:308 in
/// `start_DPMA_thread`).
const START_LINE: i32 = 0x134;

struct Control {
    stop: Mutex<bool>,
    cond: Condvar,
}

impl Control {
    fn stopping(&self) -> bool {
        *self.stop.lock().unwrap()
    }

    /// Sleep up to `d`, returning early (true) when a stop is requested.
    fn sleep(&self, d: Duration) -> bool {
        let g = self.stop.lock().unwrap();
        let (g, _) = self.cond.wait_timeout_while(g, d, |stop| !*stop).unwrap();
        *g
    }
}

struct Running {
    handle: JoinHandle<()>,
    control: Arc<Control>,
}

/// The thread (`threadlock` and the thread id at 0x5e7df8).
static THREAD: Mutex<Option<Running>> = Mutex::new(None);

/// Handle one complete transaction the way the loop does: answers from
/// phones to server requests are only logged; requests are dispatched.
/// Returns None for a logged response, otherwise the dispatch result.
pub fn dispatch(tx: Arc<Transaction>) -> Option<Result<(), ()>> {
    if !tx.response_type.is_empty() {
        dpma_log!("Received response of unknown type '{}'", tx.response_type);
        None
    } else {
        Some(crate::request::handle_incoming(tx))
    }
}

fn phone_main(control: Arc<Control>) {
    threadpool::register_thread(&threadpool::thread_name(
        "phone_main",
        START_LINE,
        "res_digium_phone.c",
        "start_DPMA_thread",
    ));

    let mut started = false;
    while !control.stopping() {
        if !started {
            if !dpma_ast::fully_booted() {
                control.sleep(Duration::from_secs(1));
                continue;
            }
            if dpma_ast::log::verb_sys_level() > 1 {
                dpma_log!("Digium Phone Module Started");
            }
            started = true;
        }
        let begin = Instant::now();
        let tx = dpma_ast::guard(None, || crate::session::next_transaction(READ_TIMEOUT_MS));
        match tx {
            Some(tx) => {
                dpma_ast::guard(None, || dispatch(tx));
            }
            None => {
                // next_transaction returns None after its timeout or when
                // woken.  Should it ever return at once (no transport yet,
                // or a closed queue), do not spin.
                if begin.elapsed() < Duration::from_millis(100) {
                    control.sleep(Duration::from_millis(100));
                }
            }
        }
    }

    threadpool::unregister_thread();
}

/// `start_DPMA_thread`: start the thread if it is not running.
pub fn start() -> Result<(), ()> {
    let mut g = THREAD.lock().unwrap();
    if let Some(r) = g.as_ref() {
        if !r.handle.is_finished() {
            return Ok(());
        }
        // The thread ended on its own (it never does unless something
        // panicked outside the guards); reap it and start a new one.
        if let Some(r) = g.take() {
            let _ = r.handle.join();
        }
    }
    let control = Arc::new(Control { stop: Mutex::new(false), cond: Condvar::new() });
    let c = control.clone();
    let handle = std::thread::Builder::new()
        .name("phone_main".into())
        .spawn(move || phone_main(c))
        .map_err(|_| ())?;
    *g = Some(Running { handle, control });
    Ok(())
}

/// `stop_DPMA_thread`: stop the thread and wait for it.
pub fn stop() {
    let Some(r) = THREAD.lock().unwrap().take() else {
        return;
    };
    *r.control.stop.lock().unwrap() = true;
    r.control.cond.notify_all();
    crate::transport::wake_reader();
    let _ = r.handle.join();
}
