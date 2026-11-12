//! Small helpers shared by the modules.

use std::time::{Duration, Instant};

/// Polls `f` every `interval` until it returns `Some`, for at most
/// `timeout`; `None` on timeout.  `f` runs at least once.
pub fn wait_for<T>(
    timeout: Duration,
    interval: Duration,
    mut f: impl FnMut() -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Polls `f` every `interval` until it returns true, for at most
/// `timeout`; whether it did.
pub fn wait_until(timeout: Duration, interval: Duration, mut f: impl FnMut() -> bool) -> bool {
    wait_for(timeout, interval, || f().then_some(())).is_some()
}

/// `n` random bytes as lowercase hex.
pub fn token_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}

/// Seconds as a [`Duration`] (negative values count as zero).
pub fn secs(s: f64) -> Duration {
    Duration::from_secs_f64(s.max(0.0))
}
