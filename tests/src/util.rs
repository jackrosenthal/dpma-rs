//! Small helpers shared by the modules: JSON text in the forms the test
//! documents use, waiting with timeouts, and random tokens.

use std::time::{Duration, Instant};

use serde_json::Value;

/// JSON text as Python's `json.dumps(value)` writes it: `", "` and `": "`
/// separators and every non-ASCII character escaped (`\uXXXX`).
pub fn json_python(value: &Value) -> String {
    let mut out = String::new();
    write_json(value, &mut out, true, ", ", ": ");
    out
}

/// Compact JSON with non-ASCII characters kept, as Python's
/// `json.dumps(value, separators=(",", ":"), ensure_ascii=False)` and the
/// module's (jansson's) compact documents write it.
pub fn json_compact(value: &Value) -> String {
    let mut out = String::new();
    write_json(value, &mut out, false, ",", ":");
    out
}

fn write_json(v: &Value, out: &mut String, ascii: bool, item_sep: &str, key_sep: &str) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out, ascii),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write_json(item, out, ascii, item_sep, key_sep);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write_json_string(k, out, ascii);
                out.push_str(key_sep);
                write_json(item, out, ascii, item_sep, key_sep);
            }
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String, ascii: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (ascii && (c as u32) > 0x7e) => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

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

/// `n` random bytes as lowercase hex (Python's `secrets.token_hex(n)`).
pub fn token_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}

/// Seconds as a [`Duration`] (negative values count as zero).
pub fn secs(s: f64) -> Duration {
    Duration::from_secs_f64(s.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_json() {
        let v: Value = serde_json::from_str(
            r#"{"request": {"method": "m", "parameters": {"x": [1, "é😀"]}}}"#,
        )
        .unwrap();
        assert_eq!(
            json_python(&v),
            concat!(
                r#"{"request": {"method": "m", "parameters": {"x": [1, ""#,
                "\\u00e9\\ud83d\\ude00",
                r#""]}}}"#
            )
        );
        assert_eq!(
            json_compact(&v),
            r#"{"request":{"method":"m","parameters":{"x":[1,"é😀"]}}}"#
        );
    }
}
