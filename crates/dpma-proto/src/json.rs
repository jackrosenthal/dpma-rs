//! JSON text as Asterisk produces it (`ast_json_dump_string`, i.e.,
//! jansson's `json_dumps` with `JSON_COMPACT`).
//!
//! serde_json's compact writer already matches jansson's separators
//! (`,` and `:` without spaces), its set of escaped characters (`"`, `\`,
//! and control characters below 0x20, with `\b`, `\f`, `\n`, `\r`, and `\t`
//! short forms), and, with the workspace's `preserve_order` feature, its
//! key order (insertion order).  The one difference is the case of the
//! hex digits in `\u00XX` escapes: jansson writes them in upper case.

use serde_json::ser::{CharEscape, CompactFormatter, Formatter};
use std::io;

struct JanssonFormatter;

impl Formatter for JanssonFormatter {
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, writer: &mut W, escape: CharEscape) -> io::Result<()> {
        match escape {
            CharEscape::AsciiControl(b) => write!(writer, "\\u{:04X}", b),
            other => CompactFormatter.write_char_escape(writer, other),
        }
    }
}

/// The text of a JSON string made from the bytes of a C string, or None
/// where jansson refuses them: `json_string` and `ast_json_pack`'s `s`
/// accept only valid UTF-8 (the same rules as Rust's: no overlong forms,
/// surrogates, or values above U+10FFFF).
pub fn utf8(b: &[u8]) -> Option<&str> {
    std::str::from_utf8(b).ok()
}

/// `ast_json_dump_string(value)`: compact JSON text.
pub fn dump(value: &serde_json::Value) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, JanssonFormatter);
    // Serializing a Value into memory cannot fail.
    let _ = serde::Serialize::serialize(value, &mut ser);
    String::from_utf8(buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_and_ordered() {
        let v = serde_json::json!({"response": {"method": "m", "errors": {"error": {"code": 10005, "message": "a/b"}}}});
        assert_eq!(
            dump(&v),
            r#"{"response":{"method":"m","errors":{"error":{"code":10005,"message":"a/b"}}}}"#
        );
    }

    #[test]
    fn utf8_like_jansson() {
        assert_eq!(utf8("Jos\u{e9}".as_bytes()), Some("Jos\u{e9}"));
        assert_eq!(utf8(b"Jos\xe9"), None);
        // Overlong, surrogate, and out of range forms.
        assert_eq!(utf8(b"\xc0\xaf"), None);
        assert_eq!(utf8(b"\xed\xa0\x80"), None);
        assert_eq!(utf8(b"\xf4\x90\x80\x80"), None);
    }

    #[test]
    fn escapes_like_jansson() {
        let v = serde_json::Value::String("q\"b\\\u{1}\u{1f}\n\t\u{7f}é".into());
        assert_eq!(dump(&v), "\"q\\\"b\\\\\\u0001\\u001F\\n\\t\u{7f}é\"");
    }
}
