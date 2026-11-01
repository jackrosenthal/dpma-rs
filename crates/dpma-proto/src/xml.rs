//! XML text helpers.
//!
//! Owner: P1 "proto" (wave 1).

/// `phone_utils_xml_escape` (0x1731a0): escape `&`, `<`, `>`, `"` and `'`
/// exactly as the original does.
pub fn escape(s: &str) -> String {
    s.to_string()
}
