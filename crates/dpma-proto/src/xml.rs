//! XML text helpers.

use crate::cbuf::c_bytes;

/// The entity for a character `phone_utils_xml_escape` replaces.
fn entity(c: u8) -> Option<&'static [u8]> {
    match c {
        b'"' => Some(b"&quot;"),
        b'&' => Some(b"&amp;"),
        b'\'' => Some(b"&apos;"),
        b'<' => Some(b"&lt;"),
        b'>' => Some(b"&gt;"),
        _ => None,
    }
}

/// `phone_utils_xml_escape(in, out, size)` (0x1731a0) into a buffer of
/// `size` bytes: `"`, `&`, `'`, `<`, and `>` become entities.  When an
/// entity does not fit (it must be shorter than the space left, which
/// keeps one byte free), the character is copied unescaped instead; when
/// not even that fits, the output ends.  The input is a C string (it ends
/// at a NUL).  Returns the output without its terminating NUL.
pub fn escape_bounded(input: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if size == 0 {
        // The C code would write before its buffer; nothing sensible to do.
        return out;
    }
    let mut left = size - 1;
    for &c in c_bytes(input) {
        match entity(c) {
            Some(e) if e.len() < left => {
                out.extend_from_slice(e);
                left -= e.len();
            }
            _ => {
                if left < 1 {
                    break;
                }
                out.push(c);
                left -= 1;
            }
        }
    }
    out
}

/// `phone_utils_xml_escape` with unlimited room: escape `&`, `<`, `>`,
/// `"`, and `'` exactly as the original does (bytewise; every other byte
/// is copied).
pub fn escape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        match entity(c) {
            Some(e) => out.extend_from_slice(e),
            None => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(escape(b"a&b<c>d\"e'f"), b"a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(escape("plain ünïcödé".as_bytes()), "plain ünïcödé".as_bytes());
        assert_eq!(escape(b"Jos\xe9 <\xff>"), b"Jos\xe9 &lt;\xff&gt;");
        assert_eq!(escape(b""), b"");
    }

    #[test]
    fn bounded() {
        let s = b"a&b<c>d\"e'f";
        assert_eq!(escape_bounded(s, 1024), escape(s));
        // size 1: nothing fits.
        assert_eq!(escape_bounded(b"abc", 1), b"");
        assert_eq!(escape_bounded(b"abc", 3), b"ab");
        // "&amp;" (5) needs more than 5 bytes left, i.e., size >= 7.
        assert_eq!(escape_bounded(b"&", 6), b"&");
        assert_eq!(escape_bounded(b"&", 7), b"&amp;");
        assert_eq!(escape_bounded(b"x&", 7), b"x&");
        // "&quot;" and "&apos;" (6) need size >= 8; "&lt;" and "&gt;" (4)
        // need size >= 6.
        assert_eq!(escape_bounded(b"\"'", 8), b"&quot;'");
        assert_eq!(escape_bounded(b"<>", 6), b"&lt;>");
        assert_eq!(escape_bounded(b"<>", 10), b"&lt;&gt;");
        // A NUL ends the input.
        assert_eq!(escape_bounded(b"ab\0cd", 100), b"ab");
        assert_eq!(escape_bounded(b"ab", 0), b"");
    }
}
