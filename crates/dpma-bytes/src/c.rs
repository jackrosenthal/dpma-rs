//! The C library's string functions, as the official DPMA gets them in
//! the C locale: a string ends at its first NUL, and only the ASCII
//! letters have a case (`tolower` and `toupper` leave every other byte,
//! 0x80 and up included, alone).

use std::cmp::Ordering;
use std::ffi::CString;

/// The C string in `s`: everything before the first NUL.
pub fn c_view(s: &[u8]) -> &[u8] {
    match s.iter().position(|&b| b == 0) {
        Some(i) => &s[..i],
        None => s,
    }
}

/// A C string with the bytes of `s` up to its first NUL, as C sees a
/// buffer that holds a NUL.
pub fn cstring(s: impl AsRef<[u8]>) -> CString {
    // c_view leaves no NUL, so this cannot fail.
    CString::new(c_view(s.as_ref())).unwrap_or_default()
}

/// `strcasecmp(a, b) == 0`.
pub fn eq_ic(a: &[u8], b: &[u8]) -> bool {
    c_view(a).eq_ignore_ascii_case(c_view(b))
}

/// The sign of `strcasecmp(a, b)`: the first byte that differs after
/// `tolower`, as unsigned values.
pub fn cmp_ic(a: &[u8], b: &[u8]) -> Ordering {
    let (a, b) = (c_view(a), c_view(b));
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

/// `strncasecmp(s, prefix, strlen(prefix)) == 0`.
pub fn starts_with_ic(s: &[u8], prefix: &[u8]) -> bool {
    let (s, prefix) = (c_view(s), c_view(prefix));
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// `strcasestr(haystack, needle)`: the offset of the first match.
pub fn find_ic(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let (h, n) = (c_view(haystack), c_view(needle));
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w.eq_ignore_ascii_case(n))
}

/// Asterisk's `ast_str_case_hash`: djb2 over the `tolower`ed bytes, masked
/// to a non-negative value.
pub fn case_hash(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in c_view(s) {
        h = h.wrapping_mul(33) ^ u32::from(b.to_ascii_lowercase());
    }
    h & 0x7fff_ffff
}

/// `isspace` in the C locale.
pub fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `strtol(s, &end, 10)`: optional leading white space and sign, then
/// decimal digits, saturating at the `long` range.  Returns the value and
/// the number of bytes used (0 when there are no digits, as `end == s`).
pub fn strtol(s: &[u8]) -> (i64, usize) {
    let s = c_view(s);
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let neg = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let digits = i;
    let mut v: i64 = 0;
    let mut overflow = false;
    while let Some(d) = s.get(i).filter(|c| c.is_ascii_digit()) {
        let d = i64::from(d - b'0');
        match v.checked_mul(10).and_then(|x| {
            if neg {
                x.checked_sub(d)
            } else {
                x.checked_add(d)
            }
        }) {
            Some(n) => v = n,
            None => overflow = true,
        }
        i += 1;
    }
    if i == digits {
        return (0, 0);
    }
    let v = match (overflow, neg) {
        (false, _) => v,
        (true, true) => i64::MIN,
        (true, false) => i64::MAX,
    };
    (v, i)
}

/// `atoi(s)` (glibc: `(int) strtol(s, NULL, 10)`).
pub fn atoi(s: &[u8]) -> i32 {
    strtol(s).0 as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_and_cstrings() {
        assert_eq!(c_view(b"ab\0cd"), b"ab");
        assert_eq!(c_view(b"abc"), b"abc");
        assert_eq!(cstring(b"ab\0cd").as_bytes(), b"ab");
        assert_eq!(cstring(b"Jos\xe9").as_bytes(), b"Jos\xe9");
    }

    #[test]
    fn case_functions_fold_ascii_only() {
        assert!(eq_ic(b"Jos\xe9", b"jOS\xe9"));
        assert!(!eq_ic(b"\xc9", b"\xe9"));
        assert!(eq_ic(b"abc\0x", b"ABC\0y"));
        assert_eq!(cmp_ic(b"a", b"B"), Ordering::Less);
        assert_eq!(cmp_ic(b"z", b"\xe9"), Ordering::Less);
        assert_eq!(cmp_ic(b"ab", b"a"), Ordering::Greater);
        assert!(starts_with_ic(b"SIP:x", b"sip:"));
        assert!(!starts_with_ic(b"si", b"sip:"));
        assert_eq!(find_ic(b"Digium D65", b"digium"), Some(0));
        assert_eq!(find_ic(b"x Sangoma P330", b"sangoma p"), Some(2));
        assert_eq!(find_ic(b"abc", b"x"), None);
        assert_eq!(case_hash(b"Phone"), case_hash(b"PHONE"));
        assert_ne!(case_hash(b"\xc9"), case_hash(b"\xe9"));
    }

    #[test]
    fn numbers() {
        assert_eq!(strtol(b"  -12x"), (-12, 5));
        assert_eq!(strtol(b"x"), (0, 0));
        assert_eq!(strtol(b"+"), (0, 0));
        assert_eq!(strtol(b"99999999999999999999"), (i64::MAX, 20));
        assert_eq!(atoi(b"4294967297"), 1);
        assert_eq!(atoi(b"\t7"), 7);
    }
}
