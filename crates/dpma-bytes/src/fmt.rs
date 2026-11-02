//! `format!` for byte strings: [`bformat!`](crate::bformat),
//! [`bwrite!`](crate::bwrite), and [`bwriteln!`](crate::bwriteln).
//!
//! ```
//! use dpma_bytes::bformat;
//! let name: Vec<u8> = b"Jos\xe9".to_vec();
//! assert_eq!(bformat!("Name: {} ({})\n", name, 7), b"Name: Jos\xe9 (7)\n");
//! ```
//!
//! The macros take `format!`'s format strings.  Each argument that is a
//! byte string (`Vec<u8>`, `[u8]`, `[u8; N]`, `Cow<[u8]>`, or one
//! reference to one of these) is written as its exact bytes, and text
//! (`str`, `String`, `Cow<str>`, or one reference to one of these) as its
//! UTF-8 bytes; any other argument as its `Display` (or `Debug`, `{:x}`,
//! ...), as `format!` would.  Width and precision count bytes for byte
//! strings and text, as `printf`'s `%s` does (`{:<20.20}` is
//! `%-20.20s`), so a precision can cut a multi-byte character as it does
//! in C.  Their `{:?}` is `bstr`'s escaped form.  Arguments captured in the format string (`{name}`) are not
//! byte-string aware; byte strings have no `Display`, so the compiler
//! refuses them.
//!
//! How it works: `std::fmt` can only carry `str`, so a byte string is
//! written as text in which each byte that is not part of valid UTF-8
//! (and each byte of the rare valid characters U+10FF00 to U+10FFFF) is
//! replaced by the character U+10FF00 plus that byte, and the output sink
//! maps those characters back.  Nothing else writes characters in that
//! range: text arguments are escaped the same way, the escaping only
//! happens while one of these macros is formatting, and a byte string
//! formatted anywhere else (for example, by `format!` on a [`Raw`]) is
//! written lossily, with U+FFFD for invalid bytes.  (Only the format
//! string itself is not escaped; it would have to contain such a
//! character literally.)

use std::borrow::Cow;
use std::cell::Cell;
use std::fmt::{self, Write as _};

/// First character of the escape range: byte `b` travels as
/// U+10FF00 + `b`.
const ESC_BASE: u32 = 0x10_FF00;

thread_local! {
    /// How many byte sinks are writing on this thread.
    static SINKS: Cell<usize> = const { Cell::new(0) };
}

fn esc(b: u8) -> char {
    // ESC_BASE + 0xff is U+10FFFF, a valid scalar value.
    char::from_u32(ESC_BASE + u32::from(b)).unwrap_or(char::REPLACEMENT_CHARACTER)
}

/// Write `b` escaped for a byte sink.
fn write_escaped(f: &mut fmt::Formatter<'_>, b: &[u8]) -> fmt::Result {
    for chunk in b.utf8_chunks() {
        let valid = chunk.valid();
        if valid.as_bytes().contains(&0xf4) {
            let mut start = 0;
            for (i, c) in valid.char_indices() {
                if u32::from(c) >= ESC_BASE {
                    f.write_str(&valid[start..i])?;
                    for &byte in &valid.as_bytes()[i..i + c.len_utf8()] {
                        f.write_char(esc(byte))?;
                    }
                    start = i + c.len_utf8();
                }
            }
            f.write_str(&valid[start..])?;
        } else {
            f.write_str(valid)?;
        }
        for &byte in chunk.invalid() {
            f.write_char(esc(byte))?;
        }
    }
    Ok(())
}

/// A byte string to format with its exact bytes (see the module
/// documentation).  The macros wrap byte-string arguments in it
/// themselves.
#[derive(Clone, Copy)]
pub struct Raw<'a>(pub &'a [u8]);

impl fmt::Display for Raw<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut b = self.0;
        if let Some(p) = f.precision() {
            b = &b[..b.len().min(p)];
        }
        let pad = f.width().map_or(0, |w| w.saturating_sub(b.len()));
        let (before, after) = match f.align() {
            Some(fmt::Alignment::Right) => (pad, 0),
            Some(fmt::Alignment::Center) => (pad / 2, pad - pad / 2),
            _ => (0, pad),
        };
        let fill = f.fill();
        for _ in 0..before {
            f.write_char(fill)?;
        }
        if SINKS.get() > 0 {
            write_escaped(f, b)?;
        } else {
            for chunk in b.utf8_chunks() {
                f.write_str(chunk.valid())?;
                if !chunk.invalid().is_empty() {
                    f.write_char(char::REPLACEMENT_CHARACTER)?;
                }
            }
        }
        for _ in 0..after {
            f.write_char(fill)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Raw<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(bstr::BStr::new(self.0), f)
    }
}

/// The sink: appends to a byte vector, mapping escaped bytes back.
struct Sink<'a>(&'a mut Vec<u8>);

impl fmt::Write for Sink<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let b = s.as_bytes();
        if !b.contains(&0xf4) {
            self.0.extend_from_slice(b);
            return Ok(());
        }
        for c in s.chars() {
            let u = u32::from(c);
            if u >= ESC_BASE {
                self.0.push((u - ESC_BASE) as u8);
            } else {
                self.0
                    .extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
            }
        }
        Ok(())
    }
}

/// Counts an active sink for as long as it lives (also when formatting
/// panics).
struct Active;

impl Active {
    fn new() -> Active {
        SINKS.set(SINKS.get() + 1);
        Active
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        SINKS.set(SINKS.get() - 1);
    }
}

/// Append formatted text to `out` (what [`bwrite!`](crate::bwrite) calls).
pub fn write_to(out: &mut Vec<u8>, args: fmt::Arguments<'_>) {
    let _active = Active::new();
    // Only an argument's own formatting can fail; like `format!`, ignore
    // it and keep what was written.
    let _ = fmt::write(&mut Sink(out), args);
}

/// Format to a new byte vector (what [`bformat!`](crate::bformat) calls).
pub fn format(args: fmt::Arguments<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    write_to(&mut out, args);
    out
}

// ---- argument selection (used by the macros) ----
//
// `(&&Arg(&x)).dpma_fmt_arg()` picks `BytesArg` when `x` is a byte string
// (its impls are for `&Arg<..>`, matched first by method resolution) and
// otherwise `DisplayArg`, which forwards to `x`'s own formatting.

#[doc(hidden)]
pub struct Arg<'a, T: ?Sized>(pub &'a T);

#[doc(hidden)]
pub trait BytesArg<'a> {
    fn dpma_fmt_arg(&self) -> Raw<'a>;
}

macro_rules! bytes_arg {
    ($($t:ty => |$v:ident| $e:expr;)*) => {
        $(
            impl<'a, 'b: 'a> BytesArg<'a> for &Arg<'a, $t> {
                #[allow(clippy::needless_borrow)]
                fn dpma_fmt_arg(&self) -> Raw<'a> {
                    let $v: &'a $t = self.0;
                    Raw($e)
                }
            }
        )*
    };
}

bytes_arg! {
    [u8] => |v| v;
    Vec<u8> => |v| v.as_slice();
    &'b [u8] => |v| v;
    &'b Vec<u8> => |v| v.as_slice();
    &'b mut Vec<u8> => |v| v.as_slice();
    Cow<'b, [u8]> => |v| v.as_ref();
    &'b Cow<'b, [u8]> => |v| v.as_ref();
    bstr::BStr => |v| v.as_ref();
    &'b bstr::BStr => |v| v.as_ref();
    // Text is its UTF-8 bytes (so text can never be mistaken for the
    // escapes below, whatever it holds).
    str => |v| v.as_bytes();
    &'b str => |v| v.as_bytes();
    String => |v| v.as_bytes();
    &'b String => |v| v.as_bytes();
    Cow<'b, str> => |v| v.as_bytes();
    &'b Cow<'b, str> => |v| v.as_bytes();
}

impl<'a, const N: usize> BytesArg<'a> for &Arg<'a, [u8; N]> {
    fn dpma_fmt_arg(&self) -> Raw<'a> {
        Raw(self.0)
    }
}

impl<'a, 'b: 'a, const N: usize> BytesArg<'a> for &Arg<'a, &'b [u8; N]> {
    fn dpma_fmt_arg(&self) -> Raw<'a> {
        Raw(*self.0)
    }
}

#[doc(hidden)]
pub trait DisplayArg<'a, T: ?Sized> {
    fn dpma_fmt_arg(&self) -> Fwd<'a, T>;
}

impl<'a, T: ?Sized> DisplayArg<'a, T> for Arg<'a, T> {
    fn dpma_fmt_arg(&self) -> Fwd<'a, T> {
        Fwd(self.0)
    }
}

/// Formats as the wrapped value does.
#[doc(hidden)]
pub struct Fwd<'a, T: ?Sized>(&'a T);

macro_rules! forward {
    ($($tr:ident),*) => {
        $(
            impl<T: ?Sized + fmt::$tr> fmt::$tr for Fwd<'_, T> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::$tr::fmt(self.0, f)
                }
            }
        )*
    };
}

forward!(Display, Debug, LowerHex, UpperHex, Octal, Binary, LowerExp, UpperExp, Pointer);

/// `format!` producing a `Vec<u8>`, with byte-string arguments written as
/// their exact bytes (see the [module documentation](crate::fmt)).
#[macro_export]
macro_rules! bformat {
    ($($t:tt)*) => {{
        let mut __dpma_out = ::std::vec::Vec::<u8>::new();
        $crate::bwrite!(__dpma_out, $($t)*);
        __dpma_out
    }};
}

/// `write!` into a `Vec<u8>` (or `&mut Vec<u8>`), with byte-string
/// arguments written as their exact bytes.  Appends; returns nothing.
#[macro_export]
macro_rules! bwrite {
    ($out:expr, $fmt:literal $(,)?) => {
        $crate::fmt::write_to(&mut $out, ::std::format_args!($fmt))
    };
    ($out:expr, $fmt:literal, $($arg:expr),+ $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::fmt::{BytesArg as _, DisplayArg as _};
        $crate::fmt::write_to(
            &mut $out,
            ::std::format_args!($fmt, $((&&$crate::fmt::Arg(&$arg)).dpma_fmt_arg()),+),
        )
    }};
}

/// `writeln!` into a `Vec<u8>`: [`bwrite!`](crate::bwrite) plus a newline.
#[macro_export]
macro_rules! bwriteln {
    ($out:expr, $($t:tt)*) => {{
        $crate::bwrite!($out, $($t)*);
        $out.push(b'\n');
    }};
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    #[test]
    fn bytes_pass_through() {
        let v: Vec<u8> = b"Jos\xe9".to_vec();
        let s: &[u8] = b"\xff\xfe";
        let a = [0x80u8, b'x'];
        assert_eq!(
            bformat!("{}|{}|{}|{}", v, s, a, &v),
            b"Jos\xe9|\xff\xfe|\x80x|Jos\xe9"
        );
        let c: Cow<[u8]> = Cow::Borrowed(b"\xe9");
        assert_eq!(bformat!("<{}>", c), b"<\xe9>");
        assert_eq!(
            bformat!("{} {} {}", "str", String::from("s"), 42),
            b"str s 42"
        );
        let t = "\u{10FF41}é";
        assert_eq!(
            bformat!("{}|{}|{:<4}|", t, t.to_string(), "é"),
            "\u{10FF41}é|\u{10FF41}é|é  |".as_bytes()
        );
        assert_eq!(bformat!("plain"), b"plain");
        let n = 5;
        assert_eq!(bformat!("{n}:{:02x}:{:>3}", 10, 7), b"5:0a:  7");
    }

    #[test]
    fn escape_range_and_utf8() {
        // Valid characters in the escape range survive.
        let v = "a\u{10FF41}b\u{10FFFF}é".as_bytes().to_vec();
        assert_eq!(bformat!("{}", v), v);
        let mixed = b"\xc3\xa9\xc3\x28\xf4\x8f\xbd".to_vec();
        assert_eq!(
            bformat!("[{}]", mixed),
            [b"[".as_slice(), &mixed, b"]"].concat()
        );
    }

    #[test]
    fn width_and_precision_count_bytes() {
        let v = "é".as_bytes().to_vec();
        assert_eq!(bformat!("{:<4}|", v), "é  |".as_bytes());
        assert_eq!(bformat!("{:>4}|", v), "  é|".as_bytes());
        // %.1s cuts the character in half.
        assert_eq!(bformat!("{:.1}|", v), b"\xc3|");
        assert_eq!(bformat!("{:<3.3}|", b"\xe9abcdef".to_vec()), b"\xe9ab|");
    }

    #[test]
    fn debug_and_lossy_elsewhere() {
        let v = b"a\xffb".to_vec();
        assert_eq!(bformat!("{:?}", v), b"\"a\\xffb\"");
        // Outside a byte sink a Raw is written lossily.
        assert_eq!(format!("{}", super::Raw(&v)), "a\u{FFFD}b");
    }

    #[test]
    fn write_appends() {
        let mut out = b"x".to_vec();
        bwrite!(out, "{}{}", b"\xe9".to_vec(), 1);
        bwrite!(out, ";");
        assert_eq!(out, b"x\xe91;");
        let r = &mut out;
        bwrite!(*r, "!");
        bwriteln!(*r, "{}", 2);
        assert_eq!(out, b"x\xe91;!2\n");
    }

    #[test]
    fn nested_format_inside_display() {
        struct T(Vec<u8>);
        impl std::fmt::Display for T {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let s = format!("({})", super::Raw(&self.0));
                f.write_str(&s)
            }
        }
        assert_eq!(bformat!("{}", T(b"\xe9".to_vec())), b"(\xe9)");
    }
}
