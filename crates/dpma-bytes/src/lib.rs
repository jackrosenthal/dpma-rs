//! C strings as bytes.
//!
//! Asterisk hands the modules C strings: bytes up to a NUL, in no
//! particular encoding.  The original module passes them through
//! unchanged, so a Latin-1 "José" in a configuration file reaches the
//! phone, the CLI, AMI, and AstDB as the same bytes.  dpma-rs does the
//! same: text that comes from Asterisk or from a phone is kept as bytes
//! (`Vec<u8>` and `&[u8]`, with [`bstr`]'s [`ByteSlice`] and [`ByteVec`]
//! string methods) from the point it enters the module to the point it
//! leaves, and is never converted through UTF-8.
//!
//! This crate has the two pieces that make that readable:
//!
//! - [`bformat!`], [`bwrite!`], and [`bwriteln!`]: `format!`, `write!`,
//!   and `writeln!` for bytes, with the same format strings, where an
//!   argument that is a byte string (`Vec<u8>`, `&[u8]`, `[u8; N]`, ...)
//!   is written as its exact bytes, text as its UTF-8 bytes, and anything
//!   else as its `Display` (see [`mod@fmt`]).
//! - the C library's string functions with the semantics the original
//!   gets from them in the C locale ([`mod@c`]): strings end at their first
//!   NUL, and case-insensitive comparisons and hashes fold only ASCII
//!   letters.

pub mod c;
pub mod fmt;

pub use bstr::{BStr, ByteSlice, ByteVec};
pub use c::{c_view, case_hash, cmp_ic, cstring, eq_ic, find_ic, starts_with_ic};
