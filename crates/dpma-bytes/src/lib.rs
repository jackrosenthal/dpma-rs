//! C strings as bytes.
//!
//! Asterisk hands the modules C strings: bytes up to a NUL, in no
//! particular encoding.  The official DPMA passes them through
//! unchanged, so a Latin-1 "José" in a configuration file reaches the
//! phone as the same bytes.  dpma-rs does the same: text that comes from
//! Asterisk or from a phone is kept as bytes (`Vec<u8>` and `&[u8]`, with
//! [`bstr`]'s [`ByteSlice`] and [`ByteVec`] string methods) from the point
//! it enters the module to the point it leaves, and is never converted
//! through UTF-8.
//!
//! This crate has what makes that readable:
//!
//! - [`bformat!`], [`bwrite!`], and [`bwriteln!`]: `format!`, `write!`,
//!   and `writeln!` for bytes (see [`mod@fmt`]).
//! - the C library's string functions with the semantics the official DPMA
//!   gets from them in the C locale ([`mod@c`]).

pub mod c;
pub mod fmt;

pub use bstr::{BStr, ByteSlice, ByteVec};
pub use c::{c_view, case_hash, cmp_ic, cstring, eq_ic, find_ic, starts_with_ic};
