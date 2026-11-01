//! Small helpers shared across the module.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub use dpma_ast::dpma_bytes::case_hash as str_case_hash;

/// A map keyed by case-insensitive name (`strcasecmp`: ASCII letters
/// fold, every other byte is itself) that iterates in the same order as
/// an ao2 hash container with `buckets` buckets hashed by
/// `ast_str_case_hash` (bucket order, then insertion order within a
/// bucket), so CLI listings come out in the same order as the original
/// module's.
#[derive(Debug, Clone)]
pub struct NamedMap<T> {
    buckets: u32,
    seq: u64,
    order: BTreeMap<(u32, u64), Vec<u8>>,
    items: HashMap<Vec<u8>, ((u32, u64), T)>,
}

impl<T> NamedMap<T> {
    pub fn new(buckets: u32) -> Self {
        NamedMap { buckets, seq: 0, order: BTreeMap::new(), items: HashMap::new() }
    }

    fn key(name: &[u8]) -> Vec<u8> {
        dpma_ast::dpma_bytes::c_view(name).to_ascii_lowercase()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn contains(&self, name: &[u8]) -> bool {
        self.items.contains_key(&Self::key(name))
    }

    pub fn get(&self, name: &[u8]) -> Option<&T> {
        self.items.get(&Self::key(name)).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, name: &[u8]) -> Option<&mut T> {
        self.items.get_mut(&Self::key(name)).map(|(_, v)| v)
    }

    /// Insert `value` under `name`, replacing (in place) any existing entry.
    pub fn insert(&mut self, name: &[u8], value: T) {
        let k = Self::key(name);
        if let Some(e) = self.items.get_mut(&k) {
            e.1 = value;
            return;
        }
        let pos = (str_case_hash(name) % self.buckets, self.seq);
        self.seq += 1;
        self.order.insert(pos, k.clone());
        self.items.insert(k, (pos, value));
    }

    /// Get the entry for `name`, creating it with `f` when absent.  Returns
    /// the entry and whether it was created.
    pub fn get_or_insert_with(&mut self, name: &[u8], f: impl FnOnce() -> T) -> (&mut T, bool) {
        let created = !self.contains(name);
        if created {
            self.insert(name, f());
        }
        (self.get_mut(name).unwrap(), created)
    }

    pub fn remove(&mut self, name: &[u8]) -> Option<T> {
        let (pos, v) = self.items.remove(&Self::key(name))?;
        self.order.remove(&pos);
        Some(v)
    }

    /// Remove every entry for which `f` returns true.
    pub fn retain(&mut self, mut f: impl FnMut(&mut T) -> bool) {
        let mut gone = Vec::new();
        for (k, (pos, v)) in self.items.iter_mut() {
            if !f(v) {
                gone.push((k.clone(), *pos));
            }
        }
        for (k, pos) in gone {
            self.items.remove(&k);
            self.order.remove(&pos);
        }
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.order.values().map(move |k| &self.items[k].1)
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        let order: Vec<Vec<u8>> = self.order.values().cloned().collect();
        let mut refs: HashMap<&Vec<u8>, &mut T> =
            self.items.iter_mut().map(|(k, (_, v))| (k, v)).collect();
        let mut out = Vec::with_capacity(order.len());
        for k in &order {
            if let Some(v) = refs.remove(k) {
                out.push(v);
            }
        }
        out.into_iter()
    }

    pub fn clear(&mut self) {
        self.order.clear();
        self.items.clear();
    }
}

/// `strsep`-style split: the part of `s` before the first of the bytes in
/// `delims`.
pub fn first_token<'a>(s: &'a [u8], delims: &[u8]) -> &'a [u8] {
    match s.iter().position(|c| delims.contains(c)) {
        Some(i) => &s[..i],
        None => s,
    }
}

/// C `%u` scanf semantics: optional leading whitespace and sign, then
/// digits; the value wraps like an unsigned int.  Returns None when no
/// digits were found.
pub fn scan_u32(s: &[u8]) -> Option<i64> {
    let start = s.iter().position(|&c| !dpma_ast::dpma_bytes::c::is_space(c)).unwrap_or(s.len());
    let t = &s[start..];
    let (neg, digits) = match t.first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let end = digits.iter().position(|c| !c.is_ascii_digit()).unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    let v = std::str::from_utf8(&digits[..end]).ok()?.parse::<u64>().unwrap_or(u64::MAX) as u32;
    let v = if neg { v.wrapping_neg() } else { v };
    Some(i64::from(v as i32))
}

/// C `%d` scanf semantics (see `scan_u32`).
pub fn scan_i32(s: &[u8]) -> Option<i64> {
    scan_u32(s)
}

/// Copy at most `max - 1` bytes (C `ast_copy_string` into a `max` byte
/// buffer).  As in C, the cut can fall inside a multi-byte character.
pub fn truncate(s: &[u8], max: usize) -> Vec<u8> {
    let s = dpma_ast::dpma_bytes::c_view(s);
    s[..s.len().min(max.saturating_sub(1))].to_vec()
}

/// A file system path from the bytes of a C string.
pub fn path(s: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(dpma_ast::dpma_bytes::c_view(s)))
}

/// `str::parse` on the bytes of a (test or CLI) argument; Err when they
/// are not UTF-8 or do not parse.
pub fn parse<T: std::str::FromStr>(s: &[u8]) -> Result<T, ()> {
    std::str::from_utf8(s).map_err(|_| ())?.parse().map_err(|_| ())
}
