//! Small helpers shared across the module.

use std::collections::{BTreeMap, HashMap};

/// Asterisk's `ast_str_case_hash`: djb2 over the lower-cased bytes, masked
/// to a non-negative value.
pub fn str_case_hash(s: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in s.bytes() {
        h = h.wrapping_mul(33) ^ u32::from(b.to_ascii_lowercase());
    }
    h & 0x7fff_ffff
}

/// A map keyed by case-insensitive name that iterates in the same order as
/// an ao2 hash container with `buckets` buckets (bucket order, then
/// insertion order within a bucket), so CLI listings come out in the same
/// order as the original module's.
#[derive(Debug, Clone)]
pub struct NamedMap<T> {
    buckets: u32,
    seq: u64,
    order: BTreeMap<(u32, u64), String>,
    items: HashMap<String, ((u32, u64), T)>,
}

impl<T> NamedMap<T> {
    pub fn new(buckets: u32) -> Self {
        NamedMap { buckets, seq: 0, order: BTreeMap::new(), items: HashMap::new() }
    }

    fn key(name: &str) -> String {
        name.to_ascii_lowercase()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.items.contains_key(&Self::key(name))
    }

    pub fn get(&self, name: &str) -> Option<&T> {
        self.items.get(&Self::key(name)).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut T> {
        self.items.get_mut(&Self::key(name)).map(|(_, v)| v)
    }

    /// Insert `value` under `name`, replacing (in place) any existing entry.
    pub fn insert(&mut self, name: &str, value: T) {
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
    pub fn get_or_insert_with(&mut self, name: &str, f: impl FnOnce() -> T) -> (&mut T, bool) {
        let created = !self.contains(name);
        if created {
            self.insert(name, f());
        }
        (self.get_mut(name).unwrap(), created)
    }

    pub fn remove(&mut self, name: &str) -> Option<T> {
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
        let order: Vec<String> = self.order.values().cloned().collect();
        let mut refs: HashMap<&String, &mut T> =
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

/// `strsep`-style split on any of the characters in `delims`.
pub fn first_token<'a>(s: &'a str, delims: &[char]) -> &'a str {
    match s.find(|c| delims.contains(&c)) {
        Some(i) => &s[..i],
        None => s,
    }
}

/// C `%u` scanf semantics: optional leading whitespace and sign, then
/// digits; the value wraps like an unsigned int.  Returns None when no
/// digits were found.
pub fn scan_u32(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let end = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    let v = digits[..end].parse::<u64>().unwrap_or(u64::MAX) as u32;
    let v = if neg { v.wrapping_neg() } else { v };
    Some(i64::from(v as i32))
}

/// C `%d` scanf semantics (see `scan_u32`).
pub fn scan_i32(s: &str) -> Option<i64> {
    scan_u32(s)
}

/// Copy at most `max - 1` bytes (C `ast_copy_string` into a `max` byte
/// buffer), never splitting a UTF-8 character.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() < max {
        return s.to_string();
    }
    let mut end = max - 1;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}
