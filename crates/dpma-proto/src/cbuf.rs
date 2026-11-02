//! A NUL-terminated byte buffer for porting C string code that writes NULs
//! into its input and hands out pointers into it (strsep-style parsers).
//!
//! Positions stand in for `char *`; [`EMPTY`] stands for a pointer to a
//! static empty string.  Results are read with [`CBuf::get`] after all
//! writes, exactly as the C callers read them after the call returns.

/// A "pointer" to a static `""`.
pub(crate) const EMPTY: usize = usize::MAX;

pub(crate) struct CBuf {
    b: Vec<u8>,
}

impl CBuf {
    /// Copy `s` up to its first NUL and terminate it.
    pub fn new(s: &[u8]) -> CBuf {
        let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        let mut b = Vec::with_capacity(n + 1);
        b.extend_from_slice(&s[..n]);
        b.push(0);
        CBuf { b }
    }

    /// The byte at `i` (0 past the end and for [`EMPTY`]).
    pub fn at(&self, i: usize) -> u8 {
        self.b.get(i).copied().unwrap_or(0)
    }

    pub fn set(&mut self, i: usize, c: u8) {
        if let Some(p) = self.b.get_mut(i) {
            *p = c;
        }
    }

    /// Position of the NUL ending the string at `i`.
    pub fn end(&self, i: usize) -> usize {
        if i == EMPTY {
            return EMPTY;
        }
        let mut j = i;
        while self.at(j) != 0 {
            j += 1;
        }
        j
    }

    pub fn strlen(&self, i: usize) -> usize {
        if i == EMPTY {
            0
        } else {
            self.end(i) - i
        }
    }

    /// `strchr(s + i, c)` for `c != 0`.
    pub fn strchr(&self, i: usize, c: u8) -> Option<usize> {
        if i == EMPTY {
            return None;
        }
        let mut j = i;
        loop {
            match self.at(j) {
                0 => return None,
                x if x == c => return Some(j),
                _ => j += 1,
            }
        }
    }

    /// `strrchr(s + i, c)` for `c != 0`.
    pub fn strrchr(&self, i: usize, c: u8) -> Option<usize> {
        if i == EMPTY {
            return None;
        }
        (i..self.end(i)).rev().find(|&j| self.b[j] == c)
    }

    /// The C string at `i`.
    pub fn bytes(&self, i: usize) -> &[u8] {
        if i == EMPTY {
            return b"";
        }
        &self.b[i..self.end(i)]
    }

    /// A copy of the C string at `i`.
    pub fn get(&self, i: usize) -> Vec<u8> {
        self.bytes(i).to_vec()
    }

    /// `strcmp(s + i, t) == 0`.
    pub fn eq(&self, i: usize, t: &[u8]) -> bool {
        self.bytes(i) == t
    }

    /// `strncmp(s + i, t, strlen(t)) == 0`.
    pub fn starts_with(&self, i: usize, t: &[u8]) -> bool {
        self.bytes(i).starts_with(t)
    }

    /// `strcpy(s + i, t)`; the buffer grows if needed (the C callers
    /// guarantee room).
    pub fn strcpy(&mut self, i: usize, t: &[u8]) {
        let need = i + t.len() + 1;
        if self.b.len() < need {
            self.b.resize(need, 0);
        }
        self.b[i..i + t.len()].copy_from_slice(t);
        self.b[i + t.len()] = 0;
    }
}

/// `strcasecmp(a, b) == 0` in the C locale.
pub(crate) fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `strcasestr(hay, needle) != NULL` in the C locale.
pub(crate) fn contains_ignore_case(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// The bytes of a C string: everything before the first NUL.
pub(crate) fn c_bytes(s: &[u8]) -> &[u8] {
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    &s[..n]
}
