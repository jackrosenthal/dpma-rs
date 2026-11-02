//! Check reporting: one line per check (`ok   NAME` or `FAIL NAME` with
//! an indented detail), counted for the summary.

use std::fmt::{Debug, Display};

use anyhow::{bail, Result};
use bstr::BStr;
use regex::bytes::RegexBuilder;

/// Collects the outcome of checks and prints one line per check.
///
/// ```
/// use dpma_tests::harness::Checker;
/// let mut c = Checker::quiet();
/// c.same("two", 1 + 1, 2);
/// c.contains("greeting", b"hello world", &["world"]);
/// assert!(c.passed());
/// ```
#[derive(Debug)]
pub struct Checker {
    checks: usize,
    failures: Vec<String>,
    verbose: bool,
    print: bool,
    prefix: String,
}

impl Default for Checker {
    fn default() -> Self {
        Checker::new()
    }
}

/// Indents every line of `detail` after the first by five spaces.
fn indent(detail: &str) -> String {
    detail.replace('\n', "\n     ")
}

impl Checker {
    /// A checker that prints to standard output.
    pub fn new() -> Checker {
        Checker {
            checks: 0,
            failures: Vec::new(),
            verbose: false,
            print: true,
            prefix: String::new(),
        }
    }

    /// A checker that prints nothing (for unit tests).
    pub fn quiet() -> Checker {
        Checker {
            print: false,
            ..Checker::new()
        }
    }

    /// Also print the details of passing checks.
    pub fn verbose(mut self, yes: bool) -> Self {
        self.verbose = yes;
        self
    }

    /// Whether details of passing checks are printed.
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Prefixes every following check name with `prefix` (and `": "`);
    /// an empty prefix removes it.
    pub fn set_prefix(&mut self, prefix: &str) {
        self.prefix = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}: ")
        };
    }

    /// Records a check; `detail` is printed when it fails.  Returns `ok`.
    pub fn check(&mut self, name: impl AsRef<str>, ok: bool, detail: impl Display) -> bool {
        let name = format!("{}{}", self.prefix, name.as_ref());
        self.checks += 1;
        let detail = detail.to_string();
        if ok {
            self.out(&format!("ok   {name}"));
            if self.verbose && !detail.is_empty() {
                self.out(&format!("     {}", indent(&detail)));
            }
        } else {
            if detail.is_empty() {
                self.out(&format!("FAIL {name}"));
            } else {
                self.out(&format!("FAIL {name}\n     {}", indent(&detail)));
            }
            self.failures.push(name);
        }
        ok
    }

    /// [`Checker::check`] with a detail that is computed only when needed.
    pub fn check_with(
        &mut self,
        name: impl AsRef<str>,
        ok: bool,
        detail: impl FnOnce() -> String,
    ) -> bool {
        let d = if ok && !self.verbose {
            String::new()
        } else {
            detail()
        };
        self.check(name, ok, d)
    }

    /// Checks that `got == want`.
    pub fn same<T: PartialEq + Debug>(&mut self, name: impl AsRef<str>, got: T, want: T) -> bool {
        let ok = got == want;
        self.check_with(name, ok, || format!("got:  {got:?}\nwant: {want:?}"))
    }

    /// Checks that two byte strings are equal (shown as escaped text).
    pub fn same_bytes(
        &mut self,
        name: impl AsRef<str>,
        got: impl AsRef<[u8]>,
        want: impl AsRef<[u8]>,
    ) -> bool {
        let (g, w) = (got.as_ref(), want.as_ref());
        self.check_with(name, g == w, || {
            format!("got:  {:?}\nwant: {:?}", BStr::new(g), BStr::new(w))
        })
    }

    /// Checks that `haystack` contains every one of `needles`.
    pub fn contains<N: AsRef<[u8]>>(
        &mut self,
        name: impl AsRef<str>,
        haystack: impl AsRef<[u8]>,
        needles: &[N],
    ) -> bool {
        let h = haystack.as_ref();
        let missing: Vec<&BStr> = needles
            .iter()
            .map(|n| BStr::new(n.as_ref()))
            .filter(|n| !contains_bytes(h, n))
            .collect();
        self.check_with(name, missing.is_empty(), || {
            format!(
                "missing {missing:?}\nin {:?}",
                BStr::new(&h[..h.len().min(3000)])
            )
        })
    }

    /// Checks that `haystack` contains none of `needles`.
    pub fn lacks<N: AsRef<[u8]>>(
        &mut self,
        name: impl AsRef<str>,
        haystack: impl AsRef<[u8]>,
        needles: &[N],
    ) -> bool {
        let h = haystack.as_ref();
        let present: Vec<&BStr> = needles
            .iter()
            .map(|n| BStr::new(n.as_ref()))
            .filter(|n| contains_bytes(h, n))
            .collect();
        self.check_with(name, present.is_empty(), || {
            format!(
                "present {present:?}\nin {:?}",
                BStr::new(&h[..h.len().min(3000)])
            )
        })
    }

    /// Checks that `pattern` (a regular expression; `.` matches line
    /// breaks) matches somewhere in `haystack`.
    pub fn matches(
        &mut self,
        name: impl AsRef<str>,
        haystack: impl AsRef<[u8]>,
        pattern: &str,
    ) -> bool {
        let h = haystack.as_ref();
        let ok = regex_search(pattern, h);
        self.check_with(name, ok, || {
            format!(
                "{:?} does not match {pattern:?}",
                BStr::new(&h[..h.len().min(3000)])
            )
        })
    }

    /// Records a check and fails the caller (`Err`) when it does not pass:
    /// for preconditions the rest of a test part needs.
    pub fn require(&mut self, name: impl AsRef<str>, ok: bool, detail: impl Display) -> Result<()> {
        let name = name.as_ref().to_string();
        if self.check(&name, ok, detail) {
            Ok(())
        } else {
            bail!("required check failed: {name}")
        }
    }

    /// Records a failure that is not a check (an error that ended a test
    /// part).
    pub fn fail(&mut self, name: impl AsRef<str>, detail: impl Display) {
        self.check(name, false, detail);
    }

    /// Prints a note (indented, not counted).
    pub fn note(&self, text: impl Display) {
        self.out(&format!("     {}", indent(&text.to_string())));
    }

    /// Prints a skipped check (not counted).
    pub fn skip(&self, name: impl AsRef<str>, why: impl Display) {
        self.out(&format!("skip {}{} ({why})", self.prefix, name.as_ref()));
    }

    /// Prints a line as is.
    pub fn say(&self, text: impl Display) {
        self.out(&text.to_string());
    }

    fn out(&self, text: &str) {
        if self.print {
            println!("{text}");
        }
    }

    /// The number of checks.
    pub fn count(&self) -> usize {
        self.checks
    }

    /// The names of the failed checks.
    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    /// Whether every check passed.
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// `"N checks, M failed"` and the failed names, one per line.
    pub fn summary(&self) -> String {
        let mut s = format!("{} checks, {} failed", self.checks, self.failures.len());
        for f in &self.failures {
            s.push_str("\n  ");
            s.push_str(f);
        }
        s
    }

    /// Adds the counts of another checker.
    pub fn absorb(&mut self, other: Checker) {
        self.checks += other.checks;
        self.failures.extend(other.failures);
    }
}

/// Whether `needle` occurs in `haystack`.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether the regular expression `pattern` matches somewhere in `text`
/// (`.` matches line breaks, as Python's `re.S`); an invalid pattern
/// matches nothing.
pub fn regex_search(pattern: &str, text: &[u8]) -> bool {
    RegexBuilder::new(pattern)
        .dot_matches_new_line(true)
        .build()
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

/// The first capture group (or the whole match) of `pattern` in `text`.
pub fn regex_capture(pattern: &str, text: &[u8]) -> Option<Vec<u8>> {
    let re = RegexBuilder::new(pattern)
        .dot_matches_new_line(true)
        .build()
        .ok()?;
    let c = re.captures(text)?;
    Some(c.get(1).or_else(|| c.get(0))?.as_bytes().to_vec())
}
