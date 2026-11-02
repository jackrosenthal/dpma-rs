//! Line diffs for check details: [`unified`] shows how a transcript or a
//! captured output differs from the expected one, as `diff -u`
//! would.

/// A unified diff of `old` and `new` (split into lines; a missing final
/// line break is ignored), with `context` lines around each change;
/// empty when they are equal.
///
/// ```
/// let d = dpma_tests::diff::unified("a\nb\nc\n", "a\nB\nc\n", "expected", "got", 1);
/// assert_eq!(d, "--- expected\n+++ got\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n");
/// ```
pub fn unified(old: &str, new: &str, old_name: &str, new_name: &str, context: usize) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let ops = edit_script(&a, &b);
    if ops.iter().all(|o| matches!(o, Op::Same(..))) {
        return String::new();
    }
    let mut out = format!("--- {old_name}\n+++ {new_name}\n");
    // Group the operations into hunks: changes and up to `context`
    // unchanged lines around them (hunks closer than 2 * context merge).
    let changed: Vec<usize> = (0..ops.len())
        .filter(|&i| !matches!(ops[i], Op::Same(..)))
        .collect();
    let mut i = 0;
    while i < changed.len() {
        let start = changed[i].saturating_sub(context);
        let mut end = changed[i];
        while i + 1 < changed.len() && changed[i + 1] <= end + 2 * context + 1 {
            i += 1;
            end = changed[i];
        }
        let end = (end + context + 1).min(ops.len());
        let (mut a0, mut b0) = (None, None);
        let (mut na, mut nb) = (0, 0);
        let mut body = String::new();
        for op in &ops[start..end] {
            match *op {
                Op::Same(x, y) => {
                    a0.get_or_insert(x);
                    b0.get_or_insert(y);
                    na += 1;
                    nb += 1;
                    body.push_str(&format!(" {}\n", a[x]));
                }
                Op::Del(x, y) => {
                    a0.get_or_insert(x);
                    b0.get_or_insert(y);
                    na += 1;
                    body.push_str(&format!("-{}\n", a[x]));
                }
                Op::Ins(x, y) => {
                    a0.get_or_insert(x);
                    b0.get_or_insert(y);
                    nb += 1;
                    body.push_str(&format!("+{}\n", b[y]));
                }
            }
        }
        // Line numbers count from 1; an empty range names the line before.
        let range = |first: Option<usize>, n: usize| {
            let first = first.unwrap_or(0);
            if n == 0 {
                format!("{first},0")
            } else if n == 1 {
                format!("{}", first + 1)
            } else {
                format!("{},{n}", first + 1)
            }
        };
        out.push_str(&format!("@@ -{} +{} @@\n", range(a0, na), range(b0, nb)));
        out.push_str(&body);
        i += 1;
    }
    out
}

/// One step of an edit script, with the positions in both sequences
/// where it applies.
#[derive(Clone, Copy, Debug)]
enum Op {
    Same(usize, usize),
    Del(usize, usize),
    Ins(usize, usize),
}

/// The shortest edit script from `a` to `b` by longest common
/// subsequence (quadratic, which suits transcripts of a few thousand
/// lines).
fn edit_script(a: &[&str], b: &[&str]) -> Vec<Op> {
    // Common prefix and suffix first: most outputs differ in a few lines.
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ma, mb) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let (n, m) = (ma.len(), mb.len());
    // lcs[i][j]: the LCS length of ma[i..] and mb[j..].
    let mut lcs = vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[at(i, j)] = if ma[i] == mb[j] {
                lcs[at(i + 1, j + 1)] + 1
            } else {
                lcs[at(i + 1, j)].max(lcs[at(i, j + 1)])
            };
        }
    }
    let mut ops: Vec<Op> = (0..pre).map(|k| Op::Same(k, k)).collect();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && ma[i] == mb[j] {
            ops.push(Op::Same(pre + i, pre + j));
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[at(i, j + 1)] > lcs[at(i + 1, j)]) {
            ops.push(Op::Ins(pre + i, pre + j));
            j += 1;
        } else {
            ops.push(Op::Del(pre + i, pre + j));
            i += 1;
        }
    }
    ops.extend((0..suf).map(|k| Op::Same(a.len() - suf + k, b.len() - suf + k)));
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_texts_have_no_diff() {
        assert_eq!(unified("a\nb\n", "a\nb", "x", "y", 3), "");
    }

    #[test]
    fn hunks_and_ranges() {
        let old: String = (1..=20).map(|i| format!("{i}\n")).collect();
        let new: String = (1..=21)
            .filter(|&i| i != 18)
            .map(|i| match i {
                3 => "three\n".to_string(),
                i => format!("{i}\n"),
            })
            .collect();
        let d = unified(&old, &new, "a", "b", 2);
        assert_eq!(
            d,
            "--- a\n+++ b\n@@ -1,5 +1,5 @@\n 1\n 2\n-3\n+three\n 4\n 5\n\
             @@ -16,5 +16,5 @@\n 16\n 17\n-18\n 19\n 20\n+21\n"
        );
        assert_eq!(
            unified("", "x\n", "a", "b", 3),
            "--- a\n+++ b\n@@ -0,0 +1 @@\n+x\n"
        );
        assert_eq!(
            unified("x\n", "", "a", "b", 3),
            "--- a\n+++ b\n@@ -1 +0,0 @@\n-x\n"
        );
    }
}
