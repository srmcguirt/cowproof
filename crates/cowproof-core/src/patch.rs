/// A parsed delta from a unified diff patch.
#[derive(Clone, Debug)]
pub struct PatchDelta {
    pub path: String,
    pub added: Vec<(usize, String)>,
    pub removed: Vec<(usize, String)>,
    /// Unchanged lines shown in hunks, consulted by `requires`.
    pub context: Vec<String>,
}

/// Parse a unified diff patch into deltas per file.
pub fn parse_patch(patch: &str) -> Vec<PatchDelta> {
    let mut out: Vec<PatchDelta> = Vec::new();
    let mut new_line = 1usize;
    // `---`/`+++` are file headers only before the first hunk. Inside a hunk
    // an added line such as `++ x` renders as `+++ x` and must still count.
    let mut in_hunk = false;
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            in_hunk = false;
            let path = rest
                .split_once(" b/")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            out.push(PatchDelta {
                path,
                added: Vec::new(),
                removed: Vec::new(),
                context: Vec::new(),
            });
            new_line = 1;
            continue;
        }
        let Some(d) = out.last_mut() else {
            continue;
        };
        if line.starts_with('\\') {
            continue;
        }
        if !in_hunk && !line.starts_with("@@") {
            continue;
        }
        if line.starts_with("@@") {
            in_hunk = true;
            if let Some((_, rest)) = line.split_once('+') {
                new_line = rest
                    .split([',', ' '])
                    .next()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(1);
            }
            continue;
        }
        if let Some(s) = line.strip_prefix('+') {
            d.added.push((new_line, s.to_string()));
            new_line += 1;
        } else if let Some(s) = line.strip_prefix('-') {
            d.removed.push((0, s.to_string()));
        } else if let Some(s) = line.strip_prefix(' ') {
            d.context.push(s.to_string());
            new_line += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_line_in_second_hunk_has_correct_line_number() {
        let patch = r#"diff --git a/file.rs b/file.rs
--- a/file.rs
+++ b/file.rs
@@ -1,3 +1,4 @@
 line 1
 line 2
+added line 1
 line 3
@@ -10,2 +11,3 @@ line 10
 line 10
+added line 2
 line 11"#;
        let deltas = parse_patch(patch);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].path, "file.rs");
        // First hunk: line added at position 3
        // Second hunk: line added at position 12 (10 context + 1 from first hunk + 1 = 12)
        let added_lines: Vec<_> = deltas[0].added.iter().map(|(line, _)| *line).collect();
        assert_eq!(added_lines, vec![3, 12]);
    }
}
