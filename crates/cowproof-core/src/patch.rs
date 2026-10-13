/// A parsed delta from a unified diff patch.
#[derive(Clone, Debug)]
pub struct PatchDelta {
    pub path: String,
    pub added: Vec<(usize, String)>,
    pub removed: Vec<(usize, String)>,
    /// Unchanged lines shown in hunks, consulted by `requires`.
    pub context: Vec<String>,
    /// The mode git printed on a `new file mode` header (`100644`, `120000` for a symlink,
    /// ...): `Some` only when the patch creates the file. A rename, a copy, a mode change
    /// and an edit carry no such header.
    pub new_file_mode: Option<String>,
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
                new_file_mode: None,
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
            // Extended header lines sit between `diff --git` and the first hunk (a binary
            // patch's data lines contain no spaces, so none can pass for one).
            if let Some(mode) = line.strip_prefix("new file mode ") {
                d.new_file_mode = Some(mode.trim().to_string());
            }
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

    #[test]
    fn new_file_mode_is_read_from_the_header_only() {
        let patch = "diff --git a/new.md b/new.md\nnew file mode 100644\nindex 0000000..e69de29\n--- /dev/null\n+++ b/new.md\n@@ -0,0 +1,2 @@\n+new file mode 120000\n+x\n\
diff --git a/link b/link\nnew file mode 120000\nindex 0000000..e69de29\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+target\n\
diff --git a/old.md b/old.md\nindex 1111111..2222222 100644\n--- a/old.md\n+++ b/old.md\n@@ -1 +1 @@\n-a\n+b\n\
diff --git a/gone.md b/gone.md\ndeleted file mode 100644\nindex 1111111..0000000\n--- a/gone.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n";
        let modes: Vec<(String, Option<String>)> = parse_patch(patch)
            .into_iter()
            .map(|d| (d.path, d.new_file_mode))
            .collect();
        assert_eq!(
            modes,
            vec![
                ("new.md".to_string(), Some("100644".to_string())),
                ("link".to_string(), Some("120000".to_string())),
                ("old.md".to_string(), None),
                ("gone.md".to_string(), None),
            ]
        );
    }
}
