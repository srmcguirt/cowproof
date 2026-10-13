//! Local paths in a lane-written `yarn.lock` or `pnpm-lock.yaml`.
//!
//! The lockfile is lane-written and the install that reads it has registry network and the
//! host's files. A local resolution (`file:`, `link:`, `portal:`, a pnpm `directory`) with an
//! absolute path or a `..` component copies or links a host file into the cache entry, and a
//! Yarn Berry `exec:` runs a Node script at fetch time. [`yarn_local_path`] and
//! [`pnpm_local_path`] name the first such entry; the fetch is then `not_fetched`.
//!
//! `package-lock.json` and `npm-shrinkwrap.json` are read as JSON ([`npm_local_path`]) for the
//! same entries: a `packages` key or `resolved` that leaves the tree, a `"link": true` entry
//! whose target does, and lockfile v1's `dependencies` `version` and `resolved`.
//!
//! The yarn and pnpm readers are line-based, like the other lockfile readers, and only look at the fields
//! that can carry a path: yarn's descriptors (the header lines) and its `resolved` or
//! `resolution` line, pnpm's keys and the values of `specifier`, `version`, `directory`,
//! `tarball` and `resolution`. Anything in those fields the reader does not understand (a
//! block scalar, an alias, an escape in a double-quoted string, an unbalanced flow map, an
//! empty path) counts as an offending entry: it fails closed.
//!
//! Relative paths inside the tree (`./packages/a`, `link:packages/a`) stay allowed; a Berry
//! `exec:` is refused whatever its path, because it runs code.

/// Whether `path` leaves the tree or cannot be told to stay in it: empty, absolute (`/x`,
/// `\x`, `C:\x`, `~/x`, `//host/x`), percent-encoded, or holding a `..` component.
fn escapes_tree(path: &str) -> bool {
    let p = path.trim();
    let b = p.as_bytes();
    let Some(&first) = b.first() else {
        return true;
    };
    if matches!(first, b'/' | b'\\' | b'~') || p.contains('%') {
        return true;
    }
    if b.len() >= 2 && first.is_ascii_alphabetic() && b[1] == b':' {
        return true;
    }
    p.split(['/', '\\']).any(|c| c == "..")
}

/// The part of a local-path range that is the path: before the `::` parameters (Berry) and
/// the `#` fragment (a classic `file:` hash).
fn path_of(rest: &str) -> &str {
    let rest = rest.split("::").next().unwrap_or("");
    rest.split('#').next().unwrap_or("")
}

/// `text` with its `%XX` escapes decoded; `None` for a bad escape or bytes that are not UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A descriptor or locator `name@range` split at the `@` that ends the name (a scoped name
/// starts with one). `None` when there is no range.
fn split_descriptor(d: &str) -> Option<(&str, &str)> {
    let from = usize::from(d.starts_with('@'));
    let at = d.get(from..)?.find('@')? + from;
    Some((&d[..at], &d[at + 1..]))
}

/// Whether the descriptor `name@range` is a local path that leaves the tree, or runs code.
fn descriptor_is_local(d: &str) -> bool {
    split_descriptor(d).is_some_and(|(_, range)| range_is_local(range, true))
}

/// Whether a range (the part after the `@`, or a classic `resolved` value) is `exec:`, a
/// `file:`, `link:` or `portal:` path that leaves the tree, a `patch:` whose source or patch
/// path does, or (with `bare`) a bare path such as `../x` or `/x` that the tool reads as `file:`.
fn range_is_local(range: &str, bare: bool) -> bool {
    let r = range.trim();
    let Some((proto, rest)) = r.split_once(':') else {
        return bare && bare_path(r) && escapes_tree(r);
    };
    match proto.to_ascii_lowercase().as_str() {
        "file" | "link" | "portal" => escapes_tree(path_of(rest)),
        "exec" => true,
        "patch" => patch_is_local(rest),
        p if p.len() == 1 && p.as_bytes()[0].is_ascii_alphabetic() => rest.starts_with(['/', '\\']),
        _ => bare && bare_path(r) && escapes_tree(r),
    }
}

/// Whether `r` is spelled like a path and not like a semver range.
fn bare_path(r: &str) -> bool {
    r == "."
        || r == ".."
        || r.starts_with(['/', '\\'])
        || r.starts_with("./")
        || r.starts_with("../")
        || r.starts_with(".\\")
        || r.starts_with("..\\")
        || r.starts_with("~/")
        || r.starts_with("~\\")
}

/// A Berry `patch:` range: `<percent-encoded source descriptor>#<patch path>[&<path>]::<params>`.
fn patch_is_local(rest: &str) -> bool {
    let body = rest.split("::").next().unwrap_or("");
    let Some((source, paths)) = body.split_once('#') else {
        return true;
    };
    let Some(source) = percent_decode(source) else {
        return true;
    };
    if split_descriptor(&source).is_none() || descriptor_is_local(&source) {
        return true;
    }
    paths.split('&').any(patch_path_is_local)
}

/// One patch path of a `patch:` range: a path in the tree, or Berry's own `builtin<...>`.
fn patch_path_is_local(path: &str) -> bool {
    let p = path.strip_prefix("optional!").unwrap_or(path);
    let builtin = p.strip_prefix('~').unwrap_or(p);
    if let Some(name) = builtin
        .strip_prefix("builtin<")
        .and_then(|n| n.strip_suffix('>'))
    {
        return name.is_empty() || name.contains("..") || name.contains(['\\', '<', '>']);
    }
    escapes_tree(p)
}

/// The value of a one-line YAML scalar: unquoted, comment cut. `None` for a form the reader
/// does not understand (empty, a block scalar, an alias, an anchor, a tag, a flow collection,
/// an unterminated quote, a backslash in a double-quoted string).
fn scalar(value: &str) -> Option<String> {
    let v = value.trim();
    let first = v.chars().next()?;
    if matches!(
        first,
        '|' | '>' | '&' | '*' | '!' | '{' | '[' | '%' | '@' | '`'
    ) {
        return None;
    }
    if first == '"' || first == '\'' {
        let inner = v.get(1..)?.strip_suffix(first)?;
        if first == '"' && inner.contains('\\') {
            return None;
        }
        if inner.contains(first) && first == '"' {
            return None;
        }
        return Some(inner.replace("''", "'"));
    }
    Some(v.split(" #").next().unwrap_or(v).trim_end().to_string())
}

/// The first entry of a `yarn.lock` (classic or Berry) that names a local path outside the
/// tree or code to run, as the trimmed line.
pub(crate) fn yarn_local_path(text: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        let bad = if indented {
            yarn_field_is_local(t)
        } else {
            yarn_header_is_local(t)
        };
        if bad {
            return Some(t.to_string());
        }
    }
    None
}

/// A header line: the descriptors one entry answers to. Classic quotes each (`"a@^1", b@^2:`),
/// Berry quotes the list (`"a@npm:^1, b@npm:^2":`); the quotes come off and the commas split.
fn yarn_header_is_local(t: &str) -> bool {
    if t.contains('\\') {
        return true;
    }
    let list = t.trim_end().trim_end_matches(':').replace(['"', '\''], "");
    list.split(',').any(|spec| descriptor_is_local(spec.trim()))
}

/// An indented line: only classic `resolved "<range>"` and Berry `resolution: "<descriptor>"`.
fn yarn_field_is_local(t: &str) -> bool {
    let u = t.trim_start_matches(['"', '\'']);
    for key in ["resolved", "resolution"] {
        let Some(rest) = u.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start_matches(['"', '\'']);
        if !rest.starts_with([':', ' ', '\t']) {
            continue;
        }
        let Some(value) = scalar(rest.trim_start().trim_start_matches(':')) else {
            return true;
        };
        return if key == "resolved" {
            range_is_local(&value, true)
        } else {
            descriptor_is_local(&value) || range_is_local(&value, false)
        };
    }
    false
}

/// The first entry of a `pnpm-lock.yaml` that names a local path outside the tree, as the
/// trimmed line.
pub(crate) fn pnpm_local_path(text: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let t = t.strip_prefix("- ").unwrap_or(t).trim_start();
        if pnpm_line_is_local(t) {
            return Some(t.to_string());
        }
    }
    None
}

/// A line cut into the key and the value of a `key: value` pair. A quoted key may hold colons
/// (`'foo@file:../x':`); an unquoted one ends at the first `: ` or at a trailing colon.
fn key_value(t: &str) -> (Option<String>, &str) {
    if let Some(q) = t.chars().next().filter(|c| matches!(c, '"' | '\'')) {
        if let Some(end) = t.get(1..).and_then(|r| r.find(q)) {
            let after = t[end + 2..].trim_start();
            if let Some(value) = after.strip_prefix(':') {
                return (Some(t[1..=end].to_string()), value.trim());
            }
        }
        return (None, t);
    }
    if let Some(i) = t.find(": ") {
        return (Some(t[..i].to_string()), t[i + 2..].trim());
    }
    if let Some(key) = t.strip_suffix(':') {
        return (Some(key.to_string()), "");
    }
    (None, t)
}

fn pnpm_line_is_local(t: &str) -> bool {
    let (key, value) = key_value(t);
    let Some(key) = key else {
        // A list item or bare scalar.
        return scalar(value).is_none_or(|v| range_is_local(&v, false));
    };
    // A package or snapshot key (`foo@file:../x(react@18)`, `/foo@link:../x`).
    let package = key.trim_start_matches('/');
    let package = package.split('(').next().unwrap_or(package);
    if descriptor_is_local(package) {
        return true;
    }
    let name = key.trim().trim_matches(['"', '\'']);
    match name {
        "resolution" if value.is_empty() => false,
        "resolution" => resolution_is_local(value),
        "directory" => scalar(value).is_none_or(|v| escapes_tree(&v)),
        "tarball" => scalar(value).is_none_or(|v| range_is_local(&v, false)),
        "specifier" => scalar(value).is_none_or(|v| range_is_local(&v, true)),
        "version" => {
            scalar(value).is_none_or(|v| range_is_local(v.split('(').next().unwrap_or(&v), false))
        }
        _ if value.is_empty() => false,
        _ if value.starts_with(['{', '[']) => flow_is_local(value),
        _ => scalar(value).is_some_and(|v| range_is_local(&v, false)),
    }
}

/// The items of a one-line flow mapping or sequence (`{a: b, c: [d]}`), flattened: nested
/// brackets and quotes become separators, so no item hides inside another. `None` when the
/// value is not enclosed on this line (a flow that continues on the next line).
fn flow_items(value: &str) -> Option<Vec<String>> {
    let v = value.trim();
    let (open, close) = if v.starts_with('{') {
        ('{', '}')
    } else {
        ('[', ']')
    };
    let inner = v.strip_prefix(open)?.trim_end().strip_suffix(close)?;
    Some(
        inner
            .replace(['"', '\'', '{', '}', '[', ']'], ",")
            .split(',')
            .map(|i| i.trim().to_string())
            .filter(|i| !i.is_empty())
            .collect(),
    )
}

/// A `resolution: {directory: ../x, type: directory}` or `{tarball: file:../x.tgz}` flow
/// mapping: every item is `key: value`, and a `directory` is a path.
fn resolution_is_local(value: &str) -> bool {
    let Some(items) = flow_items(value) else {
        return true;
    };
    items.iter().any(|item| {
        let Some((k, v)) = item.split_once(':') else {
            return true;
        };
        match k.trim() {
            "directory" => escapes_tree(v),
            _ => range_is_local(v, false),
        }
    })
}

/// Any other flow collection on a line: an item that is a local range.
fn flow_is_local(value: &str) -> bool {
    let Some(items) = flow_items(value) else {
        return true;
    };
    items.iter().any(|item| {
        let v = item.split_once(':').map_or(item.as_str(), |(_, v)| v);
        range_is_local(v, false)
    })
}

/// The first entry of an npm lockfile (`package-lock.json`, `npm-shrinkwrap.json`) that names a
/// local path outside the tree, as its key: a `packages` key (the `node_modules/...` path) that
/// leaves the tree, a `packages` entry whose `resolved` is a `file:` path that does, a
/// `"link": true` entry whose `resolved` does, and (lockfile v1, and the v1 copy that v2 keeps)
/// a `dependencies` entry whose `version` or `resolved` does. Workspace links inside the tree
/// (`"resolved": "packages/a", "link": true`) are allowed. `Err` for text that is not a JSON
/// object, so the caller fails closed: the JSON reader of this crate is stricter than npm's.
pub(crate) fn npm_local_path(text: &str) -> Result<Option<String>, String> {
    let doc: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("is not valid JSON: {e}"))?;
    let Some(root) = doc.as_object() else {
        return Err("is not a JSON object".to_string());
    };
    if let Some(packages) = root.get("packages") {
        let Some(map) = packages.as_object() else {
            return Ok(Some("packages".to_string()));
        };
        for (key, entry) in map {
            if (!key.is_empty() && escapes_tree(key)) || npm_entry_is_local(entry) {
                return Ok(Some(key.clone()));
            }
        }
    }
    Ok(root
        .get("dependencies")
        .and_then(|deps| npm_v1_local("dependencies", deps)))
}

/// Whether one lockfile entry resolves to a local path that leaves the tree, or is not an
/// entry this reader understands.
fn npm_entry_is_local(entry: &serde_json::Value) -> bool {
    use serde_json::Value;
    let Some(o) = entry.as_object() else {
        return true;
    };
    let link = match o.get("link") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return true,
    };
    match o.get("version") {
        Some(Value::String(v)) if range_is_local(v, false) => return true,
        _ => {}
    }
    match o.get("resolved") {
        None => link,
        Some(Value::String(r)) => {
            range_is_local(r, false) || (link && escapes_tree(r.strip_prefix("file:").unwrap_or(r)))
        }
        Some(_) => true,
    }
}

/// The v1 `dependencies` tree below `path`: the dotted key of the first entry that is local.
fn npm_v1_local(path: &str, deps: &serde_json::Value) -> Option<String> {
    let Some(map) = deps.as_object() else {
        return Some(path.to_string());
    };
    for (name, entry) in map {
        let here = format!("{path}.{name}");
        if npm_entry_is_local(entry) {
            return Some(here);
        }
        if let Some(nested) = entry.get("dependencies")
            && let Some(found) = npm_v1_local(&format!("{here}.dependencies"), nested)
        {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_tree_is_absolute_dotdot_encoded_or_empty() {
        for bad in [
            "",
            "/etc",
            "\\x",
            "C:\\x",
            "~/x",
            "//host/x",
            "../x",
            "a/../../x",
            "a\\..\\x",
            "..",
            "%2e%2e/x",
        ] {
            assert!(escapes_tree(bad), "{bad:?}");
        }
        for ok in [
            ".",
            "./x",
            "x",
            "packages/a",
            "a..b/c",
            "./.yarn/patches/a.patch",
        ] {
            assert!(!escapes_tree(ok), "{ok:?}");
        }
    }

    #[test]
    fn classic_yarn_lock_refuses_an_absolute_or_dotdot_file_and_link() {
        for bad in [
            "\"foo@file:../x\":\n  version \"1.0.0\"\n  resolved \"file:../x\"\n",
            "foo@^1.0.0:\n  version \"1.0.0\"\n  resolved \"file:/etc/passwd#abc\"\n",
            "foo@^1.0.0:\n  version \"1.0.0\"\n  resolved \"link:/home/u/x\"\n",
            "foo@^1.0.0:\n  version \"1.0.0\"\n  resolved \"link:./a/../../x\"\n",
            "\"foo@link:/abs\":\n  version \"1.0.0\"\n",
            "foo@^1.0.0, \"bar@file:..\":\n  version \"1.0.0\"\n",
            "\"@s/foo@file:../x\":\n  version \"1.0.0\"\n",
            "foo@^1.0.0:\n  resolved \"../x\"\n",
            "foo@^1.0.0:\n  resolved \"file:\\u002fetc\"\n",
            "foo@^1.0.0:\n  resolved \"file:\"\n",
            "foo@^1.0.0:\n  resolved >-\n",
        ] {
            assert!(yarn_local_path(bad).is_some(), "{bad:?}");
        }
        for ok in [
            "# yarn lockfile v1\n\n\nfoo@^1.0.0:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/foo/-/foo-1.0.0.tgz#abc\"\n  integrity sha512-x\n  dependencies:\n    bar \"^2\"\n",
            "\"@s/foo@^1.0.0\":\n  resolved \"https://registry.yarnpkg.com/@s/foo/-/foo-1.0.0.tgz\"\n",
            "foo@file:./vendor/foo:\n  version \"1.0.0\"\n  resolved \"file:./vendor/foo\"\n",
            "foo@link:packages/a:\n  version \"1.0.0\"\n",
            "foo@git+ssh://git@github.com/x/y.git#abc:\n  resolved \"git+ssh://git@github.com/x/y.git#abc\"\n",
        ] {
            assert_eq!(yarn_local_path(ok), None, "{ok:?}");
        }
    }

    #[test]
    fn berry_yarn_lock_refuses_portal_link_exec_file_and_patch_paths_that_leave_the_tree() {
        for bad in [
            "\"foo@portal:/abs::locator=app%40workspace%3A.\":\n  version: 0.0.0-use.local\n",
            "\"foo@npm:^1.0.0\":\n  resolution: \"foo@portal:../x::locator=app%40workspace%3A.\"\n",
            "\"foo@npm:^1.0.0\":\n  resolution: \"foo@link:/x::locator=app%40workspace%3A.\"\n",
            "\"foo@npm:^1.0.0\":\n  resolution: \"foo@file:../x.tgz#../x.tgz::hash=abc\"\n",
            "\"foo@npm:^1.0.0\":\n  resolution: \"foo@exec:./gen.js#./gen.js::hash=abc\"\n",
            "\"foo@exec:./gen.js\":\n  version: 1.0.0\n",
            "\"foo@npm:^1\":\n  resolution: \"foo@patch:foo@npm%3A1.0.0#../x.patch::version=1.0.0&hash=a\"\n",
            "\"foo@npm:^1\":\n  resolution: \"foo@patch:foo@npm%3A1.0.0#/etc/x.patch::version=1.0.0\"\n",
            "\"foo@npm:^1\":\n  resolution: \"foo@patch:foo@npm%3A1.0.0#./a.patch&../b.patch::v=1\"\n",
            "\"foo@npm:^1\":\n  resolution: \"foo@patch:foo@portal%3A/abs#./a.patch::v=1\"\n",
            "\"foo@npm:^1\":\n  resolution: \"foo@patch:foo@npm%3A1.0.0::v=1\"\n",
            "\"foo@npm:^1\":\n  resolution: foo@portal:/abs\n",
            "\"foo@npm:^1\":\n  resolution: \"foo@portal:\\u002fabs\"\n",
            "\"foo@npm:^1\":\n  resolution: >-\n    foo@portal:/abs\n",
            "\"foo@patch:foo@npm%3A1.0.0#~/x.patch::v=1\":\n  version: 1.0.0\n",
        ] {
            assert!(yarn_local_path(bad).is_some(), "{bad:?}");
        }
        for ok in [
            "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"foo@npm:^1.0.0, foo@npm:^1.1.0\":\n  version: 1.1.0\n  resolution: \"foo@npm:1.1.0\"\n  checksum: abc\n  languageName: node\n  linkType: hard\n",
            "\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  linkType: soft\n",
            "\"a@portal:packages/a::locator=app%40workspace%3A.\":\n  version: 0.0.0-use.local\n  resolution: \"a@portal:packages/a::locator=app%40workspace%3A.\"\n",
            "\"a@link:./packages/a::locator=app%40workspace%3A.\":\n  resolution: \"a@link:./packages/a::locator=app%40workspace%3A.\"\n",
            "\"foo@patch:foo@npm%3A1.0.0#./.yarn/patches/foo.patch::version=1.0.0&hash=a\":\n  resolution: \"foo@patch:foo@npm%3A1.0.0#./.yarn/patches/foo.patch::version=1.0.0&hash=a&locator=app%40workspace%3A.\"\n",
            "\"typescript@patch:typescript@npm%3A5.0.0#~builtin<compat/typescript>::version=5.0.0&hash=a\":\n  resolution: \"typescript@patch:typescript@npm%3A5.0.0#~builtin<compat/typescript>::version=5.0.0&hash=a\"\n",
        ] {
            assert_eq!(yarn_local_path(ok), None, "{ok:?}");
        }
    }

    #[test]
    fn pnpm_lock_refuses_directory_link_and_file_entries_that_leave_the_tree() {
        for bad in [
            "packages:\n  foo@file:../x:\n    resolution: {directory: ../x, type: directory}\n",
            "packages:\n  'foo@file:/abs':\n    version: 1.0.0\n",
            "packages:\n  /foo@link:/abs(react@18):\n    version: 1.0.0\n",
            "packages:\n  foo@1.0.0:\n    resolution: {directory: /abs, type: directory}\n",
            "packages:\n  foo@1.0.0:\n    resolution: {\"directory\": \"/abs\", type: directory}\n",
            "packages:\n  foo@1.0.0:\n    resolution: {integrity: sha512-x, tarball: file:../x.tgz}\n",
            "packages:\n  foo@1.0.0:\n    resolution:\n      directory: ../x\n",
            "importers:\n  .:\n    dependencies:\n      foo:\n        specifier: link:../foo\n        version: link:../foo\n",
            "importers:\n  .:\n    dependencies:\n      foo:\n        specifier: ^1.0.0\n        version: file:/abs/foo\n",
            "importers:\n  .:\n    dependencies:\n      foo:\n        specifier: ../foo\n        version: 1.0.0\n",
            "importers:\n  .:\n    dependencies:\n      foo: link:/abs\n",
            "overrides:\n  foo: link:../x\n",
            "packages:\n  foo@1.0.0:\n    resolution: {integrity: sha512-x,\n",
            "packages:\n  foo@1.0.0:\n    resolution: *alias\n",
            "packages:\n  foo@1.0.0:\n    resolution: {directory: \"\\u002fabs\"}\n",
            "importers:\n  .:\n    dependencies:\n      foo:\n        specifier: x\n        version: >-\n          link:../x\n",
        ] {
            assert!(pnpm_local_path(bad).is_some(), "{bad:?}");
        }
        for ok in [
            "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n  .:\n    dependencies:\n      foo:\n        specifier: ^1.0.0\n        version: 1.0.0\n\npackages:\n  foo@1.0.0:\n    resolution: {integrity: sha512-x}\n    engines: {node: '>=14'}\n\nsnapshots:\n  foo@1.0.0: {}\n",
            "importers:\n  .:\n    dependencies:\n      a:\n        specifier: link:packages/a\n        version: link:packages/a\n      b:\n        specifier: file:./vendor/b\n        version: file:vendor/b\n",
            "packages:\n  b@file:vendor/b:\n    resolution: {directory: vendor/b, type: directory}\n",
            "packages:\n  '@s/foo@1.0.0(react@18.0.0)':\n    resolution: {integrity: sha512-x, tarball: 'https://registry.npmjs.org/@s/foo/-/foo-1.0.0.tgz'}\n",
            "importers:\n  packages/@s/a:\n    dependencies: {}\n",
        ] {
            assert_eq!(pnpm_local_path(ok), None, "{ok:?}");
        }
    }

    #[test]
    fn the_offending_entry_is_the_first_one_as_a_trimmed_line() {
        let text = "a@^1:\n  resolved \"https://r/a.tgz\"\nb@^1:\n  resolved \"file:../b\"\nc@^1:\n  resolved \"file:/c\"\n";
        assert_eq!(
            yarn_local_path(text).as_deref(),
            Some("resolved \"file:../b\"")
        );
    }

    #[test]
    fn npm_lock_refuses_host_file_paths_links_and_keys_that_leave_the_tree() {
        for bad in [
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","resolved":"file:/etc/a.tgz"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"file:../a.tgz"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"file:~/a.tgz"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"file:"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"file:%2e%2e/a"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"../a","link":true}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"/abs/a","link":true}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"file:../a","link":true}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"link":true}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"link":"yes","resolved":"x"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"../outside":{"version":"1.0.0"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/../../x":{"version":"1.0.0"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"/abs/x":{"version":"1.0.0"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":7}}}"#,
            r#"{"lockfileVersion":3,"packages":[]}"#,
            r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"file:../a"}}}"#,
            r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","resolved":"file:/abs/a.tgz"}}}"#,
            r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"file:/abs/b"}}}}}"#,
            r#"{"lockfileVersion":2,"packages":{},"dependencies":{"a":{"version":"file:../a"}}}"#,
        ] {
            assert!(
                matches!(npm_local_path(bad), Ok(Some(_))),
                "{bad}: {:?}",
                npm_local_path(bad)
            );
        }
    }

    #[test]
    fn npm_lock_allows_workspace_links_and_registry_entries_and_names_the_entry() {
        for ok in [
            r#"{"name":"app","lockfileVersion":3,"packages":{"":{"workspaces":["packages/*"]},"node_modules/a":{"resolved":"packages/a","link":true},"packages/a":{"name":"a","version":"1.0.0"},"node_modules/foo":{"version":"1.0.0","resolved":"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz","integrity":"sha512-x"},"node_modules/@s/bar":{"version":"2.0.0","resolved":"https://registry.npmjs.org/@s/bar/-/bar-2.0.0.tgz"}}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"resolved":"file:vendor/a.tgz"},"node_modules/b":{"resolved":"vendor/b","link":true}}}"#,
            r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"file:vendor/a","dependencies":{"b":{"version":"1.0.0","resolved":"https://r/b.tgz"}}}}}"#,
            r#"{"lockfileVersion":3,"packages":{}}"#,
        ] {
            assert_eq!(npm_local_path(ok), Ok(None), "{ok}");
        }
        assert_eq!(
            npm_local_path(
                r#"{"packages":{"":{},"node_modules/a":{"resolved":"https://r/a.tgz"},"node_modules/b":{"resolved":"file:/etc/b"}}}"#
            ),
            Ok(Some("node_modules/b".to_string()))
        );
        assert_eq!(
            npm_local_path(
                r#"{"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"file:/b"}}}}}"#
            ),
            Ok(Some("dependencies.a.dependencies.b".to_string()))
        );
        // Not JSON, or not an object: refused by the caller.
        assert!(npm_local_path("{").is_err());
        assert!(npm_local_path("[]").is_err());
    }
}
