//! A tolerant structural JSON differ.
//!
//! Porting Python to Rust almost never reproduces floating point bit for bit —
//! the two languages sum in different orders and round differently at the last
//! place. A strict `==` on results would flag every port as broken, so the
//! parity harness compares with an epsilon and reports differences by path
//! rather than dumping two blobs and leaving you to spot the delta.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How strict a comparison should be.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffOptions {
    /// Absolute tolerance for numeric leaves. Differences at or below this are
    /// not reported. Set to `0.0` to demand exact equality.
    pub epsilon: f64,
    /// Relative tolerance, applied as `epsilon_rel * max(|a|, |b|)`. Guards
    /// large magnitudes where an absolute epsilon is meaninglessly tight.
    pub epsilon_rel: f64,
    /// JSON Pointer prefixes to skip entirely, e.g. `/metadata/generated_at`.
    /// Use for genuinely incomparable fields — timestamps, run ids, hostnames.
    pub ignore_paths: Vec<String>,
    /// Treat arrays as multisets, comparing only after both sides are sorted
    /// by their serialized form. Use when the Python original had no stable
    /// ordering guarantee and you do not want to inherit its accidents.
    pub unordered_arrays: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            epsilon: 1e-9,
            epsilon_rel: 1e-9,
            ignore_paths: Vec::new(),
            unordered_arrays: false,
        }
    }
}

impl DiffOptions {
    /// Demand exact equality, including bit-identical floats.
    pub fn exact() -> Self {
        Self {
            epsilon: 0.0,
            epsilon_rel: 0.0,
            ..Default::default()
        }
    }

    pub fn with_epsilon(mut self, epsilon: f64) -> Self {
        self.epsilon = epsilon;
        self
    }

    pub fn ignoring(mut self, path: impl Into<String>) -> Self {
        self.ignore_paths.push(path.into());
        self
    }

    fn is_ignored(&self, path: &str) -> bool {
        self.ignore_paths
            .iter()
            .any(|p| path == p || path.starts_with(&format!("{p}/")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    /// Same path, different JSON type (e.g. string vs number).
    TypeMismatch,
    /// Same type, different value.
    ValueMismatch,
    /// Present in the reference output, absent from the port's.
    Missing,
    /// Absent from the reference output, present in the port's.
    Unexpected,
    /// Arrays of differing length.
    LengthMismatch,
}

impl fmt::Display for DiffKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DiffKind::TypeMismatch => "type mismatch",
            DiffKind::ValueMismatch => "value mismatch",
            DiffKind::Missing => "missing",
            DiffKind::Unexpected => "unexpected",
            DiffKind::LengthMismatch => "length mismatch",
        };
        f.write_str(s)
    }
}

/// One difference, located by JSON Pointer (RFC 6901).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Difference {
    pub path: String,
    pub kind: DiffKind,
    /// The reference (expected) value, if present at this path.
    pub expected: Option<Value>,
    /// The port's (actual) value, if present at this path.
    pub actual: Option<Value>,
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.path.is_empty() {
            "<root>"
        } else {
            &self.path
        };
        write!(f, "{path}: {}", self.kind)?;
        match (&self.expected, &self.actual) {
            (Some(e), Some(a)) => write!(f, "\n  expected  {}\n  actual    {}", trunc(e), trunc(a)),
            (Some(e), None) => write!(f, "\n  expected  {}", trunc(e)),
            (None, Some(a)) => write!(f, "\n  actual    {}", trunc(a)),
            (None, None) => Ok(()),
        }
    }
}

/// Keep failure output readable when a leaf holds a whole document.
fn trunc(v: &Value) -> String {
    const LIMIT: usize = 160;
    let s = v.to_string();
    if s.chars().count() <= LIMIT {
        return s;
    }
    let head: String = s.chars().take(LIMIT).collect();
    format!("{head}… ({} bytes total)", s.len())
}

/// Compare `expected` against `actual`, returning every difference found.
///
/// An empty result means the two are equal under `opts`.
pub fn diff(expected: &Value, actual: &Value, opts: &DiffOptions) -> Vec<Difference> {
    let mut out = Vec::new();
    walk("", expected, actual, opts, &mut out);
    out
}

/// Whether the two values are equal under `opts`.
pub fn matches(expected: &Value, actual: &Value, opts: &DiffOptions) -> bool {
    diff(expected, actual, opts).is_empty()
}

fn walk(
    path: &str,
    expected: &Value,
    actual: &Value,
    opts: &DiffOptions,
    out: &mut Vec<Difference>,
) {
    if opts.is_ignored(path) {
        return;
    }

    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, ev) in e {
                let child = format!("{path}/{}", escape(k));
                match a.get(k) {
                    Some(av) => walk(&child, ev, av, opts, out),
                    None if !opts.is_ignored(&child) => out.push(Difference {
                        path: child,
                        kind: DiffKind::Missing,
                        expected: Some(ev.clone()),
                        actual: None,
                    }),
                    None => {}
                }
            }
            for (k, av) in a {
                if e.contains_key(k) {
                    continue;
                }
                let child = format!("{path}/{}", escape(k));
                if !opts.is_ignored(&child) {
                    out.push(Difference {
                        path: child,
                        kind: DiffKind::Unexpected,
                        expected: None,
                        actual: Some(av.clone()),
                    });
                }
            }
        }

        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                out.push(Difference {
                    path: path.to_string(),
                    kind: DiffKind::LengthMismatch,
                    expected: Some(Value::from(e.len())),
                    actual: Some(Value::from(a.len())),
                });
                // Still compare the common prefix — usually the first
                // mismatching element explains the length difference.
            }
            if opts.unordered_arrays {
                let (mut e, mut a) = (e.clone(), a.clone());
                e.sort_by_key(Value::to_string);
                a.sort_by_key(Value::to_string);
                for (i, (ev, av)) in e.iter().zip(a.iter()).enumerate() {
                    walk(&format!("{path}/{i}"), ev, av, opts, out);
                }
            } else {
                for (i, (ev, av)) in e.iter().zip(a.iter()).enumerate() {
                    walk(&format!("{path}/{i}"), ev, av, opts, out);
                }
            }
        }

        (Value::Number(e), Value::Number(a)) => {
            // Compare integers exactly when both sides are integral — an id or
            // a count that drifts by one is a real bug, not rounding.
            if let (Some(e), Some(a)) = (e.as_i64(), a.as_i64()) {
                if e != a {
                    push_value_mismatch(path, expected, actual, out);
                }
                return;
            }
            let (Some(ef), Some(af)) = (e.as_f64(), a.as_f64()) else {
                push_value_mismatch(path, expected, actual, out);
                return;
            };
            if !close_enough(ef, af, opts) {
                push_value_mismatch(path, expected, actual, out);
            }
        }

        (Value::Null, Value::Null) => {}
        (Value::Bool(e), Value::Bool(a)) if e == a => {}
        (Value::String(e), Value::String(a)) if e == a => {}

        (e, a) if std::mem::discriminant(e) == std::mem::discriminant(a) => {
            push_value_mismatch(path, expected, actual, out);
        }

        _ => out.push(Difference {
            path: path.to_string(),
            kind: DiffKind::TypeMismatch,
            expected: Some(expected.clone()),
            actual: Some(actual.clone()),
        }),
    }
}

fn push_value_mismatch(path: &str, expected: &Value, actual: &Value, out: &mut Vec<Difference>) {
    out.push(Difference {
        path: path.to_string(),
        kind: DiffKind::ValueMismatch,
        expected: Some(expected.clone()),
        actual: Some(actual.clone()),
    });
}

fn close_enough(a: f64, b: f64, opts: &DiffOptions) -> bool {
    if a == b {
        return true;
    }
    // NaN never equals itself, but two NaNs in the same slot mean the two
    // implementations agree, which is what parity actually asks.
    if a.is_nan() && b.is_nan() {
        return true;
    }
    if a.is_infinite() || b.is_infinite() {
        return false;
    }
    let delta = (a - b).abs();
    delta <= opts.epsilon || delta <= opts.epsilon_rel * a.abs().max(b.abs())
}

/// Escape a key for use in a JSON Pointer (RFC 6901 §3).
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identical_documents_have_no_differences() {
        let v = json!({"a": 1, "b": ["x", {"c": true}]});
        assert!(diff(&v, &v, &DiffOptions::default()).is_empty());
    }

    #[test]
    fn float_drift_within_epsilon_is_tolerated() {
        // The motivating case: Python and Rust summing in a different order.
        let expected = json!({"score": 0.1 + 0.2});
        let actual = json!({"score": 0.30000000000000004});
        assert!(matches(&expected, &actual, &DiffOptions::default()));
    }

    #[test]
    fn float_drift_beyond_epsilon_is_reported() {
        let expected = json!({"score": 0.813});
        let actual = json!({"score": 0.812});
        let d = diff(&expected, &actual, &DiffOptions::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "/score");
        assert_eq!(d[0].kind, DiffKind::ValueMismatch);
    }

    #[test]
    fn exact_mode_rejects_any_float_drift() {
        let expected = json!(0.1 + 0.2);
        let actual = json!(0.3);
        assert!(!matches(&expected, &actual, &DiffOptions::exact()));
    }

    #[test]
    fn integers_are_compared_exactly_regardless_of_epsilon() {
        let opts = DiffOptions::default().with_epsilon(10.0);
        let d = diff(&json!({"count": 41}), &json!({"count": 42}), &opts);
        assert_eq!(d.len(), 1, "an off-by-one count is a bug, not rounding");
    }

    #[test]
    fn missing_and_unexpected_keys_are_distinguished() {
        let d = diff(&json!({"a": 1}), &json!({"b": 2}), &DiffOptions::default());
        let kinds: Vec<_> = d.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&DiffKind::Missing));
        assert!(kinds.contains(&DiffKind::Unexpected));
    }

    #[test]
    fn type_changes_are_reported_as_type_mismatch() {
        let d = diff(
            &json!({"n": 1}),
            &json!({"n": "1"}),
            &DiffOptions::default(),
        );
        assert_eq!(d[0].kind, DiffKind::TypeMismatch);
    }

    #[test]
    fn array_length_mismatch_is_reported_once() {
        let d = diff(&json!([1, 2, 3]), &json!([1, 2]), &DiffOptions::default());
        assert_eq!(
            d.iter()
                .filter(|x| x.kind == DiffKind::LengthMismatch)
                .count(),
            1
        );
    }

    #[test]
    fn ignored_paths_are_skipped_including_descendants() {
        let opts = DiffOptions::default().ignoring("/meta");
        let expected = json!({"v": 1, "meta": {"generated_at": "monday"}});
        let actual = json!({"v": 1, "meta": {"generated_at": "tuesday"}});
        assert!(matches(&expected, &actual, &opts));
    }

    #[test]
    fn unordered_arrays_ignore_ordering_when_asked() {
        let opts = DiffOptions {
            unordered_arrays: true,
            ..Default::default()
        };
        assert!(matches(&json!(["a", "b"]), &json!(["b", "a"]), &opts));
        assert!(!matches(
            &json!(["a", "b"]),
            &json!(["b", "a"]),
            &DiffOptions::default()
        ));
    }

    #[test]
    fn pointer_escaping_follows_rfc6901() {
        let d = diff(
            &json!({"a/b": 1}),
            &json!({"a/b": 2}),
            &DiffOptions::default(),
        );
        assert_eq!(d[0].path, "/a~1b");
    }

    #[test]
    fn nested_paths_locate_the_difference() {
        let expected = json!({"items": [{"id": 1}, {"id": 2}]});
        let actual = json!({"items": [{"id": 1}, {"id": 99}]});
        let d = diff(&expected, &actual, &DiffOptions::default());
        assert_eq!(d[0].path, "/items/1/id");
    }
}
