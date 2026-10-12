//! Function-level capture adapters, shipped with the crate.
//!
//! An adapter is a small, standard-library-only file in the reference's own language that
//! loads a module and a function, speaks [`capture`](crate::capture)'s contract (one JSON
//! request on stdin, one JSON result on stdout) and pins what makes runs differ. It is meant to
//! be copied beside the source it wraps and committed there; `pk port adapter <lang>` prints or
//! writes it.

/// The Node adapter (`node adapter.mjs <module> [<function>]`). Also runs TypeScript where Node
/// strips types.
pub const NODE: &str = include_str!("../adapters/node/adapter.mjs");

/// The Python adapter (`python3 adapter.py <module> [<function>]`).
pub const PYTHON: &str = include_str!("../adapters/python/adapter.py");

/// One shipped adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adapter {
    /// The language it wraps, as a port packet's `port.lang` names the family.
    pub lang: &'static str,
    /// The file name it is written under.
    pub file: &'static str,
    /// Its text.
    pub source: &'static str,
    /// What invokes it: a reference command is `<runner> <file> <module> [<function>]`.
    pub runner: &'static str,
}

/// Every shipped adapter.
pub const ADAPTERS: [Adapter; 2] = [
    Adapter {
        lang: "node",
        file: "adapter.mjs",
        source: NODE,
        runner: "node",
    },
    Adapter {
        lang: "python",
        file: "adapter.py",
        source: PYTHON,
        runner: "python3",
    },
];

/// The adapter for `lang`: `node` (also `typescript`, `ts`, `js`, `javascript`) or `python`
/// (also `py`), ignoring case.
pub fn adapter_for(lang: &str) -> Option<Adapter> {
    let family = match lang.to_ascii_lowercase().as_str() {
        "node" | "nodejs" | "typescript" | "ts" | "javascript" | "js" => "node",
        "python" | "python3" | "py" => "python",
        _ => return None,
    };
    ADAPTERS.iter().copied().find(|a| a.lang == family)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_language_and_its_aliases_name_one_adapter() {
        for name in ["node", "Node", "typescript", "ts", "js", "javascript"] {
            assert_eq!(adapter_for(name).unwrap().file, "adapter.mjs", "{name}");
        }
        for name in ["python", "py", "python3", "PYTHON"] {
            assert_eq!(adapter_for(name).unwrap().file, "adapter.py", "{name}");
        }
        assert!(adapter_for("shell").is_none());
        assert!(adapter_for("").is_none());
    }

    #[test]
    fn the_shipped_text_is_the_file_on_disk() {
        for adapter in ADAPTERS {
            assert!(
                adapter.source.starts_with("#!/usr/bin/env "),
                "{}",
                adapter.file
            );
            assert!(adapter.source.contains("PORTKIT_NOW"), "{}", adapter.file);
            assert!(adapter.source.contains("__defaults"), "{}", adapter.file);
        }
    }
}
