//! Symbol extraction, by parsing rather than scanning lines.
//!
//! The first version of this was a line scanner, on the argument that
//! extraction quality affects index *build* time — which is amortized — and
//! not the query latency the prototype was measuring. That held, and the
//! numbers it produced still stand. What it could not do is be correct: a
//! brace inside a string literal or a doc comment moved the end of every
//! symbol after it, and `fn` inside a string became a symbol.
//!
//! `ast-grep-core` is tree-sitter with the parsing rewritten in Rust. One
//! dependency covers a dozen languages, so a repo of mixed TypeScript, Rust
//! and Python indexes through one path.

use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Function,
    Method,
    Struct,
    Enum,
    Trait,
    Class,
    Interface,
    TypeAlias,
    Const,
    Module,
    Impl,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Function => "fn",
            Kind::Method => "method",
            Kind::Struct => "struct",
            Kind::Enum => "enum",
            Kind::Trait => "trait",
            Kind::Class => "class",
            Kind::Interface => "interface",
            Kind::TypeAlias => "type",
            Kind::Const => "const",
            Kind::Module => "mod",
            Kind::Impl => "impl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: Kind,
    /// Index into the index's `files` table, so paths are stored once.
    pub file: u32,
    /// 1-based, inclusive.
    pub line_start: u32,
    pub line_end: u32,
    /// The declaration line, trimmed — enough to answer "what is this?"
    /// without reading the body.
    pub signature: String,
}

/// Language for a path, or `None` when nothing here can parse it.
///
/// Declining is deliberate. Falling back to a line scanner for an unknown
/// language would reintroduce exactly the wrongness this module exists to
/// remove, and a confidently wrong span is worse than no answer.
pub fn language_of(path: &str) -> Option<SupportLang> {
    Some(match path.rsplit('.').next()? {
        "rs" => SupportLang::Rust,
        "ts" | "mts" | "cts" => SupportLang::TypeScript,
        "tsx" => SupportLang::Tsx,
        "js" | "jsx" | "mjs" | "cjs" => SupportLang::JavaScript,
        "py" => SupportLang::Python,
        "go" => SupportLang::Go,
        "java" => SupportLang::Java,
        "c" | "h" => SupportLang::C,
        "cpp" | "cc" | "hpp" | "cxx" => SupportLang::Cpp,
        "rb" => SupportLang::Ruby,
        "swift" => SupportLang::Swift,
        "kt" | "kts" => SupportLang::Kotlin,
        _ => return None,
    })
}

/// Node kinds worth indexing, per language, with what to call them.
fn kind_of(lang: SupportLang, node_kind: &str) -> Option<Kind> {
    use SupportLang as L;
    Some(match (lang, node_kind) {
        (L::Rust, "function_item") => Kind::Function,
        (L::Rust, "struct_item") => Kind::Struct,
        (L::Rust, "enum_item") => Kind::Enum,
        (L::Rust, "trait_item") => Kind::Trait,
        (L::Rust, "type_item") => Kind::TypeAlias,
        (L::Rust, "mod_item") => Kind::Module,
        (L::Rust, "const_item" | "static_item") => Kind::Const,
        (L::Rust, "impl_item") => Kind::Impl,

        (L::TypeScript | L::Tsx | L::JavaScript, "function_declaration") => Kind::Function,
        (L::TypeScript | L::Tsx | L::JavaScript, "class_declaration") => Kind::Class,
        (L::TypeScript | L::Tsx, "interface_declaration") => Kind::Interface,
        (L::TypeScript | L::Tsx, "type_alias_declaration") => Kind::TypeAlias,
        (L::TypeScript | L::Tsx, "enum_declaration") => Kind::Enum,
        (L::TypeScript | L::Tsx | L::JavaScript, "method_definition") => Kind::Method,

        (L::Python, "function_definition") => Kind::Function,
        (L::Python, "class_definition") => Kind::Class,

        (L::Go, "function_declaration") => Kind::Function,
        (L::Go, "method_declaration") => Kind::Method,
        (L::Go, "type_declaration") => Kind::TypeAlias,

        (L::Java, "class_declaration") => Kind::Class,
        (L::Java, "interface_declaration") => Kind::Interface,
        (L::Java, "method_declaration") => Kind::Method,

        (L::C | L::Cpp, "function_definition") => Kind::Function,
        (L::C | L::Cpp, "struct_specifier") => Kind::Struct,
        (L::Cpp, "class_specifier") => Kind::Class,

        (L::Ruby, "method") => Kind::Method,
        (L::Ruby, "class") => Kind::Class,

        (L::Swift, "function_declaration") => Kind::Function,
        (L::Swift, "class_declaration") => Kind::Class,

        (L::Kotlin, "function_declaration") => Kind::Function,
        (L::Kotlin, "class_declaration") => Kind::Class,

        _ => return None,
    })
}

/// The declared name of a node.
///
/// Tree-sitter grammars disagree on field names, so try the common ones and
/// fall back to the first identifier-shaped child.
fn name_of<D: ast_grep_core::Doc>(node: &Node<D>) -> Option<String> {
    for field in ["name", "declarator", "type"] {
        if let Some(n) = node.field(field) {
            let text = n.text();
            if !text.is_empty() {
                // A declarator can carry parameters; the name is its head.
                return Some(first_identifier(&text));
            }
        }
    }
    node.children()
        .find(|c| c.kind().ends_with("identifier") || c.kind() == "type_identifier")
        .map(|c| c.text().to_string())
}

fn first_identifier(text: &str) -> String {
    let text = text.trim_start_matches(['*', '&', ' ']);
    let end = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(text.len());
    text[..end].to_string()
}

/// Parse `text` and return the symbols it declares.
pub fn extract(text: &str, lang: SupportLang, file: u32) -> Vec<Symbol> {
    let ast = AstGrep::new(text, lang);
    // Byte offset -> line, computed once rather than per symbol.
    let line_index = LineIndex::new(text);

    let mut out = Vec::new();
    for node in ast.root().dfs() {
        let Some(kind) = kind_of(lang, &node.kind()) else {
            continue;
        };
        let Some(name) = name_of(&node) else { continue };
        if name.is_empty() {
            continue;
        }

        let range = node.range();
        let line_start = line_index.line_of(range.start);
        let line_end = line_index.line_of(range.end.saturating_sub(1));

        out.push(Symbol {
            name,
            kind,
            file,
            line_start,
            line_end,
            signature: signature_at(text, line_start),
        });
    }
    out
}

/// The declaration line, trimmed of a trailing brace.
fn signature_at(text: &str, line: u32) -> String {
    let Some(raw) = text.lines().nth(line.saturating_sub(1) as usize) else {
        return String::new();
    };
    raw.trim()
        .trim_end_matches('{')
        .trim()
        .chars()
        .take(200)
        .collect()
}

/// Byte offset to 1-based line number.
struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0usize];
        starts.extend(
            text.bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i + 1),
        );
        Self { starts }
    }

    fn line_of(&self, offset: usize) -> u32 {
        match self.starts.binary_search(&offset) {
            Ok(i) => (i + 1) as u32,
            Err(i) => i as u32,
        }
    }
}
