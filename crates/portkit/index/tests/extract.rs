//! Extraction correctness.
//!
//! The line scanner this replaced produced plausible-looking wrong answers: a
//! brace inside a string moved the end of every symbol after it, and `fn` in a
//! string literal became a symbol. A wrong span is worse than no span, because
//! the caller acts on it.

use ast_grep_language::SupportLang;
use portkit_index::extract::{extract, language_of, Kind};

#[test]
fn code_inside_a_string_literal_is_not_a_symbol() {
    let src = r#"
pub fn real(x: u32) -> u32 {
    let s = "fn fake() { }";
    let t = "struct Fake;";
    x + s.len() as u32 + t.len() as u32
}
"#;
    let names: Vec<String> = extract(src, SupportLang::Rust, 0)
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert!(names.contains(&"real".to_string()), "{names:?}");
    assert!(
        !names.contains(&"fake".to_string()),
        "string contents leaked: {names:?}"
    );
    assert!(
        !names.contains(&"Fake".to_string()),
        "string contents leaked: {names:?}"
    );
}

#[test]
fn a_brace_in_a_doc_comment_does_not_move_the_span() {
    let src = r#"
/// A doc comment with a brace { in it
pub fn f() -> u32 {
    1
}
pub fn g() -> u32 {
    2
}
"#;
    let syms = extract(src, SupportLang::Rust, 0);
    let f = syms.iter().find(|s| s.name == "f").expect("f");
    let g = syms.iter().find(|s| s.name == "g").expect("g");
    assert_eq!((f.line_start, f.line_end), (3, 5));
    assert_eq!((g.line_start, g.line_end), (6, 8));
}

#[test]
fn methods_inside_an_impl_are_found() {
    let src = "pub struct S; impl S { pub fn method(&self) -> u32 { 1 } }";
    let names: Vec<String> = extract(src, SupportLang::Rust, 0)
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert!(names.contains(&"method".to_string()), "{names:?}");
}

#[test]
fn typescript_declarations_are_found() {
    let src = r#"
export interface Config { retries: number }
export class Registry { register(n: string): void {} }
export function replayOne(c: Config): number { return c.retries }
type Alias = string;
"#;
    let syms = extract(src, SupportLang::TypeScript, 0);
    let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
    for expected in ["Config", "Registry", "replayOne", "Alias"] {
        assert!(names.contains(&expected), "missing {expected} in {names:?}");
    }
    assert!(syms.iter().any(|s| s.kind == Kind::Interface));
}

#[test]
fn python_definitions_are_found_with_indentation_spans() {
    let src = "def outer():\n    x = 1\n    return x\n\nclass K:\n    def m(self):\n        pass\n";
    let syms = extract(src, SupportLang::Python, 0);
    let outer = syms.iter().find(|s| s.name == "outer").expect("outer");
    assert_eq!(outer.line_start, 1);
    assert_eq!(outer.line_end, 3, "the body ends before the blank line");
    assert!(syms.iter().any(|s| s.name == "K" && s.kind == Kind::Class));
}

#[test]
fn an_unknown_language_declines_rather_than_guessing() {
    // Falling back to a line scanner would reintroduce exactly the wrongness
    // this module exists to remove.
    assert!(language_of("notes.txt").is_none());
    assert!(language_of("Makefile").is_none());
    assert!(language_of("a.rs").is_some());
}

#[test]
fn signatures_carry_the_declaration_not_the_body() {
    let syms = extract(
        "pub fn wide(a: u32, b: u32) -> u32 {\n  a + b\n}",
        SupportLang::Rust,
        0,
    );
    let s = &syms[0];
    assert!(s.signature.contains("pub fn wide"), "{}", s.signature);
    assert!(
        !s.signature.contains("a + b"),
        "body leaked into signature: {}",
        s.signature
    );
}
