//! The packet checks behind `Requirement` (D28 clause 5): whether a packet's text meets one
//! requirement of a profile. Each check reads the packet text (and the parsed header for
//! `checks`) and nothing else. No model is involved and nothing is graded: a check says a
//! structure is present, not that it is good.
//!
//! Shared rules:
//!
//! - A *heading* is a Markdown line of one to six `#` followed by a space, outside a fenced
//!   code block. A *section* is the lines after a heading up to the next heading of the same
//!   or a higher level (fewer or equal `#`). A requirement is met when any matching section
//!   meets it.
//! - A *fence* is a line starting with three backticks or three tildes. Lines inside one are
//!   *fenced*; the fence lines themselves belong to no section body.
//! - A *list item* starts with `-`, `*`, `+` or a number and `.` or `)`, then a space.

use cowproof_core::{Header, Requirement};

/// What is missing for `requirement`, as the sentence to add to the packet, or `None` when the
/// packet meets it.
pub(crate) fn missing(
    requirement: Requirement,
    packet_text: &str,
    header: &Header,
) -> Option<&'static str> {
    let lines = scan(packet_text);
    let met = match requirement {
        Requirement::Tests => tests(&lines),
        Requirement::Mutations => mutations(&lines),
        Requirement::DoneChecklist => done_checklist(&lines),
        Requirement::Checks => !header.checks.is_empty(),
    };
    if met {
        return None;
    }
    Some(match requirement {
        Requirement::Tests => {
            "add a \"## Tests\" section that lists at least one test by its name in backticks, each with a sentence of at least four words saying what it asserts"
        }
        Requirement::Mutations => {
            "add a \"## Mutations\" section with at least one item: a list item, or a command inside a fenced block, that breaks the code on purpose"
        }
        Requirement::DoneChecklist => {
            "add a numbered list (1. 2. 3.) under a heading that contains the word \"Done\", for example \"## Done checklist\""
        }
        Requirement::Checks => {
            "declare at least one check in the header's \"checks\", so the packet can be proven"
        }
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Ordinary Markdown.
    Text,
    /// A fence line (opening or closing).
    Fence,
    /// A line inside a fenced code block.
    Fenced,
}

struct Line<'a> {
    kind: Kind,
    text: &'a str,
}

fn scan(text: &str) -> Vec<Line<'_>> {
    let mut lines = Vec::new();
    let mut open: Option<&str> = None;
    for raw in text.lines() {
        let trimmed = raw.trim_start();
        let marker = ["```", "~~~"].into_iter().find(|m| trimmed.starts_with(m));
        let kind = match (open, marker) {
            (None, Some(m)) => {
                open = Some(m);
                Kind::Fence
            }
            (Some(o), Some(m)) if o == m => {
                open = None;
                Kind::Fence
            }
            (Some(_), _) => Kind::Fenced,
            (None, None) => Kind::Text,
        };
        lines.push(Line { kind, text: raw });
    }
    lines
}

/// `(level, title)` when `line` is a heading.
fn heading(line: &Line<'_>) -> Option<(usize, String)> {
    if line.kind != Kind::Text {
        return None;
    }
    let trimmed = line.text.trim_start();
    if line.text.len() - trimmed.len() > 3 {
        return None;
    }
    let level = trimmed.chars().take_while(|c| *c == '#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = trimmed[level..].strip_prefix(' ')?;
    Some((level, rest.trim().trim_end_matches('#').trim().to_string()))
}

fn words(title: &str) -> Vec<String> {
    title
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The bodies (fence lines left out) of every section whose heading title satisfies `matches`.
fn sections<'a, 'b>(
    lines: &'b [Line<'a>],
    matches: impl Fn(&[String]) -> bool,
) -> Vec<Vec<&'b Line<'a>>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some((level, title)) = heading(&lines[i])
            && matches(&words(&title))
        {
            let mut body = Vec::new();
            let mut j = i + 1;
            while j < lines.len() {
                if heading(&lines[j]).is_some_and(|(l, _)| l <= level) {
                    break;
                }
                if lines[j].kind != Kind::Fence {
                    body.push(&lines[j]);
                }
                j += 1;
            }
            out.push(body);
        }
        i += 1;
    }
    out
}

/// The text after a list marker, when `text` (indentation allowed) is a list item.
fn list_item(text: &str) -> Option<&str> {
    let t = text.trim_start();
    if let Some(rest) = ["- ", "* ", "+ "].iter().find_map(|m| t.strip_prefix(m)) {
        return Some(rest);
    }
    numbered_item(t)
}

fn numbered_item(text: &str) -> Option<&str> {
    let t = text.trim_start();
    let digits = t.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let rest = t[digits..].strip_prefix(['.', ')'])?;
    rest.strip_prefix(' ')
}

fn has_alphanumeric(text: &str) -> bool {
    text.chars().any(char::is_alphanumeric)
}

/// `tests`: a section whose heading starts with the word "Tests" and holds a block (a list
/// item with its continuation lines, or a paragraph) that names a test in backticks and says,
/// outside the backticks, at least four words.
fn tests(lines: &[Line<'_>]) -> bool {
    sections(lines, |w| w.first().is_some_and(|f| f == "tests"))
        .iter()
        .any(|body| blocks(body).iter().any(|block| is_test_entry(block)))
}

/// Blocks of unfenced text: a blank line ends one, and a list item with less than two spaces
/// of indentation starts one. Deeper list items stay with their parent.
fn blocks(body: &[&Line<'_>]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in body.iter().filter(|l| l.kind == Kind::Text) {
        if line.text.trim().is_empty() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        let indent = line.text.len() - line.text.trim_start().len();
        let item = list_item(line.text);
        if item.is_some() && indent < 2 && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        // The marker of a top-level item is not a word.
        current.push_str(if indent < 2 {
            item.unwrap_or(line.text.trim())
        } else {
            line.text.trim()
        });
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn is_test_entry(block: &str) -> bool {
    let mut named = false;
    let mut prose = String::new();
    for (i, part) in block.split('`').enumerate() {
        if i % 2 == 1 {
            named |= is_test_name(part.trim());
        } else {
            prose.push(' ');
            prose.push_str(part);
        }
    }
    named
        && prose
            .split_whitespace()
            .filter(|w| has_alphanumeric(w))
            .count()
            >= 4
}

/// A Rust-style identifier path: `name`, or `module::name`.
fn is_test_name(name: &str) -> bool {
    !name.is_empty()
        && name.split("::").all(|segment| {
            let mut chars = segment.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// `mutations`: a section whose heading starts with the word "Mutations" and holds a list item
/// with some text, or a non-blank line inside a fenced block.
fn mutations(lines: &[Line<'_>]) -> bool {
    sections(lines, |w| w.first().is_some_and(|f| f == "mutations"))
        .iter()
        .any(|body| {
            body.iter().any(|l| match l.kind {
                Kind::Fenced => !l.text.trim().is_empty(),
                Kind::Text => list_item(l.text).is_some_and(has_alphanumeric),
                Kind::Fence => false,
            })
        })
}

/// `done-checklist`: a section whose heading has the word "Done" anywhere in its title and
/// holds a numbered list item (`1.` or `1)`) with some text.
fn done_checklist(lines: &[Line<'_>]) -> bool {
    sections(lines, |w| w.iter().any(|x| x == "done"))
        .iter()
        .any(|body| {
            body.iter().any(|l| {
                l.kind == Kind::Text && numbered_item(l.text).is_some_and(has_alphanumeric)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cowproof_core::parse_header;

    fn header(checks: bool) -> Header {
        let checks = if checks {
            r#","checks":[{"id":"unit","command":"cargo test"}]"#
        } else {
            ""
        };
        parse_header(&format!(
            "<!-- lane {{\"id\":\"lane-x\",\"owns\":[\"README.md\"]{checks}}} -->\n"
        ))
        .unwrap()
    }

    fn met(requirement: Requirement, text: &str) -> bool {
        missing(requirement, text, &header(false)).is_none()
    }

    #[test]
    fn tests_pass_with_a_named_test_and_an_assertion_sentence() {
        for text in [
            "## Tests\n\n- `a_lint_error_stops_the_run` asserts exit code 1 and no lane directory.\n",
            "## Tests (write first)\n\n1. `module::case_one`: stderr names the rung and the exit code is 4.\n",
            "# Plan\n\n## Tests\n\n- `case_one`\n  - asserts the lane is refused before it starts\n",
            "## Tests\n\n`case_one` fails when the header names a rung off the ladder.\n",
            // A deeper heading stays inside the section.
            "## Tests\n\n### Lint\n\n- `case_one` reports the missing section as an error.\n",
        ] {
            assert!(met(Requirement::Tests, text), "{text}");
        }
    }

    #[test]
    fn tests_fail_without_a_name_a_sentence_or_the_heading() {
        for (why, text) in [
            (
                "no named test",
                "## Tests\n\nWrite some tests that cover the change.\n",
            ),
            (
                "empty section",
                "## Tests\n\n## Mutations\n\n- `x` breaks the code for good measure\n",
            ),
            (
                "a command is not an identifier",
                "## Tests\n\n- `cargo test foo` asserts that everything passes now\n",
            ),
            (
                "a name and no sentence",
                "## Tests\n\n- `case_one`\n- `case_two`\n",
            ),
            (
                "a sentence too short",
                "## Tests\n\n- `case_one` passes ok\n",
            ),
            (
                "the name is outside the section",
                "- `case_one` asserts that the lane refuses to start\n\n## Tests\n\nTBD\n",
            ),
            (
                "heading word is not first",
                "## Write the tests\n\n- `case_one` asserts that the lane refuses to start\n",
            ),
            (
                "fenced names do not count",
                "## Tests\n\n```\n`case_one` asserts that the lane refuses to start\n```\n",
            ),
            (
                "no heading",
                "Tests: `case_one` asserts that the lane refuses to start.\n",
            ),
        ] {
            assert!(!met(Requirement::Tests, text), "{why}: {text}");
        }
    }

    #[test]
    fn a_name_in_one_item_and_a_sentence_in_another_do_not_combine() {
        let text = "## Tests\n\n- `case_one`\n- the lane refuses to start with a bad rung\n";
        assert!(!met(Requirement::Tests, text));
    }

    #[test]
    fn mutations_pass_with_a_list_item_or_a_fenced_command() {
        for text in [
            "## Mutations\n\n- (a) sed -i s/a/b/ src/lib.rs, then run the tests\n",
            "## Mutations\n\n1. break the parser\n",
            "## Mutations\n\n```\nsed -i 's/>=/>/' src/lib.rs\n```\n",
            "## Mutations (by hand)\n\n- one\n",
        ] {
            assert!(met(Requirement::Mutations, text), "{text}");
        }
    }

    #[test]
    fn mutations_fail_when_empty_absent_or_empty_items() {
        for text in [
            "## Mutations\n\nBreak things by hand.\n",
            "## Mutations\n\n## Checks\n\n- one\n",
            "## Mutations\n\n```\n\n```\n",
            "## Mutations\n\n- \n",
            "Mutations\n\n- one\n",
            "## Checks\n\n- mutations are nice\n",
        ] {
            assert!(!met(Requirement::Mutations, text), "{text}");
        }
    }

    #[test]
    fn a_done_checklist_is_a_numbered_list_under_a_done_heading() {
        for text in [
            "## Done checklist\n\n1. tests pass\n2. fmt clean\n",
            "## Definition of DONE\n\n1) tests pass\n",
            "### Done when\n\n  1. tests pass\n",
        ] {
            assert!(met(Requirement::DoneChecklist, text), "{text}");
        }
    }

    #[test]
    fn a_done_heading_with_an_unnumbered_list_or_a_list_elsewhere_fails() {
        for (why, text) in [
            (
                "bullets",
                "## Done checklist\n\n- tests pass\n- fmt clean\n",
            ),
            ("checkboxes", "## Done\n\n- [ ] tests pass\n"),
            (
                "numbers in another section",
                "## Steps\n\n1. do it\n\n## Done\n\nWhen it works.\n",
            ),
            (
                "the word inside another word",
                "## Abandoned work\n\n1. nothing\n",
            ),
            ("fenced numbers", "## Done\n\n```\n1. tests pass\n```\n"),
            ("empty item", "## Done\n\n1. \n"),
            ("list before the heading", "1. tests pass\n\n## Done\n"),
        ] {
            assert!(!met(Requirement::DoneChecklist, text), "{why}: {text}");
        }
    }

    #[test]
    fn a_section_ends_at_the_next_heading_of_the_same_or_higher_level() {
        let text = "## Done\n\n### Notes\n\n1. inside the section\n";
        assert!(met(Requirement::DoneChecklist, text));
        let text = "## Done\n\nwhen finished\n\n## Notes\n\n1. outside the section\n";
        assert!(!met(Requirement::DoneChecklist, text));
        // A heading line inside a fence ends nothing and starts nothing.
        let text = "## Done\n\n```\n## Notes\n```\n\n1. still inside\n";
        assert!(met(Requirement::DoneChecklist, text));
    }

    #[test]
    fn checks_need_a_non_empty_header_list() {
        assert!(missing(Requirement::Checks, "", &header(true)).is_none());
        let need = missing(Requirement::Checks, "", &header(false)).unwrap();
        assert!(need.contains("header's \"checks\""), "{need}");
    }

    #[test]
    fn every_missing_requirement_says_what_to_add() {
        let empty = header(false);
        for r in Requirement::ALL {
            let need = missing(r, "nothing here\n", &empty).unwrap();
            assert!(
                need.starts_with("add ") || need.starts_with("declare "),
                "{r}: {need}"
            );
        }
    }
}
