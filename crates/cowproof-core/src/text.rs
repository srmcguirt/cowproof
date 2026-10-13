//! Text that came from a lane (a builder's file, a tool's output, a fixture's name) on its way
//! to the director's terminal or an agent director's context.

/// `text` with every control character shown as an escape (`\n`, `\u{1b}`, `\u{9b}`), so it is
/// one line and cannot move the cursor, clear the screen, set the title or write the
/// clipboard. [`char::is_control`] is the Unicode `Cc` class: C0 (`U+0000..=U+001F`), DEL
/// (`U+007F`) and C1 (`U+0080..=U+009F`), which includes the 8-bit CSI `U+009B` and OSC `U+009D`
/// that some terminals take for `ESC [` and `ESC ]`.
pub fn one_line(text: &str) -> String {
    escape_capped(text, usize::MAX)
}

/// [`one_line`], cut so the result is at most `max_bytes` bytes, on a character boundary and
/// never in the middle of an escape. Escaping runs first, so the cut counts what is printed.
pub fn escape_capped(text: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    for c in text.chars() {
        let piece = if c.is_control() {
            c.escape_default().to_string()
        } else {
            c.to_string()
        };
        if out.len().saturating_add(piece.len()) > max_bytes {
            break;
        }
        out.push_str(&piece);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_control_class_is_escaped() {
        let shown = one_line("a\nb\x1b[31mred\r\u{7f}\u{9b}31m\u{9d}0;t\u{7}");
        assert_eq!(
            shown,
            "a\\nb\\u{1b}[31mred\\r\\u{7f}\\u{9b}31m\\u{9d}0;t\\u{7}"
        );
        assert!(!shown.chars().any(char::is_control));
    }

    #[test]
    fn a_cap_cuts_on_a_character_boundary_and_not_inside_an_escape() {
        let long = "é".repeat(10_000);
        let cut = escape_capped(&long, 500);
        assert!(cut.len() <= 500 && cut.len() >= 498, "{}", cut.len());
        assert!(cut.chars().all(|c| c == 'é'));
        // An escape is six bytes: five bytes of room hold none of it.
        assert_eq!(escape_capped("\u{1b}", 5), "");
        assert_eq!(escape_capped("\u{1b}", 6), "\\u{1b}");
    }
}
