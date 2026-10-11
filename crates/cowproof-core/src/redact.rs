use regex::Regex;
use std::sync::OnceLock;

/// Redact sensitive tokens from text, matching the behavior of the Node reference.
/// Rules are applied in order:
/// 1. `sk-` tokens: `sk-` followed by 8+ of [A-Za-z0-9_-]
/// 2. JWT tokens: `eyJ` followed by 16+ of [A-Za-z0-9_-], optionally `.` and more chars
/// 3. Bearer tokens: `Bearer` followed by whitespace and non-whitespace (case-insensitive)
/// 4. GitHub tokens: word boundary + `ghp_` followed by 10+ alphanumeric chars
/// 5. Slack tokens: word boundary + `xox[baprs]-` followed by 8+ [A-Za-z0-9-]
/// 6. OpenRouter API key: `OPENROUTER_API_KEY` = followed by non-whitespace (case-insensitive)
pub fn redact(value: &str) -> String {
    let value = get_sk_regex().replace_all(value, "[redacted]");
    let value = get_jwt_regex().replace_all(&value, "[redacted JWT]");
    let value = get_bearer_regex().replace_all(&value, "Bearer [redacted]");
    let value = get_ghp_regex().replace_all(&value, "[redacted]");
    let value = get_xox_regex().replace_all(&value, "[redacted]");
    let value = get_openrouter_regex().replace_all(&value, "$1[redacted]");
    value.into_owned()
}

fn get_sk_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"sk-[A-Za-z0-9_-]{8,}").expect("sk- regex should be valid"))
}

fn get_jwt_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{16,}\.?[A-Za-z0-9._-]*").expect("JWT regex should be valid")
    })
}

fn get_bearer_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)Bearer\s+\S+").expect("Bearer regex should be valid"))
}

fn get_ghp_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\bghp_[A-Za-z0-9]{10,}").expect("ghp_ regex should be valid"))
}

fn get_xox_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{8,}").expect("xox regex should be valid")
    })
}

fn get_openrouter_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)(OPENROUTER_API_KEY\s*=)\S+")
            .expect("OPENROUTER_API_KEY regex should be valid")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_sk_token_minimum_length() {
        // sk- with exactly 8 characters
        assert_eq!(redact("secret: sk-aaaabbbb"), "secret: [redacted]");
        // sk- with exactly 7 characters (should NOT redact)
        assert_eq!(redact("secret: sk-aaabbb"), "secret: sk-aaabbb");
    }

    #[test]
    fn redact_sk_token_with_special_chars() {
        assert_eq!(redact("key is sk-abcd_efgh-ijkl"), "key is [redacted]");
        assert_eq!(
            redact("multiple: sk-aaaabbbb and sk-ccccdddd"),
            "multiple: [redacted] and [redacted]"
        );
    }

    #[test]
    fn redact_jwt() {
        assert_eq!(
            redact("token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"),
            "token: [redacted JWT]"
        );
        // JWT minimum: eyJ (3) + 16+ chars = 19+ minimum
        assert_eq!(
            redact("short jwt eyJ1234567890123456 is ok"),
            "short jwt [redacted JWT] is ok"
        );
        // JWT without the dot (still valid pattern)
        assert_eq!(
            redact("just eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "just [redacted JWT]"
        );
    }

    #[test]
    fn redact_bearer_case_insensitive() {
        assert_eq!(
            redact("auth: Bearer sk-secret123456"),
            "auth: Bearer [redacted]"
        );
        assert_eq!(
            redact("auth: bearer secrettoken"),
            "auth: Bearer [redacted]"
        );
        assert_eq!(
            redact("auth: BEARER secrettoken"),
            "auth: Bearer [redacted]"
        );
        // Note: Bearer\s+\S+ matches Bearer + spaces + one word, leaving remaining spaces
        assert_eq!(
            redact("header: Bearer  token extra"),
            "header: Bearer [redacted] extra"
        );
    }

    #[test]
    fn redact_ghp_token() {
        // ghp_ with exactly 10 characters (should NOT redact - needs 10+, but token is ghp_0123456789 = 14 chars total)
        assert_eq!(redact("ghp_123456789"), "ghp_123456789");
        // ghp_ with 10+ characters (should redact) - ghp_0123456789 = 14 total
        assert_eq!(redact("token: ghp_0123456789"), "token: [redacted]");
        assert_eq!(redact("github: ghp_0123456789abc"), "github: [redacted]");
    }

    #[test]
    fn redact_ghp_with_word_boundary() {
        // Word boundary: ghp_ in the middle of a word should NOT redact
        assert_eq!(redact("myghp_12345678901extra"), "myghp_12345678901extra");
        // But with space or punctuation it should
        assert_eq!(redact("token ghp_12345678901"), "token [redacted]");
    }

    #[test]
    fn redact_xox_token() {
        // Various xox types - need at least xox[baprs]- (5 chars) + 8+ alphanumeric = 13+ minimum
        assert_eq!(redact("slack: xoxb-1234567890abc"), "slack: [redacted]");
        assert_eq!(
            redact("app: xoxp-SYNTHtesta-SYNTHtestb-SYNTHtestc-abcdefg"),
            "app: [redacted]"
        );
        // xoxa-secret is only 12 chars, needs 13+
        assert_eq!(redact("token xoxa-secrettoken"), "token [redacted]");
    }

    #[test]
    fn redact_xox_with_word_boundary() {
        // Word boundary check
        assert_eq!(redact("myxoxb-1234567890abc"), "myxoxb-1234567890abc");
        assert_eq!(redact("token: xoxb-1234567890abc"), "token: [redacted]");
    }

    #[test]
    fn redact_openrouter_api_key() {
        assert_eq!(
            redact("OPENROUTER_API_KEY=sk-123456789abcdef"),
            "OPENROUTER_API_KEY=[redacted]"
        );
        // Space before = is preserved by the regex
        assert_eq!(
            redact("export OPENROUTER_API_KEY = sk-123456789abcdef"),
            "export OPENROUTER_API_KEY = [redacted]"
        );
        // Case insensitive
        assert_eq!(
            redact("openrouter_api_key=secret"),
            "openrouter_api_key=[redacted]"
        );
    }

    #[test]
    fn redact_multiple_secrets_on_one_line() {
        assert_eq!(
            redact("sk-aaaabbbb Bearer secret ghp_12345678901"),
            "[redacted] Bearer [redacted] [redacted]"
        );
    }

    #[test]
    fn redact_multiple_lines() {
        let input = "line1: sk-aaaabbbb\nline2: Bearer secret\nline3: ghp_0123456789";
        let output = "line1: [redacted]\nline2: Bearer [redacted]\nline3: [redacted]";
        assert_eq!(redact(input), output);
    }

    #[test]
    fn redact_no_secrets_unchanged() {
        let text = "This is just normal text with no secrets";
        assert_eq!(redact(text), text);
    }

    #[test]
    fn redact_jwt_inside_bearer() {
        // Bearer header with a JWT token
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI";
        let output = redact(input);
        // Both the Bearer and the JWT should be redacted
        assert!(output.contains("Bearer [redacted]"));
        assert!(!output.contains("Bearer [redacted JWT]"));
    }

    #[test]
    fn redact_sk_inside_jwt_like_string() {
        // A string that looks like JWT but contains sk-
        let input = "eyJzay1hYWFhYmJiYmNjY2NkZGRkZWVlZWZmZmZnZ2dnIn0";
        let output = redact(input);
        // This should be redacted as a JWT (eyJ pattern matches first)
        assert_eq!(output, "[redacted JWT]");
    }

    #[test]
    fn redact_preserves_key_name_in_env_var() {
        assert_eq!(
            redact("OPENROUTER_API_KEY=sk-token123456"),
            "OPENROUTER_API_KEY=[redacted]"
        );
        // Key name should be preserved
        assert!(redact("OPENROUTER_API_KEY=secret").starts_with("OPENROUTER_API_KEY"));
    }
}
