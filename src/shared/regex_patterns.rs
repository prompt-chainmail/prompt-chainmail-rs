//! Shared regex patterns for rivets.

use std::sync::LazyLock;

use regex::Regex;

#[allow(dead_code)] // Unused fields reserved for later rivets.
pub struct CommonPatterns {
    pub whitespace: Regex,
    pub whitespace_multiple: Regex,
    pub uppercase: Regex,
    pub lowercase: Regex,
    pub alphabetic: Regex,
    pub alphanumeric: Regex,
    pub word_char: Regex,
    pub word_chars: Regex,
    pub digit: Regex,
    pub digits: Regex,
    pub non_word_chars: Regex,
    pub consecutive_consonants: Regex,
    pub slot_pattern: Regex,
    pub bracket_open: Regex,
    pub bracket_close: Regex,
}

pub struct HtmlEntities {
    pub lt: Regex,
    pub gt: Regex,
    pub amp: Regex,
    pub quot: Regex,
    pub apos: Regex,
    pub numeric: Regex,
    pub numeric_detection: Regex,
    pub named_detection: Regex,
}

#[allow(dead_code)] // Unused fields reserved for later rivets.
pub struct EncodingPatterns {
    pub unicode_escape: Regex,
    pub octal_escape: Regex,
    pub hex_digits: Regex,
    pub binary_digits: Regex,
    pub base64: Regex,
    pub hex_escape: Regex,
    pub url_escape: Regex,
    pub binary: Regex,
    pub octal: Regex,
    pub unicode_escape_regex: Regex,
}

pub static COMMON_PATTERNS: LazyLock<CommonPatterns> = LazyLock::new(|| CommonPatterns {
    whitespace: Regex::new(r"\s").unwrap(),
    whitespace_multiple: Regex::new(r"\s+").unwrap(),
    uppercase: Regex::new(r"[A-Z]").unwrap(),
    lowercase: Regex::new(r"[a-z]").unwrap(),
    alphabetic: Regex::new(r"[a-zA-Z]").unwrap(),
    alphanumeric: Regex::new(r"[a-zA-Z0-9]").unwrap(),
    word_char: Regex::new(r"\w").unwrap(),
    word_chars: Regex::new(r"\w+").unwrap(),
    digit: Regex::new(r"\d").unwrap(),
    digits: Regex::new(r"\d+").unwrap(),
    // Unicode letter/number classes (`\p{L}`, `\p{N}`) — requires regex unicode features.
    non_word_chars: Regex::new(r"[^\p{L}\p{N}\s]").unwrap(),
    consecutive_consonants: Regex::new(r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{4,}")
        .unwrap(),
    slot_pattern: Regex::new(r"\[(\w+)\]").unwrap(),
    bracket_open: Regex::new(r"\[").unwrap(),
    bracket_close: Regex::new(r"\]").unwrap(),
});

pub static HTML_ENTITIES: LazyLock<HtmlEntities> = LazyLock::new(|| HtmlEntities {
    lt: Regex::new(r"&lt;").unwrap(),
    gt: Regex::new(r"&gt;").unwrap(),
    amp: Regex::new(r"&amp;").unwrap(),
    quot: Regex::new(r"&quot;").unwrap(),
    apos: Regex::new(r"&#x27;").unwrap(),
    numeric: Regex::new(r"&#(\d+);").unwrap(),
    numeric_detection: Regex::new(r"&#\d{2,3};").unwrap(),
    named_detection: Regex::new(r"&[a-zA-Z]+;").unwrap(),
});

pub static ENCODING_PATTERNS: LazyLock<EncodingPatterns> = LazyLock::new(|| EncodingPatterns {
    unicode_escape: Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap(),
    octal_escape: Regex::new(r"\\([0-7]{3})").unwrap(),
    hex_digits: Regex::new(r"[0-9a-fA-F]").unwrap(),
    binary_digits: Regex::new(r"[01]").unwrap(),
    base64: Regex::new(r"[A-Za-z0-9+/=]{20,}").unwrap(),
    hex_escape: Regex::new(r"(?:0x)?[0-9a-fA-F\s]{20,}").unwrap(),
    url_escape: Regex::new(r"(%[0-9a-fA-F]{2}){4,}").unwrap(),
    binary: Regex::new(r"^[01\s]{32,}$").unwrap(),
    octal: Regex::new(r"\\[0-7]{3}").unwrap(),
    unicode_escape_regex: Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap(),
});
