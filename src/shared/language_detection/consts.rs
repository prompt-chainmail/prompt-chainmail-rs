//! Lookalike maps and regexes for language-detection normalization.

use std::sync::LazyLock;

use regex::Regex;

/// Cyrillic / Greek lookalike characters → Latin replacements.
///
/// Replacement order is significant (applied sequentially).
pub static LANGUAGE_DETECTION_LOOKALIKE_CHARS: LazyLock<Vec<(&'static str, &'static str)>> =
    LazyLock::new(|| {
        vec![
            ("а", "a"),
            ("е", "e"),
            ("о", "o"),
            ("р", "p"),
            ("с", "c"),
            ("х", "x"),
            ("А", "A"),
            ("В", "B"),
            ("Е", "E"),
            ("К", "K"),
            ("М", "M"),
            ("О", "O"),
            ("α", "a"),
            ("ο", "o"),
            ("ρ", "p"),
            ("Α", "A"),
            ("Β", "B"),
            ("Ο", "O"),
        ]
    });

pub static LANGUAGE_DETECTION_COMBINING_DIACRITICS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\u{0300}-\u{036f}]").unwrap());

pub static LANGUAGE_DETECTION_COMMON_PUNCTUATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[:;,!?]").unwrap());

pub static LANGUAGE_DETECTION_OPERATORS_AND_PIPES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[|&<>]").unwrap());

/// Letters separated by `-`, `.`, or `_` (obfuscation like `o-v-e-r-r-i-d-e`).
pub static LANGUAGE_DETECTION_OBFUSCATION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\p{L})(?:[-._]+\p{L})+").unwrap());

pub static LANGUAGE_DETECTION_SEPARATORS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[-._|]+").unwrap());
