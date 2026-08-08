//! Language detection helpers (normalize, script mixing, lookalikes).

mod consts;
mod detector;

pub use detector::{DetectOptions, LanguageDetector};

use unicode_normalization::UnicodeNormalization;

use crate::shared::COMMON_PATTERNS;

use self::consts::{
    LANGUAGE_DETECTION_COMBINING_DIACRITICS, LANGUAGE_DETECTION_COMMON_PUNCTUATION,
    LANGUAGE_DETECTION_LOOKALIKE_CHARS, LANGUAGE_DETECTION_OBFUSCATION_PATTERN,
    LANGUAGE_DETECTION_OPERATORS_AND_PIPES, LANGUAGE_DETECTION_SEPARATORS,
};

/// Normalizes text for language detection: lowercase, NFD + strip diacritics,
/// punctuation/operator cleanup, space collapse, obfuscation join, and
/// lookalike replacement when the text has no Cyrillic.
pub fn normalize_text(text: &str) -> String {
    let space_char = " ";
    let empty_char = "";

    let mut normalized: String = text.to_lowercase().nfd().collect();

    normalized = LANGUAGE_DETECTION_COMBINING_DIACRITICS
        .replace_all(&normalized, empty_char)
        .into_owned();
    normalized = LANGUAGE_DETECTION_COMMON_PUNCTUATION
        .replace_all(&normalized, space_char)
        .into_owned();
    normalized = LANGUAGE_DETECTION_OPERATORS_AND_PIPES
        .replace_all(&normalized, space_char)
        .into_owned();
    normalized = COMMON_PATTERNS
        .whitespace_multiple
        .replace_all(&normalized, space_char)
        .into_owned();

    // Collapse obfuscation separators inside letter runs (`o-v-e-r` → `over`).
    let mut collapsed = String::with_capacity(normalized.len());
    let mut last_end = 0;
    for m in LANGUAGE_DETECTION_OBFUSCATION_PATTERN.find_iter(&normalized) {
        collapsed.push_str(&normalized[last_end..m.start()]);
        let joined = LANGUAGE_DETECTION_SEPARATORS.replace_all(m.as_str(), empty_char);
        collapsed.push_str(&joined);
        last_end = m.end();
    }
    collapsed.push_str(&normalized[last_end..]);
    normalized = collapsed.trim().to_string();

    let has_cyrillic = normalized.chars().any(|c| {
        let code = c as u32;
        (0x0400..=0x04FF).contains(&code)
    });

    if !has_cyrillic {
        for (lookalike, replacement) in LANGUAGE_DETECTION_LOOKALIKE_CHARS.iter() {
            if normalized.contains(lookalike) {
                normalized = normalized.replace(lookalike, replacement);
            }
        }
    }

    normalized
}

pub fn has_language_script_mixing(text: &str) -> bool {
    let mut scripts = std::collections::HashSet::new();

    for c in text.chars() {
        let code = c as u32;
        if (0x0000..=0x007F).contains(&code) {
            scripts.insert("Latin");
        } else if (0x0400..=0x04FF).contains(&code) {
            scripts.insert("Cyrillic");
        } else if (0x0370..=0x03FF).contains(&code) {
            scripts.insert("Greek");
        } else if (0x0590..=0x05FF).contains(&code) {
            scripts.insert("Hebrew");
        } else if (0x0600..=0x06FF).contains(&code) {
            scripts.insert("Arabic");
        } else if (0x4E00..=0x9FFF).contains(&code) {
            scripts.insert("CJK");
        } else if (0x3040..=0x309F).contains(&code) {
            scripts.insert("Hiragana");
        } else if (0x30A0..=0x30FF).contains(&code) {
            scripts.insert("Katakana");
        } else if (0x0900..=0x097F).contains(&code) {
            scripts.insert("Devanagari");
        }
    }

    scripts.len() > 1
}

pub fn detect_lookalike_chars(text: &str) -> bool {
    LANGUAGE_DETECTION_LOOKALIKE_CHARS
        .iter()
        .any(|(lookalike, _)| text.contains(lookalike))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_diacritics_and_lowercases() {
        assert_eq!(normalize_text("café résumé naïve"), normalize_text("cafe resume naive"));
        assert_eq!(normalize_text("HELLO WORLD"), "hello world");
    }

    #[test]
    fn normalize_collapses_obfuscation() {
        assert_eq!(normalize_text("o-v-e-r-r-i-d-e"), "override");
    }

    #[test]
    fn normalize_greek_lookalikes_without_cyrillic() {
        // ο → o; ε is not in the lookalike map
        assert_eq!(normalize_text("hεllo wοrld"), "hεllo world");
    }

    #[test]
    fn script_mixing_and_lookalikes() {
        assert!(has_language_script_mixing("hello мир"));
        assert!(!has_language_script_mixing("hello world"));
        assert!(detect_lookalike_chars("а"));
        assert!(!detect_lookalike_chars("a"));
    }
}
