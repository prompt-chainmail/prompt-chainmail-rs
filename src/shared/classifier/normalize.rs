//! NFKC normalization + UTF-8 windowing for the classifier.

use unicode_normalization::UnicodeNormalization;

const DEFAULT_WINDOW_SIZE: usize = 1024;
const DEFAULT_WINDOW_STRIDE: usize = 768;

/// One windowed slice of the normalized UTF-8 byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifierWindow {
    pub bytes: Vec<u8>,
    pub start: usize,
    pub end: usize,
}

fn is_unicode_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            | '\u{2001}'
            | '\u{2002}'
            | '\u{2003}'
            | '\u{2004}'
            | '\u{2005}'
            | '\u{2006}'
            | '\u{2007}'
            | '\u{2008}'
            | '\u{2009}'
            | '\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// Replace lone surrogates with U+FFFD (no-op for valid Rust `str`).
fn replace_lone_surrogates(text: &str) -> String {
    text.chars()
        .map(|c| {
            let code = c as u32;
            if (0xD800..=0xDFFF).contains(&code) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Normalize text: lone surrogates → U+FFFD, NFKC, unicode whitespace → space,
/// lowercase, trim a single leading/trailing ASCII space (after collapse).
pub fn normalize_classifier_text(text: &str) -> String {
    let replaced = replace_lone_surrogates(text);
    let nfkc: String = replaced.nfkc().collect();

    let mut collapsed = String::with_capacity(nfkc.len());
    let mut in_ws = false;
    for c in nfkc.chars() {
        if is_unicode_whitespace(c) {
            if !in_ws {
                collapsed.push(' ');
                in_ws = true;
            }
        } else {
            collapsed.push(c);
            in_ws = false;
        }
    }

    let lower = collapsed.to_lowercase();
    // Remove at most one leading and one trailing ASCII space (not full trim).
    let mut out = lower.as_str();
    if let Some(stripped) = out.strip_prefix(' ') {
        out = stripped;
    }
    if let Some(stripped) = out.strip_suffix(' ') {
        out = stripped;
    }
    out.to_string()
}

fn is_continuation_byte(value: u8) -> bool {
    (value & 0b1100_0000) == 0b1000_0000
}

/// Window the normalized UTF-8 byte stream with boundary snapping off continuation bytes.
pub fn window_classifier_ranges(
    text: &str,
    size: usize,
    stride: usize,
) -> Result<Vec<ClassifierWindow>, String> {
    if size == 0 || stride == 0 {
        return Err("size and stride must be positive integers".to_string());
    }

    let encoded = normalize_classifier_text(text).into_bytes();
    let mut windows = Vec::new();
    let mut previous_start: isize = -1;

    let mut nominal_start = 0usize;
    while nominal_start < encoded.len() {
        let mut start = nominal_start;
        while start > 0 && is_continuation_byte(encoded[start]) {
            start -= 1;
        }

        if start as isize == previous_start {
            nominal_start = nominal_start.saturating_add(stride);
            continue;
        }

        let mut end = (start + size).min(encoded.len());
        while end < encoded.len() && end > start && is_continuation_byte(encoded[end]) {
            end -= 1;
        }

        if end == start {
            return Err("size is too small for a UTF-8 code point".to_string());
        }

        windows.push(ClassifierWindow {
            bytes: encoded[start..end].to_vec(),
            start,
            end,
        });
        previous_start = start as isize;

        if end == encoded.len() {
            break;
        }

        nominal_start = nominal_start.saturating_add(stride);
    }

    Ok(windows)
}

/// Compatibility view over [`window_classifier_ranges`] for callers that only need bytes.
pub fn window_classifier_bytes(
    text: &str,
    size: usize,
    stride: usize,
) -> Result<Vec<Vec<u8>>, String> {
    Ok(window_classifier_ranges(text, size, stride)?
        .into_iter()
        .map(|w| w.bytes)
        .collect())
}

/// Default window size / stride from the artifact contract.
pub fn default_window_params() -> (usize, usize) {
    (DEFAULT_WINDOW_SIZE, DEFAULT_WINDOW_STRIDE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_basic() {
        assert_eq!(normalize_classifier_text("  HELLO WORLD  "), "hello world");
        assert_eq!(normalize_classifier_text("Ｆｏｏ ① K"), "foo 1 k");
    }

    #[test]
    fn window_empty() {
        let windows = window_classifier_ranges("", 1024, 768).unwrap();
        assert!(windows.is_empty());
    }
}
