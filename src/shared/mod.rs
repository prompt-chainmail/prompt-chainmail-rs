//! Shared utilities (language detection, regex patterns, classifier).

#[cfg(feature = "classifier")]
pub mod classifier;
pub mod configs;
pub mod language_detection;
pub mod regex_patterns;

pub use language_detection::{
    detect_lookalike_chars, has_language_script_mixing, normalize_text, DetectOptions,
    LanguageDetector,
};
pub use regex_patterns::{COMMON_PATTERNS, ENCODING_PATTERNS, HTML_ENTITIES};
