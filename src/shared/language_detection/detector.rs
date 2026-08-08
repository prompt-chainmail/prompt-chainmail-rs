//! `LanguageDetector` wrapping `whatlang`.

use whatlang::{detect, Detector, Lang};

use super::normalize_text;

/// Optional allow/deny filters (ISO 639-3 codes).
#[derive(Debug, Clone, Default)]
pub struct DetectOptions {
    pub only: Option<Vec<String>>,
    pub ignore: Option<Vec<String>>,
}

#[derive(Debug, Default)]
pub struct LanguageDetector;

impl LanguageDetector {
    pub fn new() -> Self {
        Self
    }

    /// Ranked `(iso639-3, score)` pairs. On failure returns `[("und", 1.0)]`.
    ///
    /// `whatlang` exposes a single top language with confidence.
    pub fn detect(&self, text: &str, options: Option<&DetectOptions>) -> Vec<(String, f64)> {
        let normalized = normalize_text(text);
        if normalized.is_empty() {
            return vec![("und".to_string(), 1.0)];
        }

        let info = match build_detector(options) {
            Some(detector) => detector.detect(&normalized),
            None => detect(&normalized),
        };

        match info {
            Some(info) => {
                vec![(info.lang().code().to_string(), info.confidence())]
            }
            None => vec![("und".to_string(), 1.0)],
        }
    }
}

fn codes_to_langs(codes: &[String]) -> Vec<Lang> {
    codes
        .iter()
        .filter_map(|c| Lang::from_code(c.as_str()))
        .collect()
}

fn build_detector(options: Option<&DetectOptions>) -> Option<Detector> {
    let opts = options?;
    if let Some(only) = opts.only.as_ref() {
        let langs = codes_to_langs(only);
        if !langs.is_empty() {
            return Some(Detector::with_allowlist(langs));
        }
    }
    if let Some(ignore) = opts.ignore.as_ref() {
        let langs = codes_to_langs(ignore);
        if !langs.is_empty() {
            return Some(Detector::with_denylist(langs));
        }
    }
    None
}
