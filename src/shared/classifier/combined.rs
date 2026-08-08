//! Family-filtered classification API (sync).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use super::backend::ClassifierBackend;
use super::config::ClassifierConfigLoader;
use super::labels::{labels_for_family, ClassifierFamily};
use super::manifest::CLASSIFIER_MANIFEST;
use super::risk::{calculate_language_code_risk_score, language_group_for_code};
use super::types::{ClassifyFamilyOptions, SemanticDetectionResult};

fn empty_result(language_code: &str) -> SemanticDetectionResult {
    SemanticDetectionResult {
        is_attack: false,
        attack_types: Vec::new(),
        confidence: 0.0,
        risk_score: 0.0,
        detected_language: language_code.to_string(),
        details: Vec::new(),
        matches: Some(Vec::new()),
        detector_error: None,
    }
}

/// Wrapper around the classifier backend. Family rivets share one instance so
/// the same sanitized text is classified once and filtered per attack family.
pub struct CombinedClassifier {
    backend: ClassifierBackend,
}

impl Default for CombinedClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CombinedClassifier {
    pub fn new() -> Self {
        Self {
            backend: ClassifierBackend::default(),
        }
    }

    pub fn with_backend(backend: ClassifierBackend) -> Self {
        Self { backend }
    }

    /// Classify `text` and keep matches belonging to `family`.
    pub fn classify_family(
        &self,
        text: &str,
        language_code: &str,
        family: ClassifierFamily,
        options: ClassifyFamilyOptions,
    ) -> SemanticDetectionResult {
        if text.trim().is_empty() {
            return empty_result(language_code);
        }

        let classification = match self.backend.classify(text) {
            Ok(c) => c,
            Err(error) => {
                let detector_error_code = error.code;
                let mut result = empty_result(language_code);
                result.details = vec![format!(
                    "Classifier detection error: {detector_error_code}"
                )];
                result.detector_error = Some(detector_error_code);
                return result;
            }
        };

        let family_labels: HashSet<&str> = labels_for_family(family).iter().copied().collect();
        let language_group = language_group_for_code(language_code);
        let risk_config = ClassifierConfigLoader::get(family);

        let matches: Vec<_> = classification
            .matches
            .iter()
            .filter(|m| family_labels.contains(m.label.as_str()))
            .cloned()
            .collect();

        let mut attack_types: Vec<String> = matches.iter().map(|m| m.label.clone()).collect();
        attack_types.sort();
        attack_types.dedup();

        let confidence = classification.attack_probability;
        let passes_attack_threshold = confidence >= CLASSIFIER_MANIFEST.attack_threshold;
        let passes_confidence_floor = options
            .confidence_threshold
            .map(|t| confidence >= t)
            .unwrap_or(true);
        let passes_attack_gate =
            passes_attack_threshold || family == ClassifierFamily::ToolUseHijacking;
        let is_attack =
            passes_attack_gate && !attack_types.is_empty() && passes_confidence_floor;

        let risk_score = if is_attack {
            calculate_language_code_risk_score(
                confidence,
                &language_group,
                attack_types.len(),
                &risk_config.risk_calculation,
            )
        } else {
            0.0
        };

        let details = matches
            .iter()
            .map(|m| {
                format!(
                    "Classifier label {} probability {:.3} (window {})",
                    m.label, m.probability, m.window_index
                )
            })
            .collect();

        SemanticDetectionResult {
            is_attack,
            attack_types: if is_attack {
                attack_types
            } else {
                Vec::new()
            },
            confidence,
            risk_score,
            detected_language: if language_group.is_empty() {
                language_code.to_string()
            } else {
                language_group
            },
            details,
            matches: Some(matches),
            detector_error: None,
        }
    }
}

static SHARED: OnceLock<Mutex<Option<Arc<CombinedClassifier>>>> = OnceLock::new();

fn shared_slot() -> &'static Mutex<Option<Arc<CombinedClassifier>>> {
    SHARED.get_or_init(|| Mutex::new(None))
}

/// Shared classifier instance reused across requests and family rivets.
pub fn get_combined_classifier() -> Arc<CombinedClassifier> {
    let mut guard = shared_slot().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = guard.as_ref() {
        return Arc::clone(existing);
    }
    let created = Arc::new(CombinedClassifier::new());
    *guard = Some(Arc::clone(&created));
    created
}

/// Test-only hook to inject a fake classifier.
#[doc(hidden)]
pub fn set_combined_classifier_for_tests(classifier: CombinedClassifier) {
    let mut guard = shared_slot().lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(Arc::new(classifier));
}

/// Test-only hook to restore the default shared classifier.
#[doc(hidden)]
pub fn reset_combined_classifier_for_tests() {
    let mut guard = shared_slot().lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

