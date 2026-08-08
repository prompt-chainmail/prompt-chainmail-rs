//! Classifier types shared across the ONNX backend and family rivets.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::labels::ClassifierLabel;

/// Versioned artifact manifest contract (snake_case, matches models repo schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierManifest {
    pub attack_threshold: f64,
    pub thresholds: HashMap<String, f64>,
    pub schema_version: u32,
    pub artifact_version: String,
    pub model_sha256: String,
    pub model_size_bytes: u64,
    pub labels: Vec<String>,
    pub normalization_version: String,
    pub window_size_bytes: usize,
    pub window_stride_bytes: usize,
    pub corpus_revision: String,
    pub quantization: Quantization,
    pub metrics: Metrics,
    pub release_quality: bool,
    pub gate_failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quantization {
    pub format: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub macro_f1: f64,
    pub macro_recall: f64,
    pub benign_false_positive_rate: f64,
    pub attack_precision: f64,
    pub attack_recall: f64,
    pub attack_f1: f64,
    pub per_language: HashMap<String, LanguageRecall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageRecall {
    pub recall: f64,
}

/// A single classifier match — evidence for one label crossing its threshold.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassifierMatch {
    pub label: ClassifierLabel,
    pub probability: f64,
    pub window_index: usize,
    pub window_start_byte: usize,
    pub window_end_byte: usize,
    pub model_version: String,
}

/// Semantic detection result consumed by family rivets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticDetectionResult {
    pub is_attack: bool,
    pub attack_types: Vec<String>,
    pub confidence: f64,
    pub risk_score: f64,
    pub detected_language: String,
    pub details: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<Vec<ClassifierMatch>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_error: Option<String>,
}

/// Full classification for one input string from the dual-head model.
#[derive(Debug, Clone)]
pub struct ClassifierClassification {
    /// Max, across windows, of the binary attack head's sigmoid output.
    pub attack_probability: f64,
    /// Max, across windows, of the per-label subtype head's sigmoid output.
    pub probabilities: HashMap<ClassifierLabel, f64>,
    /// Subtype-label matches whose probability crossed its manifest threshold.
    pub matches: Vec<ClassifierMatch>,
    /// Present when a window failed to classify; other windows still contribute.
    pub window_errors: usize,
}

/// Risk-scoring knobs from `classifier_detector.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCalculationConfig {
    pub cybercrime_index_base: f64,
    pub max_attack_type_multiplier: f64,
    pub attack_type_divisor: f64,
    pub high_risk_boost: f64,
    pub max_risk_score: f64,
    #[serde(default)]
    pub fallback_threshold: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierDetectionConfig {
    pub risk_calculation: RiskCalculationConfig,
}

/// Optional additional confidence floor on top of per-label manifest thresholds.
#[derive(Debug, Clone, Default)]
pub struct ClassifyFamilyOptions {
    pub confidence_threshold: Option<f64>,
}
