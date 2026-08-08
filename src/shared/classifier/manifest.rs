//! Manifest load + structural validation.

use std::sync::LazyLock;

use super::labels::CLASSIFIER_LABELS;
use super::types::ClassifierManifest;

#[derive(Debug, Clone)]
pub struct ClassifierManifestError {
    pub message: String,
}

impl std::fmt::Display for ClassifierManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ClassifierManifestError {}

const SHA256_HEX_PATTERN: &str = r"^[0-9a-f]{64}$";

fn is_probability(value: f64) -> bool {
    (0.0..=1.0).contains(&value) && value.is_finite()
}

fn fail(message: impl Into<String>) -> ClassifierManifestError {
    ClassifierManifestError {
        message: message.into(),
    }
}

pub fn validate_manifest(candidate: &serde_json::Value) -> Result<ClassifierManifest, ClassifierManifestError> {
    let obj = candidate
        .as_object()
        .ok_or_else(|| fail("Classifier manifest must be an object"))?;

    let schema_version = obj
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| fail("Classifier manifest schema_version missing"))?;
    if schema_version != 1 {
        return Err(fail(format!(
            "Unsupported classifier manifest schema_version: {schema_version}"
        )));
    }

    let artifact_version = obj
        .get("artifact_version")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail("Classifier manifest artifact_version must be a non-empty string"))?
        .to_string();

    let model_sha256 = obj
        .get("model_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| fail("Classifier manifest model_sha256 must be a 64-character hex string"))?
        .to_string();
    if model_sha256.len() != 64 || !model_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(fail(
            "Classifier manifest model_sha256 must be a 64-character hex string",
        ));
    }
    // Require lowercase hex.
    if !regex::Regex::new(SHA256_HEX_PATTERN)
        .expect("static regex")
        .is_match(&model_sha256)
    {
        return Err(fail(
            "Classifier manifest model_sha256 must be a 64-character hex string",
        ));
    }

    let model_size_bytes = obj
        .get("model_size_bytes")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            fail("Classifier manifest model_size_bytes must be between 1 byte and 10 MiB")
        })?;
    if model_size_bytes == 0 || model_size_bytes > 10 * 1024 * 1024 {
        return Err(fail(
            "Classifier manifest model_size_bytes must be between 1 byte and 10 MiB",
        ));
    }

    let labels = obj
        .get("labels")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            fail(format!(
                "Classifier manifest labels must exactly equal {:?} in order",
                CLASSIFIER_LABELS
            ))
        })?;
    if labels.len() != CLASSIFIER_LABELS.len()
        || !labels
            .iter()
            .zip(CLASSIFIER_LABELS.iter())
            .all(|(a, b)| a.as_str() == Some(*b))
    {
        return Err(fail(format!(
            "Classifier manifest labels must exactly equal {:?} in order",
            CLASSIFIER_LABELS
        )));
    }

    let normalization_version = obj
        .get("normalization_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| fail("Unsupported classifier normalization_version: <missing>"))?;
    if normalization_version != "nfkc-whitespace-lower-v1" {
        return Err(fail(format!(
            "Unsupported classifier normalization_version: {normalization_version}"
        )));
    }

    let window_size_bytes = obj
        .get("window_size_bytes")
        .and_then(|v| v.as_u64())
        .filter(|&n| n > 0)
        .ok_or_else(|| fail("Classifier manifest window_size_bytes must be a positive number"))?
        as usize;

    let window_stride_bytes = obj
        .get("window_stride_bytes")
        .and_then(|v| v.as_u64())
        .filter(|&n| n > 0)
        .ok_or_else(|| fail("Classifier manifest window_stride_bytes must be a positive number"))?
        as usize;

    let thresholds = obj
        .get("thresholds")
        .and_then(|v| v.as_object())
        .ok_or_else(|| fail("Classifier manifest thresholds must be an object"))?;
    for label in CLASSIFIER_LABELS {
        let Some(v) = thresholds.get(*label).and_then(|v| v.as_f64()) else {
            return Err(fail(format!(
                "Classifier manifest thresholds.{label} must be a number between 0 and 1"
            )));
        };
        if !is_probability(v) {
            return Err(fail(format!(
                "Classifier manifest thresholds.{label} must be a number between 0 and 1"
            )));
        }
    }

    let attack_threshold = obj
        .get("attack_threshold")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| {
            fail("Classifier manifest attack_threshold must be a number between 0 and 1")
        })?;
    if !is_probability(attack_threshold) {
        return Err(fail(
            "Classifier manifest attack_threshold must be a number between 0 and 1",
        ));
    }

    let corpus_revision = obj
        .get("corpus_revision")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail("Classifier manifest corpus_revision must be a non-empty string"))?
        .to_string();

    let quantization = obj
        .get("quantization")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            fail(
                "Classifier manifest quantization must be { format: 'INT8' | 'FLOAT32', method: string }",
            )
        })?;
    let q_format = quantization
        .get("format")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            fail(
                "Classifier manifest quantization must be { format: 'INT8' | 'FLOAT32', method: string }",
            )
        })?;
    if q_format != "INT8" && q_format != "FLOAT32" {
        return Err(fail(
            "Classifier manifest quantization must be { format: 'INT8' | 'FLOAT32', method: string }",
        ));
    }
    let q_method = quantization
        .get("method")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            fail(
                "Classifier manifest quantization must be { format: 'INT8' | 'FLOAT32', method: string }",
            )
        })?;

    let metrics = obj
        .get("metrics")
        .and_then(|v| v.as_object())
        .ok_or_else(|| fail("Classifier manifest metrics are missing or malformed"))?;
    for key in [
        "macro_f1",
        "macro_recall",
        "benign_false_positive_rate",
        "attack_precision",
        "attack_recall",
        "attack_f1",
    ] {
        let Some(v) = metrics.get(key).and_then(|v| v.as_f64()) else {
            return Err(fail("Classifier manifest metrics are missing or malformed"));
        };
        if !is_probability(v) {
            return Err(fail("Classifier manifest metrics are missing or malformed"));
        }
    }
    if !metrics
        .get("per_language")
        .map(|v| v.is_object())
        .unwrap_or(false)
    {
        return Err(fail("Classifier manifest metrics are missing or malformed"));
    }

    let release_quality = obj
        .get("release_quality")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| fail("Classifier manifest release_quality must be a boolean"))?;

    let gate_failures = obj
        .get("gate_failures")
        .and_then(|v| v.as_array())
        .ok_or_else(|| fail("Classifier manifest gate_failures must be an array of strings"))?;
    if !gate_failures.iter().all(|v| v.is_string()) {
        return Err(fail(
            "Classifier manifest gate_failures must be an array of strings",
        ));
    }
    if !release_quality && gate_failures.is_empty() {
        return Err(fail(
            "Classifier manifest release_quality is false but gate_failures is empty; \
             a non-release artifact must record why it failed release gates",
        ));
    }

    // Re-parse through serde for the typed struct after structural checks.
    serde_json::from_value(candidate.clone()).map_err(|e| fail(e.to_string()))
        .map(|mut m: ClassifierManifest| {
                    m.artifact_version = artifact_version;
            m.model_sha256 = model_sha256;
            m.model_size_bytes = model_size_bytes;
            m.normalization_version = normalization_version.to_string();
            m.window_size_bytes = window_size_bytes;
            m.window_stride_bytes = window_stride_bytes;
            m.corpus_revision = corpus_revision;
            m.quantization.format = q_format.to_string();
            m.quantization.method = q_method.to_string();
            m.release_quality = release_quality;
            m
        })
}

pub const EMBEDDED_MANIFEST_JSON: &str = include_str!("manifest.json");

pub static CLASSIFIER_MANIFEST: LazyLock<ClassifierManifest> = LazyLock::new(|| {
    let value: serde_json::Value =
        serde_json::from_str(EMBEDDED_MANIFEST_JSON).expect("embedded classifier manifest JSON");
    validate_manifest(&value).expect("embedded classifier manifest must validate")
});
