//! Offline ONNX classifier shared by family rivets.
//!
//! Enabled by the `classifier` Cargo feature (default).

mod backend;
mod cache;
mod checksum;
mod combined;
mod config;
mod labels;
mod manifest;
mod normalize;
mod risk;
mod session;
mod types;

pub use backend::ClassifierBackend;
pub use cache::BoundedCache;
pub use checksum::sha256_hex;
pub use combined::{
    get_combined_classifier, reset_combined_classifier_for_tests, set_combined_classifier_for_tests,
    CombinedClassifier,
};
pub use labels::{
    labels_for_family, ClassifierFamily, CLASSIFIER_LABELS, INSTRUCTION_HIJACKING_LABELS,
    ROLE_CONFUSION_LABELS, TOOL_USE_HIJACKING_LABELS,
};
pub use manifest::{validate_manifest, CLASSIFIER_MANIFEST, EMBEDDED_MANIFEST_JSON};
pub use normalize::{
    default_window_params, normalize_classifier_text, window_classifier_bytes,
    window_classifier_ranges, ClassifierWindow,
};
pub use risk::{calculate_language_code_risk_score, language_group_for_code};
pub use session::{
    embedded_model_bytes, get_classifier_session, load_and_verify_model,
    load_classifier_model_bytes, pinned_model_version, resolve_model_dir, ClassifierError,
    ClassifierSessionHandle,
};
#[cfg(feature = "parallel")]
pub use session::{get_classifier_session_pool, ClassifierSessionPool};
pub use types::{
    ClassifierClassification, ClassifierDetectionConfig, ClassifierMatch, ClassifierManifest,
    ClassifyFamilyOptions, RiskCalculationConfig, SemanticDetectionResult,
};
