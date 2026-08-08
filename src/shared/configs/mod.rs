//! Embedded JSON configs for classifier risk scoring.

#![allow(dead_code)]

/// ISO 639-3 code → language group mapping used by classifier risk scoring.
pub const LANGUAGE_ISO3_TO_LANGUAGE_GROUPS_JSON: &str =
    include_str!("language_iso3_to_language_groups.json");

/// Language-region cybercrime index used by classifier risk scoring.
pub const LANGUAGE_REGION_CYBERCRIME_INDEX_JSON: &str =
    include_str!("language_region_cybercrime_index.json");

/// Classifier detector metadata (model id, labels, thresholds).
pub const CLASSIFIER_DETECTOR_JSON: &str = include_str!("classifier_detector.json");
