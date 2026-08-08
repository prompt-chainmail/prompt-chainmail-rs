//! Per-family risk-scoring configuration loader.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

use super::labels::ClassifierFamily;
use super::types::{ClassifierDetectionConfig, RiskCalculationConfig};
use crate::shared::configs::CLASSIFIER_DETECTOR_JSON;

#[derive(Deserialize)]
struct FamilyConfig {
    risk_calculation: RiskCalculationConfig,
}

#[derive(Deserialize)]
struct Wrapper {
    value: HashMap<String, FamilyConfig>,
}

static DETECTOR_CONFIG: LazyLock<HashMap<String, FamilyConfig>> = LazyLock::new(|| {
    let wrapper: Wrapper =
        serde_json::from_str(CLASSIFIER_DETECTOR_JSON).expect("classifier_detector.json");
    wrapper.value
});

pub struct ClassifierConfigLoader;

impl ClassifierConfigLoader {
    pub fn get(family: ClassifierFamily) -> ClassifierDetectionConfig {
        let key = family.as_str();
        let config = DETECTOR_CONFIG
            .get(key)
            .unwrap_or_else(|| panic!("missing classifier_detector config for {key}"));
        ClassifierDetectionConfig {
            risk_calculation: config.risk_calculation.clone(),
        }
    }
}
