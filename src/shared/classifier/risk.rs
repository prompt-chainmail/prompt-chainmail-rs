//! Language-weighted risk scoring for classifier detections.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

use super::types::RiskCalculationConfig;
use crate::shared::configs::{
    LANGUAGE_ISO3_TO_LANGUAGE_GROUPS_JSON, LANGUAGE_REGION_CYBERCRIME_INDEX_JSON,
};

#[derive(Deserialize)]
struct ConfigWrapper<T> {
    value: T,
}

static LANGUAGE_GROUP_MAP: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let wrapper: ConfigWrapper<HashMap<String, String>> =
        serde_json::from_str(LANGUAGE_ISO3_TO_LANGUAGE_GROUPS_JSON)
            .expect("language_iso3_to_language_groups.json");
    wrapper.value
});

static CYBERCRIME_INDEX: LazyLock<HashMap<String, f64>> = LazyLock::new(|| {
    let wrapper: ConfigWrapper<HashMap<String, f64>> =
        serde_json::from_str(LANGUAGE_REGION_CYBERCRIME_INDEX_JSON)
            .expect("language_region_cybercrime_index.json");
    wrapper.value
});

static FIFTH_HIGHEST_THRESHOLD: LazyLock<f64> = LazyLock::new(|| {
    let mut values: Vec<f64> = CYBERCRIME_INDEX.values().copied().collect();
    values.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    values.get(4).copied().unwrap_or(0.0)
});

/// ISO 639-3 → language group (defaults to `"eng"`).
pub fn language_group_for_code(language_code: &str) -> String {
    LANGUAGE_GROUP_MAP
        .get(language_code)
        .cloned()
        .unwrap_or_else(|| "eng".to_string())
}

/// Weights raw classifier confidence by cybercrime index and attack-type count.
pub fn calculate_language_code_risk_score(
    confidence: f64,
    language_group: &str,
    attack_type_count: usize,
    config: &RiskCalculationConfig,
) -> f64 {
    let base_risk = confidence * 100.0;

    let cybercrime_index_value = CYBERCRIME_INDEX
        .get(language_group)
        .copied()
        .unwrap_or(config.cybercrime_index_base);
    let cybercrime_multiplier = cybercrime_index_value / config.cybercrime_index_base;

    let calculated_multiplier = attack_type_count as f64 / config.attack_type_divisor;
    let attack_type_multiplier = if calculated_multiplier < config.max_attack_type_multiplier {
        calculated_multiplier
    } else {
        config.max_attack_type_multiplier
    };

    let fifth_highest = if *FIFTH_HIGHEST_THRESHOLD > 0.0 {
        *FIFTH_HIGHEST_THRESHOLD
    } else {
        config.fallback_threshold.unwrap_or(50.0)
    };

    let risk_boost = if attack_type_count > 1 && cybercrime_index_value >= fifth_highest {
        config.high_risk_boost
    } else {
        1.0
    };

    let risk_score =
        base_risk * cybercrime_multiplier * (1.0 + attack_type_multiplier) * risk_boost;
    if risk_score < config.max_risk_score {
        risk_score
    } else {
        config.max_risk_score
    }
}
