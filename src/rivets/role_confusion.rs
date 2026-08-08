//! Role-confusion family rivet (ONNX classifier-backed).

use std::sync::Arc;

use serde_json::json;

use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::shared::classifier::{
    get_combined_classifier, ClassifierFamily, ClassifyFamilyOptions, CombinedClassifier,
};
use crate::shared::language_detection::{
    detect_lookalike_chars, has_language_script_mixing, LanguageDetector,
};
use crate::types::{ChainmailContext, ChainmailResult};

const DEFAULT_LANGUAGE: &str = "eng";
const HIGH_RISK_ROLE_CONFIDENCE_THRESHOLD: f64 = 0.7;

struct RoleConfusionRivet {
    classifier: Arc<CombinedClassifier>,
    languages_limit: usize,
    languages_detection_threshold: f64,
    confidence_threshold: Option<f64>,
    language_detector: LanguageDetector,
}

impl Rivet for RoleConfusionRivet {
    fn name(&self) -> &'static str {
        "role_confusion"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        if context.input.trim().is_empty() {
            return next(context);
        }

        let mut languages: Vec<(String, f64)> = self
            .language_detector
            .detect(&context.input, None)
            .into_iter()
            .filter(|(_, confidence)| *confidence > self.languages_detection_threshold)
            .collect();

        if languages.is_empty() {
            languages.push((DEFAULT_LANGUAGE.to_string(), 0.1));
        }

        let top_languages: Vec<(String, f64)> = languages
            .iter()
            .take(self.languages_limit)
            .cloned()
            .collect();
        let has_script_mixing = has_language_script_mixing(&context.sanitized);
        let has_lookalikes = detect_lookalike_chars(&context.sanitized);
        let primary_language = top_languages[0].0.clone();

        let result = self.classifier.classify_family(
            &context.sanitized,
            &primary_language,
            ClassifierFamily::RoleConfusion,
            ClassifyFamilyOptions {
                confidence_threshold: self.confidence_threshold,
            },
        );

        let attack_types = &result.attack_types;
        let max_confidence = result.confidence;
        let max_risk_score = result.risk_score;
        let is_attack = result.is_attack;

        if is_attack {
            context
                .flags
                .insert(security_flags::ROLE_CONFUSION.to_string());

            for attack_type in attack_types {
                match attack_type.as_str() {
                    "role_assumption" => {
                        context
                            .flags
                            .insert(security_flags::ROLE_CONFUSION_ROLE_ASSUMPTION.to_string());
                    }
                    "mode_switching" => {
                        context
                            .flags
                            .insert(security_flags::ROLE_CONFUSION_MODE_SWITCHING.to_string());
                    }
                    "permission_assertion" => {
                        context.flags.insert(
                            security_flags::ROLE_CONFUSION_PERMISSION_ASSERTION.to_string(),
                        );
                    }
                    "role_indicator" => {
                        context
                            .flags
                            .insert(security_flags::ROLE_CONFUSION_ROLE_INDICATOR.to_string());
                    }
                    _ => {}
                }
            }

            if max_confidence > HIGH_RISK_ROLE_CONFIDENCE_THRESHOLD && attack_types.len() > 1 {
                context
                    .flags
                    .insert(security_flags::ROLE_CONFUSION_HIGH_RISK_ROLE.to_string());
            }

            if languages.len() > 1 {
                context
                    .flags
                    .insert(security_flags::ROLE_CONFUSION_MULTILINGUAL_ATTACK.to_string());
            }

            if has_script_mixing {
                context
                    .flags
                    .insert(security_flags::ROLE_CONFUSION_SCRIPT_MIXING.to_string());
            }

            if has_lookalikes {
                context
                    .flags
                    .insert(security_flags::ROLE_CONFUSION_LOOKALIKE_CHARACTERS.to_string());
            }

            if max_confidence >= 0.4 {
                let threat_level = if max_confidence > 0.7 {
                    ThreatLevel::Critical
                } else if max_confidence > 0.5 {
                    ThreatLevel::High
                } else {
                    ThreatLevel::Medium
                };
                apply_threat_penalty(context, threat_level);
            }

            context
                .metadata
                .insert("role_confusion_detected".to_string(), json!(true));
            context.metadata.insert(
                "role_confusion_attack_types".to_string(),
                json!(attack_types),
            );
        } else {
            context
                .metadata
                .insert("role_confusion_detected".to_string(), json!(false));
            context
                .metadata
                .insert("role_confusion_attack_types".to_string(), json!([]));
        }

        context.metadata.insert(
            "role_confusion_confidence".to_string(),
            json!(max_confidence),
        );
        context.metadata.insert(
            "role_confusion_risk_score".to_string(),
            json!(max_risk_score),
        );
        context.metadata.insert(
            "role_confusion_dominant_language".to_string(),
            json!(primary_language),
        );
        context.metadata.insert(
            "role_confusion_detected_languages".to_string(),
            json!(top_languages
                .iter()
                .map(|(iso3, _)| iso3.clone())
                .collect::<Vec<_>>()),
        );
        context.metadata.insert(
            "role_confusion_matches".to_string(),
            json!(result.matches.unwrap_or_default()),
        );
        context
            .metadata
            .insert("has_script_mixing".to_string(), json!(has_script_mixing));
        context
            .metadata
            .insert("has_lookalikes".to_string(), json!(has_lookalikes));

        if let Some(detector_error) = result.detector_error {
            context
                .flags
                .insert(security_flags::CLASSIFIER_UNAVAILABLE.to_string());
            context.metadata.insert(
                "role_confusion_detector_error".to_string(),
                json!(detector_error),
            );
        }

        next(context)
    }
}

pub fn role_confusion(
    languages_limit: Option<usize>,
    languages_detection_threshold: Option<f64>,
    confidence_threshold: Option<f64>,
) -> Arc<dyn Rivet> {
    Arc::new(RoleConfusionRivet {
        classifier: get_combined_classifier(),
        languages_limit: languages_limit.unwrap_or(3),
        languages_detection_threshold: languages_detection_threshold.unwrap_or(0.6),
        confidence_threshold,
        language_detector: LanguageDetector::new(),
    })
}
