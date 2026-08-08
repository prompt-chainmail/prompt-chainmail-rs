//! Instruction-hijacking family rivet (ONNX classifier-backed).

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

struct InstructionHijackingRivet {
    classifier: Arc<CombinedClassifier>,
    languages_limit: usize,
    languages_detection_threshold: f64,
    confidence_threshold: Option<f64>,
    language_detector: LanguageDetector,
}

impl Rivet for InstructionHijackingRivet {
    fn name(&self) -> &'static str {
        "instruction_hijacking"
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
            ClassifierFamily::InstructionHijacking,
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
                .insert(security_flags::INSTRUCTION_HIJACKING.to_string());

            for attack_type in attack_types {
                match attack_type.as_str() {
                    "instruction_override" => {
                        context
                            .flags
                            .insert(security_flags::INSTRUCTION_HIJACKING_OVERRIDE.to_string());
                    }
                    "instruction_forgetting" => {
                        context
                            .flags
                            .insert(security_flags::INSTRUCTION_HIJACKING_IGNORE.to_string());
                    }
                    "reset_system" => {
                        context
                            .flags
                            .insert(security_flags::INSTRUCTION_HIJACKING_RESET.to_string());
                    }
                    "bypass_security" => {
                        context
                            .flags
                            .insert(security_flags::INSTRUCTION_HIJACKING_BYPASS.to_string());
                    }
                    "information_extraction" => {
                        context
                            .flags
                            .insert(security_flags::INSTRUCTION_HIJACKING_REVEAL.to_string());
                    }
                    _ => {
                        context
                            .flags
                            .insert(security_flags::INSTRUCTION_HIJACKING_UNKNOWN.to_string());
                    }
                }
            }

            if languages.len() > 1 {
                context.flags.insert(
                    security_flags::INSTRUCTION_HIJACKING_MULTILINGUAL_ATTACK.to_string(),
                );
            }

            if has_script_mixing {
                context
                    .flags
                    .insert(security_flags::INSTRUCTION_HIJACKING_SCRIPT_MIXING.to_string());
            }

            if has_lookalikes {
                context
                    .flags
                    .insert(security_flags::INSTRUCTION_HIJACKING_LOOKALIKES.to_string());
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
                .insert("instruction_hijacking_detected".to_string(), json!(true));
            context.metadata.insert(
                "instruction_hijacking_attack_types".to_string(),
                json!(attack_types),
            );
        } else {
            context
                .metadata
                .insert("instruction_hijacking_detected".to_string(), json!(false));
            context.metadata.insert(
                "instruction_hijacking_attack_types".to_string(),
                json!([]),
            );
        }

        context.metadata.insert(
            "instruction_hijacking_confidence".to_string(),
            json!(max_confidence),
        );
        context.metadata.insert(
            "instruction_hijacking_risk_score".to_string(),
            json!(max_risk_score),
        );
        context.metadata.insert(
            "instruction_hijacking_detected_language".to_string(),
            json!(primary_language),
        );
        context.metadata.insert(
            "instruction_hijacking_detected_languages".to_string(),
            json!(top_languages
                .iter()
                .map(|(iso3, _)| iso3.clone())
                .collect::<Vec<_>>()),
        );
        context.metadata.insert(
            "instruction_hijacking_matches".to_string(),
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
                "instruction_hijacking_detector_error".to_string(),
                json!(detector_error),
            );
        }

        next(context)
    }
}

pub fn instruction_hijacking(
    languages_limit: Option<usize>,
    languages_detection_threshold: Option<f64>,
    confidence_threshold: Option<f64>,
) -> Arc<dyn Rivet> {
    Arc::new(InstructionHijackingRivet {
        classifier: get_combined_classifier(),
        languages_limit: languages_limit.unwrap_or(3),
        languages_detection_threshold: languages_detection_threshold.unwrap_or(0.1),
        confidence_threshold,
        language_detector: LanguageDetector::new(),
    })
}
