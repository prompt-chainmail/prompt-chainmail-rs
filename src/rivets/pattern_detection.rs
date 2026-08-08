use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::Value;

use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

static DEFAULT_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    create_pattern_detection_patterns()
});

/// Shared injection patterns used by `pattern_detection` and `encoding_detection` (ROT13).
pub fn create_pattern_detection_patterns() -> Vec<(Regex, &'static str)> {
    let sources: &[(&str, &str)] = &[
        (
            r"(?i)\b(you\s+are|act\s+as|behave\s+like)\s+(a\s+)?(admin|administrator|system|root|developer|expert|master)\b",
            "role_confusion",
        ),
        (
            r"(?i)\b(you\s+are\s+now|now\s+you\s+are)\s+(a\s+)?(helpful\s+)?(assistant|ai|bot|system)\s+(that|who)\s+(ignores?|disregards?|bypasses?)\b",
            "assistant_redefinition",
        ),
        (
            r"(?i)\b(ignore|forget|disregard|override)\s+(all\s+)?(previous\s+)?(instructions?|rules?|prompts?|safety\s+guidelines?)\b",
            "instruction_override",
        ),
        (
            r"(?i)\b(act\s+as\s+dan|as\s+dan|do\s+anything\s+now)\b",
            "dan_jailbreak",
        ),
        (
            r"(?i)\b(forget\s+everything\s+above\s+and\s+act)\b",
            "forget_and_act",
        ),
        (
            r"(?i)\b(switch\s+to|change\s+to|enter)\s+(developer|debug|admin|test)\s+mode\b",
            "mode_switching",
        ),
        (
            r"(?i)\b(system|admin)\s*:\s*(ignore|override|reset|disable)\b",
            "system_command",
        ),
        (
            r"(?i)\b(jailbreak|break\s+out|escape\s+from)\s+(the\s+)?(system|constraints?)\b",
            "jailbreak",
        ),
    ];

    sources
        .iter()
        .map(|(pat, label)| (Regex::new(pat).expect("valid pattern"), *label))
        .collect()
}

pub fn injection_patterns() -> &'static [(Regex, &'static str)] {
    DEFAULT_PATTERNS.as_slice()
}

struct PatternDetectionRivet {
    custom_patterns: Vec<Regex>,
}

impl Rivet for PatternDetectionRivet {
    fn name(&self) -> &'static str {
        "pattern_detection"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        for (pattern, label) in DEFAULT_PATTERNS.iter() {
            if pattern.is_match(&context.sanitized) {
                context
                    .flags
                    .insert(security_flags::INJECTION_PATTERN.to_string());
                apply_threat_penalty(context, ThreatLevel::High);
                context.metadata.insert(
                    "matched_pattern".to_string(),
                    Value::String((*label).to_string()),
                );
                return next(context);
            }
        }

        for pattern in &self.custom_patterns {
            if pattern.is_match(&context.sanitized) {
                context
                    .flags
                    .insert(security_flags::INJECTION_PATTERN.to_string());
                apply_threat_penalty(context, ThreatLevel::High);
                context.metadata.insert(
                    "matched_pattern".to_string(),
                    Value::String(pattern.as_str().to_string()),
                );
                break;
            }
        }

        next(context)
    }
}

/// Optional `custom_patterns`; defaults to the shared injection patterns.
pub fn pattern_detection(custom_patterns: Option<Vec<Regex>>) -> Arc<dyn Rivet> {
    Arc::new(PatternDetectionRivet {
        custom_patterns: custom_patterns.unwrap_or_default(),
    })
}
