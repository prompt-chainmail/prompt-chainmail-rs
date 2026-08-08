use std::collections::HashSet;
use std::sync::Arc;

use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::shared::COMMON_PATTERNS;
use crate::types::{ChainmailContext, ChainmailResult};

const EXCESSIVE_LINES_THRESHOLD: usize = 50;
const NON_ASCII_THRESHOLD: f64 = 0.3;
const WORD_THRESHOLD: usize = 10;
const UNIQUE_WORDS_THRESHOLD: f64 = 0.3;

struct StructureAnalysisRivet;

impl Rivet for StructureAnalysisRivet {
    fn name(&self) -> &'static str {
        "structure_analysis"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let lines: Vec<&str> = context.sanitized.split('\n').collect();

        if lines.len() > EXCESSIVE_LINES_THRESHOLD {
            context
                .flags
                .insert(security_flags::EXCESSIVE_LINES.to_string());
            apply_threat_penalty(context, ThreatLevel::Low);
        }

        let char_len = context.sanitized.chars().count();
        let non_ascii = context
            .sanitized
            .chars()
            .filter(|c| {
                let u = *c as u32;
                !(0x20..=0x7E).contains(&u)
            })
            .count();
        if char_len > 0 && (non_ascii as f64) / (char_len as f64) > NON_ASCII_THRESHOLD {
            context
                .flags
                .insert(security_flags::NON_ASCII_HEAVY.to_string());
            apply_threat_penalty(context, ThreatLevel::Low);
        }

        let lower = context.sanitized.to_lowercase();
        let words: Vec<&str> = COMMON_PATTERNS.whitespace_multiple.split(&lower).collect();
        let unique_words: HashSet<&str> = words.iter().copied().collect();
        if words.len() > WORD_THRESHOLD
            && (unique_words.len() as f64) / (words.len() as f64) < UNIQUE_WORDS_THRESHOLD
        {
            context
                .flags
                .insert(security_flags::REPETITIVE_CONTENT.to_string());
            apply_threat_penalty(context, ThreatLevel::Low);
        }

        next(context)
    }
}

pub fn structure_analysis() -> Arc<dyn Rivet> {
    Arc::new(StructureAnalysisRivet)
}
