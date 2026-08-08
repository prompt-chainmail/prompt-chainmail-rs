use crate::types::ChainmailContext;
use crate::rivets::types::ThreatLevel;

/// Reduces confidence based on threat level, flag count, and content length.
pub fn apply_threat_penalty(context: &mut ChainmailContext, level: ThreatLevel) {
    let confidence = if context.confidence.is_finite() {
        context.confidence
    } else {
        1.0
    };
    let base_penalty = level.penalty();
    let global_severity_multiplier = 1.0;

    let mut adjusted_penalty = base_penalty * global_severity_multiplier;

    let flag_count = context.flags.len() as f64;
    let flag_scaling = (1.0 + flag_count * 0.025).min(2.5);
    adjusted_penalty *= flag_scaling;

    let content_length = context.sanitized.len() as f64;
    if content_length > 1000.0 {
        let length_scaling = (1.0 - content_length / 10000.0).max(0.5);
        adjusted_penalty *= length_scaling;
    }

    let result = (confidence - adjusted_penalty).max(0.0);
    context.confidence = (result * 1000.0).round() / 1000.0;
}
