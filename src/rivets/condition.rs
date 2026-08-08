use std::sync::Arc;

use crate::rivets::types::ThreatLevel;
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

type Predicate = Arc<dyn Fn(&ChainmailContext) -> bool + Send + Sync>;

struct ConditionRivet {
    predicate: Predicate,
    flag_name: String,
    confidence_multiplier: f64,
}

impl Rivet for ConditionRivet {
    fn name(&self) -> &'static str {
        "condition"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        if (self.predicate)(context) {
            context.flags.insert(self.flag_name.clone());
            let penalty = if self.confidence_multiplier <= 0.5 {
                ThreatLevel::High
            } else if self.confidence_multiplier <= 0.7 {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };
            apply_threat_penalty(context, penalty);
        }
        next(context)
    }
}

/// Applies a flag and confidence penalty when `predicate` returns true.
///
/// Defaults: `flag_name="custom_condition"`, `confidence_multiplier=0.8`.
pub fn condition(
    predicate: Predicate,
    flag_name: Option<&str>,
    confidence_multiplier: Option<f64>,
) -> Arc<dyn Rivet> {
    Arc::new(ConditionRivet {
        predicate,
        flag_name: flag_name.unwrap_or("custom_condition").to_string(),
        confidence_multiplier: confidence_multiplier.unwrap_or(0.8),
    })
}
