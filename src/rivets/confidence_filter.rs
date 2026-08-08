use std::sync::Arc;

use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

struct ConfidenceFilterRivet {
    min_threshold: f64,
    max_threshold: Option<f64>,
}

impl Rivet for ConfidenceFilterRivet {
    fn name(&self) -> &'static str {
        "confidence_filter"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let should_block = match self.max_threshold {
            Some(max) => context.confidence >= self.min_threshold && context.confidence <= max,
            None => context.confidence < self.min_threshold,
        };

        if should_block {
            context.set_blocked(true);
        }

        next(context)
    }
}

/// Blocks requests based on confidence thresholds.
///
/// When only `min_threshold` is provided, blocks content with confidence below
/// the threshold. When both are provided, blocks content within the range.
pub fn confidence_filter(min_threshold: f64, max_threshold: Option<f64>) -> Arc<dyn Rivet> {
    Arc::new(ConfidenceFilterRivet {
        min_threshold,
        max_threshold,
    })
}
