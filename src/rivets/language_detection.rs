use std::sync::Arc;

use serde_json::{json, Value};

use crate::rivets::Rivet;
use crate::shared::language_detection::LanguageDetector;
use crate::types::{ChainmailContext, ChainmailResult};

struct LanguageDetectionRivet {
    detector: LanguageDetector,
}

impl Rivet for LanguageDetectionRivet {
    fn name(&self) -> &'static str {
        "language_detection"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let detected = self.detector.detect(&context.sanitized, None);
        let pairs: Vec<Value> = detected
            .into_iter()
            .map(|(code, score)| json!([code, score]))
            .collect();
        context
            .metadata
            .insert("detected_languages".to_string(), Value::Array(pairs));
        next(context)
    }
}

/// Attempts to detect prompt language and stores results in
/// `context.metadata["detected_languages"]` as `[[code, score], ...]`.
pub fn language_detection() -> Arc<dyn Rivet> {
    Arc::new(LanguageDetectionRivet {
        detector: LanguageDetector::new(),
    })
}
