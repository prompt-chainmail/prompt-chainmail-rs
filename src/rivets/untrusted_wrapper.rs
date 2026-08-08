use std::sync::Arc;

use serde_json::Value;

use crate::rivets::types::security_flags;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

struct UntrustedWrapperRivet {
    tag_name: String,
    preserve_original: bool,
}

impl Rivet for UntrustedWrapperRivet {
    fn name(&self) -> &'static str {
        "untrusted_wrapper"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let wrapped_content = format!(
            "<{}>\n{}\n</{}>",
            self.tag_name, context.sanitized, self.tag_name
        );

        if self.preserve_original {
            context.metadata.insert(
                "original_content".to_string(),
                Value::String(context.sanitized.clone()),
            );
        }

        context.sanitized = wrapped_content;
        context
            .flags
            .insert(security_flags::UNTRUSTED_WRAPPED.to_string());

        next(context)
    }
}

/// Wraps content in a tag (optionally preserving the original).
///
/// Defaults: `tag_name="UNTRUSTED_CONTENT"`, `preserve_original=false`.
pub fn untrusted_wrapper(tag_name: Option<&str>, preserve_original: Option<bool>) -> Arc<dyn Rivet> {
    Arc::new(UntrustedWrapperRivet {
        tag_name: tag_name.unwrap_or("UNTRUSTED_CONTENT").to_string(),
        preserve_original: preserve_original.unwrap_or(false),
    })
}
