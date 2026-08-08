use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::Value;

use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

/// Template patterns; braces that are JS literals but Rust quantifiers are escaped.
static TEMPLATE_INJECTION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let sources: &[&str] = &[
        r"\{\{.*\}\}",
        r"\$\{.*\}",
        r"<%.*%>",
        r"\[\[.*\]\]",
        r"#\{.*\}",
        r"\{%.*%\}",
        r"(?i)\{php\}.*\{/php\}",
        r"(?i)\{literal\}.*\{/literal\}",
        r"(?i)\{if.*\}.*\{/if\}",
    ];

    sources
        .iter()
        .map(|pat| Regex::new(pat).expect("valid template injection pattern"))
        .collect()
});

struct TemplateInjectionRivet;

impl Rivet for TemplateInjectionRivet {
    fn name(&self) -> &'static str {
        "template_injection"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        for pattern in TEMPLATE_INJECTION_PATTERNS.iter() {
            if pattern.is_match(&context.sanitized) {
                context
                    .flags
                    .insert(security_flags::TEMPLATE_INJECTION.to_string());
                apply_threat_penalty(context, ThreatLevel::High);
                context.metadata.insert(
                    "template_pattern".to_string(),
                    Value::String(pattern.as_str().to_string()),
                );
                break;
            }
        }
        next(context)
    }
}

pub fn template_injection() -> Arc<dyn Rivet> {
    Arc::new(TemplateInjectionRivet)
}
