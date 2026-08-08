use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::Value;

use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

static DELIMITER_CONFUSION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let sources: &[&str] = &[
        r#""{3,}|'{3,}"#,
        r"`{3,}",
        r"(?i)</(?:prompt|system|instruction|assistant|user|human|ai|bot)>",
        r"(?i)</(?:example|demo|test|input|output|response)>",
        r"(?i)\[(?:END|STOP|DONE|EXIT|QUIT)\]",
        r"(?i)(?:---|\*\*\*|===)(?:END|STOP|DONE)(?:---|\*\*\*|===)",
        r"\{{3,}|\}{3,}",
        r"\[\[\[|\]\]\]",
        r"\$\${2,}|#{3,}",
        r"!{3,}|\?{3,}",
        r"(?i)\[/(?:INST|SYS)\]|\[(?:INST|SYS)\]",
        r"(?i)<\|(?:endoftext|im_end|im_start|end_of_turn)\|>",
        r"(?i)<(?:start|end)_of_turn>",
        r"```[\s\S]*?```",
        r"~~~[\s\S]*?~~~",
        r"<!--[\s\S]*?-->",
        r"/\*[\s\S]*?\*/",
        r"(?m)//.*$",
        r"(?i)<(?:system|instruction|prompt)>[\s\S]*?</(?:system|instruction|prompt)>",
        r"(?i)\[(?:SYSTEM|INSTRUCTION|PROMPT)\][\s\S]*?\[/(?:SYSTEM|INSTRUCTION|PROMPT)\]",
        r"(?i)<(?:user|human|assistant|ai|bot)>[\s\S]*?</(?:user|human|assistant|ai|bot)>",
        r"(?i)\[(?:USER|HUMAN|ASSISTANT|AI|BOT)\][\s\S]*?\[/(?:USER|HUMAN|ASSISTANT|AI|BOT)\]",
        r"[-=_]{10,}",
        r"\*{5,}",
        r"\\n\\n\\n+",
        r"\\[trn]{3,}",
        r"(?:%[0-9A-Fa-f]{2}){5,}",
        r"(?:&#x?[0-9A-Fa-f]+;){3,}",
        r"[\x01-\x1F\x7F]{2,}",
        r"[\u{2000}-\u{200F}\u{202A}-\u{202E}]",
    ];

    sources
        .iter()
        .map(|pat| Regex::new(pat).expect("valid delimiter confusion pattern"))
        .collect()
});

struct DelimiterConfusionRivet;

impl Rivet for DelimiterConfusionRivet {
    fn name(&self) -> &'static str {
        "delimiter_confusion"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        for pattern in DELIMITER_CONFUSION_PATTERNS.iter() {
            if pattern.is_match(&context.sanitized) {
                context
                    .flags
                    .insert(security_flags::DELIMITER_CONFUSION.to_string());
                apply_threat_penalty(context, ThreatLevel::High);
                context.metadata.insert(
                    "delimiter_pattern".to_string(),
                    Value::String(pattern.as_str().to_string()),
                );
                break;
            }
        }
        next(context)
    }
}

pub fn delimiter_confusion() -> Arc<dyn Rivet> {
    Arc::new(DelimiterConfusionRivet)
}
