use std::sync::{Arc, LazyLock};

use regex::Regex;

use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::shared::{COMMON_PATTERNS, HTML_ENTITIES};
use crate::types::{ChainmailContext, ChainmailResult};

static HTML_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").unwrap());
static CONTROL_CHAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\x7F]").unwrap());

const CONTROL_CHAR_REPLACEMENT: &str = "[CTRL_REDACTED]";
const DEFAULT_MAX_LENGTH: usize = 8000;

struct SanitizeRivet {
    max_length: usize,
}

impl Rivet for SanitizeRivet {
    fn name(&self) -> &'static str {
        "sanitize"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let mut sanitized = context.sanitized.clone();
        let original_length = sanitized.len();

        let mut sanitized_html = sanitized.clone();
        while HTML_TAG.is_match(&sanitized_html) {
            sanitized_html = HTML_TAG.replace_all(&sanitized_html, "").into_owned();
        }
        if sanitized_html != sanitized {
            context
                .flags
                .insert(security_flags::SANITIZED_HTML_TAGS.to_string());
            sanitized = sanitized_html;
        }

        sanitized = HTML_ENTITIES.amp.replace_all(&sanitized, "&").into_owned();
        sanitized = HTML_ENTITIES.lt.replace_all(&sanitized, "<").into_owned();
        sanitized = HTML_ENTITIES.gt.replace_all(&sanitized, ">").into_owned();
        sanitized = HTML_ENTITIES.quot.replace_all(&sanitized, "\"").into_owned();
        sanitized = HTML_ENTITIES.apos.replace_all(&sanitized, "'").into_owned();

        let mut controls_removed = sanitized.clone();
        while CONTROL_CHAR.is_match(&controls_removed) {
            controls_removed = CONTROL_CHAR
                .replace_all(&controls_removed, CONTROL_CHAR_REPLACEMENT)
                .into_owned();
        }
        if controls_removed != sanitized {
            context
                .flags
                .insert(security_flags::SANITIZED_CONTROL_CHARS.to_string());
            sanitized = controls_removed;
        }

        let before_whitespace = sanitized.clone();
        let mut normalized = sanitized.clone();
        loop {
            match COMMON_PATTERNS.whitespace_multiple.find(&normalized) {
                Some(m) if m.as_str().len() > 1 => {
                    normalized = COMMON_PATTERNS
                        .whitespace_multiple
                        .replace(&normalized, " ")
                        .into_owned();
                }
                _ => break,
            }
        }
        sanitized = normalized.trim().to_string();

        if sanitized != before_whitespace {
            context
                .flags
                .insert(security_flags::SANITIZED_WHITESPACE.to_string());
        }

        if sanitized.len() > self.max_length {
            sanitized.truncate(self.max_length);
        }

        if sanitized.len() < original_length {
            if sanitized.len() < context.input.len() {
                context
                    .flags
                    .insert(security_flags::SANITIZED_CONTROL_CHARS.to_string());
            }

            let sanitization_ratio =
                (original_length - sanitized.len()) as f64 / original_length as f64;
            if sanitization_ratio > 0.1 {
                apply_threat_penalty(context, ThreatLevel::Medium);
            } else {
                apply_threat_penalty(context, ThreatLevel::Low);
            }
        }

        if sanitized.len() < context.input.len() {
            context.flags.insert(security_flags::TRUNCATED.to_string());
        }

        context.sanitized = sanitized;
        next(context)
    }
}

/// Strip HTML tags, normalize whitespace/control chars, enforce `max_length` (default 8000).
pub fn sanitize(max_length: Option<usize>) -> Arc<dyn Rivet> {
    Arc::new(SanitizeRivet {
        max_length: max_length.unwrap_or(DEFAULT_MAX_LENGTH),
    })
}
