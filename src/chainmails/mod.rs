//! Pre-forged chainmail configurations.

use crate::rivets::Rivets;
use crate::PromptChainmail;

pub struct Chainmails;

impl Chainmails {
    /// Basic protection: sanitize, patterns, role confusion, delimiters, confidence filter.
    ///
    /// Defaults: `max_length = 8000`, `confidence_filter = 0.6`.
    pub fn basic(max_length: Option<usize>, confidence_filter: Option<f64>) -> PromptChainmail {
        let max_length = max_length.or(Some(8000));
        let confidence_filter = confidence_filter.unwrap_or(0.6);
        PromptChainmail::new()
            .forge(Rivets::sanitize(max_length))
            .forge(Rivets::pattern_detection(None))
            .forge(Rivets::role_confusion(None, None, None))
            .forge(Rivets::delimiter_confusion())
            .forge(Rivets::confidence_filter(confidence_filter, None))
    }

    /// Advanced protection including encoding detection and rate limiting.
    ///
    /// Defaults: `max_length = 8000`, `confidence_filter = 0.6`.
    pub fn advanced(max_length: Option<usize>, confidence_filter: Option<f64>) -> PromptChainmail {
        let max_length = max_length.or(Some(8000));
        let confidence_filter = confidence_filter.unwrap_or(0.6);
        PromptChainmail::new()
            .forge(Rivets::sanitize(max_length))
            .forge(Rivets::pattern_detection(None))
            .forge(Rivets::role_confusion(None, None, None))
            .forge(Rivets::delimiter_confusion())
            .forge(Rivets::instruction_hijacking(None, None, None))
            .forge(Rivets::tool_use_hijacking(None, None, None))
            .forge(Rivets::code_injection())
            .forge(Rivets::sql_injection())
            .forge(Rivets::template_injection())
            .forge(Rivets::encoding_detection())
            .forge(Rivets::structure_analysis())
            .forge(Rivets::confidence_filter(confidence_filter, None))
            .forge(Rivets::rate_limit(None, None, None, None))
    }

    /// [`Self::advanced`] plus logging.
    pub fn development() -> PromptChainmail {
        Chainmails::advanced(None, None).forge(Rivets::logger(None, None))
    }

    /// Stricter defaults for high-security environments.
    ///
    /// Defaults: `max_length = 8000`, `confidence_filter = 0.8`,
    /// `rate_limit(50, 60000)`.
    pub fn strict(max_length: Option<usize>, confidence_filter: Option<f64>) -> PromptChainmail {
        let max_length = max_length.or(Some(8000));
        let confidence_filter = confidence_filter.unwrap_or(0.8);
        PromptChainmail::new()
            .forge(Rivets::sanitize(max_length))
            .forge(Rivets::pattern_detection(None))
            .forge(Rivets::role_confusion(None, None, None))
            .forge(Rivets::delimiter_confusion())
            .forge(Rivets::instruction_hijacking(None, None, None))
            .forge(Rivets::tool_use_hijacking(None, None, None))
            .forge(Rivets::code_injection())
            .forge(Rivets::sql_injection())
            .forge(Rivets::template_injection())
            .forge(Rivets::encoding_detection())
            .forge(Rivets::structure_analysis())
            .forge(Rivets::confidence_filter(confidence_filter, None))
            .forge(Rivets::rate_limit(Some(50), Some(60_000), None, None))
    }
}
