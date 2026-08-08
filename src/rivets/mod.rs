mod code_injection;
mod condition;
mod confidence_filter;
mod delimiter_confusion;
mod encoding_detection;
mod http_fetch;
#[cfg(feature = "classifier")]
mod instruction_hijacking;
mod language_detection;
mod logger;
mod pattern_detection;
mod rate_limit;
#[cfg(feature = "classifier")]
mod role_confusion;
mod sanitize;
mod sql_injection;
mod structure_analysis;
mod telemetry;
mod template_injection;
#[cfg(feature = "classifier")]
mod tool_use_hijacking;
mod types;
mod untrusted_wrapper;
mod utils;

use std::sync::Arc;

use regex::Regex;

pub use code_injection::code_injection;
pub use condition::condition;
pub use confidence_filter::confidence_filter;
pub use delimiter_confusion::delimiter_confusion;
pub use encoding_detection::encoding_detection;
pub use http_fetch::{http_fetch, HttpFetchOptions, HTTP_FETCH_PRIVATE_RANGES};
#[cfg(feature = "classifier")]
pub use instruction_hijacking::instruction_hijacking;
pub use language_detection::language_detection;
pub use logger::{logger, LogLevel};
pub use pattern_detection::pattern_detection;
pub use rate_limit::rate_limit;
#[cfg(feature = "classifier")]
pub use role_confusion::role_confusion;
pub use sanitize::sanitize;
pub use sql_injection::sql_injection;
pub use structure_analysis::structure_analysis;
pub use telemetry::{
    create_console_provider, get_log_level_from_confidence, get_threat_level_from_confidence_score,
    telemetry, ConsoleTelemetryProvider, TelemetryData, TelemetryEvent, TelemetryEventType,
    TelemetryLogLevel, TelemetryOptions, TelemetryProvider,
};
pub use template_injection::template_injection;
#[cfg(feature = "classifier")]
pub use tool_use_hijacking::tool_use_hijacking;
pub use types::{security_flags, ThreatLevel};
pub use untrusted_wrapper::untrusted_wrapper;
pub use utils::apply_threat_penalty;

use crate::types::{ChainmailContext, ChainmailResult};

/// A rivet processes context and may call `next` to continue the chain.
pub trait Rivet: Send + Sync {
    fn name(&self) -> &'static str;

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult;
}

/// Factory namespace for built-in rivets.
pub struct Rivets;

impl Rivets {
    pub fn sanitize(max_length: Option<usize>) -> Arc<dyn Rivet> {
        sanitize(max_length)
    }

    pub fn pattern_detection(custom_patterns: Option<Vec<Regex>>) -> Arc<dyn Rivet> {
        pattern_detection(custom_patterns)
    }

    pub fn confidence_filter(min_threshold: f64, max_threshold: Option<f64>) -> Arc<dyn Rivet> {
        confidence_filter(min_threshold, max_threshold)
    }

    pub fn encoding_detection() -> Arc<dyn Rivet> {
        encoding_detection()
    }

    pub fn sql_injection() -> Arc<dyn Rivet> {
        sql_injection()
    }

    pub fn code_injection() -> Arc<dyn Rivet> {
        code_injection()
    }

    pub fn delimiter_confusion() -> Arc<dyn Rivet> {
        delimiter_confusion()
    }

    pub fn template_injection() -> Arc<dyn Rivet> {
        template_injection()
    }

    pub fn structure_analysis() -> Arc<dyn Rivet> {
        structure_analysis()
    }

    pub fn language_detection() -> Arc<dyn Rivet> {
        language_detection()
    }

    pub fn rate_limit(
        max_requests: Option<usize>,
        window_ms: Option<u128>,
        key_fn: Option<Arc<dyn Fn(&ChainmailContext) -> String + Send + Sync>>,
        max_keys: Option<usize>,
    ) -> Arc<dyn Rivet> {
        rate_limit(max_requests, window_ms, key_fn, max_keys)
    }

    pub fn logger(
        level: Option<LogLevel>,
        log_fn: Option<Arc<dyn Fn(&ChainmailContext) + Send + Sync>>,
    ) -> Arc<dyn Rivet> {
        logger(level, log_fn)
    }

    pub fn untrusted_wrapper(
        tag_name: Option<&str>,
        preserve_original: Option<bool>,
    ) -> Arc<dyn Rivet> {
        untrusted_wrapper(tag_name, preserve_original)
    }

    pub fn http_fetch(url: impl Into<String>, options: HttpFetchOptions) -> Arc<dyn Rivet> {
        http_fetch(url, options)
    }

    pub fn condition(
        predicate: Arc<dyn Fn(&ChainmailContext) -> bool + Send + Sync>,
        flag_name: Option<&str>,
        confidence_multiplier: Option<f64>,
    ) -> Arc<dyn Rivet> {
        condition(predicate, flag_name, confidence_multiplier)
    }

    pub fn telemetry(options: TelemetryOptions) -> Arc<dyn Rivet> {
        telemetry(options)
    }

    #[cfg(feature = "classifier")]
    pub fn role_confusion(
        languages_limit: Option<usize>,
        languages_detection_threshold: Option<f64>,
        confidence_threshold: Option<f64>,
    ) -> Arc<dyn Rivet> {
        crate::rivets::role_confusion::role_confusion(
            languages_limit,
            languages_detection_threshold,
            confidence_threshold,
        )
    }

    #[cfg(feature = "classifier")]
    pub fn instruction_hijacking(
        languages_limit: Option<usize>,
        languages_detection_threshold: Option<f64>,
        confidence_threshold: Option<f64>,
    ) -> Arc<dyn Rivet> {
        crate::rivets::instruction_hijacking::instruction_hijacking(
            languages_limit,
            languages_detection_threshold,
            confidence_threshold,
        )
    }

    #[cfg(feature = "classifier")]
    pub fn tool_use_hijacking(
        languages_limit: Option<usize>,
        languages_detection_threshold: Option<f64>,
        confidence_threshold: Option<f64>,
    ) -> Arc<dyn Rivet> {
        crate::rivets::tool_use_hijacking::tool_use_hijacking(
            languages_limit,
            languages_detection_threshold,
            confidence_threshold,
        )
    }
}
