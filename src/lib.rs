//! Prompt Chainmail — composable security middleware for AI prompts.

#[cfg(feature = "classifier")]
mod chainmails;
mod rivets;
mod shared;
mod types;
mod utils;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "classifier")]
pub use chainmails::Chainmails;
pub use rivets::{
    apply_threat_penalty, code_injection, condition, confidence_filter, create_console_provider,
    delimiter_confusion, encoding_detection, get_log_level_from_confidence,
    get_threat_level_from_confidence_score, http_fetch, language_detection, logger,
    pattern_detection, rate_limit, sanitize, security_flags, sql_injection, structure_analysis,
    telemetry, template_injection, untrusted_wrapper, ConsoleTelemetryProvider, HttpFetchOptions,
    LogLevel, Rivet, Rivets, TelemetryData, TelemetryEvent, TelemetryEventType, TelemetryLogLevel,
    TelemetryOptions, TelemetryProvider, ThreatLevel, HTTP_FETCH_PRIVATE_RANGES,
};
#[cfg(feature = "classifier")]
pub use rivets::{instruction_hijacking, role_confusion, tool_use_hijacking};
#[cfg(feature = "classifier")]
pub use shared::classifier;
pub use shared::{
    detect_lookalike_chars, has_language_script_mixing, normalize_text, DetectOptions,
    LanguageDetector,
};
pub use types::{ChainmailContext, ChainmailResult};
pub use utils::{to_chunks, MAX_CHUNK_SIZE, MAX_INPUT_SIZE, STRING_CHUNKING_THRESHOLD};

use serde_json::Value;
use uuid::Uuid;

/// Ordered pipeline of forged security rivets.
#[derive(Clone, Default)]
pub struct PromptChainmail {
    rivets: Vec<Arc<dyn Rivet>>,
}

impl PromptChainmail {
    pub fn new() -> Self {
        Self { rivets: Vec::new() }
    }

    /// Forge a rivet into the chainmail. Panics if a rivet with the same name
    /// was already forged.
    pub fn forge(mut self, rivet: Arc<dyn Rivet>) -> Self {
        if self.rivets.iter().any(|r| r.name() == rivet.name()) {
            panic!(
                "Duplicate rivet: '{}' has already been forged into the chainmail",
                rivet.name()
            );
        }
        self.rivets.push(rivet);
        self
    }

    pub fn len(&self) -> usize {
        self.rivets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rivets.is_empty()
    }

    /// New chainmail with the same rivets (`Arc` clones).
    pub fn clone_chainmail(&self) -> Self {
        Self {
            rivets: self.rivets.iter().map(Arc::clone).collect(),
        }
    }

    /// Run input through all forged rivets.
    ///
    /// Empty strings are valid (not blocked as `invalid_input`).
    /// Strings longer than [`STRING_CHUNKING_THRESHOLD`] are processed in
    /// [`MAX_CHUNK_SIZE`] character chunks with stream-style aggregation
    /// (min confidence, merged flags/metadata, early-stop on block in the
    /// serial path).
    pub fn protect(&self, input: &str) -> ChainmailResult {
        let start_time = now_ms();
        let session_id = Uuid::new_v4().to_string();

        if input.chars().count() > STRING_CHUNKING_THRESHOLD {
            return self.protect_chunked(input, start_time, session_id);
        }

        self.protect_string(input, start_time, session_id)
    }

    /// Decode bytes as UTF-8 (lossy) then run [`Self::protect`].
    ///
    /// Invalid sequences become the Unicode replacement character.
    pub fn protect_bytes(&self, input: &[u8]) -> ChainmailResult {
        let decoded = String::from_utf8_lossy(input);
        self.protect(decoded.as_ref())
    }

    fn protect_string(
        &self,
        input: &str,
        start_time: u128,
        session_id: String,
    ) -> ChainmailResult {
        let mut context = ChainmailContext {
            input: input.to_string(),
            sanitized: input.to_string(),
            flags: HashSet::new(),
            confidence: 1.0,
            metadata: HashMap::new(),
            blocked: false,
            start_time,
            session_id,
        };

        if self.rivets.is_empty() {
            return self.create_result(context, now_ms() - start_time, None);
        }

        self.run_rivets(&mut context, start_time)
    }

    /// Process chunks, merge flags/metadata, take min confidence, early-stop on
    /// block (serial path), and flag `stream_size_exceeded` if total characters
    /// exceed [`MAX_INPUT_SIZE`].
    ///
    /// With the `parallel` feature (default), chunks run concurrently via rayon.
    /// Aggregation still follows chunk index so metadata merge matches the
    /// serial path.
    fn protect_chunked(
        &self,
        input: &str,
        start_time: u128,
        session_id: String,
    ) -> ChainmailResult {
        let chunks = to_chunks(input, MAX_CHUNK_SIZE);
        let total_length: usize = chunks.iter().map(|c| c.chars().count()).sum();
        let chunk_count = chunks.len();

        if total_length > MAX_INPUT_SIZE {
            let mut stream_flags = HashSet::new();
            stream_flags.insert("stream_size_exceeded".to_string());
            let mut stream_metadata = HashMap::new();
            stream_metadata.insert(
                "stream_size_limit".to_string(),
                Value::from(MAX_INPUT_SIZE as u64),
            );
            return self.create_stream_result(
                true,
                chunk_count,
                total_length,
                stream_flags,
                stream_metadata,
                0.0,
                start_time,
                session_id,
            );
        }

        #[cfg(feature = "parallel")]
        {
            return self.protect_chunked_parallel(
                &chunks,
                chunk_count,
                total_length,
                start_time,
                session_id,
            );
        }

        #[cfg(not(feature = "parallel"))]
        {
            self.protect_chunked_serial(&chunks, start_time, session_id)
        }
    }

    #[cfg(not(feature = "parallel"))]
    fn protect_chunked_serial(
        &self,
        chunks: &[&str],
        start_time: u128,
        session_id: String,
    ) -> ChainmailResult {
        let mut chunk_count = 0usize;
        let mut total_length = 0usize;
        let mut stream_flags: HashSet<String> = HashSet::new();
        let mut stream_metadata: HashMap<String, Value> = HashMap::new();
        let mut min_confidence = 1.0_f64;

        for chunk in chunks {
            chunk_count += 1;
            total_length += chunk.chars().count();

            let chunk_result = self.protect_one_chunk(chunk, start_time, &session_id);

            stream_flags.extend(chunk_result.context.flags.iter().cloned());
            for (k, v) in chunk_result.context.metadata {
                stream_metadata.insert(k, v);
            }
            min_confidence = min_confidence.min(chunk_result.context.confidence);

            if chunk_result.context.blocked {
                return self.create_stream_result(
                    true,
                    chunk_count,
                    total_length,
                    stream_flags,
                    stream_metadata,
                    min_confidence,
                    start_time,
                    session_id,
                );
            }
        }

        self.create_stream_result(
            false,
            chunk_count,
            total_length,
            stream_flags,
            stream_metadata,
            min_confidence,
            start_time,
            session_id,
        )
    }

    #[cfg(feature = "parallel")]
    fn protect_chunked_parallel(
        &self,
        chunks: &[&str],
        chunk_count: usize,
        total_length: usize,
        start_time: u128,
        session_id: String,
    ) -> ChainmailResult {
        use rayon::prelude::*;

        // Early-stop is not applied mid-flight (would serialize the hot path);
        // we still report blocked if any chunk blocked.
        let mut results: Vec<(usize, ChainmailResult)> = chunks
            .par_iter()
            .enumerate()
            .map(|(idx, chunk)| {
                let result = self.protect_one_chunk(chunk, start_time, &session_id);
                (idx, result)
            })
            .collect();

        results.sort_by_key(|(idx, _)| *idx);

        let mut stream_flags: HashSet<String> = HashSet::new();
        let mut stream_metadata: HashMap<String, Value> = HashMap::new();
        let mut min_confidence = 1.0_f64;
        let mut blocked = false;

        for (_idx, chunk_result) in results {
            stream_flags.extend(chunk_result.context.flags.iter().cloned());
            for (k, v) in chunk_result.context.metadata {
                stream_metadata.insert(k, v);
            }
            min_confidence = min_confidence.min(chunk_result.context.confidence);
            if chunk_result.context.blocked {
                blocked = true;
            }
        }

        self.create_stream_result(
            blocked,
            chunk_count,
            total_length,
            stream_flags,
            stream_metadata,
            min_confidence,
            start_time,
            session_id,
        )
    }

    fn protect_one_chunk(
        &self,
        chunk: &str,
        start_time: u128,
        session_id: &str,
    ) -> ChainmailResult {
        let mut chunk_context = ChainmailContext {
            input: chunk.to_string(),
            sanitized: chunk.to_string(),
            flags: HashSet::new(),
            confidence: 1.0,
            metadata: HashMap::new(),
            blocked: false,
            start_time,
            session_id: session_id.to_string(),
        };

        if self.rivets.is_empty() {
            self.create_result(chunk_context, now_ms() - start_time, None)
        } else {
            self.run_rivets(&mut chunk_context, start_time)
        }
    }

    fn run_rivets(&self, context: &mut ChainmailContext, start_time: u128) -> ChainmailResult {
        let rivets = &self.rivets;
        let mut index = 0usize;

        fn run_from(
            rivets: &[Arc<dyn Rivet>],
            index: &mut usize,
            context: &mut ChainmailContext,
            start_time: u128,
            create: &dyn Fn(ChainmailContext, u128, Option<String>) -> ChainmailResult,
        ) -> ChainmailResult {
            if *index >= rivets.len() {
                return create(context.clone(), now_ms() - start_time, None);
            }

            let rivet = Arc::clone(&rivets[*index]);
            *index += 1;

            let mut next = |ctx: &mut ChainmailContext| {
                run_from(rivets, index, ctx, start_time, create)
            };

            rivet.process(context, &mut next)
        }

        let create = |context: ChainmailContext, processing_time: u128, error: Option<String>| {
            ChainmailResult {
                success: !context.blocked && error.is_none(),
                context,
                error,
                processing_time,
            }
        };

        run_from(rivets, &mut index, context, start_time, &create)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_stream_result(
        &self,
        blocked: bool,
        chunk_count: usize,
        total_length: usize,
        stream_flags: HashSet<String>,
        mut stream_metadata: HashMap<String, Value>,
        confidence: f64,
        start_time: u128,
        session_id: String,
    ) -> ChainmailResult {
        stream_metadata.insert("chunk_count".to_string(), Value::from(chunk_count as u64));
        stream_metadata.insert("total_length".to_string(), Value::from(total_length as u64));

        let stream_desc = format!("[Stream: {chunk_count} chunks, {total_length} chars]");
        let mut final_context = ChainmailContext {
            input: stream_desc.clone(),
            sanitized: stream_desc,
            flags: stream_flags,
            confidence,
            metadata: stream_metadata,
            blocked: false,
            start_time,
            session_id,
        };
        final_context.set_blocked(blocked);

        self.create_result(final_context, now_ms() - start_time, None)
    }

    fn create_result(
        &self,
        context: ChainmailContext,
        processing_time: u128,
        error: Option<String>,
    ) -> ChainmailResult {
        ChainmailResult {
            success: !context.blocked && error.is_none(),
            context,
            error,
            processing_time,
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
