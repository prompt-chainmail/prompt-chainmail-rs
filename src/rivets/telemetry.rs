//! Telemetry rivet.

use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::rivets::types::ThreatLevel;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

/// Telemetry log levels for the default console path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryLogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Silent,
}

/// Security / processing event kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryEventType {
    ProcessingError,
    ThreatDetected,
    ThreatBlocked,
    SecurityScan,
}

impl TelemetryEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            TelemetryEventType::ProcessingError => "processing_error",
            TelemetryEventType::ThreatDetected => "threat_detected",
            TelemetryEventType::ThreatBlocked => "threat_blocked",
            TelemetryEventType::SecurityScan => "security_scan",
        }
    }
}

/// Snapshot emitted after a protect pass.
#[derive(Debug, Clone)]
pub struct TelemetryData {
    pub session_id: String,
    pub flags: Vec<String>,
    pub confidence: f64,
    pub processing_time: u128,
    pub input_length: usize,
    pub blocked: bool,
    pub success: bool,
}

/// Security event payload for [`TelemetryProvider::log_security_event`].
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    pub event_type: TelemetryEventType,
    pub threat_level: ThreatLevel,
    pub message: String,
    pub context: TelemetryData,
    pub metadata: Option<HashMap<String, Value>>,
    pub flags: Option<Vec<String>>,
    pub risk_score: Option<f64>,
    pub attack_types: Option<Vec<String>>,
}

/// Sync telemetry backend.
pub trait TelemetryProvider: Send + Sync {
    fn log_security_event(&self, event: &TelemetryEvent);
    fn track_metric(&self, name: &str, value: f64, tags: Option<&HashMap<String, String>>);
    fn capture_error(&self, error: &str, context: Option<&HashMap<String, Value>>);
    fn add_breadcrumb(&self, message: &str, data: Option<&HashMap<String, Value>>);
}

type LogFn = Arc<dyn Fn(TelemetryLogLevel, &str, &TelemetryData) + Send + Sync>;

/// Options for [`telemetry`].
#[derive(Default)]
pub struct TelemetryOptions {
    pub log_fn: Option<LogFn>,
    pub track_metrics: Option<bool>,
    pub log_errors: Option<bool>,
    pub provider: Option<Arc<dyn TelemetryProvider>>,
}

/// Console-backed [`TelemetryProvider`].
pub struct ConsoleTelemetryProvider;

impl TelemetryProvider for ConsoleTelemetryProvider {
    fn log_security_event(&self, event: &TelemetryEvent) {
        let _ = writeln!(
            io::stderr(),
            "[Security] {}: {} session_id={} blocked={} confidence={} flags={:?}",
            event.event_type.as_str(),
            event.message,
            event.context.session_id,
            event.context.blocked,
            event.context.confidence,
            event.context.flags
        );
    }

    fn track_metric(&self, name: &str, value: f64, tags: Option<&HashMap<String, String>>) {
        let _ = writeln!(io::stdout(), "[Metric] {name}: {value} tags={tags:?}");
    }

    fn capture_error(&self, error: &str, context: Option<&HashMap<String, Value>>) {
        let _ = writeln!(io::stderr(), "[Error] {error} context={context:?}");
    }

    fn add_breadcrumb(&self, message: &str, data: Option<&HashMap<String, Value>>) {
        let _ = writeln!(io::stdout(), "[Breadcrumb] {message} data={data:?}");
    }
}

pub fn create_console_provider() -> Arc<dyn TelemetryProvider> {
    Arc::new(ConsoleTelemetryProvider)
}

pub fn get_threat_level_from_confidence_score(confidence: Option<f64>) -> ThreatLevel {
    match confidence {
        None => ThreatLevel::Low,
        Some(c) if c > 0.8 => ThreatLevel::Critical,
        Some(c) if c > 0.6 => ThreatLevel::High,
        Some(c) if c > 0.3 => ThreatLevel::Medium,
        Some(_) => ThreatLevel::Low,
    }
}

pub fn get_log_level_from_confidence(confidence: f64) -> TelemetryLogLevel {
    if confidence < 0.5 {
        TelemetryLogLevel::Error
    } else if confidence < 0.7 {
        TelemetryLogLevel::Warn
    } else {
        TelemetryLogLevel::Info
    }
}

fn default_log_fn(level: TelemetryLogLevel, message: &str, data: &TelemetryData) {
    let line = format!(
        "[PromptChainmail] {message} session_id={} flags={:?} confidence={} blocked={} success={} processing_time={} input_length={}",
        data.session_id,
        data.flags,
        data.confidence,
        data.blocked,
        data.success,
        data.processing_time,
        data.input_length
    );
    match level {
        TelemetryLogLevel::Error | TelemetryLogLevel::Warn => {
            let _ = writeln!(io::stderr(), "{line}");
        }
        TelemetryLogLevel::Silent => {}
        TelemetryLogLevel::Debug | TelemetryLogLevel::Info => {
            let _ = writeln!(io::stdout(), "{line}");
        }
    }
}

struct TelemetryRivet {
    log_fn: LogFn,
    track_metrics: bool,
    log_errors: bool,
    provider: Option<Arc<dyn TelemetryProvider>>,
}

impl Rivet for TelemetryRivet {
    fn name(&self) -> &'static str {
        "telemetry"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let start = now_ms();

        if let Some(provider) = &self.provider {
            let mut data = HashMap::new();
            data.insert(
                "session_id".to_string(),
                Value::String(context.session_id.clone()),
            );
            data.insert(
                "input_length".to_string(),
                Value::from(context.input.len() as u64),
            );
            provider.add_breadcrumb("Processing started", Some(&data));
        }

        let result = next(context);
        let processing_time = now_ms().saturating_sub(start);

        let telemetry_data = TelemetryData {
            session_id: context.session_id.clone(),
            flags: context.flags.iter().cloned().collect(),
            confidence: context.confidence,
            processing_time,
            input_length: context.input.len(),
            blocked: context.blocked,
            success: result.success,
        };

        if let Some(err) = &result.error {
            if let Some(provider) = &self.provider {
                let mut ctx_map = HashMap::new();
                ctx_map.insert(
                    "session_id".to_string(),
                    Value::String(telemetry_data.session_id.clone()),
                );
                ctx_map.insert("success".to_string(), Value::Bool(false));
                provider.capture_error(err, Some(&ctx_map));
                provider.log_security_event(&TelemetryEvent {
                    event_type: TelemetryEventType::ProcessingError,
                    threat_level: ThreatLevel::Low,
                    message: format!("Processing failed: {err}"),
                    context: TelemetryData {
                        success: false,
                        ..telemetry_data.clone()
                    },
                    metadata: None,
                    flags: None,
                    risk_score: None,
                    attack_types: None,
                });
            } else if self.log_errors {
                (self.log_fn)(
                    TelemetryLogLevel::Error,
                    &format!("Processing failed: {err}"),
                    &telemetry_data,
                );
            }
            return result;
        }

        if let Some(provider) = &self.provider {
            let mut tags = HashMap::new();
            tags.insert("success".to_string(), result.success.to_string());
            tags.insert("flags_count".to_string(), context.flags.len().to_string());
            provider.track_metric("processing_time", processing_time as f64, Some(&tags));

            if !result.success || !context.flags.is_empty() {
                let threat_level = get_threat_level_from_confidence_score(Some(context.confidence));
                let event_type = if context.blocked {
                    TelemetryEventType::ThreatBlocked
                } else if !context.flags.is_empty() {
                    TelemetryEventType::ThreatDetected
                } else {
                    TelemetryEventType::SecurityScan
                };
                let flags: Vec<String> = context.flags.iter().cloned().collect();
                let risk_score = context
                    .metadata
                    .get("risk_score")
                    .and_then(|v| v.as_f64());
                let attack_types = context.metadata.get("attack_types").and_then(|v| {
                    v.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                });
                provider.log_security_event(&TelemetryEvent {
                    event_type,
                    threat_level,
                    message: format!(
                        "Security check {}: {}",
                        if result.success { "passed" } else { "failed" },
                        flags.join(", ")
                    ),
                    context: telemetry_data,
                    metadata: None,
                    flags: Some(flags),
                    risk_score,
                    attack_types,
                });
            }
        } else if self.track_metrics {
            (self.log_fn)(
                TelemetryLogLevel::Info,
                &format!("Processing completed in {processing_time}ms"),
                &telemetry_data,
            );

            if !result.success || !context.flags.is_empty() {
                let level = get_log_level_from_confidence(context.confidence);
                let flags: Vec<&str> = context.flags.iter().map(|s| s.as_str()).collect();
                (self.log_fn)(
                    level,
                    &format!("Security flags detected: {}", flags.join(", ")),
                    &telemetry_data,
                );
            }
        }

        result
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Breadcrumb (if provider set), then `next`, then metrics/security events.
pub fn telemetry(options: TelemetryOptions) -> Arc<dyn Rivet> {
    let log_fn = options
        .log_fn
        .unwrap_or_else(|| Arc::new(default_log_fn));
    Arc::new(TelemetryRivet {
        log_fn,
        track_metrics: options.track_metrics.unwrap_or(true),
        log_errors: options.log_errors.unwrap_or(true),
        provider: options.provider,
    })
}
