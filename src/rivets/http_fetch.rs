//! HTTP fetch rivet with SSRF guards.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

#[cfg(not(feature = "http"))]
use crate::rivets::types::security_flags;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

/// Hostname prefixes rejected as private/local.
pub const HTTP_FETCH_PRIVATE_RANGES: &[&str] = &[
    "127.",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "localhost",
    "0.0.0.0",
    "::1",
    "fe80::",
];

type ValidateResponseFn = Arc<dyn Fn(u16, &Value) -> bool + Send + Sync>;
type OnSuccessFn = Arc<dyn Fn(&mut ChainmailContext, &Value) + Send + Sync>;
type OnErrorFn = Arc<dyn Fn(&mut ChainmailContext, &str) + Send + Sync>;

/// Options for [`http_fetch`].
#[derive(Default)]
pub struct HttpFetchOptions {
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub timeout_ms: Option<u64>,
    pub validate_response: Option<ValidateResponseFn>,
    pub on_success: Option<OnSuccessFn>,
    pub on_error: Option<OnErrorFn>,
    pub allowed_hosts: Option<Vec<String>>,
    pub max_response_size: Option<usize>,
}

#[allow(dead_code)] // fields used when `http` feature is enabled
struct HttpFetchRivet {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    timeout_ms: u64,
    validate_response: Option<ValidateResponseFn>,
    on_success: Option<OnSuccessFn>,
    on_error: Option<OnErrorFn>,
    allowed_hosts: Vec<String>,
    max_response_size: usize,
}

impl Rivet for HttpFetchRivet {
    fn name(&self) -> &'static str {
        "http_fetch"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        #[cfg(not(feature = "http"))]
        {
            let _ = self;
            context.flags.insert(security_flags::HTTP_ERROR.to_string());
            context.metadata.insert(
                "http_error".to_string(),
                Value::String("http feature disabled".to_string()),
            );
            return next(context);
        }

        #[cfg(feature = "http")]
        {
            self.run_fetch(context);
            next(context)
        }
    }
}

#[cfg(feature = "http")]
mod fetch_impl {
    use std::time::Duration;

    use serde_json::{json, Value};

    use super::{HttpFetchRivet, HTTP_FETCH_PRIVATE_RANGES};
    use crate::rivets::types::{security_flags, ThreatLevel};
    use crate::rivets::utils::apply_threat_penalty;
    use crate::types::ChainmailContext;

    impl HttpFetchRivet {
        pub(super) fn run_fetch(&self, context: &mut ChainmailContext) {
            let (scheme, hostname) = match parse_url_scheme_host(&self.url) {
                Ok(parts) => parts,
                Err(reason) => {
                    context.flags.insert(security_flags::HTTP_ERROR.to_string());
                    apply_threat_penalty(context, ThreatLevel::High);
                    context
                        .metadata
                        .insert("http_error".to_string(), Value::String(reason));
                    return;
                }
            };

            if HTTP_FETCH_PRIVATE_RANGES
                .iter()
                .any(|range| hostname.starts_with(range))
            {
                context.flags.insert(security_flags::HTTP_ERROR.to_string());
                apply_threat_penalty(context, ThreatLevel::High);
                context.metadata.insert(
                    "http_error".to_string(),
                    Value::String("Private/local IP addresses are not allowed".to_string()),
                );
                return;
            }

            if !self.allowed_hosts.is_empty() && !self.allowed_hosts.iter().any(|h| h == &hostname)
            {
                context.flags.insert(security_flags::HTTP_ERROR.to_string());
                apply_threat_penalty(context, ThreatLevel::High);
                context.metadata.insert(
                    "http_error".to_string(),
                    Value::String(format!("Host {hostname} is not in allowlist")),
                );
                return;
            }

            if scheme != "http" && scheme != "https" {
                context.flags.insert(security_flags::HTTP_ERROR.to_string());
                apply_threat_penalty(context, ThreatLevel::High);
                context.metadata.insert(
                    "http_error".to_string(),
                    Value::String("Only HTTP/HTTPS protocols are allowed".to_string()),
                );
                return;
            }

            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_millis(self.timeout_ms)))
                .build()
                .into();

            let method = self.method.to_ascii_uppercase();
            let body = json!({ "input": context.sanitized });

            let result = match method.as_str() {
                "GET" => {
                    let mut request = agent.get(&self.url);
                    for (key, value) in &self.headers {
                        request = request.header(key, value);
                    }
                    request.call()
                }
                "PUT" => {
                    let mut request = agent.put(&self.url);
                    for (key, value) in &self.headers {
                        request = request.header(key, value);
                    }
                    request.send_json(&body)
                }
                "PATCH" => {
                    let mut request = agent.patch(&self.url);
                    for (key, value) in &self.headers {
                        request = request.header(key, value);
                    }
                    request.send_json(&body)
                }
                "DELETE" => {
                    let mut request = agent.delete(&self.url);
                    for (key, value) in &self.headers {
                        request = request.header(key, value);
                    }
                    request.call()
                }
                _ => {
                    let mut request = agent.post(&self.url);
                    for (key, value) in &self.headers {
                        request = request.header(key, value);
                    }
                    request.send_json(&body)
                }
            };

            match result {
                Ok(mut response) => {
                    let status = response.status();
                    if !(200..300).contains(&status.as_u16()) {
                        let msg = format!("HTTP {status}");
                        context.flags.insert(security_flags::HTTP_ERROR.to_string());
                        apply_threat_penalty(context, ThreatLevel::Medium);
                        context
                            .metadata
                            .insert("http_error".to_string(), Value::String(msg.clone()));
                        if let Some(on_error) = &self.on_error {
                            on_error(context, &msg);
                        }
                        return;
                    }

                    if let Some(content_length) = response
                        .headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<usize>().ok())
                    {
                        if content_length > self.max_response_size {
                            context.flags.insert(security_flags::HTTP_ERROR.to_string());
                            apply_threat_penalty(context, ThreatLevel::Medium);
                            context.metadata.insert(
                                "http_error".to_string(),
                                Value::String(format!(
                                    "Response size {content_length} exceeds limit {}",
                                    self.max_response_size
                                )),
                            );
                            return;
                        }
                    }

                    match response.body_mut().read_json::<Value>() {
                        Ok(data) => {
                            if let Some(validate) = &self.validate_response {
                                if !validate(status.as_u16(), &data) {
                                    context.flags.insert(
                                        security_flags::HTTP_VALIDATION_FAILED.to_string(),
                                    );
                                    apply_threat_penalty(context, ThreatLevel::High);
                                    context.metadata.insert(
                                        "http_validation_error".to_string(),
                                        Value::String("Response validation failed".to_string()),
                                    );
                                    return;
                                }
                            }

                            context
                                .flags
                                .insert(security_flags::HTTP_SUCCESS.to_string());
                            context
                                .metadata
                                .insert("http_response".to_string(), data.clone());
                            if let Some(on_success) = &self.on_success {
                                on_success(context, &data);
                            }
                        }
                        Err(err) => {
                            let msg = err.to_string();
                            context.flags.insert(security_flags::HTTP_ERROR.to_string());
                            apply_threat_penalty(context, ThreatLevel::Medium);
                            context
                                .metadata
                                .insert("http_error".to_string(), Value::String(msg.clone()));
                            if let Some(on_error) = &self.on_error {
                                on_error(context, &msg);
                            }
                        }
                    }
                }
                Err(err) => {
                    let msg = err.to_string();
                    let lower = msg.to_ascii_lowercase();
                    let timed_out = lower.contains("timed out") || lower.contains("timeout");
                    if timed_out {
                        context
                            .flags
                            .insert(security_flags::HTTP_TIMEOUT.to_string());
                        apply_threat_penalty(context, ThreatLevel::Medium);
                        context.metadata.insert(
                            "http_error".to_string(),
                            Value::String(format!(
                                "Request timed out after {}ms",
                                self.timeout_ms
                            )),
                        );
                    } else {
                        context.flags.insert(security_flags::HTTP_ERROR.to_string());
                        apply_threat_penalty(context, ThreatLevel::Medium);
                        context
                            .metadata
                            .insert("http_error".to_string(), Value::String(msg.clone()));
                    }
                    if let Some(on_error) = &self.on_error {
                        on_error(context, &msg);
                    }
                }
            }
        }
    }

    fn parse_url_scheme_host(url: &str) -> Result<(String, String), String> {
        let uri: ureq::http::Uri = url
            .parse()
            .map_err(|_| "Invalid URL format".to_string())?;
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| "Invalid URL format".to_string())?
            .to_ascii_lowercase();
        let host = uri
            .host()
            .ok_or_else(|| "Invalid URL format".to_string())?
            .to_ascii_lowercase();
        Ok((scheme, host))
    }
}

/// Optional HTTP check against an external URL.
///
/// Without the `http` Cargo feature, sets `http_error` with reason
/// `"http feature disabled"` and continues (fail-open).
///
/// Defaults: `POST`, `Content-Type: application/json`,
/// `timeout_ms=5000`, `max_response_size=1MiB`.
pub fn http_fetch(url: impl Into<String>, options: HttpFetchOptions) -> Arc<dyn Rivet> {
    let mut headers = options.headers.unwrap_or_default();
    if headers.is_empty() {
        headers.insert("Content-Type".to_string(), "application/json".to_string());
    }

    Arc::new(HttpFetchRivet {
        url: url.into(),
        method: options.method.unwrap_or_else(|| "POST".to_string()),
        headers,
        timeout_ms: options.timeout_ms.unwrap_or(5000),
        validate_response: options.validate_response,
        on_success: options.on_success,
        on_error: options.on_error,
        allowed_hosts: options.allowed_hosts.unwrap_or_default(),
        max_response_size: options.max_response_size.unwrap_or(1024 * 1024),
    })
}
