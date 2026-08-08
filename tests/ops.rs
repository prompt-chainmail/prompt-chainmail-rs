//! Ops rivets: rate_limit, condition, untrusted_wrapper, logger, telemetry, http_fetch.

use std::sync::{Arc, Mutex};

use prompt_chainmail::{
    create_console_provider, security_flags, HttpFetchOptions, PromptChainmail, Rivets,
    TelemetryOptions,
};

#[test]
fn rate_limit_eventually_blocks() {
    let mail = PromptChainmail::new().forge(Rivets::rate_limit(Some(2), Some(60_000), None, None));

    let r1 = mail.protect("test 1");
    let r2 = mail.protect("test 2");
    let r3 = mail.protect("test 3");

    assert!(r1.success);
    assert!(r2.success);
    assert!(!r3.success);
    assert!(r3.context.blocked);
    assert!(r3.context.flags.contains(security_flags::RATE_LIMITED));
}

#[test]
fn condition_predicate_runs_and_skips() {
    let predicate = Arc::new(|ctx: &prompt_chainmail::ChainmailContext| {
        ctx.sanitized.contains("secret")
    });

    let mail = PromptChainmail::new().forge(Rivets::condition(
        predicate,
        Some("contains_secret"),
        Some(0.5),
    ));

    let hit = mail.protect("This contains a secret word");
    assert!(hit.context.flags.contains("contains_secret"));
    assert!(hit.context.confidence < 1.0);

    let miss = mail.protect("Nothing to see here");
    assert!(!miss.context.flags.contains("contains_secret"));
    assert_eq!(miss.context.confidence, 1.0);
}

#[test]
fn untrusted_wrapper_wraps_sanitized() {
    let mail = PromptChainmail::new().forge(Rivets::untrusted_wrapper(None, None));
    let result = mail.protect("Some user input");

    assert_eq!(
        result.context.sanitized,
        "<UNTRUSTED_CONTENT>\nSome user input\n</UNTRUSTED_CONTENT>"
    );
    assert!(result
        .context
        .flags
        .contains(security_flags::UNTRUSTED_WRAPPED));
}

#[test]
fn logger_does_not_break_pipeline() {
    let called = Arc::new(Mutex::new(false));
    let called_clone = Arc::clone(&called);
    let log_fn = Arc::new(move |_ctx: &prompt_chainmail::ChainmailContext| {
        *called_clone.lock().unwrap() = true;
    });

    let mail = PromptChainmail::new()
        .forge(Rivets::sanitize(None))
        .forge(Rivets::logger(None, Some(log_fn)));

    let result = mail.protect("test input");
    assert!(result.success);
    assert!(*called.lock().unwrap());
}

#[test]
fn telemetry_console_provider_does_not_break() {
    let mail = PromptChainmail::new().forge(Rivets::telemetry(TelemetryOptions {
        provider: Some(create_console_provider()),
        track_metrics: Some(true),
        log_errors: Some(true),
        log_fn: None,
    }));

    let result = mail.protect("Hello world");
    assert!(result.success);
    assert!(!result.context.blocked);
}

#[test]
fn http_fetch_invalid_url_sets_http_flags_fail_open() {
    let mail = PromptChainmail::new().forge(Rivets::http_fetch(
        "not a url",
        HttpFetchOptions::default(),
    ));

    let result = mail.protect("payload");
    // Fail-open: pipeline continues (success unless something else blocks).
    assert!(result.success);
    assert!(result.context.flags.contains(security_flags::HTTP_ERROR));
    assert!(result.context.metadata.contains_key("http_error"));
}
