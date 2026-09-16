# Prompt Chainmail

<div align="center">
  <img src="src/logo.png" alt="Prompt Chainmail Logo" width="200" height="234">
</div>

<br/>

**Security middleware for AI prompt protection**

Security middleware that shields AI applications from prompt injection, jailbreaking, role confusion, tool hijacking attempts and obfuscated attacks through composable defense layers.

Also available in TypeScript ([`prompt-chainmail-ts`](https://github.com/prompt-chainmail/prompt-chainmail-ts)) and Python ([`prompt-chainmail-py`](https://github.com/prompt-chainmail/prompt-chainmail-py)).

[![CI/CD Pipeline](https://github.com/prompt-chainmail/prompt-chainmail-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/prompt-chainmail/prompt-chainmail-rs/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE.md)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](https://github.com/prompt-chainmail/prompt-chainmail-rs/actions/workflows/security.yml)
[![Beta](https://img.shields.io/badge/status-beta-orange.svg)](https://github.com/prompt-chainmail/prompt-chainmail-rs)

The public API is **synchronous** (no Tokio). Method names use idiomatic Rust `snake_case`; preset composition and flag strings match the TypeScript package.

## Features

- **Security** — Composable rivet system (dedicated security plugins) for layered defenses
- **Offline Classifier** — Portable ONNX classifier (no network calls, no API keys) backs `role_confusion()`, `instruction_hijacking()`, `tool_use_hijacking()`, and `side_channel()`
- **Minimal Dependencies** — `whatlang` for language detection and `ort` for local model inference; no cloud embedding APIs
- **Rust** — Strong typing, feature-gated optional deps, sync `protect` / `protect_bytes`
- **Compliance Ready** — Flags, confidence, and metadata suitable for audit logging
- **Monitoring Integration** — Telemetry rivet with a console provider and a `TelemetryProvider` trait for custom backends
- **Parallel by default** — Concurrent chunk pipelines and ORT session pool on large inputs (`parallel` feature; disable with `default-features = false`)

> The bundled ONNX classifier (pin `2026.09.08` from [`prompt-chainmail-models`](https://github.com/prompt-chainmail/prompt-chainmail-models); `release_quality: false`) is a 12-head development artifact: macro_f1 ≈ 0.763, macro_recall ≈ 0.767, attack F1 ≈ 0.946, benign false-positive rate ≈ 1.3%. A few release gates are still open (macro_recall is under 0.90; benign FPR is just over 1%; some language-recall gates). It is included so the classifier-backed rivets, including `side_channel()`, work end-to-end. Treat scores as directional until a `release_quality: true` artifact is published.

## Quick Start

```toml
# Cargo.toml
[dependencies]
prompt-chainmail = "0.1" # default: classifier + parallel; ONNX embedded — no download, no API keys
# Optional:
# prompt-chainmail = { version = "0.1", features = ["http"] }
# prompt-chainmail = { version = "0.1", default-features = false, features = ["classifier"] } # serial only
```

No model setup for consumers: the pinned ONNX weights are compiled into the crate and verified at load time. Works offline out of the box.

**Note:** `Chainmails` provides a security preset for quick setup. For complete control over your protection chain, use `PromptChainmail::new()` and compose your own chainmail.

### Basic usage with security presets (Chainmails)

#### Basic security preset

```rust
Chainmails::basic(Some(8000), Some(0.6));
// Equivalent to:
PromptChainmail::new()
    .forge(Rivets::sanitize(Some(8000)))
    .forge(Rivets::pattern_detection(None))
    .forge(Rivets::role_confusion(None, None, None))
    .forge(Rivets::delimiter_confusion())
    .forge(Rivets::confidence_filter(0.6, None));
```

#### Advanced security preset

```rust
Chainmails::advanced(None, None);
// Equivalent to:
PromptChainmail::new()
    .forge(Rivets::sanitize(Some(8000)))
    .forge(Rivets::pattern_detection(None))
    .forge(Rivets::role_confusion(None, None, None))
    .forge(Rivets::delimiter_confusion())
    .forge(Rivets::instruction_hijacking(None, None, None))
    .forge(Rivets::tool_use_hijacking(None, None, None))
    .forge(Rivets::side_channel(None, None, None))
    .forge(Rivets::code_injection())
    .forge(Rivets::sql_injection())
    .forge(Rivets::template_injection())
    .forge(Rivets::encoding_detection())
    .forge(Rivets::structure_analysis())
    .forge(Rivets::confidence_filter(0.6, None))
    .forge(Rivets::rate_limit_filter(None, None, None, None));
```

#### Development security preset

```rust
Chainmails::development();
// Equivalent to:
Chainmails::advanced(None, None).forge(Rivets::logger(None, None));
```

#### Strict security preset

```rust
Chainmails::strict(Some(8000), Some(0.8));
// Equivalent to:
PromptChainmail::new()
    .forge(Rivets::sanitize(Some(8000)))
    .forge(Rivets::pattern_detection(None))
    .forge(Rivets::role_confusion(None, None, None))
    .forge(Rivets::delimiter_confusion())
    .forge(Rivets::instruction_hijacking(None, None, None))
    .forge(Rivets::tool_use_hijacking(None, None, None))
    .forge(Rivets::side_channel(None, None, None))
    .forge(Rivets::code_injection())
    .forge(Rivets::sql_injection())
    .forge(Rivets::template_injection())
    .forge(Rivets::encoding_detection())
    .forge(Rivets::structure_analysis())
    .forge(Rivets::confidence_filter(0.8, None))
    .forge(Rivets::rate_limit_filter(Some(50), Some(60_000), None, None));
```

```rust
use prompt_chainmail::Chainmails;

let chainmail = Chainmails::strict(None, None);
let result = chainmail.protect(&user_input);

if !result.success {
    println!("Security violation: {:?}", result.context.flags);
} else {
    println!("Safe input: {}", result.context.sanitized);
}
```

### Custom Protection

```rust
use prompt_chainmail::{PromptChainmail, Rivets};

let chainmail = PromptChainmail::new()
    .forge(Rivets::sanitize(None))
    .forge(Rivets::pattern_detection(None))
    .forge(Rivets::confidence_filter(0.8, None));

let result = chainmail.protect(&user_input);
```

### Production Monitoring

```rust
use prompt_chainmail::{
    create_console_provider, Chainmails, Rivets, TelemetryOptions,
};

let chainmail = Chainmails::strict(None, None).forge(Rivets::telemetry(TelemetryOptions {
    provider: Some(create_console_provider()),
    ..Default::default()
}));

let _ = chainmail.protect(&user_input);
```

Implement `TelemetryProvider` for Sentry/Datadog/New Relic (or any backend) — the TypeScript package ships ready-made adapters; this crate exposes the trait plus a console provider.

### Conditional Assembly

```rust
use prompt_chainmail::{PromptChainmail, Rivets};
use std::sync::Arc;

let mut chainmail = PromptChainmail::new();

if needs_basic_protection {
    chainmail = chainmail.forge(Rivets::sanitize(None));
}

if detect_injections {
    chainmail = chainmail.forge(Rivets::pattern_detection(None));
}

chainmail = chainmail.forge(Rivets::condition(
    Arc::new(|ctx| ctx.sanitized.contains("sensitive_keyword")),
    Some("sensitive_content"),
    Some(0.3),
));

let result = chainmail.protect(&user_input);
```

## LLM Integration

```rust
use prompt_chainmail::Chainmails;

fn secure_prompt(user_message: &str) -> Result<String, String> {
    let chainmail = Chainmails::strict(None, None);
    let result = chainmail.protect(user_message);

    if !result.success {
        let flags: Vec<_> = result.context.flags.iter().cloned().collect();
        return Err(format!("Security violation: {}", flags.join(", ")));
    }

    // Pass result.context.sanitized to your LLM client
    Ok(result.context.sanitized)
}
```

## Rivets

**Rivets** are composable security middleware that process input sequentially. Each rivet can inspect, modify, or block content before calling `next`. They execute in the order they are forged.

### Rivet Signature

```rust
pub trait Rivet: Send + Sync {
    fn name(&self) -> &'static str;
    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult;
}
```

Factories return `Arc<dyn Rivet>` for forging:

```rust
let chainmail = PromptChainmail::new()
    .forge(Rivets::sanitize(None))              // 1st: Clean HTML/whitespace
    .forge(Rivets::pattern_detection(None))     // 2nd: Detect injection patterns
    .forge(Rivets::confidence_filter(0.8, None)); // 3rd: Block low confidence

// Input flows: sanitize → pattern_detection → confidence_filter → result
```

### Built-in security rivets

Detectors add flags and subtract leftover trust. They do not set `blocked`. `context.blocked` is set only by a forged filter: `confidence_filter` (trust gate) or `rate_limit_filter` (quota).

| Rivet | Role | Blocks |
| --- | --- | --- |
| `Rivets::sanitize()` | HTML removal, whitespace normalization | no |
| `Rivets::pattern_detection()` | Common injection patterns | no |
| `Rivets::role_confusion()` | Role manipulation detection (classifier-backed, see below) | no |
| `Rivets::encoding_detection()` | Base64/hex/binary/octal/ROT13/URL encoding detection | no |
| `Rivets::structure_analysis()` | Input structure anomaly detection | no |
| `Rivets::code_injection()` | Code execution attempts | no |
| `Rivets::sql_injection()` | SQL injection patterns | no |
| `Rivets::delimiter_confusion()` | Context-breaking attempts | no |
| `Rivets::instruction_hijacking()` | Instruction override detection (classifier-backed) | no |
| `Rivets::tool_use_hijacking()` | Indirect tool-use / agent-tool abuse detection (classifier-backed) | no |
| `Rivets::side_channel()` | Unofficial side-channel use (classifier-backed) | no |
| `Rivets::language_detection()` | Language detection (`whatlang`) | no |
| `Rivets::template_injection()` | Template syntax injection detection | no |
| `Rivets::confidence_filter()` | Trust gate on leftover confidence (`<` min) | yes |
| `Rivets::rate_limit_filter()` | Quota filter | yes |
| `Rivets::untrusted_wrapper()` | Wrap content in security boundary tags | no |
| `Rivets::http_fetch()` | External HTTP calls via blocking `ureq` (Cargo feature `http`) | no |
| `Rivets::condition()` | Custom logic with predicates | no |
| `Rivets::logger()` | Request logging and debugging | no |
| `Rivets::telemetry()` | Monitoring integration | no |

#### Classifier-backed rivets

`Rivets::role_confusion()`, `Rivets::instruction_hijacking()`, `Rivets::tool_use_hijacking()`, and `Rivets::side_channel()` run text through a shared ONNX classifier (`src/shared/classifier`) instead of cloud embeddings:

- The model runs fully offline via `ort` from **embedded** `classifier.onnx` (no network, no sibling repo). Checksum/size are verified against the embedded manifest. Pin is `classifier-model-version.json` → [`prompt-chainmail-models`](https://github.com/prompt-chainmail/prompt-chainmail-models).
- Long inputs are split into byte windows; per-label probabilities are max-aggregated across windows before thresholding.
- All four rivets accept classifier-relevant options (confidence threshold, language filters). There is no embedding/similarity API.
- `Rivets::tool_use_hijacking()` targets indirect tool abuse rather than classic instruction-override phrasing.
- `Rivets::side_channel()` targets unofficial out-of-band paths (wiki/paste/signal pages used as a peer board or durable memory).
- The artifact is `release_quality: false` (see the note above). Treat scores as directional until a release-quality pin ships.

**Maintainers / contributors only:** bump `classifier-model-version.json`, run `make fetch-classifier` to refresh embeds. Optional runtime override: `PROMPT_CHAINMAIL_MODEL_DIR`. Consumers never need these.

Local checks: `make format`, `make lint`, `make test`, `make audit` (`cargo-audit` required for the last). GitHub Actions runs the same on `main` / `master`.

## Cargo Features

| Feature | Default | Purpose |
|---------|---------|---------|
| `classifier` | yes | ONNX classifier via `ort` for hijacking rivets |
| `parallel` | yes | Rayon: parallel chunk pipelines + ORT session pool |
| `http` | no | Blocking `ureq` for `Rivets::http_fetch` |

### `parallel` (default on)

Enables concurrent **chunk** pipelines for inputs above the 64 KiB threshold (main win) and concurrent classifier windows via an ORT session pool (size defaults to CPU count; override with `PROMPT_CHAINMAIL_ORT_POOL`). Short inputs stay serial. To opt out (lower RSS from a single ORT session):

```toml
prompt-chainmail = { version = "0.1", default-features = false, features = ["classifier"] }
```

Wall-clock avg ms (cache-busted), same machine — Rust serial / Rust parallel / TypeScript. Parallel helps once inputs hit the chunked path (≥64 KB).

**`Chainmails::basic`**

| Case | Rust serial | Rust parallel | TypeScript | vs serial | vs TS |
|------|-------------|---------------|------------|-----------|-------|
| short (11 B) | 0.031 | 0.031 | 0.110 | ~1× | 3.5× |
| 64 KB | 5.3 | **1.1** | 17.5 | 4.9× | 16× |
| 128 KB | 10.8 | **1.9** | 32.8 | 5.7× | 17× |
| 256 KB | 21.4 | **3.3** | 64.4 | 6.4× | 19× |
| 512 KB | 42.8 | **6.3** | 126.6 | 6.8× | 20× |
| 1 MB | 84.7 | **12.3** | 253.2 | 6.9× | 21× |
| 1.5 MB | 128.0 | **18.2** | 377.5 | 7.0× | 21× |
| role_attack | 0.066 | 0.072 | 0.290 | ~1× | 4× |

**`Chainmails::advanced`** (bench raises `rate_limit` so the default 100 req/min gate does not skew timings)

| Case | Rust serial | Rust parallel | TypeScript | vs serial | vs TS |
|------|-------------|---------------|------------|-----------|-------|
| short (11 B) | 0.085 | 0.100 | 0.272 | ~1× | 2.7× |
| 64 KB | 18.6 | **2.8** | 54.9 | 6.6× | 20× |
| 128 KB | 36.7 | **4.9** | 107.7 | 7.6× | 22× |
| 256 KB | 74.3 | **9.0** | 214.1 | 8.2× | 24× |
| 512 KB | 147.3 | **17.3** | 429.1 | 8.5× | 25× |
| 1 MB | 296.3 | **33.5** | 848.5 | 8.8× | 25× |
| 1.5 MB | 440.0 | **54.5** | 1261.2 | 8.1× | 23× |
| role_attack | 0.213 | 0.208 | 0.910 | ~1× | 4.4× |

Reproduce (`CHAIN=basic|advanced|all`, default `all`):

```bash
cargo run --release --example bench_basic_compare
cargo run --release --no-default-features --features classifier --example bench_basic_compare  # serial
# in prompt-chainmail-ts:
node scripts/bench-basic-compare.mjs
```

Without `http`, `Rivets::http_fetch` still compiles and fail-opens with flag `http_error`.

## Security Flags

Prompt Chainmail uses standardized security flag **strings** (same values as the TypeScript `SecurityFlags` enum). Each rivet can add one or more flags to `context.flags`.

| Flag | Description | Triggered By |
|------|-------------|--------------|
| `truncated` | Input truncated due to length limits | `sanitize` |
| `untrusted_wrapped` | Content wrapped in security tags | `untrusted_wrapper` |
| `sanitized_html_tags` | HTML tags removed | `sanitize` |
| `sanitized_control_chars` | Control characters sanitized | `sanitize` |
| `sanitized_whitespace` | Whitespace normalized | `sanitize` |
| `injection_pattern` | Common prompt injection patterns | `pattern_detection` |
| `excessive_lines` / `non_ascii_heavy` / `repetitive_content` | Structure anomalies | `structure_analysis` |
| `base64_encoding`, `hex_encoding`, `url_encoding`, … | Encoding obfuscation | `encoding_detection` |
| `rate_limited` | Rate limit exceeded | `rate_limit_filter` |
| `http_*` | HTTP validation / errors | `http_fetch` |
| `sql_injection` / `code_injection` / `template_injection` / `delimiter_confusion` | Injection families | matching rivets |
| `tool_use_hijacking` | Indirect tool abuse | `tool_use_hijacking` |
| `side_channel` | Unofficial side-channel use detected | `side_channel` |
| `side_channel_coordination` | Peer coordination over a side channel | `side_channel` |
| `side_channel_state_write` | Durable shared-state write over a side channel | `side_channel` |
| `role_confusion` (+ subtypes) | Role manipulation | `role_confusion` |
| `instruction_hijacking` (+ subtypes) | Instruction override | `instruction_hijacking` |
| `classifier_unavailable` | Classifier failed open | classifier-backed rivets |

Constants live in `prompt_chainmail::security_flags`.

```rust
use prompt_chainmail::security_flags;

let result = chainmail.protect(&user_input);

if result.context.flags.contains(security_flags::SQL_INJECTION) {
    println!("SQL injection attempt detected!");
}
```

> **Note:** `context.metadata` (`HashMap<String, serde_json::Value>`) holds rivet-specific detail (languages, matches, patterns) for threat intelligence and debugging.

## Confidence Scoring

Confidence is a score from 0.0 to 1.0. Lower scores indicate higher security risk.

| Confidence Range | Risk Level | Description | Action |
|------------------|------------|-------------|--------|
| `0.9 - 1.0` | **Very Low Risk** | Clean input | Allow |
| `0.7 - 0.8` | **Low Risk** | Minor issues | Allow with monitoring |
| `0.5 - 0.6` | **Medium Risk** | Suspicious patterns | Review / sanitize |
| `0.3 - 0.4` | **High Risk** | Clear attack patterns | Block recommended |
| `0.0 - 0.2` | **Critical Risk** | Multiple attack vectors | Block immediately |

Penalties come from `apply_threat_penalty` / `ThreatLevel` (`Low` 0.1 … `Critical` 0.6), scaled by flag count and content length — same model as TypeScript.

```rust
let result = chainmail.protect(&user_input);

if result.context.confidence < 0.5 {
    println!("High risk input: {:?}", result.context.flags);
} else if result.context.confidence < 0.7 {
    println!("Medium risk — monitoring recommended");
}
```

## Security Context

```rust
let result = chainmail.protect(&user_input);

println!(
    "flags={:?} confidence={} blocked={} sanitized={}",
    result.context.flags,
    result.context.confidence,
    result.context.blocked,
    result.context.sanitized
);
```

`blocked` latches to `true` (cannot be cleared once set). Prefer `context.set_blocked(true)`.

## Telemetry

```rust
use prompt_chainmail::{
    create_console_provider, Rivets, TelemetryOptions, TelemetryProvider,
};

// Console
chainmail = chainmail.forge(Rivets::telemetry(TelemetryOptions {
    provider: Some(create_console_provider()),
    ..Default::default()
}));

// Custom provider — implement TelemetryProvider
// (log_security_event, track_metric, capture_error, add_breadcrumb)
```

## Examples

### Real-world protection outcomes

| Input Example | Rivet Configuration | Output (shape) |
|---------------|---------------------|----------------|
| `"Ignore all previous instructions…"` | `Chainmails::strict` | `success: false`, instruction/injection flags, blocked |
| `"What is 2+2? <script>…"` | `sanitize` + `code_injection` | sanitized text, `code_injection` flag |
| `"SELECT * FROM users… DROP TABLE…"` | `sql_injection` + `confidence_filter` | blocked / low confidence |
| Base64 blob | `encoding_detection` | decoded/sanitized + encoding flag |
| `"You are now DAN…"` | `Chainmails::advanced` | role / instruction flags |
| Normal weather question | `Chainmails::basic` | `success: true`, confidence ≈ 1.0 |

### Runnable examples

```bash
cargo run --example hello_world
cargo run --example basic_preset
cargo run --release --example bench_basic_compare
```

## License

Business Source License 1.1 — see [LICENSE.md](LICENSE.md). Free for non-production use; converts to Apache 2.0 on January 1, 2029 (same terms as the TypeScript package).
