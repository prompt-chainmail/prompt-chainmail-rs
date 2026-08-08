use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::Value;

use crate::rivets::pattern_detection::injection_patterns;
use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::shared::{COMMON_PATTERNS, ENCODING_PATTERNS, HTML_ENTITIES};
use crate::types::{ChainmailContext, ChainmailResult};

static ROT13_EXTRA_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\bignore\b[\s\S]{0,24}\b(system|instructions?|rules?|prompts?)\b")
            .unwrap(),
        Regex::new(r"(?i)\b(forget|disregard|override|bypass)\b[\s\S]{0,24}\b(all|previous|safety)\b")
            .unwrap(),
    ]
});

struct EncodingDetectionRivet;

impl Rivet for EncodingDetectionRivet {
    fn name(&self) -> &'static str {
        "encoding_detection"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        if let Some(m) = ENCODING_PATTERNS.base64.find(&context.sanitized) {
            if let Some(decoded) = decode_base64(m.as_str()) {
                context
                    .flags
                    .insert(security_flags::BASE64_ENCODING.to_string());
                apply_threat_penalty(context, ThreatLevel::Medium);
                context.metadata.insert(
                    "decoded_content".to_string(),
                    Value::String(decoded.chars().take(100).collect()),
                );
            }
        }

        if ENCODING_PATTERNS.hex_escape.is_match(&context.sanitized) {
            context
                .flags
                .insert(security_flags::HEX_ENCODING.to_string());
            apply_threat_penalty(context, ThreatLevel::Medium);
        }

        if let Some(m) = ENCODING_PATTERNS.url_escape.find(&context.sanitized) {
            if let Ok(decoded) = decode_uri_component(m.as_str()) {
                context
                    .flags
                    .insert(security_flags::URL_ENCODING.to_string());
                apply_threat_penalty(context, ThreatLevel::Medium);
                context.metadata.insert(
                    "url_decoded_content".to_string(),
                    Value::String(decoded.chars().take(100).collect()),
                );
            }
        }

        if ENCODING_PATTERNS
            .unicode_escape_regex
            .is_match(&context.sanitized)
        {
            let mut decoded = context.sanitized.clone();
            while let Some(caps) = ENCODING_PATTERNS.unicode_escape.captures(&decoded) {
                let full = caps.get(0).unwrap().as_str().to_string();
                let hex = caps.get(1).unwrap().as_str();
                if let Ok(code) = u32::from_str_radix(hex, 16) {
                    if let Some(ch) = char::from_u32(code) {
                        decoded = decoded.replacen(&full, &ch.to_string(), 1);
                        continue;
                    }
                }
                break;
            }
            context
                .flags
                .insert(security_flags::UNICODE_ENCODING.to_string());
            apply_threat_penalty(context, ThreatLevel::Medium);
            context.metadata.insert(
                "unicode_decoded_content".to_string(),
                Value::String(decoded.chars().take(100).collect()),
            );
        }

        if HTML_ENTITIES.numeric_detection.is_match(&context.sanitized)
            || HTML_ENTITIES.named_detection.is_match(&context.sanitized)
        {
            let mut decoded = context.sanitized.clone();
            while let Some(caps) = HTML_ENTITIES.numeric.captures(&decoded) {
                let full = caps.get(0).unwrap().as_str().to_string();
                let num = caps.get(1).unwrap().as_str();
                if let Ok(code) = num.parse::<u32>() {
                    if let Some(ch) = char::from_u32(code) {
                        decoded = decoded.replacen(&full, &ch.to_string(), 1);
                        continue;
                    }
                }
                break;
            }
            decoded = HTML_ENTITIES.lt.replace_all(&decoded, "<").into_owned();
            decoded = HTML_ENTITIES.gt.replace_all(&decoded, ">").into_owned();
            decoded = HTML_ENTITIES.amp.replace_all(&decoded, "&").into_owned();
            decoded = HTML_ENTITIES.quot.replace_all(&decoded, "\"").into_owned();
            decoded = HTML_ENTITIES.apos.replace_all(&decoded, "'").into_owned();

            context
                .flags
                .insert(security_flags::HTML_ENTITY_ENCODING.to_string());
            apply_threat_penalty(context, ThreatLevel::Medium);
            context.metadata.insert(
                "html_decoded_content".to_string(),
                Value::String(decoded.chars().take(100).collect()),
            );
        }

        if ENCODING_PATTERNS
            .binary
            .is_match(context.sanitized.trim())
        {
            let mut binary_string = context.sanitized.clone();
            while COMMON_PATTERNS.whitespace.is_match(&binary_string) {
                binary_string = COMMON_PATTERNS
                    .whitespace
                    .replace(&binary_string, "")
                    .into_owned();
            }
            let mut decoded = String::new();
            for chunk in binary_string.as_bytes().chunks(8) {
                if chunk.len() == 8 {
                    if let Ok(s) = std::str::from_utf8(chunk) {
                        if let Ok(byte) = u8::from_str_radix(s, 2) {
                            decoded.push(byte as char);
                        }
                    }
                }
            }
            context
                .flags
                .insert(security_flags::BINARY_ENCODING.to_string());
            apply_threat_penalty(context, ThreatLevel::High);
            context.metadata.insert(
                "binary_decoded_content".to_string(),
                Value::String(decoded.chars().take(100).collect()),
            );
        }

        if ENCODING_PATTERNS.octal.is_match(&context.sanitized) {
            let mut decoded = context.sanitized.clone();
            while let Some(caps) = ENCODING_PATTERNS.octal_escape.captures(&decoded) {
                let full = caps.get(0).unwrap().as_str().to_string();
                let oct = caps.get(1).unwrap().as_str();
                if let Ok(code) = u32::from_str_radix(oct, 8) {
                    if let Some(ch) = char::from_u32(code) {
                        decoded = decoded.replacen(&full, &ch.to_string(), 1);
                        continue;
                    }
                }
                break;
            }
            context
                .flags
                .insert(security_flags::OCTAL_ENCODING.to_string());
            apply_threat_penalty(context, ThreatLevel::Medium);
            context.metadata.insert(
                "octal_decoded_content".to_string(),
                Value::String(decoded.chars().take(100).collect()),
            );
        }

        let rot13_decoded = rot13(&context.sanitized);
        let mut suspicious: Vec<&Regex> = injection_patterns()
            .iter()
            .map(|(re, _)| re)
            .collect();
        for p in ROT13_EXTRA_PATTERNS.iter() {
            suspicious.push(p);
        }

        let decoded_matches = suspicious.iter().any(|p| p.is_match(&rot13_decoded));
        let original_matches = suspicious.iter().any(|p| p.is_match(&context.sanitized));

        if decoded_matches && !original_matches {
            context
                .flags
                .insert(security_flags::ROT13_ENCODING.to_string());
            apply_threat_penalty(context, ThreatLevel::Medium);
            context.metadata.insert(
                "rot13_decoded_content".to_string(),
                Value::String(rot13_decoded.chars().take(100).collect()),
            );
        }

        let mixed_case_preview: Option<String> = {
            let words: Vec<&str> = COMMON_PATTERNS
                .whitespace_multiple
                .split(&context.sanitized)
                .collect();
            let mixed_case_words: Vec<&str> = words
                .iter()
                .copied()
                .filter(|word| {
                    if word.len() < 4 {
                        return false;
                    }
                    let upper_count = COMMON_PATTERNS.uppercase.find_iter(word).count();
                    let lower_count = COMMON_PATTERNS.lowercase.find_iter(word).count();
                    upper_count > 0
                        && lower_count > 0
                        && (upper_count as f64) / (word.len() as f64) > 0.3
                })
                .collect();
            if mixed_case_words.len() > 2 {
                Some(
                    mixed_case_words
                        .into_iter()
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(","),
                )
            } else {
                None
            }
        };

        if let Some(preview) = mixed_case_preview {
            context
                .flags
                .insert(security_flags::MIXED_CASE_OBFUSCATION.to_string());
            apply_threat_penalty(context, ThreatLevel::Medium);
            context
                .metadata
                .insert("mixed_case_words".to_string(), Value::String(preview));
        }

        next(context)
    }
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let start = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let offset = (c as u8 - start + 13) % 26;
                (start + offset) as char
            } else {
                c
            }
        })
        .collect()
}

/// Minimal base64 decoder (STANDARD alphabet). Returns `None` on invalid input.
fn decode_base64(input: &str) -> Option<String> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        // Lenient like Node Buffer.from: non-padded lengths accepted.
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = [0u8; 4];
    let mut buf_len = 0usize;
    let mut pad = 0usize;

    for &b in bytes {
        if b == b'=' {
            pad += 1;
            buf[buf_len] = 0;
            buf_len += 1;
        } else if let Some(v) = value(b) {
            if pad > 0 {
                return None;
            }
            buf[buf_len] = v;
            buf_len += 1;
        } else if b.is_ascii_whitespace() {
            continue;
        } else {
            return None;
        }

        if buf_len == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            if pad < 2 {
                out.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if pad < 1 {
                out.push((buf[2] << 6) | buf[3]);
            }
            buf_len = 0;
            if pad > 0 {
                break;
            }
        }
    }

    if buf_len != 0 {
        // Flush remaining partial quartet.
        while buf_len < 4 {
            buf[buf_len] = 0;
            buf_len += 1;
            pad += 1;
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if pad < 2 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if pad < 1 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }

    String::from_utf8(out).ok()
}

fn decode_uri_component(input: &str) -> Result<String, ()> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let h = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| ())?;
            let v = u8::from_str_radix(h, 16).map_err(|_| ())?;
            out.push(v);
            i += 3;
        } else if bytes[i] == b'+' {
            // `+` is literal (unlike application/x-www-form-urlencoded).
            out.push(b'+');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

pub fn encoding_detection() -> Arc<dyn Rivet> {
    Arc::new(EncodingDetectionRivet)
}
