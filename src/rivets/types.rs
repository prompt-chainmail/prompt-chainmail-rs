/// Threat levels for security violations (confidence penalty amounts).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThreatLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl ThreatLevel {
    pub fn penalty(self) -> f64 {
        match self {
            ThreatLevel::Low => 0.1,
            ThreatLevel::Medium => 0.25,
            ThreatLevel::High => 0.4,
            ThreatLevel::Critical => 0.6,
        }
    }
}

/// Canonical security flag strings used by default rivets.
pub mod security_flags {
    pub const TRUNCATED: &str = "truncated";
    pub const UNTRUSTED_WRAPPED: &str = "untrusted_wrapped";

    pub const SANITIZED_HTML_TAGS: &str = "sanitized_html_tags";
    pub const SANITIZED_CONTROL_CHARS: &str = "sanitized_control_chars";
    pub const SANITIZED_WHITESPACE: &str = "sanitized_whitespace";

    pub const INJECTION_PATTERN: &str = "injection_pattern";

    pub const EXCESSIVE_LINES: &str = "excessive_lines";
    pub const NON_ASCII_HEAVY: &str = "non_ascii_heavy";
    pub const REPETITIVE_CONTENT: &str = "repetitive_content";

    pub const BASE64_ENCODING: &str = "base64_encoding";
    pub const HEX_ENCODING: &str = "hex_encoding";
    pub const URL_ENCODING: &str = "url_encoding";
    pub const UNICODE_ENCODING: &str = "unicode_encoding";
    pub const HTML_ENTITY_ENCODING: &str = "html_entity_encoding";
    pub const BINARY_ENCODING: &str = "binary_encoding";
    pub const OCTAL_ENCODING: &str = "octal_encoding";
    pub const ROT13_ENCODING: &str = "rot13_encoding";
    pub const MIXED_CASE_OBFUSCATION: &str = "mixed_case_obfuscation";

    pub const RATE_LIMITED: &str = "rate_limited";

    pub const CLASSIFIER_UNAVAILABLE: &str = "classifier_unavailable";

    pub const HTTP_VALIDATION_FAILED: &str = "http_validation_failed";
    pub const HTTP_SUCCESS: &str = "http_success";
    pub const HTTP_ERROR: &str = "http_error";
    pub const HTTP_TIMEOUT: &str = "http_timeout";

    pub const SQL_INJECTION: &str = "sql_injection";
    pub const CODE_INJECTION: &str = "code_injection";
    pub const TEMPLATE_INJECTION: &str = "template_injection";
    pub const DELIMITER_CONFUSION: &str = "delimiter_confusion";
    pub const TOOL_USE_HIJACKING: &str = "tool_use_hijacking";

    pub const ROLE_CONFUSION: &str = "role_confusion";
    pub const ROLE_CONFUSION_ROLE_ASSUMPTION: &str = "role_confusion_role_assumption";
    pub const ROLE_CONFUSION_MODE_SWITCHING: &str = "role_confusion_mode_switching";
    pub const ROLE_CONFUSION_PERMISSION_ASSERTION: &str = "role_confusion_permission_assertion";
    pub const ROLE_CONFUSION_ROLE_INDICATOR: &str = "role_confusion_role_indicator";
    pub const ROLE_CONFUSION_SCRIPT_MIXING: &str = "role_confusion_script_mixing";
    pub const ROLE_CONFUSION_LOOKALIKE_CHARACTERS: &str = "role_confusion_lookalike_characters";
    pub const ROLE_CONFUSION_MULTILINGUAL_ATTACK: &str = "role_confusion_multilingual_attack";
    pub const ROLE_CONFUSION_HIGH_RISK_ROLE: &str = "role_confusion_high_risk_role";

    pub const INSTRUCTION_HIJACKING: &str = "instruction_hijacking";
    pub const INSTRUCTION_HIJACKING_OVERRIDE: &str = "instruction_hijacking_override";
    pub const INSTRUCTION_HIJACKING_IGNORE: &str = "instruction_hijacking_ignore";
    pub const INSTRUCTION_HIJACKING_RESET: &str = "instruction_hijacking_reset";
    pub const INSTRUCTION_HIJACKING_BYPASS: &str = "instruction_hijacking_bypass";
    pub const INSTRUCTION_HIJACKING_REVEAL: &str = "instruction_hijacking_reveal";
    pub const INSTRUCTION_HIJACKING_UNKNOWN: &str = "instruction_hijacking_unknown";
    pub const INSTRUCTION_HIJACKING_SCRIPT_MIXING: &str = "instruction_hijacking_script_mixing";
    pub const INSTRUCTION_HIJACKING_LOOKALIKES: &str = "instruction_hijacking_lookalikes";
    pub const INSTRUCTION_HIJACKING_MULTILINGUAL_ATTACK: &str =
        "instruction_hijacking_multilingual_attack";
}
