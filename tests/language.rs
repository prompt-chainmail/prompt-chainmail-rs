//! Language detection helpers + rivet metadata tests.

use prompt_chainmail::{
    detect_lookalike_chars, has_language_script_mixing, normalize_text, PromptChainmail, Rivets,
};

#[test]
fn normalize_text_smoke() {
    assert_eq!(
        normalize_text("café résumé naïve"),
        normalize_text("cafe resume naive")
    );
    assert_eq!(normalize_text("HELLO WORLD"), "hello world");
    assert_eq!(normalize_text("o-v-e-r-r-i-d-e"), "override");
}

#[test]
fn lookalike_and_script_mixing_smoke() {
    assert!(has_language_script_mixing("hello мир"));
    assert!(!has_language_script_mixing("hello world"));
    assert!(detect_lookalike_chars("а")); // Cyrillic a
    assert!(!detect_lookalike_chars("a"));
    // Greek omicron lookalike → latin o when no Cyrillic present
    assert_eq!(normalize_text("hεllo wοrld"), "hεllo world");
}

#[test]
fn language_detection_rivet_writes_detected_languages_metadata() {
    let mail = PromptChainmail::new().forge(Rivets::language_detection());
    let result = mail.protect("The quick brown fox jumps over the lazy dog.");

    let langs = result
        .context
        .metadata
        .get("detected_languages")
        .expect("detected_languages metadata");
    let arr = langs.as_array().expect("array of [code, score] pairs");
    assert!(!arr.is_empty());
    let first = arr[0].as_array().expect("pair");
    assert!(first[0].as_str().is_some());
    assert!(first[1].as_f64().is_some());
}
