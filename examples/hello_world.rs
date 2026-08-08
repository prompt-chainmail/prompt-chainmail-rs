use prompt_chainmail::{PromptChainmail, Rivets};

fn main() {
    let mail = PromptChainmail::new()
        .forge(Rivets::sanitize(None))
        .forge(Rivets::pattern_detection(None))
        .forge(Rivets::confidence_filter(0.8, None));

    let result = mail.protect("Hello world");
    println!(
        "success={} blocked={} confidence={}",
        result.success, result.context.blocked, result.context.confidence
    );
}
