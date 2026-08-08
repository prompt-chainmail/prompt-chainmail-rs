use prompt_chainmail::Chainmails;

fn main() {
    let mail = Chainmails::basic(None, None);
    let result = mail.protect("Hello world");
    println!(
        "success={} blocked={} confidence={} flags={:?}",
        result.success,
        result.context.blocked,
        result.context.confidence,
        result.context.flags
    );
}
