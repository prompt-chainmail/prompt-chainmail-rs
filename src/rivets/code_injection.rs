use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::Value;

use crate::rivets::types::{security_flags, ThreatLevel};
use crate::rivets::utils::apply_threat_penalty;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

static CODE_INJECTION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let sources: &[&str] = &[
        r"(?i)\b(eval|exec|execfile|compile)\s*\(",
        r"(?i)\b(import\s+os|import\s+subprocess|import\s+sys)\b",
        r"(?i)\b(require\s*\(|module\.exports)\b",
        r"(?i)<script[^>]*>|</script>",
        r"(?i)\b(function\s*\(|=>\s*\{|\$\{)",
        r"(?i)\b(rm\s+-rf|del\s+/|sudo\s+)",
        r"(?i)\b(wget|curl|fetch)\s+http",
        r"(?i)\b(__import__|getattr|setattr|hasattr)\s*\(",
        r"(?i)\b(process\.env|process\.exit|process\.kill)",
        r"(?i)\b(setTimeout|setInterval)\s*\(",
        r"(?i)\bnew\s+Function\s*\(",
        r"(?i)\bimport\s*\(",
        r"(?i)\b(child_process|fs\.unlink|fs\.rmdir)\b",
        r"(?i)\b(sh\s+-c|bash\s+-c|cmd\s+/c|powershell\s+-c)\b",
        r"(?i)\b(system\s*\(|popen\s*\(|shell_exec\s*\()\b",
        r"(?i)\b(os\.system|subprocess\.call|subprocess\.run)\b",
        r"(?i)\b(cat\s+/etc/passwd|ls\s+-la|ps\s+aux|netstat\s+-an)\b",
        r"(?i)\b(whoami|id|uname\s+-a|pwd|env)\b",
        r"(?i)\b(chmod\s+\+x|chown\s+|mount\s+|umount\s+)\b",
        r"(?i)\b(nc\s+-|ncat\s+-|telnet\s+|ssh\s+)\b",
        r"(?i)\b(iptables\s+|firewall\s+|selinux\s+)\b",
        r"(?i)\b(crontab\s+-|at\s+now|systemctl\s+)\b",
        r"(?i)\b(find\s+.*-exec|xargs\s+.*rm|grep\s+-r)\b",
        r"(?i)\b(tar\s+-|zip\s+-|unzip\s+-|gzip\s+-)\b",
        r"(?i)\b(kill\s+-9|killall\s+|pkill\s+)\b",
        r"(?i)\b(nohup\s+|screen\s+-|tmux\s+)\b",
        r"(?i)\b(dd\s+if=|fdisk\s+-|mkfs\s+)\b",
        r"(?i)\b(echo\s+.*>\s*/|cat\s+.*>\s*/)\b",
        r"(?i)\b(\|\s*sh|\|\s*bash|\|\s*zsh)\b",
        r"(?i)\b(`[^`]*`|\$\([^)]*\))\b",
    ];

    sources
        .iter()
        .map(|pat| Regex::new(pat).expect("valid code injection pattern"))
        .collect()
});

struct CodeInjectionRivet;

impl Rivet for CodeInjectionRivet {
    fn name(&self) -> &'static str {
        "code_injection"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        for pattern in CODE_INJECTION_PATTERNS.iter() {
            if pattern.is_match(&context.sanitized) {
                context
                    .flags
                    .insert(security_flags::CODE_INJECTION.to_string());
                apply_threat_penalty(context, ThreatLevel::Critical);
                context.metadata.insert(
                    "code_pattern".to_string(),
                    Value::String(pattern.as_str().to_string()),
                );
                break;
            }
        }
        next(context)
    }
}

pub fn code_injection() -> Arc<dyn Rivet> {
    Arc::new(CodeInjectionRivet)
}
