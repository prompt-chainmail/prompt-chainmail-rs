use std::io::{self, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

/// Log levels for the logger rivet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    #[default]
    Log,
    Warn,
    Debug,
    Info,
}

type LogFn = Arc<dyn Fn(&ChainmailContext) + Send + Sync>;

struct LoggerRivet {
    level: LogLevel,
    log_fn: Option<LogFn>,
}

impl Rivet for LoggerRivet {
    fn name(&self) -> &'static str {
        "logger"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let start = now_ms();
        let result = next(context);
        let duration = now_ms().saturating_sub(start);

        if let Some(log_fn) = &self.log_fn {
            log_fn(context);
        } else {
            let flags: Vec<&str> = context.flags.iter().map(|s| s.as_str()).collect();
            let message = format!(
                "[PromptChainmail] flags={:?} confidence={} blocked={} duration={} input_length={}",
                flags,
                context.confidence,
                context.blocked,
                duration,
                context.input.len()
            );
            match self.level {
                LogLevel::Warn => {
                    let _ = writeln!(io::stderr(), "{message}");
                }
                LogLevel::Log | LogLevel::Debug | LogLevel::Info => {
                    let _ = writeln!(io::stdout(), "{message}");
                }
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

/// Calls `next` first, then logs (order matters for timing).
pub fn logger(level: Option<LogLevel>, log_fn: Option<LogFn>) -> Arc<dyn Rivet> {
    Arc::new(LoggerRivet {
        level: level.unwrap_or_default(),
        log_fn,
    })
}
