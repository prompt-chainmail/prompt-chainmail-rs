use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rivets::types::security_flags;
use crate::rivets::Rivet;
use crate::types::{ChainmailContext, ChainmailResult};

type KeyFn = Arc<dyn Fn(&ChainmailContext) -> String + Send + Sync>;

struct RateLimitRivet {
    max_requests: usize,
    window_ms: u128,
    key_fn: KeyFn,
    max_keys: usize,
    requests: Mutex<HashMap<String, Vec<u128>>>,
}

impl Rivet for RateLimitRivet {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    fn process(
        &self,
        context: &mut ChainmailContext,
        next: &mut dyn FnMut(&mut ChainmailContext) -> ChainmailResult,
    ) -> ChainmailResult {
        let key = (self.key_fn)(context);
        let now = now_ms();

        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());

        if requests.len() >= self.max_keys && !requests.contains_key(&key) {
            context
                .flags
                .insert(security_flags::RATE_LIMITED.to_string());
            context.set_blocked(true);
            return ChainmailResult {
                success: false,
                context: context.clone(),
                error: None,
                processing_time: now.saturating_sub(context.start_time),
            };
        }

        let timestamps = requests.entry(key).or_default();

        while let Some(first) = timestamps.first() {
            if *first < now.saturating_sub(self.window_ms) {
                timestamps.remove(0);
            } else {
                break;
            }
        }

        if timestamps.len() >= self.max_requests {
            context.set_blocked(true);
            context
                .flags
                .insert(security_flags::RATE_LIMITED.to_string());
            return ChainmailResult {
                success: false,
                context: context.clone(),
                error: None,
                processing_time: now.saturating_sub(context.start_time),
            };
        }

        timestamps.push(now);
        drop(requests);

        next(context)
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Rate-limits by key within a sliding time window.
///
/// Defaults: `max_requests=100`, `window_ms=60000`, key `"global"`, `max_keys=1000`.
pub fn rate_limit(
    max_requests: Option<usize>,
    window_ms: Option<u128>,
    key_fn: Option<KeyFn>,
    max_keys: Option<usize>,
) -> Arc<dyn Rivet> {
    let key_fn = key_fn.unwrap_or_else(|| Arc::new(|_: &ChainmailContext| "global".to_string()));
    Arc::new(RateLimitRivet {
        max_requests: max_requests.unwrap_or(100),
        window_ms: window_ms.unwrap_or(60_000),
        key_fn,
        max_keys: max_keys.unwrap_or(1000),
        requests: Mutex::new(HashMap::new()),
    })
}
