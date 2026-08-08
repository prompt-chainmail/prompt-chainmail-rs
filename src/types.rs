use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// Context passed through the rivet chain during input processing.
#[derive(Debug, Clone)]
pub struct ChainmailContext {
    /// Original input (immutable after construction).
    pub input: String,
    /// Current text after rivet transformations.
    pub sanitized: String,
    pub flags: HashSet<String>,
    /// Confidence in `[0.0, 1.0]` (1.0 = safe).
    pub confidence: f64,
    pub metadata: HashMap<String, Value>,
    /// Once set to `true` via [`Self::set_blocked`], it must not be cleared.
    /// Prefer [`Self::set_blocked`] over assigning this field directly.
    pub blocked: bool,
    /// Milliseconds since UNIX epoch when processing started.
    pub start_time: u128,
    pub session_id: String,
}

impl ChainmailContext {
    /// Latch `blocked` to `true`. Clearing back to `false` is a no-op once latched.
    pub fn set_blocked(&mut self, blocked: bool) {
        if blocked {
            self.blocked = true;
        }
    }
}

/// Result after processing input through the chainmail.
#[derive(Debug, Clone)]
pub struct ChainmailResult {
    /// `true` when `!context.blocked` and no processing error.
    pub success: bool,
    pub context: ChainmailContext,
    pub error: Option<String>,
    /// Duration in milliseconds.
    pub processing_time: u128,
}
