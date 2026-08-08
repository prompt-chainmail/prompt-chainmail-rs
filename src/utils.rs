//! Sync chunking helpers for large-input stream aggregation.

/// Inputs longer than this many characters use chunked processing.
pub const STRING_CHUNKING_THRESHOLD: usize = 64 * 1024;

/// Maximum characters per chunk when streaming large inputs.
pub const MAX_CHUNK_SIZE: usize = 4096;

/// Maximum total input size in characters before `stream_size_exceeded` (2 MiB).
pub const MAX_INPUT_SIZE: usize = 2 * 1024 * 1024;

/// Split `input` into successive slices of at most `chunk_size` Unicode scalar values.
///
/// Chunks respect UTF-8 char boundaries. An empty `input` yields a single empty
/// slice — empty strings are valid protect input and must not be treated as invalid.
pub fn to_chunks(input: &str, chunk_size: usize) -> Vec<&str> {
    if chunk_size == 0 || input.is_empty() {
        return vec![input];
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut count = 0usize;

    for (idx, _) in input.char_indices() {
        if count == chunk_size {
            chunks.push(&input[start..idx]);
            start = idx;
            count = 0;
        }
        count += 1;
    }
    chunks.push(&input[start..]);
    chunks
}
