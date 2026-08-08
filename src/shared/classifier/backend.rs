//! Windowed byte-level ONNX classification (sync).
//!
//! With the `parallel` feature (default), windows are evaluated concurrently via rayon and
//! a pool of ORT sessions (`PROMPT_CHAINMAIL_ORT_POOL` overrides pool size).

use std::collections::HashMap;
use std::sync::Mutex;

use ort::value::Tensor;

use super::cache::BoundedCache;
use super::labels::CLASSIFIER_LABELS;
use super::normalize::{window_classifier_ranges, ClassifierWindow};
use super::session::{get_classifier_session, ClassifierError};
use super::types::{ClassifierClassification, ClassifierMatch};

#[cfg(feature = "parallel")]
use super::session::get_classifier_session_pool;

const DEFAULT_CACHE_SIZE: usize = 256;
/// Below this many windows, serial inference is cheaper than pool checkout.
#[cfg(feature = "parallel")]
const PARALLEL_WINDOW_THRESHOLD: usize = 4;

fn empty_probabilities() -> HashMap<String, f64> {
    let mut probabilities = HashMap::new();
    for label in CLASSIFIER_LABELS {
        probabilities.insert((*label).to_string(), 0.0);
    }
    probabilities
}

/// Runs windowed byte-level classification and max-aggregates across windows.
pub struct ClassifierBackend {
    cache: Mutex<BoundedCache<String, ClassifierClassification>>,
}

impl Default for ClassifierBackend {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_SIZE)
    }
}

impl ClassifierBackend {
    pub fn new(cache_size: usize) -> Self {
        Self {
            cache: Mutex::new(
                BoundedCache::new(cache_size).expect("cache_size must be positive"),
            ),
        }
    }

    pub fn classify(&self, text: &str) -> Result<ClassifierClassification, ClassifierError> {
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(&text.to_string()) {
                return Ok(cached);
            }
        }

        let classification = self.run_inference(text)?;

        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.set(text.to_string(), classification.clone());
        Ok(classification)
    }

    fn run_inference(&self, text: &str) -> Result<ClassifierClassification, ClassifierError> {
        if text.trim().is_empty() {
            return Ok(ClassifierClassification {
                attack_probability: 0.0,
                probabilities: empty_probabilities(),
                matches: Vec::new(),
                window_errors: 0,
            });
        }

        let handle = get_classifier_session()?;
        let manifest = &handle.manifest;
        let windows = window_classifier_ranges(
            text,
            manifest.window_size_bytes,
            manifest.window_stride_bytes,
        )
        .map_err(|e| ClassifierError::new("window_error", e))?;

        #[cfg(feature = "parallel")]
        {
            if windows.len() >= PARALLEL_WINDOW_THRESHOLD {
                let pool = get_classifier_session_pool()?;
                return aggregate_window_results(
                    &windows,
                    &pool.manifest.artifact_version,
                    &pool.manifest.thresholds,
                    pool.manifest.window_size_bytes,
                    parallel_run_windows(pool, &windows, pool.manifest.window_size_bytes),
                );
            }
        }

        let mut session = handle.session.lock().unwrap_or_else(|e| e.into_inner());
        let mut results = Vec::with_capacity(windows.len());
        for (window_index, window) in windows.iter().enumerate() {
            results.push((
                window_index,
                window.start,
                window.end,
                run_window(&mut session, &window.bytes, manifest.window_size_bytes),
            ));
        }
        aggregate_window_results(
            &windows,
            &manifest.artifact_version,
            &manifest.thresholds,
            manifest.window_size_bytes,
            results,
        )
    }

    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }
}

type WindowResult = (
    usize,
    usize,
    usize,
    Result<(f64, Vec<f64>), ClassifierError>,
);

#[cfg(feature = "parallel")]
fn parallel_run_windows(
    pool: &super::session::ClassifierSessionPool,
    windows: &[ClassifierWindow],
    window_size_bytes: usize,
) -> Vec<WindowResult> {
    use rayon::prelude::*;

    windows
        .par_iter()
        .enumerate()
        .map(|(window_index, window)| {
            let outcome = pool.with_session(|session| {
                run_window(session, &window.bytes, window_size_bytes)
            });
            (window_index, window.start, window.end, outcome)
        })
        .collect()
}

fn aggregate_window_results(
    windows: &[ClassifierWindow],
    artifact_version: &str,
    thresholds: &HashMap<String, f64>,
    _window_size_bytes: usize,
    results: Vec<WindowResult>,
) -> Result<ClassifierClassification, ClassifierError> {
    let mut attack_probability = 0.0_f64;
    let mut probabilities = empty_probabilities();
    let mut matches = Vec::new();
    let mut window_errors = 0usize;
    let mut first_window_error: Option<ClassifierError> = None;

    for (window_index, start, end, outcome) in results {
        match outcome {
            Ok((window_attack, subtype)) => {
                if window_attack > attack_probability {
                    attack_probability = window_attack;
                }
                for (label_index, label) in CLASSIFIER_LABELS.iter().enumerate() {
                    let probability = subtype.get(label_index).copied().unwrap_or(0.0);
                    let entry = probabilities.entry((*label).to_string()).or_insert(0.0);
                    if probability > *entry {
                        *entry = probability;
                    }
                    let threshold = thresholds.get(*label).copied().unwrap_or(1.0);
                    if probability >= threshold {
                        matches.push(ClassifierMatch {
                            label: (*label).to_string(),
                            probability,
                            window_index,
                            window_start_byte: start,
                            window_end_byte: end,
                            model_version: artifact_version.to_string(),
                        });
                    }
                }
            }
            Err(err) => {
                window_errors += 1;
                if first_window_error.is_none() {
                    first_window_error = Some(err);
                }
            }
        }
    }

    if !windows.is_empty() && window_errors == windows.len() {
        return Err(first_window_error.unwrap_or_else(|| {
            ClassifierError::new(
                "window_classification_failed",
                "All classifier windows failed to produce output",
            )
        }));
    }

    Ok(ClassifierClassification {
        attack_probability,
        probabilities,
        matches,
        window_errors,
    })
}

fn run_window(
    session: &mut ort::session::Session,
    window: &[u8],
    window_size_bytes: usize,
) -> Result<(f64, Vec<f64>), ClassifierError> {
    let mut ids = vec![0i64; window_size_bytes];
    let mut mask = vec![0i64; window_size_bytes];
    for (i, byte) in window.iter().enumerate() {
        ids[i] = i64::from(*byte);
        mask[i] = 1;
    }

    let input_ids = Tensor::from_array(([1usize, window_size_bytes], ids)).map_err(|e| {
        ClassifierError::new("tensor_create_failed", format!("input_ids: {e}"))
    })?;
    let attention_mask =
        Tensor::from_array(([1usize, window_size_bytes], mask)).map_err(|e| {
            ClassifierError::new("tensor_create_failed", format!("attention_mask: {e}"))
        })?;

    let outputs = session
        .run(ort::inputs! {
            "input_ids" => input_ids,
            "attention_mask" => attention_mask,
        })
        .map_err(|e| {
            ClassifierError::new(
                "window_classification_failed",
                format!("session.run failed: {e}"),
            )
        })?;

    let attack_tensor = outputs.get("attack_probability").ok_or_else(|| {
        ClassifierError::new(
            "missing_output",
            "Classifier session output is missing the 'attack_probability' tensor",
        )
    })?;
    let (_, attack_data) = attack_tensor.try_extract_tensor::<f32>().map_err(|e| {
        ClassifierError::new(
            "missing_output",
            format!("Failed to extract attack_probability: {e}"),
        )
    })?;
    let window_attack = f64::from(attack_data.first().copied().unwrap_or(0.0));

    let subtype_tensor = outputs.get("subtype_probabilities").ok_or_else(|| {
        ClassifierError::new(
            "missing_output",
            "Classifier session output is missing the 'subtype_probabilities' tensor",
        )
    })?;
    let (_, subtype_data) = subtype_tensor.try_extract_tensor::<f32>().map_err(|e| {
        ClassifierError::new(
            "missing_output",
            format!("Failed to extract subtype_probabilities: {e}"),
        )
    })?;
    let subtype: Vec<f64> = subtype_data.iter().map(|v| f64::from(*v)).collect();

    Ok((window_attack, subtype))
}
