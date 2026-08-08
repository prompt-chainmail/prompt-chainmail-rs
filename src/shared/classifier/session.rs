//! ONNX session load: embedded portable weights (offline), optional dir override.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ort::session::Session;

use super::checksum::sha256_hex;
use super::manifest::CLASSIFIER_MANIFEST;
use super::types::ClassifierManifest;

/// Pinned FLOAT32 ONNX weights (~1.3 MiB), vendored for offline/portable use.
/// Refresh via `make fetch-classifier` (copies into this path).
static EMBEDDED_MODEL_ONNX: &[u8] = include_bytes!("classifier.onnx");

/// Classifier error with a stable machine-readable `code`.
#[derive(Debug, Clone)]
pub struct ClassifierError {
    pub code: String,
    pub message: String,
}

impl ClassifierError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ClassifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ClassifierError {}

/// Pinned model version from crate-root `classifier-model-version.json`.
pub fn pinned_model_version() -> &'static str {
    static PIN: OnceLock<String> = OnceLock::new();
    PIN.get_or_init(|| {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/classifier-model-version.json"
        ));
        let value: serde_json::Value =
            serde_json::from_str(raw).expect("classifier-model-version.json");
        value
            .get("model_version")
            .and_then(|v| v.as_str())
            .expect("model_version field")
            .to_string()
    })
    .as_str()
}

/// Optional override directory for on-disk weights (`PROMPT_CHAINMAIL_MODEL_DIR`).
///
/// Default runtime path uses [`embedded_model_bytes`] — no filesystem required.
pub fn resolve_model_dir() -> Result<PathBuf, ClassifierError> {
    if let Ok(dir) = std::env::var("PROMPT_CHAINMAIL_MODEL_DIR") {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            return Ok(path);
        }
        return Err(ClassifierError::new(
            "model_dir_missing",
            format!(
                "PROMPT_CHAINMAIL_MODEL_DIR is set but is not a directory: {}",
                path.display()
            ),
        ));
    }

    Err(ClassifierError::new(
        "model_dir_not_used",
        "No PROMPT_CHAINMAIL_MODEL_DIR set; using embedded classifier.onnx",
    ))
}

fn model_filename(manifest: &ClassifierManifest) -> &'static str {
    match manifest.quantization.format.as_str() {
        "INT8" => "classifier.int8.onnx",
        _ => "classifier.onnx",
    }
}

fn verify_model_bytes(
    bytes: &[u8],
    manifest: &ClassifierManifest,
    source: &str,
) -> Result<(), ClassifierError> {
    if bytes.len() as u64 != manifest.model_size_bytes {
        return Err(ClassifierError::new(
            "model_size_mismatch",
            format!(
                "Classifier model size {} does not match manifest {} ({source})",
                bytes.len(),
                manifest.model_size_bytes,
            ),
        ));
    }

    let computed = sha256_hex(bytes);
    if computed != manifest.model_sha256 {
        return Err(ClassifierError::new(
            "checksum_mismatch",
            format!("Classifier model checksum does not match the manifest ({source})"),
        ));
    }

    Ok(())
}

/// Embedded ONNX weights (verified against the pinned manifest).
pub fn embedded_model_bytes(
    manifest: &ClassifierManifest,
) -> Result<&'static [u8], ClassifierError> {
    verify_model_bytes(EMBEDDED_MODEL_ONNX, manifest, "embedded classifier.onnx")?;
    Ok(EMBEDDED_MODEL_ONNX)
}

/// Load model bytes from `dir`, verifying size and sha256 against `manifest`.
pub fn load_and_verify_model(
    dir: &Path,
    manifest: &ClassifierManifest,
) -> Result<Vec<u8>, ClassifierError> {
    let path = dir.join(model_filename(manifest));
    let bytes = fs::read(&path).map_err(|e| {
        ClassifierError::new(
            "model_read_failed",
            format!("Failed to read {}: {e}", path.display()),
        )
    })?;
    verify_model_bytes(&bytes, manifest, &path.display().to_string())?;
    Ok(bytes)
}

/// Resolve model bytes: `PROMPT_CHAINMAIL_MODEL_DIR` override, else embedded.
pub fn load_classifier_model_bytes(
    manifest: &ClassifierManifest,
) -> Result<std::borrow::Cow<'static, [u8]>, ClassifierError> {
    if std::env::var_os("PROMPT_CHAINMAIL_MODEL_DIR").is_some() {
        let dir = resolve_model_dir()?;
        let bytes = load_and_verify_model(&dir, manifest)?;
        return Ok(std::borrow::Cow::Owned(bytes));
    }
    Ok(std::borrow::Cow::Borrowed(embedded_model_bytes(manifest)?))
}

pub struct ClassifierSessionHandle {
    pub session: Mutex<Session>,
    pub manifest: ClassifierManifest,
}

/// Pool of ORT sessions for parallel window inference (`parallel` feature).
#[cfg(feature = "parallel")]
pub struct ClassifierSessionPool {
    pub sessions: Vec<Mutex<Session>>,
    pub idle: Mutex<Vec<usize>>,
    pub manifest: ClassifierManifest,
}

#[cfg(feature = "parallel")]
impl ClassifierSessionPool {
    /// Borrow an idle session, run `f`, return the session to the pool.
    pub fn with_session<R>(&self, f: impl FnOnce(&mut Session) -> R) -> R {
        let idx = loop {
            if let Some(i) = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop() {
                break i;
            }
            std::thread::yield_now();
        };
        let result = {
            let mut session = self.sessions[idx]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            f(&mut session)
        };
        self.idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(idx);
        result
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }
}

static CACHED_SESSION: OnceLock<Result<ClassifierSessionHandle, ClassifierError>> = OnceLock::new();

#[cfg(feature = "parallel")]
static CACHED_POOL: OnceLock<Result<ClassifierSessionPool, ClassifierError>> = OnceLock::new();

fn create_ort_session(model_bytes: &[u8]) -> Result<Session, ClassifierError> {
    Session::builder()
        .map_err(|e| {
            ClassifierError::new(
                "session_create_failed",
                format!("Failed to create classifier session builder: {e}"),
            )
        })?
        .commit_from_memory(model_bytes)
        .map_err(|e| {
            ClassifierError::new(
                "session_create_failed",
                format!("Failed to create classifier inference session: {e}"),
            )
        })
}

fn create_classifier_session() -> Result<ClassifierSessionHandle, ClassifierError> {
    let manifest = CLASSIFIER_MANIFEST.clone();
    let model_bytes = load_classifier_model_bytes(&manifest)?;
    let session = create_ort_session(model_bytes.as_ref())?;

    Ok(ClassifierSessionHandle {
        session: Mutex::new(session),
        manifest,
    })
}

#[cfg(feature = "parallel")]
fn pool_size() -> usize {
    std::env::var("PROMPT_CHAINMAIL_ORT_POOL")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n: &usize| *n >= 1)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .clamp(1, 16)
}

#[cfg(feature = "parallel")]
fn create_classifier_pool() -> Result<ClassifierSessionPool, ClassifierError> {
    let manifest = CLASSIFIER_MANIFEST.clone();
    let model_bytes = load_classifier_model_bytes(&manifest)?;
    let n = pool_size();
    let mut sessions = Vec::with_capacity(n);
    for _ in 0..n {
        sessions.push(Mutex::new(create_ort_session(model_bytes.as_ref())?));
    }
    let idle = (0..n).collect();
    Ok(ClassifierSessionPool {
        sessions,
        idle: Mutex::new(idle),
        manifest,
    })
}

pub fn get_classifier_session() -> Result<&'static ClassifierSessionHandle, ClassifierError> {
    let cached = CACHED_SESSION.get_or_init(create_classifier_session);
    match cached {
        Ok(handle) => Ok(handle),
        Err(e) => Err(e.clone()),
    }
}

#[cfg(feature = "parallel")]
pub fn get_classifier_session_pool() -> Result<&'static ClassifierSessionPool, ClassifierError> {
    let cached = CACHED_POOL.get_or_init(create_classifier_pool);
    match cached {
        Ok(pool) => Ok(pool),
        Err(e) => Err(e.clone()),
    }
}
