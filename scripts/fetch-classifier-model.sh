#!/usr/bin/env bash
# Fetch the pinned classifier model and refresh compile-time embeds.
#
# Copies into models/<version>/ (optional on-disk override) and vendors
# classifier.onnx + JSON sidecars into src/shared/classifier/ for offline builds.
#
# Source resolution order:
#   1. MODELS_REPO / --models-repo (local checkout)
#   2. Sibling ../prompt-chainmail-models
#   3. GitHub raw URLs for prompt-chainmail/prompt-chainmail-models
#   4. Already-vendored files under src/shared/classifier/ (CI / private models repo)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIN_PATH="$ROOT/classifier-model-version.json"
EMBED_DIR="$ROOT/src/shared/classifier"
GITHUB_OWNER_REPO="prompt-chainmail/prompt-chainmail-models"
GITHUB_BRANCH="main"

MODELS_REPO="${MODELS_REPO:-}"
VERSION=""

usage() {
  cat <<'EOF'
Usage: scripts/fetch-classifier-model.sh [--model-version V] [--models-repo PATH]

Reads classifier-model-version.json (unless --model-version is set),
vendors into models/<version>/, and refreshes embedded artifacts under
src/shared/classifier/ (ONNX + manifest JSON) for portable offline builds.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --models-repo)
      MODELS_REPO="$2"
      shift 2
      ;;
    --model-version)
      VERSION="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(python3 -c "import json; print(json.load(open('$PIN_PATH'))['model_version'])")"
fi

if [[ -z "$MODELS_REPO" && -d "$ROOT/../prompt-chainmail-models" ]]; then
  MODELS_REPO="$(cd "$ROOT/../prompt-chainmail-models" && pwd)"
fi

DEST="$ROOT/models/$VERSION"
mkdir -p "$DEST"

vendored_path() {
  local filename="$1"
  case "$filename" in
    classifier.onnx|classifier.int8.onnx)
      echo "$EMBED_DIR/classifier.onnx"
      ;;
    *)
      echo "$EMBED_DIR/$filename"
      ;;
  esac
}

use_vendored() {
  local filename="$1"
  local dest_path="$2"
  local vendored
  vendored="$(vendored_path "$filename")"

  # Do not treat FLOAT32 classifier.onnx as a stand-in for INT8 weights.
  if [[ "$filename" == "classifier.int8.onnx" ]]; then
    return 1
  fi
  if [[ -f "$vendored" ]]; then
    cp "$vendored" "$dest_path"
    echo "using vendored $filename <- $vendored"
    return 0
  fi
  return 1
}

fetch_one() {
  local filename="$1"
  local dest_path="$DEST/$filename"
  local required="${2:-required}"

  if [[ -n "$MODELS_REPO" && -f "$MODELS_REPO/models/$VERSION/$filename" ]]; then
    local src="$MODELS_REPO/models/$VERSION/$filename"
    # Prefer hardlink/symlink for local checkouts; fall back to copy.
    if ln -sf "$src" "$dest_path" 2>/dev/null; then
      echo "linked $filename <- $src"
      return 0
    fi
    cp "$src" "$dest_path"
    echo "copied $filename <- $src"
    return 0
  fi

  local url="https://raw.githubusercontent.com/${GITHUB_OWNER_REPO}/${GITHUB_BRANCH}/models/${VERSION}/${filename}"
  if command -v curl >/dev/null 2>&1; then
    if curl -fsSL "$url" -o "$dest_path" 2>/dev/null; then
      echo "downloaded $filename <- $url"
      return 0
    fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -qO "$dest_path" "$url" 2>/dev/null; then
      echo "downloaded $filename <- $url"
      return 0
    fi
  fi
  rm -f "$dest_path"

  if use_vendored "$filename" "$dest_path"; then
    return 0
  fi

  if [[ "$required" == "required" ]]; then
    echo "Failed to fetch required file $filename" >&2
    exit 1
  fi
  echo "skipped optional $filename"
  return 0
}

fetch_one "model_version.json" optional
fetch_one "manifest.json"
fetch_one "normalization_vectors.json"
fetch_one "SHA256SUMS" optional
fetch_one "classifier.onnx" optional
fetch_one "classifier.int8.onnx" optional

MODEL_FILE="$(python3 -c "
import json, os
dest = '$DEST'
embed = '$EMBED_DIR'
version_path = os.path.join(dest, 'model_version.json')
if os.path.isfile(version_path):
    print(json.load(open(version_path))['model_filename'])
else:
    manifest = json.load(open(os.path.join(dest, 'manifest.json')))
    fmt = (manifest.get('quantization') or {}).get('format')
    print('classifier.int8.onnx' if fmt == 'INT8' else 'classifier.onnx')
")"

if [[ ! -f "$DEST/$MODEL_FILE" && -f "$EMBED_DIR/classifier.onnx" ]]; then
  cp "$EMBED_DIR/classifier.onnx" "$DEST/$MODEL_FILE"
  echo "using vendored $MODEL_FILE <- $EMBED_DIR/classifier.onnx"
fi

if [[ ! -f "$DEST/$MODEL_FILE" ]]; then
  echo "Missing model file $DEST/$MODEL_FILE" >&2
  exit 1
fi

# Refresh compile-time embeds (portable offline default).
# include_bytes always reads classifier.onnx; copy the published filename there.
cp "$DEST/$MODEL_FILE" "$EMBED_DIR/classifier.onnx"
cp "$DEST/manifest.json" "$EMBED_DIR/manifest.json"
cp "$DEST/normalization_vectors.json" "$EMBED_DIR/normalization_vectors.json"

echo "Classifier model $VERSION ready at $DEST"
echo "Embedded weights refreshed at $EMBED_DIR/classifier.onnx (from $MODEL_FILE)"
echo "Optional override: PROMPT_CHAINMAIL_MODEL_DIR=$DEST"
