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
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIN_PATH="$ROOT/classifier-model-version.json"
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

FILES=(
  classifier.onnx
  manifest.json
  normalization-vectors.json
  model_version.json
  SHA256SUMS
)

fetch_one() {
  local filename="$1"
  local dest_path="$DEST/$filename"

  if [[ -n "$MODELS_REPO" && -f "$MODELS_REPO/models/$VERSION/$filename" ]]; then
    local src="$MODELS_REPO/models/$VERSION/$filename"
    # Prefer hardlink/symlink for local checkouts; fall back to copy.
    if ln -sf "$src" "$dest_path" 2>/dev/null; then
      echo "linked $filename <- $src"
      return
    fi
    cp "$src" "$dest_path"
    echo "copied $filename <- $src"
    return
  fi

  local url="https://raw.githubusercontent.com/${GITHUB_OWNER_REPO}/${GITHUB_BRANCH}/models/${VERSION}/${filename}"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest_path"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest_path" "$url"
  else
    echo "Need curl or wget to download $url" >&2
    exit 1
  fi
  echo "downloaded $filename <- $url"
}

for f in "${FILES[@]}"; do
  fetch_one "$f"
done

# Refresh compile-time embeds (portable offline default).
EMBED_DIR="$ROOT/src/shared/classifier"
cp "$DEST/classifier.onnx" "$EMBED_DIR/classifier.onnx"
cp "$DEST/manifest.json" "$EMBED_DIR/manifest.json"
cp "$DEST/normalization-vectors.json" "$EMBED_DIR/normalization-vectors.json"

echo "Classifier model $VERSION ready at $DEST"
echo "Embedded weights refreshed at $EMBED_DIR/classifier.onnx"
echo "Optional override: PROMPT_CHAINMAIL_MODEL_DIR=$DEST"
