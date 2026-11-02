#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../.."

set -euo pipefail

TARGET="${EMBEDDING_MODEL_DIR:-models/bge-large-en-v1.5}"

EMBEDDING_MODEL_DIR="$TARGET" python3 - <<'PYCODE'
import os
from huggingface_hub import snapshot_download
snapshot_download('BAAI/bge-large-en-v1.5', local_dir=os.environ['EMBEDDING_MODEL_DIR'],
                  ignore_patterns=['onnx/*', '*.onnx'])
PYCODE
ls -la "$TARGET"
