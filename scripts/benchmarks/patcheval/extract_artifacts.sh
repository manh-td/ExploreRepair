#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../../.."

python3 -B -m src.benchmarks.patcheval.extract_artifacts --all --workers 16 "$@"
