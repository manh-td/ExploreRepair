#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../.."

set -euo pipefail

PATCHEVAL_COMMIT=ae9b3a7233e9e2fe86dcba8baba24beff9bcbba8

mkdir -p benchmarks
if [ ! -d benchmarks/PatchEval ]; then
  git clone https://github.com/bytedance/PatchEval benchmarks/PatchEval
fi
git -C benchmarks/PatchEval checkout "$PATCHEVAL_COMMIT"

echo "PatchEval: $(git -C benchmarks/PatchEval rev-parse --short HEAD)"
