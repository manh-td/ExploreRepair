#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../.."

set -euo pipefail

LOOPREPAIR_COMMIT=5d127e32014c5ad7e4a0edadbc5aaa78206f728f
IMAGE="${LOOPREPAIR_IMAGE:-fino2020/looprepair:v1.0}"

mkdir -p baselines
if [ ! -d baselines/LoopRepair ]; then
  git clone https://github.com/Fino2020/LoopRepair baselines/LoopRepair
fi
git -C baselines/LoopRepair checkout "$LOOPREPAIR_COMMIT"

docker pull "$IMAGE"

echo "LoopRepair: $(git -C baselines/LoopRepair rev-parse --short HEAD), $(ls baselines/LoopRepair/generated_patches/diff/*/*/*.txt | wc -l) generated patches"
