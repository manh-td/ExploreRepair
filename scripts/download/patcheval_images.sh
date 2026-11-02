#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../.."

pushd benchmarks/PatchEval/scripts
python3 -B -m download_images
popd
