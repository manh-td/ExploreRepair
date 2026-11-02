#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../../.."

set -euo pipefail

IMAGE="${LOOPREPAIR_IMAGE:-fino2020/looprepair:v1.0}"
PREPPED_IMAGE="looprepair-prepped:latest"
TMP_CONTAINER="looprepair-prep-tmp"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

docker rm -f "$TMP_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$TMP_CONTAINER" "$IMAGE" sleep infinity >/dev/null

docker cp "$REPO_ROOT/baselines/LoopRepair/src" "$TMP_CONTAINER:/looprepair-src"
docker cp "$REPO_ROOT/baselines/LoopRepair/generated_patches" "$TMP_CONTAINER:/generated_patches"

docker exec -i "$TMP_CONTAINER" bash -c 'cat > /looprepair-src/looprepair/LLMRepair.py' <<'EOF'
def generate_use_llms_from_localization_path(*args, **kwargs):
    raise NotImplementedError("LLM patch generation is stubbed out - not used by evaluate_in_container.py")

def generate_use_llms_from_localization_list(*args, **kwargs):
    raise NotImplementedError("LLM patch generation is stubbed out - not used by evaluate_in_container.py")
EOF

docker exec "$TMP_CONTAINER" sed -i '28,41d;15d' /looprepair-src/looprepair/candidate.py

docker exec "$TMP_CONTAINER" python3.8 -m pip install attrs loguru

docker commit "$TMP_CONTAINER" "$PREPPED_IMAGE" >/dev/null
docker rm -f "$TMP_CONTAINER" >/dev/null

echo "prepared: $PREPPED_IMAGE"
