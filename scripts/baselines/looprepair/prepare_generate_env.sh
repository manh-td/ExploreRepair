#!/bin/bash

set -euo pipefail

IMAGE="${LOOPREPAIR_IMAGE:-fino2020/looprepair:v1.0}"
GEN_IMAGE="looprepair-gen:latest"
TMP_CONTAINER="looprepair-gen-tmp"

docker rm -f "$TMP_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$TMP_CONTAINER" "$IMAGE" sleep infinity >/dev/null

docker exec "$TMP_CONTAINER" python3.8 -m pip install --quiet --upgrade 'pip<25'
docker exec -e CC=/usr/bin/gcc -e CXX=/usr/bin/g++ "$TMP_CONTAINER" \
    python3.8 -m pip install --quiet openai==1.59.8 tree_sitter==0.20.1 json_repair loguru attrs

docker exec "$TMP_CONTAINER" python3.8 -c 'import openai, tree_sitter, json_repair, loguru, attrs'

docker commit "$TMP_CONTAINER" "$GEN_IMAGE" >/dev/null
docker rm -f "$TMP_CONTAINER" >/dev/null

echo "prepared: $GEN_IMAGE"
