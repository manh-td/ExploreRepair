#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../.."
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="$REPO_ROOT/baselines/LoopRepair/src/looprepair/LLMRepair.py"
CURRENT_MARKER=PROVIDER_ROUTING

apply() {
  local patch="$REPO_ROOT/scripts/patches/$1.patch"
  if (cd "$REPO_ROOT/baselines/LoopRepair" && patch --dry-run --silent -p1 < "$patch") >/dev/null 2>&1; then
    (cd "$REPO_ROOT/baselines/LoopRepair" && patch --silent -p1 < "$patch")
    echo "Applied $1.patch to $TARGET"
  else
    echo "error: $1.patch did not apply to $TARGET" >&2
    exit 1
  fi
}

if grep -q "$CURRENT_MARKER" "$TARGET" 2>/dev/null; then
  echo "LoopRepair patches already applied"
  exit 0
fi
git -C "$REPO_ROOT/baselines/LoopRepair" checkout -- src/looprepair/LLMRepair.py
apply looprepair-model-env
apply looprepair-json-retry
