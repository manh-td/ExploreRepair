#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/.."

BENCHMARK="${1:-patcheval}"
case "$BENCHMARK" in
  patcheval)   SUFFIX="" ;;
  vulnlocplus) SUFFIX="_vulnlocplus" ;;
  *) echo "usage: $0 [patcheval|vulnlocplus]" >&2; exit 1 ;;
esac

stage() {
  bash "scripts/experiments/reactagent/$1${SUFFIX}/run_batch.sh"
  bash "scripts/experiments/reactagent/$1${SUFFIX}/evaluate.sh"
}

stage structural
stage semantic
stage executable

stage lesson_aggregator
stage patch_aggregator
stage explorerepair
