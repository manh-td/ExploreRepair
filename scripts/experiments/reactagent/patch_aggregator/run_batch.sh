#!/bin/bash
source "$(dirname "$0")/../../../env.sh"
require_model_key

python3 -B -m src.experiments.reactagent.patch_aggregator.run_batch --all --workers 16 "$@"
