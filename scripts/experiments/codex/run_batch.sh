#!/bin/bash
source "$(dirname "$0")/../../env.sh"
require_model_key

python3 -B -m src.experiments.codex.run_batch --model "$MODEL" --all --workers 8 "$@"
