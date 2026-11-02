#!/bin/bash
source "$(dirname "$0")/../../env.sh"
require_model_key

python3 -B -m src.experiments.llm.run_batch --model "$MODEL" --all --workers 16 "$@"
