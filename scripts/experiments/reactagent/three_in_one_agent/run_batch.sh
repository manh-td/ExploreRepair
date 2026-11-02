#!/bin/bash
source "$(dirname "$0")/../../../env.sh"
require_model_key

python3 -B -m src.experiments.reactagent.three_in_one_agent.run_batch --all --workers 16 "$@"
