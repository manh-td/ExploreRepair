#!/bin/bash
source "$(dirname "$0")/../../../env.sh"
require_model_key

python3 -B -m src.experiments.reactagent.structural_vulnlocplus.run_batch --all --workers 16 "$@"
