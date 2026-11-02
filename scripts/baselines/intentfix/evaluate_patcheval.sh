#!/bin/bash
source "$(dirname "$0")/../../env.sh"

python3 -B -m src.baselines.intentfix.evaluate_patcheval "$@"
