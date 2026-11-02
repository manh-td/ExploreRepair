#!/bin/bash
source "$(dirname "$0")/../../../env.sh"

python3 -B -m src.experiments.reactagent.three_in_one_agent.evaluate "$@"
