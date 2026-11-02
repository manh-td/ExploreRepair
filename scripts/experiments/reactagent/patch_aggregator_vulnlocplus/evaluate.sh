#!/bin/bash
source "$(dirname "$0")/../../../env.sh"

python3 -B -m src.experiments.reactagent.patch_aggregator_vulnlocplus.evaluate "$@"
