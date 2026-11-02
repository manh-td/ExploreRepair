#!/bin/bash
source "$(dirname "$0")/../../../env.sh"

python3 -B -m src.experiments.reactagent.structural.evaluate "$@"
