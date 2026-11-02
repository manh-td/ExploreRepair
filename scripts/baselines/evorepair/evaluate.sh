#!/bin/bash
source "$(dirname "$0")/../../env.sh"

python3 -B -m src.baselines.evorepair.grade_replication_run "$@"
