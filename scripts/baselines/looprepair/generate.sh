#!/bin/bash

source "$(dirname "$0")/../../env.sh"
configure_looprepair

python3 -B -m src.baselines.looprepair.generate --all --workers 8 "$@"
