#!/bin/bash

source "$(dirname "$0")/../../env.sh"
configure_looprepair

python3 -B -m src.baselines.looprepair.generate_nopoc --all --workers 8 "$@"
