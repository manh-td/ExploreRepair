#!/bin/bash

source "$(dirname "$0")/../../env.sh"
case " $* " in
  *" --help "*|*" -h "*) ;;
  *) require_model_key ;;
esac

python3 -B -m src.baselines.intentfix.run_patcheval --all --model "$MODEL" --workers 16 "$@"
