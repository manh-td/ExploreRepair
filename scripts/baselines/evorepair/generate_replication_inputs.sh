#!/bin/bash
source "$(dirname "$0")/../../env.sh"
case " $* " in
  *" --dry-run "*|*" --help "*|*" -h "*) ;;
  *) require_model_key ;;
esac

python3 -B -m src.baselines.evorepair.run --model "$MODEL" "$@"
