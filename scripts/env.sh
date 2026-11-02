#!/bin/bash

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

MODEL="${MODEL:-${AGENTCORE_MODEL:-gpt-5.6-luna}}"
export MODEL
export AGENTCORE_MODEL="$MODEL"

require_model_key() {
  case "$MODEL" in
    */*) : "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY to run $MODEL}" ;;
    *)   : "${OPENAI_API_KEY:?set OPENAI_API_KEY to run $MODEL}"; export OPENROUTER_API_KEY="" ;;
  esac
}

configure_looprepair() {
  export LOOPREPAIR_MODEL="${LOOPREPAIR_MODEL:-$MODEL}"
  case "$LOOPREPAIR_MODEL" in
    */*)
      export LOOPREPAIR_API_KEY="${LOOPREPAIR_API_KEY:-${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY}}"
      export LOOPREPAIR_BASE_URL="${LOOPREPAIR_BASE_URL:-https://openrouter.ai/api/v1}"
      ;;
    *) export LOOPREPAIR_API_KEY="${LOOPREPAIR_API_KEY:-${OPENAI_API_KEY:?set OPENAI_API_KEY}}" ;;
  esac
}
