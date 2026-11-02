#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../.."

INTENTFIX_REPO_URL="${INTENTFIX_REPO_URL:-https://github.com/mrhjs225/intentfix-icse2026.git}"
INTENTFIX_COMMIT="${INTENTFIX_COMMIT:-4873f172e3059c62ddc86980ef321ed25d287ac7}"
INTENTFIX_DIR="${INTENTFIX_DIR:-baselines/IntentFix}"

CREATED=0
if [ ! -e "$INTENTFIX_DIR/.git" ]; then
    if [ -e "$INTENTFIX_DIR" ]; then
        echo "error: $INTENTFIX_DIR already exists and is not a Git checkout" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$INTENTFIX_DIR")"
    git clone --filter=blob:none --no-checkout "$INTENTFIX_REPO_URL" "$INTENTFIX_DIR"
    CREATED=1
fi

if ! git -C "$INTENTFIX_DIR" cat-file -e "$INTENTFIX_COMMIT^{commit}" 2>/dev/null; then
    git -C "$INTENTFIX_DIR" fetch "$INTENTFIX_REPO_URL" "$INTENTFIX_COMMIT"
fi

REVISION="$(git -C "$INTENTFIX_DIR" rev-parse "$INTENTFIX_COMMIT^{commit}")"
CURRENT="$(git -C "$INTENTFIX_DIR" rev-parse --verify HEAD 2>/dev/null || true)"
if [ "$CREATED" = 1 ]; then
    git -C "$INTENTFIX_DIR" sparse-checkout set --no-cone \
        /intentfix/ /prompts/ /config.py /README.md /environment.yml
    git -C "$INTENTFIX_DIR" checkout --detach "$REVISION"
elif [ "$CURRENT" != "$REVISION" ]; then
    if [ -n "$(git -C "$INTENTFIX_DIR" status --porcelain)" ]; then
        echo "error: $INTENTFIX_DIR has local changes; refusing to switch revisions" >&2
        exit 1
    fi
    git -C "$INTENTFIX_DIR" checkout --detach "$REVISION"
fi

for FILE in config.py intentfix/pipeline.py intentfix/llm_interface.py intentfix/utils.py; do
    if [ ! -f "$INTENTFIX_DIR/$FILE" ]; then
        echo "error: upstream checkout is missing $FILE" >&2
        exit 1
    fi
done
if [ ! -d "$INTENTFIX_DIR/prompts" ]; then
    echo "error: upstream checkout is missing prompts/" >&2
    exit 1
fi

echo "IntentFix: $REVISION ($INTENTFIX_DIR)"
