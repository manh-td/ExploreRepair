#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../.."

EVOREPAIR_REPO_URL="${EVOREPAIR_REPO_URL:-https://github.com/iSEngLab/Learn-from-Repair-Experience.git}"
EVOREPAIR_COMMIT="${EVOREPAIR_COMMIT:-d0d885513e750d3c5bbed183e839f0c709dfbf60}"
EVOREPAIR_DIR="${EVOREPAIR_DIR:-baselines/EvoRepair}"

if [ ! -e "$EVOREPAIR_DIR/.git" ]; then
    if [ -e "$EVOREPAIR_DIR" ]; then
        echo "error: $EVOREPAIR_DIR already exists and is not a Git checkout" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$EVOREPAIR_DIR")"
    git clone --no-checkout "$EVOREPAIR_REPO_URL" "$EVOREPAIR_DIR"
fi

if ! git -C "$EVOREPAIR_DIR" cat-file -e "$EVOREPAIR_COMMIT^{commit}" 2>/dev/null; then
    git -C "$EVOREPAIR_DIR" fetch "$EVOREPAIR_REPO_URL" "$EVOREPAIR_COMMIT"
fi

REVISION="$(git -C "$EVOREPAIR_DIR" rev-parse "$EVOREPAIR_COMMIT^{commit}")"
CURRENT="$(git -C "$EVOREPAIR_DIR" rev-parse --verify HEAD 2>/dev/null || true)"
if [ "$CURRENT" != "$REVISION" ]; then
    if [ -n "$CURRENT" ] && [ -n "$(git -C "$EVOREPAIR_DIR" status --porcelain)" ]; then
        echo "error: $EVOREPAIR_DIR has local changes; refusing to switch revisions" >&2
        exit 1
    fi
    git -C "$EVOREPAIR_DIR" checkout --detach "$REVISION"
elif [ -z "$(git -C "$EVOREPAIR_DIR" ls-files)" ]; then
    git -C "$EVOREPAIR_DIR" checkout --detach "$REVISION"
fi

echo "EvoRepair: $REVISION ($EVOREPAIR_DIR)"
