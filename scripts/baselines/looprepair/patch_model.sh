#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../../.."
set -euo pipefail

bash "$(dirname "$0")/../../setup/looprepair_model.sh" "$@"
