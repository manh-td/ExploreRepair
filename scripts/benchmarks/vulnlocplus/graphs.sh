#!/bin/bash

set -euo pipefail
cd "$(dirname "$0")/../../.."

python3 -B -m src.benchmarks.vulnlocplus.graphs "$@"
