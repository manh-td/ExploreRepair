#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../../.."

python3 -B -m src.harnesses.code_knowledge_graph.build_vector_db "$@"
