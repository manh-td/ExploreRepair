#!/bin/bash

python3 -B -m src.harnesses.code_knowledge_graph.build_graphs --all --workers 16 "$@"
