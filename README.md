# ExploreRepair

Code for *ExploreRepair: Evidence-Specialized Agents for Vulnerability Repair under
Information Constraints*.

## Repository guide

| Location | Contents |
|---|---|
| [src/agentcore](src/agentcore/) | Agent loop, model client, and shell tool |
| [src/experiments](src/experiments/) | ExploreRepair, individual agents, aggregators, and comparisons |
| [src/benchmarks](src/benchmarks/) | PatchEval and VulnLoc+ adapters |
| [src/harnesses](src/harnesses/) | Containers, task construction, batch execution, and code knowledge graphs |
| [src/evaluation](src/evaluation/) | Patch evaluation |
| [src/baselines](src/baselines/) | IntentFix, EvoRepair, and LoopRepair adapters |
| [scripts](scripts/) | Setup and experiment entry points, mirroring the source layout |
| [resources](resources/) | Vulnerability lists and localization metadata |

Start reading at [scripts/run_explorerepair.sh](scripts/run_explorerepair.sh) for the full
pipeline, then follow the corresponding modules in
[src/experiments/reactagent](src/experiments/reactagent/). Each approach's `run_single.py`
contains its task and agent configuration; `run_batch.py` and `evaluate.py` handle batch runs
and grading.

## Setup and run

Use Python, Docker, and a model API key. Run commands from the repository root.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=your-key
export MODEL=gpt-5.6-luna
export EXPLOREREPAIR_RESULTS="$PWD/my-results"
bash scripts/download/benchmarks.sh
bash scripts/download/patcheval_images.sh
bash scripts/download/embedding_model.sh
bash scripts/harnesses/code_knowledge_graph/build_graphs.sh
bash scripts/harnesses/code_knowledge_graph/build_vector_db.sh --all
bash scripts/run_explorerepair.sh patcheval
```

For OpenRouter, set `OPENROUTER_API_KEY` and a slash-qualified `MODEL`, such as
`deepseek/deepseek-v4.1-flash`. Shared settings live in [scripts/env.sh](scripts/env.sh).
Individual stages have `run_batch.sh` and `evaluate.sh` wrappers under
[scripts/experiments](scripts/experiments/); use `--help` for their options.

For VulnLoc+, start with [scripts/download/looprepair.sh](scripts/download/looprepair.sh),
then the preparation scripts in [scripts/benchmarks/vulnlocplus](scripts/benchmarks/vulnlocplus/).
Run the pipeline with `bash scripts/run_explorerepair.sh vulnlocplus`.
Third-party baselines have separate downloaders in [scripts/download](scripts/download/)
and runners in [scripts/baselines](scripts/baselines/).