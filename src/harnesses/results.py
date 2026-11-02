import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = Path(os.environ.get("EXPLOREREPAIR_WORKSPACE", REPO_ROOT / "workspace")).resolve()
RESULTS_ROOT = Path(os.environ.get("EXPLOREREPAIR_RESULTS", REPO_ROOT.parent / "ExploreRepair.results")).resolve()
MODEL = os.environ.get("AGENTCORE_MODEL", os.environ.get("MODEL", "gpt-5.6-luna"))

def model_dirname(model: str) -> str:
    return model.rsplit("/", 1)[-1]

def results_dir(benchmark: str, approach: str, model: str | None = None) -> Path:
    return RESULTS_ROOT / benchmark / model_dirname(model or MODEL) / approach

def artifacts_dir(benchmark: str) -> Path:
    return WORKSPACE_ROOT / "benchmarks" / benchmark

if __name__ == "__main__":
    for benchmark, approaches in {
        "patcheval": ("intentfix", "evorepair", "llm", "multi-agent", "single-agent", "structural", "semantic", "executable", "3-in-1-agent", "lesson-aggregator", "patch-aggregator", "direct-lessons-patches", "explorerepair", "codex"),
        "vulnlocplus": ("single-agent", "structural", "semantic", "executable", "lesson-aggregator", "patch-aggregator", "explorerepair", "looprepair-pov", "looprepair-no-pov"),
    }.items():
        for approach in approaches:
            path = results_dir(benchmark, approach)
            print(f"{'recorded' if (path / 'evaluation_results.jsonl').exists() else 'missing ':8}  {path}")
