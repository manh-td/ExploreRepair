import os
from pathlib import Path

from src.agentcore.config import DEFAULT_MODEL
from src.harnesses.results import REPO_ROOT, results_dir

MODEL = os.environ.get("LOOPREPAIR_MODEL", DEFAULT_MODEL)
LOOPREPAIR_SRC = REPO_ROOT / "baselines" / "LoopRepair" / "src"
DEFAULT_TIMEOUT_S = 1800.0


def run_dir(approach: str | None = None) -> Path:
    approach = approach or os.environ.get("LOOPREPAIR_RUN", "looprepair-pov")
    if approach not in {"looprepair-pov", "looprepair-no-pov"}:
        raise ValueError("LOOPREPAIR_RUN must be looprepair-pov or looprepair-no-pov")
    return Path(os.environ.get("LOOPREPAIR_RESULTS_DIR") or results_dir("vulnlocplus", approach, MODEL))
