import os
from pathlib import Path

from src.agentcore.config import DEFAULT_MODEL
from src.harnesses.results import REPO_ROOT

INTENTFIX_DIR = Path(os.environ.get("INTENTFIX_DIR", REPO_ROOT / "baselines" / "IntentFix")).expanduser().resolve()
DEFAULT_LLM_MODEL = DEFAULT_MODEL
TEMPERATURE = 1.0
