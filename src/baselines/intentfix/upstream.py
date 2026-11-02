import ast
import hashlib
import importlib
from importlib.machinery import ModuleSpec
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
from types import ModuleType, SimpleNamespace

from src.baselines.intentfix.config import INTENTFIX_DIR, DEFAULT_LLM_MODEL, TEMPERATURE

_CACHE = {}
_LOCK = threading.Lock()


def _runtime_config(checkout: Path) -> ModuleType:
    config = ModuleType("config")
    tree = ast.parse((checkout / "config.py").read_text())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                setattr(config, target.id, value)
    config.DEFAULT_LLM_MODEL = DEFAULT_LLM_MODEL
    config.TEMPERATURE = TEMPERATURE
    config.PROMPTS_DIR = str(checkout / "prompts")
    config.logger = logging.getLogger("intentfix")
    for name in ("OPENAI_API_KEY", "OPENAI_API_KEY_SUB", "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY_SUB"):
        env_name = name.replace("ANTHROPIC", "CLAUDE")
        setattr(config, name, os.environ.get(env_name))
    return config


def load_upstream(output: Path):
    checkout = INTENTFIX_DIR
    required = ("config.py", "intentfix/pipeline.py", "intentfix/llm_interface.py",
                "intentfix/models.py", "intentfix/utils.py")
    missing = [name for name in required if not (checkout / name).is_file()]
    if missing or not (checkout / "prompts").is_dir():
        raise FileNotFoundError(
            f"IntentFix source/prompts are missing from {checkout}; "
            "run bash scripts/download/intentfix.sh or set INTENTFIX_DIR to its checkout"
        )
    output = output.resolve()
    key = (checkout, output)
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
        digest = hashlib.sha256(f"{checkout}:{output}".encode()).hexdigest()[:16]
        name = f"_explorerepair_intentfix_{digest}"
        package = ModuleType(name)
        package.__path__ = [str(checkout / "intentfix")]
        package.__package__ = name
        package.__spec__ = ModuleSpec(name, loader=None, is_package=True)
        config = _runtime_config(checkout)
        sys.modules[name] = package
        previous_config = sys.modules.get("config")
        sys.modules["config"] = config

        def save_checkpoint(data, checkpoint_name):
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", checkpoint_name)[:120]
            suffix = hashlib.sha256(checkpoint_name.encode()).hexdigest()[:12]
            path = output / "checkpoints" / f"{safe_name}-{suffix}.json"
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
                return True
            except (OSError, TypeError, ValueError):
                logging.getLogger("intentfix").exception("Cannot save IntentFix checkpoint")
                return False

        try:
            utils = importlib.import_module(f"{name}.utils")
            utils.save_checkpoint = save_checkpoint
            interface = importlib.import_module(f"{name}.llm_interface")
            pipeline = importlib.import_module(f"{name}.pipeline")
            revision = None
            if (checkout / ".git").exists():
                result = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                                        capture_output=True, text=True, check=True)
                revision = result.stdout.strip()
            runtime = SimpleNamespace(pipeline_class=pipeline.IntentFixPipeline,
                                      interface_class=interface.LLMInterface,
                                      extract_code=utils.extract_code, checkout=checkout, revision=revision)
            _CACHE[key] = runtime
            return runtime
        except BaseException:
            for module in list(sys.modules):
                if module == name or module.startswith(name + "."):
                    del sys.modules[module]
            raise
        finally:
            if previous_config is None:
                sys.modules.pop("config", None)
            else:
                sys.modules["config"] = previous_config
