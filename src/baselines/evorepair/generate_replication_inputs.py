import json
import os
import sys
import subprocess
from pathlib import Path

import yaml

from src.harnesses.code_knowledge_graph.embedder import DEFAULT_MODEL_PATH
from src.harnesses.results import REPO_ROOT, results_dir
from src.harnesses.dataset import load_cve_record

VULNERABILITY_INFO_PATH = results_dir("patcheval", "evorepair") / "_inputs" / "metadata.json"

EVOREPAIR_DIR = Path(os.environ.get("EVOREPAIR_DIR", REPO_ROOT / "baselines" / "EvoRepair")).resolve()
DEFAULT_PATCHEVAL_EXP_YAML = EVOREPAIR_DIR / "minisweagent" / "config" / "extra" / "patcheval_exp.yaml"
DEFAULT_MODEL_EXTRACTION_YAML = EVOREPAIR_DIR / "expbank" / "src" / "config" / "model" / "experience_extraction_config.yaml"
DEFAULT_PIPELINE_YAML = EVOREPAIR_DIR / "expbank" / "src" / "config" / "run" / "pipeline_config.yaml"

OUTPUT_ROOT = results_dir("patcheval", "evorepair")
INPUTS_DIR = OUTPUT_ROOT / "_inputs"
BGE_MODEL_DIR = DEFAULT_MODEL_PATH

REPLICATION_CVE_IDS = [
    line.strip()
    for line in (REPO_ROOT / "resources" / "patcheval.cves.with-unit-test.txt").read_text().splitlines()
    if line.strip()
]


def _resolve_model_credentials(model_name: str) -> dict:
    var = "OPENROUTER_API_KEY" if model_name.startswith("openrouter/") else "OPENAI_API_KEY"
    if not os.environ.get(var):
        raise RuntimeError(f"Set {var} before generating inputs for {model_name}")
    return {"base_url": None, "api_key": None}


def generate_dataset_jsonl(cve_ids: list[str], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w") as f:
        for cve_id in cve_ids:
            record = load_cve_record(cve_id)
            row = {
                "cve_id": record["cve_id"],
                "cve_description": "",
                "cwe_info": {},
                "repo": record["repo"],
                "vul_func": record.get("vul_func", []),
                "programing_language": record.get("programming_language", ""),
            }
            f.write(json.dumps(row) + "\n")


def generate_patcheval_exp_yaml(
    dest: Path, model_name: str, model_kwargs: dict | None = None, docker_run_args: list[str] | None = None
) -> None:
    cfg = yaml.safe_load(DEFAULT_PATCHEVAL_EXP_YAML.read_text())
    creds = _resolve_model_credentials(model_name)
    cfg.setdefault("model", {})
    cfg["model"]["model_name"] = model_name
    cfg["model"]["model_class"] = "litellm_tool"
    cfg["model"]["base_url"] = creds["base_url"]
    cfg["model"].pop("api_key", None)
    cfg["model"]["model_kwargs"] = dict(model_kwargs or {})
    if docker_run_args is not None:
        cfg.setdefault("environment", {})["run_args"] = list(docker_run_args)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(cfg, sort_keys=False))


def generate_model_extraction_yaml(dest: Path, model_name: str, temperature: float | None = None) -> None:
    cfg = yaml.safe_load(DEFAULT_MODEL_EXTRACTION_YAML.read_text())
    creds = _resolve_model_credentials(model_name)
    cfg["base_url"] = creds["base_url"]
    cfg["api_key"] = creds["api_key"]
    cfg["model_name"] = model_name
    if temperature is not None:
        cfg["temperature"] = temperature
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(cfg, sort_keys=False))


def generate_pipeline_yaml(
    dest: Path, *, model_yaml_path: Path, bge_model_dir: Path, output_root: Path = OUTPUT_ROOT, vulnerability_info: Path | None = None
) -> None:
    cfg = yaml.safe_load(DEFAULT_PIPELINE_YAML.read_text())
    cfg["llm"]["config_path"] = str(model_yaml_path)
    cfg["rag"]["model_path"] = str(bge_model_dir)
    cfg.setdefault("input", {})["vulnerability_info"] = str((vulnerability_info or VULNERABILITY_INFO_PATH).resolve())
    cfg["input"]["summary_path"] = str((output_root / "_inputs" / "no_oracle_summary.json").resolve())
    cfg.setdefault("output", {})["base_dir"] = str((output_root / "pipeline_artifacts").resolve())
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(cfg, sort_keys=False))


def ensure_empty_seed_vec_db(seed_dir: Path = INPUTS_DIR / "empty_seed_vec_DB") -> Path:
    if not (seed_dir / "chroma.sqlite3").exists():
        subprocess.run([
            sys.executable, "-c",
            "from src.rag.experience_store import ExperienceStore; "
            "import sys; ExperienceStore(db_path=sys.argv[1], embedder=object())",
            str(seed_dir.resolve()),
        ], cwd=EVOREPAIR_DIR / "expbank", check=True)
    return seed_dir


def ensure_bge_model() -> Path:
    if not (BGE_MODEL_DIR / "config.json").exists():
        raise FileNotFoundError("Embedding model is missing; run bash scripts/download/embedding_model.sh first")
    return BGE_MODEL_DIR
