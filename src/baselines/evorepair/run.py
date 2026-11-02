import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from src.agentcore.config import DEFAULT_MODEL
from src.baselines.evorepair.generate_replication_inputs import (
    EVOREPAIR_DIR, REPLICATION_CVE_IDS, ensure_bge_model, ensure_empty_seed_vec_db,
    generate_dataset_jsonl, generate_model_extraction_yaml, generate_patcheval_exp_yaml,
    generate_pipeline_yaml,
)
from src.harnesses.results import REPO_ROOT, results_dir


def model_settings(model: str) -> dict:
    if model.startswith("openrouter/"):
        return {"agent": model, "extraction": model, "kwargs": {"temperature": 1.0, "timeout": 120}}
    if "/" in model:
        name = f"openrouter/{model}"
        return {"agent": name, "extraction": name, "kwargs": {"temperature": 1.0, "timeout": 120}}
    return {"agent": f"openai/responses/{model}", "extraction": model,
            "kwargs": {"reasoning_effort": "medium", "temperature": 1.0, "timeout": 120}}


def command(output: Path, setup: dict, workers: int, turns: int, start: int) -> list[str]:
    inputs = output / "_inputs"
    if (inputs / "no_oracle_summary.json").exists():
        raise RuntimeError("unexpected oracle summary in inputs; use a fresh results directory")
    return [
        sys.executable, str(EVOREPAIR_DIR / "multi_turn_runner.py"),
        "-d", str(inputs / "dataset.jsonl"), "-o", str(output),
        "-w", str(workers), "--eval-workers", str(workers),
        "--model", setup["agent"], "--model-class", "litellm_tool",
        "--run-mode", "retrieve-only", "--exp-db", str(inputs / "empty_seed_vec_DB"),
        "--exp-model", str(ensure_model_path()),
        "--exp-retrieve-k", "10", "--exp-return-n", "3", "--filter-turns", "1",
        "--pipeline-config", str(inputs / "pipeline_config.yaml"),
        "--patcheval-config", str(inputs / "patcheval_exp.yaml"),
        "--no-auto-eval", "--no-early-stop", "--start-turn", str(start), "-n", str(turns),
    ]


def ensure_model_path() -> Path:
    from src.baselines.evorepair.generate_replication_inputs import BGE_MODEL_DIR
    return BGE_MODEL_DIR.resolve()


def subprocess_env(output: Path, timeout: float) -> dict:
    env = dict(os.environ)
    paths = [str(Path(__file__).parent / "hooks"), str(REPO_ROOT), str(EVOREPAIR_DIR)]
    if env.get("PYTHONPATH"):
        paths.append(env["PYTHONPATH"])
    env.update(PYTHONPATH=os.pathsep.join(paths), EXPLOREREPAIR_EVOREPAIR="1",
               EXPLOREREPAIR_EVOREPAIR_BUDGET=str(timeout),
               EXPLOREREPAIR_EVOREPAIR_OUTPUT=str(output))
    return env


def main() -> None:
    parser = argparse.ArgumentParser(description='Run upstream EvoRepair without benchmark feedback, then grade its final patches.')
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--all", action="store_true", help="the default: all 169 retained CVEs")
    parser.add_argument("--cve", action="append")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--turns", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=1800.0,
                        help="per-CVE agent wall time shared across refinement turns")
    parser.add_argument("--dry-run", action="store_true", help="print configuration without fetching or running anything")
    parser.add_argument("--skip-evaluation", action="store_true")
    args = parser.parse_args()
    if args.turns < 1 or args.workers < 1 or args.timeout <= 0 or (args.limit is not None and args.limit < 1):
        parser.error("turns, workers, timeout and limit must be positive")
    cves = args.cve or REPLICATION_CVE_IDS
    if not set(cves) <= set(REPLICATION_CVE_IDS):
        parser.error("CVEs must belong to resources/patcheval.cves.with-unit-test.txt")
    cves = cves[:args.limit] if args.limit else cves
    output = results_dir("patcheval", "evorepair", args.model)
    setup = model_settings(args.model)
    if args.dry_run:
        print(json.dumps({"output": str(output), "cves": cves, "model": setup,
                          "timeout": args.timeout, "command": command(output, setup, args.workers, args.turns, 1)}, indent=2))
        return
    if not (EVOREPAIR_DIR / "multi_turn_runner.py").is_file():
        parser.error("EvoRepair is missing; run bash scripts/download/evorepair.sh first")
    inputs = output / "_inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "run_config.json"
    manifest = {"model": args.model, "cves": cves, "timeout": args.timeout, "turns": args.turns}
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        parser.error("this output directory belongs to another configuration; set EXPLOREREPAIR_RESULTS to a fresh directory")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    generate_dataset_jsonl(cves, inputs / "dataset.jsonl")
    metadata = [json.loads(line) for line in (inputs / "dataset.jsonl").read_text().splitlines()]
    (inputs / "metadata.json").write_text(json.dumps(metadata))
    generate_patcheval_exp_yaml(inputs / "patcheval_exp.yaml", setup["agent"], setup["kwargs"],
                                docker_run_args=["--rm", "--network", "none"])
    generate_model_extraction_yaml(inputs / "model_extraction.yaml", setup["extraction"], 1.0)
    bge = ensure_bge_model().resolve()
    generate_pipeline_yaml(inputs / "pipeline_config.yaml", model_yaml_path=inputs / "model_extraction.yaml",
                           bge_model_dir=bge, output_root=output, vulnerability_info=inputs / "metadata.json")
    ensure_empty_seed_vec_db(inputs / "empty_seed_vec_DB")
    done_path = output / "turns_done.json"
    done = json.loads(done_path.read_text())["through_turn"] if done_path.exists() else 0
    for turn in range(done + 1, args.turns + 1):
        if (output / f"turn_{turn}").exists():
            parser.error(f"partial turn_{turn} exists; use a fresh results directory or recover that turn before resuming")
        subprocess.run(command(output, setup, args.workers, turn, turn), cwd=EVOREPAIR_DIR,
                       env=subprocess_env(output, args.timeout), check=True)
        preds = output / f"turn_{turn}" / "preds.json"
        report = output / "multi_turn_result.json"
        stats = json.loads(report.read_text()).get("turns", {}).get(f"turn_{turn}", {}) if report.exists() else {}
        if (not preds.exists() or not set(cves) <= set(json.loads(preds.read_text()))
                or not stats.get("repair", {}).get("success") or not stats.get("pipeline", {}).get("success")):
            raise RuntimeError(f"turn {turn} did not complete repair and experience extraction")
        done_path.write_text(json.dumps({"through_turn": turn}))
    from src.baselines.evorepair.grade_replication_run import _latest_patches
    patches = _latest_patches(output, args.turns)
    (output / "patches.jsonl").write_text("".join(
        json.dumps({"cve": cve, "fix_patch": patch}) + "\n" for cve, patch in patches.items()))
    summaries = []
    for cve in cves:
        budget = output / "budgets" / f"{cve}.json"
        elapsed = json.loads(budget.read_text())["duration_s"] if budget.exists() else None
        summaries.append({"cve_id": cve, "status": "ok" if patches.get(cve) else "no_patch",
                          "duration_s": elapsed, "model": args.model, "turns": args.turns})
    (output / "run_summary.jsonl").write_text("".join(json.dumps(row) + "\n" for row in summaries))
    if not args.skip_evaluation:
        from src.baselines.evorepair.grade_replication_run import grade
        grade(output, args.turns, canonical=True)


if __name__ == "__main__":
    main()
