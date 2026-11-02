import importlib.util
import json
import logging
from functools import lru_cache
from pathlib import Path

PATCHEVAL_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "PatchEval" / "patcheval"

@lru_cache(maxsize=1)
def _evaluation_class():
    path = PATCHEVAL_DIR / "evaluation" / "run_evaluation.py"
    if not path.is_file():
        raise FileNotFoundError("PatchEval is missing; run bash scripts/download/benchmarks.sh first")
    spec = importlib.util.spec_from_file_location("run_evaluation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Evaluation


def Evaluation(*args, **kwargs):
    return _evaluation_class()(*args, **kwargs)


def _get_language(cve_id: str) -> str:
    from src.harnesses.dataset import load_cve_record

    return load_cve_record(cve_id)["programming_language"]


def _collect_patches(cve_id: str) -> dict[str, str]:
    patches = {}

    for path in sorted((PATCHEVAL_DIR / "log" / "llm").glob("*.json")):
        data = json.loads(path.read_text())
        for entry in data:
            if cve_id in entry:
                for item in entry[cve_id]:
                    if item.get("epoch") == 1 and item.get("diff_content"):
                        patches[f"llm_{path.stem}"] = item["diff_content"]
                        break

    for path in sorted((PATCHEVAL_DIR / "log" / "agent").rglob("*.jsonl")):
        with open(path) as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if cve_id in obj.get("cve", "") and obj.get("fix_patch"):
                    rel = path.relative_to(PATCHEVAL_DIR / "log" / "agent")
                    name = str(rel.with_suffix("")).replace("/", "_")
                    patches[f"agent_{name}"] = obj["fix_patch"]
                    break

    return patches


def evaluate_patch(cve_id: str, name: str, patch: str) -> dict:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    language = _get_language(cve_id)
    logger = logging.getLogger(name)
    evaluation = Evaluation(logger=logger, cve=cve_id)
    poc_result, _, ut_result, _, error_type = evaluation.run_evaluation(
        cve=cve_id,
        llm_patch=patch,
        language=language,
        test_name=name,
    )
    return {"cve_id": cve_id, "name": name, "poc": poc_result, "unittest": ut_result, "type": error_type}


def main(cve_id: str) -> dict:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    patches = _collect_patches(cve_id)
    results = {}
    for name, patch in patches.items():
        result = evaluate_patch(cve_id, name, patch)
        results[name] = {"poc": result["poc"], "unittest": result["unittest"], "type": result["type"]}

    return {cve_id: results}


if __name__ == '__main__':
    from concurrent.futures import ProcessPoolExecutor, as_completed

    from src.harnesses.dataset import ALL_PATCHEVAL_CVES_PATH

    cve_ids = [line.strip() for line in ALL_PATCHEVAL_CVES_PATH.read_text().splitlines() if line.strip()]
    out_path = Path(__file__).parent / "evaluation_results.jsonl"

    done: set[tuple[str, str]] = set()
    if out_path.exists():
        with open(out_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    done.add((rec["cve_id"], rec["name"]))
                except json.JSONDecodeError:
                    pass
    if done:
        print(f"Skipping {len(done)} already-completed evaluations")

    work_items: list[tuple[str, str, str]] = []
    for cve_id in cve_ids:
        patches = _collect_patches(cve_id)
        for name, patch in patches.items():
            if (cve_id, name) not in done:
                work_items.append((cve_id, name, patch))

    print(f"Running {len(work_items)} evaluations with 4 workers")

    with open(out_path, "a") as f_out:
        with ProcessPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(evaluate_patch, cve_id, name, patch): (cve_id, name)
                for cve_id, name, patch in work_items
            }
            for future in as_completed(futures):
                cve_id, name = futures[future]
                try:
                    result = future.result()
                    f_out.write(json.dumps(result) + "\n")
                    f_out.flush()
                    print(f"{cve_id}/{name}: poc={result['poc']}, unittest={result['unittest']}")
                except Exception as e:
                    print(f"{cve_id}/{name}: ERROR - {e}")

    print(f"Results written to {out_path}")
