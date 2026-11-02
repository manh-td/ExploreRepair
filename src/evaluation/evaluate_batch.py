import argparse
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

from src.evaluation.evaluate import Evaluation, _get_language
from src.harnesses.jsonl import last_per_key, read_jsonl

DEFAULT_WORKERS = 16

ExtraFields = Callable[[dict], dict]


def read_patches(path: Path) -> dict[str, dict]:
    return last_per_key(read_jsonl(path), key="cve")


def read_done(out_path: Path) -> set[tuple[str, str]]:
    done: set[tuple[str, str]] = set()
    if not out_path.exists():
        return done
    with open(out_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            done.add((rec["cve_id"], rec["name"]))
    return done


def write_cve_log(
    results_dir: Path, cve_id: str, patch: str, poc_msg: Optional[str], unittest_msg: Optional[str], result: dict
) -> Path:
    cve_dir = results_dir / cve_id / "evaluation"
    cve_dir.mkdir(parents=True, exist_ok=True)
    (cve_dir / "fix_patch.diff").write_text(patch)
    (cve_dir / "poc_output.log").write_text(poc_msg or "(no output)")
    (cve_dir / "unittest_output.log").write_text(
        unittest_msg if unittest_msg is not None else "(unit test not run - PoC did not pass)"
    )
    (cve_dir / "summary.json").write_text(json.dumps(result, indent=2))
    return cve_dir


def evaluate_and_log(results_dir: Path, name: str, cve_id: str, patch: str, extra: Optional[dict] = None) -> dict:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    language = _get_language(cve_id)
    logger = logging.getLogger(name)
    evaluation = Evaluation(logger=logger, cve=cve_id)
    poc_result, poc_msg, ut_result, ut_msg, error_type = evaluation.run_evaluation(
        cve=cve_id,
        llm_patch=patch,
        language=language,
        test_name=name,
    )
    result = {"cve_id": cve_id, "name": name, "poc": poc_result, "unittest": ut_result, "type": error_type}
    result.update(extra or {})
    log_dir = write_cve_log(results_dir, cve_id, patch, poc_msg, ut_msg, result)
    print(f"=== Logs written to {log_dir} ===")
    return result


def main(
    *,
    results_dir: Path,
    patches_path: Path,
    name: str,
    extra_fields: Optional[ExtraFields] = None,
    out_name: str = "evaluation_results.jsonl",
    skip_empty_patch: bool = False,
) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", action="append", help="grade only these CVEs (repeatable)")
    parser.add_argument("--limit", type=int, help="grade at most N pending patches")
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS, help=f"concurrent evaluations (default {DEFAULT_WORKERS})"
    )
    args = parser.parse_args()

    out_path = results_dir / out_name
    records = read_patches(patches_path)

    done = read_done(out_path)
    if done:
        print(f"Skipping {len(done)} already-completed evaluations")

    pending = [
        (cve_id, rec["fix_patch"], extra_fields(rec) if extra_fields else None)
        for cve_id, rec in records.items()
        if (not args.cve or cve_id in args.cve)
        and (cve_id, name) not in done and not (skip_empty_patch and not rec.get("fix_patch", "").strip())
    ]
    if args.limit is not None:
        pending = pending[:args.limit]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    n_evaluated = 0
    with open(out_path, "a") as f_out:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(evaluate_and_log, results_dir, name, cve_id, patch, extra): cve_id
                for cve_id, patch, extra in pending
            }
            for future in as_completed(futures):
                cve_id = futures[future]
                result = future.result()
                f_out.write(json.dumps(result) + "\n")
                f_out.flush()
                n_evaluated += 1
                print(f"{cve_id}: poc={result['poc']}, unittest={result['unittest']}, type={result['type']}")

    total_elapsed = time.monotonic() - start
    print(f"Evaluated {n_evaluated} CVE(s) in {total_elapsed / 60:.1f}m ({total_elapsed:.1f}s)")
    print(f"Results written to {out_path}")
