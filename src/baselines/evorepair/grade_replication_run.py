import argparse
import json
import logging
import sys
from pathlib import Path

from src.evaluation.evaluate import Evaluation, _get_language
from src.harnesses.results import results_dir

NAME = "evorepair"


def _turn_number(preds_path: Path) -> int:
    return int(preds_path.parent.name.removeprefix("turn_"))


def _latest_patches(output_dir: Path, through_turn: int | None = None) -> dict[str, str]:
    patches: dict[str, str] = {}
    for preds_path in sorted(output_dir.glob("turn_*/preds.json"), key=_turn_number):
        if through_turn is not None and _turn_number(preds_path) > through_turn:
            continue
        preds = json.loads(preds_path.read_text())
        for cve_id, entry in preds.items():
            patch = entry.get("model_patch", "") or ""
            if patch.strip():
                patches[cve_id] = patch
    return patches


def _write_cve_log(cve_dir: Path, patch: str, poc_msg, unittest_msg, result: dict) -> Path:
    cve_dir.mkdir(parents=True, exist_ok=True)
    (cve_dir / "fix_patch.diff").write_text(patch)
    (cve_dir / "poc_output.log").write_text(poc_msg or "(no output)")
    (cve_dir / "unittest_output.log").write_text(
        unittest_msg if unittest_msg is not None else "(unit test not run - PoC did not pass)"
    )
    (cve_dir / "summary.json").write_text(json.dumps(result, indent=2))
    return cve_dir


def evaluate_and_log(cve_dir: Path, cve_id: str, patch: str) -> dict:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    language = _get_language(cve_id)
    logger = logging.getLogger(NAME)
    evaluation = Evaluation(logger=logger, cve=cve_id)
    poc_result, poc_msg, ut_result, ut_msg, error_type = evaluation.run_evaluation(
        cve=cve_id, llm_patch=patch, language=language, test_name=NAME
    )
    result = {"cve_id": cve_id, "name": NAME, "poc": poc_result, "unittest": ut_result, "type": error_type}
    log_dir = _write_cve_log(cve_dir, patch, poc_msg, ut_msg, result)
    print(f"=== Logs written to {log_dir} ===")
    return result


def grade(output_dir: Path, through_turn: int | None = None, *, canonical: bool = False) -> None:
    suffix = f".turn{through_turn}" if through_turn is not None and not canonical else ""
    out_path = output_dir / f"evaluation_results{suffix}.jsonl"

    output_dir.mkdir(parents=True, exist_ok=True)
    patches = _latest_patches(output_dir, through_turn)
    print(f"Found {len(patches)} patch(es) to grade under {output_dir}")

    done: set[tuple[str, str]] = set()
    if out_path.exists():
        for line in out_path.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                done.add((rec["cve_id"], rec["name"]))
        print(f"Skipping {len(done)} already-graded CVE(s)")

    with open(out_path, "a") as f_out:
        for cve_id, patch in patches.items():
            if (cve_id, NAME) in done:
                continue
            print(f"=== Evaluating {cve_id} ({NAME}) ===")
            cve_dir = output_dir / f"evaluation{suffix}" / cve_id if suffix else output_dir / cve_id / "evaluation"
            result = evaluate_and_log(cve_dir, cve_id, patch)
            f_out.write(json.dumps(result) + "\n")
            f_out.flush()
            print(f"{cve_id}: poc={result['poc']}, unittest={result['unittest']}, type={result['type']}")

    print(f"Results written to {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Grade the final patches of an EvoRepair run.")
    parser.add_argument("output_dir", nargs="?", type=Path, default=results_dir("patcheval", "evorepair"))
    parser.add_argument("--turns", type=int, default=3)
    args = parser.parse_args()
    grade(args.output_dir, args.turns, canonical=True)


if __name__ == "__main__":
    main()
