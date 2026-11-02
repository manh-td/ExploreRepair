import argparse
import json
import subprocess
import time
import traceback
from pathlib import Path

from src.harnesses.results import artifacts_dir

from src.baselines.looprepair.evaluate import DEFAULT_TIMEOUT_S, DriverFailed, fuzzer_corpus_for, run_driver

RESULTS_DIR = artifacts_dir("vulnlocplus") / "evaluate"


def verdict(candidate: dict) -> str:
    if not candidate.get("applies"):
        return "apply_fail"
    if not candidate.get("compiles"):
        return "compilation_fail"
    return "Repair Success" if candidate.get("is-repair") else "validation_fail"


def grade(cve_id: str, patch: str, name: str = "patch", out_dir: Path | None = None,
          timeout: float = DEFAULT_TIMEOUT_S, fuzz: bool = False) -> dict:
    row = {"cve_id": cve_id, "name": name, "poc": False, "unittest": None, "type": "apply_fail"}
    corpus = fuzzer_corpus_for(cve_id) if fuzz else None
    t0 = time.monotonic()
    if not patch.strip():
        row["error"] = "empty patch"
        return row
    try:
        raw = run_driver(cve_id, out_dir or RESULTS_DIR / cve_id / name, candidate=patch,
                         timeout=timeout, name=f"grade-{name}", fuzz_corpus=corpus)
        if not raw.get("first_build"):
            row["type"] = "compilation_fail"
            row["error"] = "the unpatched tree does not build"
            return row
        candidate = raw.get("candidate") or {}
        row["type"] = verdict(candidate)
        row["poc"] = bool(candidate.get("is-repair"))
        row["asan_enabled"] = raw.get("asan_enabled")
        row["test"] = candidate.get("test")
        if fuzz:
            row["fuzz_tests"] = raw.get("fuzz_tests")
            row["fuzz_error"] = raw.get("fuzz_error")
            if candidate.get("fuzz") is not None:
                row["unittest"] = candidate["fuzz"]["successful"]
                row["fuzz"] = candidate["fuzz"]
        return row
    except subprocess.TimeoutExpired as exc:
        row["error"] = f"timed out after {exc.timeout}s"
        return row
    except Exception as exc:
        row["error"] = str(exc) if isinstance(exc, DriverFailed) else repr(exc)
        row["traceback"] = traceback.format_exc()
        return row
    finally:
        row["duration_s"] = round(time.monotonic() - t0, 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Grade one unified diff against a VulnLoc+ CVE.")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--patch-file", type=Path, required=True)
    parser.add_argument("--name", default="patch")
    parser.add_argument("--fuzz", action="store_true", help="also run LoopRepair's saved fuzzer tests")
    args = parser.parse_args()
    print(json.dumps(grade(args.cve, args.patch_file.read_text(), args.name, fuzz=args.fuzz), indent=2))


if __name__ == "__main__":
    main()
