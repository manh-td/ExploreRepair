import json
import os
import subprocess
import sys
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
LOOPREPAIR_SRC = "/looprepair-src/looprepair"
os.chdir(LOOPREPAIR_SRC)

import evaluate_in_container as grading
from candidate import PatchCandidate
from scenario import Scenario

PATCH_LEFTOVER_SUFFIXES = (".orig", ".rej")


def generate(localization_path, candidates_path):
    import LLMRepair
    LLMRepair.generate_use_llms_from_localization_path(localization_path, candidates_path)
    return json.loads(Path(candidates_path).read_text())


def compile_status(scenario, candidate):
    target = Path(candidate.filename)
    original = target.read_bytes()
    try:
        try:
            candidate.apply()
        except subprocess.CalledProcessError:
            return "apply_fail"
        try:
            scenario.rebuild(prebuild=False, clean=False, record_compile_commands=False)
        except subprocess.CalledProcessError:
            return "compile_fail"
        return "compiles"
    finally:
        target.write_bytes(original)
        for suffix in PATCH_LEFTOVER_SUFFIXES:
            leftover = Path(str(target) + suffix)
            if leftover.exists():
                leftover.unlink()


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: generate_nopoc_in_container.py <bug.json> <file:line:col> <out-dir>")
    bug_json, location, out_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)
    localization_path = out_dir / "localization.json"
    candidates_path = out_dir / "candidates.json"
    result = {"location": location, "candidates": [], "chosen": None}
    try:
        localization_path.write_text(json.dumps([{"location": location}], indent=2))
        generated = generate(str(localization_path), str(candidates_path))
        result["n_generated"] = len(generated)

        scenario = Scenario.for_file(bug_json, skip_fuzzing=True)
        if "-fsanitize=address" in scenario.sanitizer_flags:
            grading.enable_asan()
        subprocess.run(grading.UNAME_BUILD_DIR_SHIM, shell=True, cwd=scenario.source_directory)
        result["first_build"], tail = grading.first_build(scenario)
        if not result["first_build"]:
            result["first_build_tail"] = tail
            return
        if scenario.sanitizer_flags or scenario.rebuild_for_validation:
            scenario.rebuild(record_compile_commands=False)

        for candidate in PatchCandidate.load_all(str(candidates_path)):
            status = compile_status(scenario, candidate)
            result["candidates"].append({"id": candidate.id_, "status": status})
            if status == "compiles":
                result["chosen"] = candidate.id_
                break
    except Exception as exc:
        result["error"] = repr(exc)
        result["traceback"] = traceback.format_exc()
    finally:
        (out_dir / "result.json").write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
