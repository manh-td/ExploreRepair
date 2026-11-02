import json
import os
import re
import subprocess
import sys
from pathlib import Path

LOOPREPAIR_SRC = "/looprepair-src/looprepair"
CREPAIR_ROOT = "/CrashRepair"
sys.path.insert(0, LOOPREPAIR_SRC)

from scenario import Scenario
from candidate import PatchCandidate
from location import Location
from exceptions import ShellTimeOut

ANALYZER_ENV = {
    "INJECT_CFLAGS": "-g -O0 -static -Wno-error",
    "INJECT_CXXFLAGS": "-g -O0 -static -Wno-error",
    "INJECT_LDFLAGS": "-Wno-error",
    "REPAIR_TOOL": "crashrepair",
}
SOURCE_EXTS = (".c", ".cc", ".cpp", ".h", ".hpp")
PATCH_NAME_RE = re.compile(r"^(.+)_(\d+)_(\d+)$")
LOG_TAIL_CHARS = 2000
FUZZ_FLAG = "--fuzz"
ASAN_CANCEL_FLAG = " -fno-sanitize=address"
COMPILER_WRAPPERS = ("/CrashRepair/compiler/crepair-cc", "/CrashRepair/compiler/crepair-cxx")
UNAME_BUILD_DIR_SHIM = (
    'KDIR="$(uname -msr | tr " /" "__").d"; '
    'if [ ! -e "$KDIR" ]; then OLD=$(ls -d *_x86_64.d 2>/dev/null | head -1); '
    '[ -n "$OLD" ] && ln -s "$OLD" "$KDIR"; fi'
)


def resolve_target_file(source_directory, patch_path):
    match = PATCH_NAME_RE.match(patch_path.stem)
    if not match:
        raise ValueError(f"unexpected patch filename shape: {patch_path.name}")
    base, line, candidate_id = match.group(1), int(match.group(2)), int(match.group(3))
    matches = [p for p in Path(source_directory).rglob(f"{base}.*") if p.suffix in SOURCE_EXTS]
    if not matches:
        raise ValueError(f"no source file matching '{base}.*' under {source_directory}")
    matches.sort(key=lambda p: (SOURCE_EXTS.index(p.suffix), -len(p.read_text(errors="replace").splitlines())))
    long_enough = [p for p in matches if len(p.read_text(errors="replace").splitlines()) >= line]
    return str((long_enough or matches)[0]), line, candidate_id


def enable_asan():
    for wrapper in COMPILER_WRAPPERS:
        path = Path(wrapper)
        path.write_text(path.read_text().replace(ASAN_CANCEL_FLAG, ""))


def first_build(scenario):
    code = (
        f"import sys; sys.path.insert(0, {CREPAIR_ROOT!r})\n"
        "from app import values, builder, definitions\n"
        "for name in dir(definitions):\n"
        "    if name.startswith('FILE_') and getattr(definitions, name) == '':\n"
        "        setattr(definitions, name, '/tmp/crepair-' + name.lower())\n"
        f"values.CONF_DIR_SRC = {scenario.source_directory!r}\n"
        f"values.CONF_PATH_PROGRAM = {scenario.binary_path!r}\n"
        f"values.CONF_COMMAND_CONFIG = {scenario.prebuild_command!r}\n"
        f"values.CONF_COMMAND_BUILD = {scenario.build_command!r}\n"
        "builder.build_normal()\n"
    )
    proc = subprocess.run(["python3.8", "-c", code], cwd=CREPAIR_ROOT, env={**os.environ, **ANALYZER_ENV},
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    ok = proc.returncode == 0 and os.path.isfile(scenario.binary_path)
    return ok, proc.stdout[-LOG_TAIL_CHARS:]


def run_test(scenario, test):
    try:
        return test.run(scenario.time_limit_seconds_single_test, halt_on_error=scenario.halt_on_error).to_dict()
    except ShellTimeOut:
        return {"successful": False, "return-code": None, "failure-reason": "timeout"}


def crash_test(scenario):
    return run_test(scenario, scenario.crash_test)


def fuzzer_tests(scenario):
    for test in scenario.fuzzer_tests:
        outcome = run_test(scenario, test)
        if not outcome["successful"]:
            return {"successful": False, "num-tests": len(scenario.fuzzer_tests), "failed": test.name,
                    "outcome": outcome}
    return {"successful": True, "num-tests": len(scenario.fuzzer_tests)}


def evaluate_looprepair_patch(scenario, patch_path):
    filename, line, candidate_id = resolve_target_file(scenario.source_directory, patch_path)
    candidate = PatchCandidate(id_=candidate_id, location=Location(filename=filename, line=line, column=0),
                               diff=patch_path.read_text())
    try:
        outcome = scenario.evaluate(candidate).to_dict()
    except subprocess.CalledProcessError:
        return {"target": filename, "applies": False, "is-repair": False}
    outcome.pop("candidate-diff", None)
    return {"target": filename, "applies": True, **outcome}


def source_sections(patch_text):
    sections, current = [], []
    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current:
                sections.append("".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        sections.append("".join(current))
    return [s for s in sections if s.split()[2].endswith(SOURCE_EXTS)]


def evaluate_unified_diff(scenario, patch_path):
    tmp = Path(f"/tmp/{patch_path.stem}.sources.diff")
    tmp.write_text("".join(source_sections(patch_path.read_text(errors="replace"))))
    applied = subprocess.run(f"patch -p1 --batch < {tmp}", shell=True, cwd=scenario.source_directory,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if applied.returncode != 0:
        subprocess.run(f"patch -R -p1 --batch < {tmp}", shell=True, cwd=scenario.source_directory,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"applies": False, "is-repair": False, "patch_output": applied.stdout[-LOG_TAIL_CHARS:]}
    try:
        try:
            scenario.rebuild(prebuild=False, clean=False, record_compile_commands=False)
        except subprocess.CalledProcessError:
            return {"applies": True, "compiles": False, "is-repair": False}
        outcome = crash_test(scenario)
        result = {"applies": True, "compiles": True, "is-repair": outcome["successful"], "test": outcome}
        if outcome["successful"] and scenario.fuzzer_tests:
            result["fuzz"] = fuzzer_tests(scenario)
        return result
    finally:
        subprocess.run(f"patch -R -p1 --batch < {tmp}", shell=True, cwd=scenario.source_directory,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    fuzz = FUZZ_FLAG in sys.argv
    args = [a for a in sys.argv[1:] if a != FUZZ_FLAG]
    if len(args) not in (4, 5):
        sys.exit("usage: evaluate_in_container.py <bug.json> <looprepair-patch.txt|-> <fix.patch|-> <result.json> "
                 f"[candidate.diff] [{FUZZ_FLAG}]")
    bug_json, looprepair_patch, golden_patch, result_path = args[:4]
    candidate_patch = args[4] if len(args) == 5 else "-"
    scenario = Scenario.for_file(bug_json, skip_fuzzing=not fuzz)
    result = {"asan_enabled": "-fsanitize=address" in scenario.sanitizer_flags}
    if result["asan_enabled"]:
        enable_asan()
    subprocess.run(UNAME_BUILD_DIR_SHIM, shell=True, cwd=scenario.source_directory)
    result["first_build"], tail = first_build(scenario)
    if not result["first_build"]:
        result["first_build_tail"] = tail
    else:
        if scenario.sanitizer_flags or scenario.rebuild_for_validation:
            scenario.rebuild(record_compile_commands=False)
        result["vulnerable"] = crash_test(scenario)
        if fuzz:
            try:
                scenario.fuzz()
                result["fuzz_tests"] = len(scenario.fuzzer_tests)
            except Exception as exc:
                result["fuzz_error"] = repr(exc)
        if looprepair_patch != "-":
            result["looprepair_patch"] = evaluate_looprepair_patch(scenario, Path(looprepair_patch))
        if golden_patch != "-" and os.path.isfile(golden_patch):
            result["golden"] = evaluate_unified_diff(scenario, Path(golden_patch))
        if candidate_patch != "-":
            result["candidate"] = evaluate_unified_diff(scenario, Path(candidate_patch))
    Path(result_path).write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
