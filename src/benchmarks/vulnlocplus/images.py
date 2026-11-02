import argparse
import asyncio
import json
import shlex
import subprocess
import time
import traceback
from pathlib import Path

from src.harnesses.results import artifacts_dir

from src.benchmarks.vulnlocplus.golden import golden_diff, has_golden_patch
from src.benchmarks.vulnlocplus.loading import load_record, project_for, subject_dir
from src.benchmarks.vulnlocplus.locations import working_set
from src.harnesses.batch import append_summary, run_batch

BASE_IMAGE = "fino2020/looprepair:v1.0"
IMAGE_TEMPLATE = "vulnlocplus-{cve_lower}:shipped"
RESULTS_DIR = artifacts_dir("vulnlocplus") / "images-shipped"
WORKSPACE = "/workspace"
VULNLOC_ROOT = "/data/vulnloc"
DOCKER_TIMEOUT_S = 300.0
ISOLATE_TIMEOUT_S = 1800.0
GIT_TIMEOUT_S = 1800.0
LEAK_CHECK_TIMEOUT_S = 1800.0
COMMIT_TIMEOUT_S = 1800.0
DEFAULT_TIMEOUT_S = 7200.0
DEFAULT_WORKERS = 8
MIN_NEEDLE_CHARS = 25
MAX_NEEDLE_CHARS = 200
MAX_NEEDLES = 3
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp")

STRIP_GLOBAL = (
    "/CrashRepair/experiments", "/CrashRepair/logs/*", "/CrashRepair/output/*", "/CrashRepair/backup/*",
    "/CrashRepair/tmp/*", "/log-*", "/data_bak", "/tmp/*",
)
STRAY_PATCH_GLOBS = ("*.patch", "*.diff", "*.rej", "*.orig")
AGENT_ASAN_SHIMS = {"/CrashRepair/compiler/wllvm": "/usr/local/bin/wllvm",
                    "/CrashRepair/compiler/wllvm++": "/usr/local/bin/wllvm++"}
AGENT_ASAN_OPTIONS = "detect_leaks=0:detect_odr_violation=0"
BASELINE_EXCLUDES = ("*.o", "*.bc", "*.lo", "*.la", "*.a", "*.so")
STALE_ARTIFACT_GLOBS = ("*.o", "*.bc")
BUILD_CHECK_ENV = {"INJECT_CFLAGS": "-g -O0 -Wno-error", "INJECT_CXXFLAGS": "-g -O0 -Wno-error",
                   "INJECT_LDFLAGS": "-Wno-error"}
BUILD_TIMEOUT_S = 3600.0
BUILD_CHECK_TRIES = 2
UNAME_BUILD_DIR_SHIM = (
    'KDIR="$(uname -msr | tr " /" "__").d"; '
    'if [ ! -e "$KDIR" ]; then OLD=$(ls -d *_x86_64.d 2>/dev/null | head -1); '
    '[ -n "$OLD" ] && ln -s "$OLD" "$KDIR"; fi'
)


def image_for(cve_id: str) -> str:
    return IMAGE_TEMPLATE.format(cve_lower=cve_id.lower())


def repo_dirname(cve_id: str) -> str:
    return project_for(cve_id)


def repo_path(cve_id: str) -> str:
    return f"{WORKSPACE}/{repo_dirname(cve_id)}"


def docker(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, errors="replace", timeout=timeout)


def exec_in(container: str, script: str, timeout: float) -> subprocess.CompletedProcess:
    return docker(["exec", container, "bash", "-c", script], timeout)


def isolate(container: str, cve_id: str) -> None:
    finds = " -o ".join(f"-name {shlex.quote(glob)}" for glob in STRAY_PATCH_GLOBS)
    exec_in(container, f"""
        rm -rf {' '.join(STRIP_GLOBAL)}
        cd {subject_dir(cve_id)}/src && find . -type f \\( {finds} \\) -not -path './.git/*' -print -delete
    """, ISOLATE_TIMEOUT_S)


def baseline_and_truncate(container: str, cve_id: str) -> str:
    proc = exec_in(container, f"""
        set -e
        cd {repo_path(cve_id)}
        if [ -d .git ]; then git checkout -q -B vulnlocplus; else git init -q && git symbolic-ref HEAD refs/heads/vulnlocplus; fi
        git config user.email vulnlocplus@local && git config user.name vulnlocplus
        printf '%s\\n' {' '.join(shlex.quote(glob) for glob in BASELINE_EXCLUDES)} >> .git/info/exclude
        git add -A && git commit -q --no-verify --allow-empty -m "vulnlocplus baseline"
        for remote in $(git remote); do git remote remove "$remote"; done
        for ref in $(git for-each-ref --format='%(refname)' | grep -v '^refs/heads/vulnlocplus$'); do
            git update-ref --no-deref -d "$ref"
        done
        git stash clear
        git reflog expire --expire=now --all
        git gc -q --prune=now
        git rev-parse HEAD
    """, GIT_TIMEOUT_S)
    if proc.returncode != 0:
        raise RuntimeError(f"git baseline failed: {(proc.stdout + proc.stderr).strip()[-500:]}")
    return proc.stdout.strip().splitlines()[-1]


def asan_requested(cve_id: str) -> bool:
    return "-fsanitize=address" in load_record(cve_id)["build"].get("sanitizerflags", "")


def enable_agent_asan(container: str) -> None:
    for shim, real in AGENT_ASAN_SHIMS.items():
        exec_in(container, f"printf '#!/bin/bash\\nexec {real} \"$@\" -fsanitize=address\\n' > {shim} && chmod +x {shim}",
                DOCKER_TIMEOUT_S)


def relocate(container: str, cve_id: str) -> None:
    subject = subject_dir(cve_id)
    new = repo_path(cve_id)
    rewrites = [(f"{subject}/src", new), (f"{subject.replace('/vulnloc', '//vulnloc')}/src", new), (subject, WORKSPACE)]
    seds = "\n".join(
        f"grep -rlIF --exclude-dir=.git -- {shlex.quote(old)} . | xargs -r sed -i {shlex.quote(f's#{old}#{rep}#g')}"
        for old, rep in rewrites)
    relinks = "\n".join(
        f"find . -type l -lname {shlex.quote(old + '*')} -not -path './.git/*' | while read -r link; do "
        f"target=$(readlink \"$link\"); ln -sfn \"{rep}${{target#{old}}}\" \"$link\"; done"
        for old, rep in rewrites)
    stale = " -o ".join(f"-name {shlex.quote(glob)}" for glob in STALE_ARTIFACT_GLOBS)
    proc = exec_in(container, f"""
        set -e
        mkdir -p {WORKSPACE}
        mv {subject}/src {new}
        rm -rf {VULNLOC_ROOT}
        cd {new}
        find . -type f \\( {stale} \\) -not -path './.git/*' -delete
        {seds}
        {relinks}
        {UNAME_BUILD_DIR_SHIM} || true
    """, ISOLATE_TIMEOUT_S)
    if proc.returncode != 0:
        raise RuntimeError(f"relocate failed: {(proc.stdout + proc.stderr).strip()[-500:]}")


def build_check(container: str, cve_id: str, asan: bool) -> dict:
    build = load_record(cve_id)["build"]
    binary = load_record(cve_id)["binary"].replace("//", "/").replace(f"{subject_dir(cve_id)}/src", repo_path(cve_id))
    values = {**BUILD_CHECK_ENV, **({"ASAN_OPTIONS": AGENT_ASAN_OPTIONS} if asan else {})}
    env = " ".join(f"{key}={shlex.quote(value)}" for key, value in values.items())
    attempt = (f"cd {repo_path(cve_id)} && export {env} && ({build['commands']['build']}) > /tmp/build-check.log 2>&1; "
               f"rc=$?; test -x {shlex.quote(binary)}; echo rc=$rc bin=$?; tail -5 /tmp/build-check.log")
    exec_in(container, f"cd {repo_path(cve_id)} && ({build['commands']['clean']}) >/dev/null 2>&1", BUILD_TIMEOUT_S)
    tries = 0
    for tries in range(1, BUILD_CHECK_TRIES + 1):
        status = exec_in(container, attempt, BUILD_TIMEOUT_S).stdout.strip().splitlines()
        ok = bool(status) and status[0] == "rc=0 bin=0"
        if ok:
            break
    exec_in(container, f"cd {repo_path(cve_id)} && ({build['commands']['clean']}) >/dev/null 2>&1; "
                       f"rm -f /tmp/build-check.log", BUILD_TIMEOUT_S)
    return {"ok": ok, "tries": tries, "binary": binary, "tail": [] if ok else status[1:]}


def golden_source_sections(cve_id: str) -> tuple[str, list[str]]:
    if not has_golden_patch(cve_id):
        return "", []
    sections, paths, current = [], [], []
    for line in golden_diff(cve_id).splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current:
                sections.append("".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        sections.append("".join(current))
    kept = [s for s in sections if s.split()[3].endswith(SOURCE_SUFFIXES)]
    return "".join(kept), [s.split()[3][len("b/"):] for s in kept]


def leak_needles(cve_id: str) -> list[str]:
    text, _ = golden_source_sections(cve_id)
    added, removed = set(), set()
    for line in text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.add(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.add(line[1:].strip())
    candidates = [line for line in added - removed if MIN_NEEDLE_CHARS <= len(line) <= MAX_NEEDLE_CHARS]
    return sorted(candidates, key=len, reverse=True)[:MAX_NEEDLES]


def leaks(container: str, cve_id: str, scan_filesystem: bool = True) -> dict:
    hits = {}
    src = repo_path(cve_id)
    sections, patched = golden_source_sections(cve_id)
    if sections:
        applied = exec_in(container, (f"cd {src} && printf '%s' {shlex.quote(sections)} | "
                                      f"patch -R -p1 --dry-run -s -f >/dev/null 2>&1"), DOCKER_TIMEOUT_S)
        if applied.returncode == 0:
            hits["fix_already_applied"] = patched
    if scan_filesystem:
        ids = [cve_id, cve_id.lower()]
        includes = " ".join(f"--include={shlex.quote('*' + suffix)}" for suffix in SOURCE_SUFFIXES)
        needles = [needle for needle in leak_needles(cve_id)
                   if exec_in(container, f"grep -rqF {includes} -- {shlex.quote(needle)} {src}",
                              LEAK_CHECK_TIMEOUT_S).returncode != 0]
        patterns = " ".join(f"-e {shlex.quote(text)}" for text in ids + needles)
        found = exec_in(container, (f"grep -rlIF {patterns} / --exclude-dir=proc --exclude-dir=sys "
                                    f"--exclude-dir=dev 2>/dev/null"), LEAK_CHECK_TIMEOUT_S)
        files = [line.strip() for line in found.stdout.splitlines() if line.strip()]
        if files:
            quoted = " ".join(shlex.quote(f) for f in files)
            id_patterns = " ".join(f"-e {shlex.quote(text)}" for text in ids)
            with_id = set(exec_in(container, f"grep -lIF {id_patterns} {quoted} 2>/dev/null",
                                  DOCKER_TIMEOUT_S).stdout.split())
            own = {f"{src}/{path}" for path in patched}
            fix_text = [f for f in files if f not in with_id and f not in own]
            if with_id:
                hits["cve_id_visible"] = sorted(with_id)[:5]
            if fix_text:
                hits["golden_fix_text"] = {"needles": needles, "files": fix_text[:5]}
    present = exec_in(container, f"ls -d {VULNLOC_ROOT} /CrashRepair/experiments 2>/dev/null",
                      DOCKER_TIMEOUT_S).stdout.split()
    if present:
        hits["answer_paths"] = present
    reachable = exec_in(container, f"cd {repo_path(cve_id)} && git for-each-ref --format='%(refname)'",
                        DOCKER_TIMEOUT_S).stdout.split()
    if reachable != ["refs/heads/vulnlocplus"]:
        hits["git_refs"] = reachable
    return hits


def bake_one_sync(cve_id: str, keep_container: bool = False) -> dict:
    container = f"vulnlocplus-bake-{cve_id.lower()}"
    image = image_for(cve_id)
    row = {"cve_id": cve_id, "project": project_for(cve_id), "image": image, "status": "error"}
    t0 = time.monotonic()
    try:
        docker(["rm", "-f", container], DOCKER_TIMEOUT_S)
        started = docker(["run", "-d", "--name", container, BASE_IMAGE, "sleep", "infinity"], DOCKER_TIMEOUT_S)
        if started.returncode != 0:
            row["error"] = started.stderr.strip()[-500:]
            return row
        isolate(container, cve_id)
        relocate(container, cve_id)
        row["baseline_sha"] = baseline_and_truncate(container, cve_id)
        row["agent_asan"] = asan_requested(cve_id)
        if row["agent_asan"]:
            enable_agent_asan(container)
        row["build_check"] = build_check(container, cve_id, row["agent_asan"])
        if not row["build_check"]["ok"]:
            row["status"] = "build_fail"
            return row
        row["leaks"] = leaks(container, cve_id)
        if row["leaks"]:
            row["status"] = "leak_detected"
            return row
        changes = ["--change", f"ENV ASAN_OPTIONS={AGENT_ASAN_OPTIONS}"] if row["agent_asan"] else []
        committed = docker(["commit", *changes, container, image], COMMIT_TIMEOUT_S)
        if committed.returncode != 0:
            row["status"] = "commit_fail"
            row["error"] = committed.stderr.strip()[-500:]
            return row
        row["status"] = "ok"
        return row
    except subprocess.TimeoutExpired as exc:
        row["status"] = "timeout"
        row["error"] = f"timed out after {exc.timeout}s"
        return row
    except Exception as exc:
        row["error"] = repr(exc)
        row["traceback"] = traceback.format_exc()
        return row
    finally:
        row["duration_s"] = round(time.monotonic() - t0, 1)
        if not keep_container:
            docker(["rm", "-f", container], DOCKER_TIMEOUT_S)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bake one sanitized, as-shipped image per VulnLoc+ CVE.")
    parser.add_argument("--cve", action="append", help="CVE id (repeatable)")
    parser.add_argument("--all", action="store_true", help="every CVE in the working set")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="per-CVE seconds")
    parser.add_argument("--heartbeat-interval", type=float, default=60.0)
    parser.add_argument("--keep-container", action="store_true")
    args = parser.parse_args()

    cve_list = args.cve or (working_set() if args.all else working_set()[:1])
    if args.limit:
        cve_list = cve_list[: args.limit]

    if len(cve_list) == 1:
        row = bake_one_sync(cve_list[0], args.keep_container)
        append_summary(RESULTS_DIR, row)
        print(json.dumps(row, indent=2))
        return

    asyncio.run(run_batch(
        items=cve_list,
        run_one=lambda cve_id: asyncio.to_thread(bake_one_sync, cve_id),
        results_dir=RESULTS_DIR,
        workers=args.workers,
        timeout=args.timeout,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", base {BASE_IMAGE} -> {IMAGE_TEMPLATE}",
    ))


if __name__ == "__main__":
    main()
