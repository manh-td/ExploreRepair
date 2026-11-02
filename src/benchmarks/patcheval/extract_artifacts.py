import argparse
import asyncio
import io
import json
import re
import shlex
import subprocess
import tarfile
import time
from pathlib import Path

from src.harnesses.results import artifacts_dir

from src.harnesses.batch import add_common_args, append_summary, run_batch, select_cve_ids
from src.harnesses.dataset import load_cve_record, repo_dirname

RESULTS_DIR = artifacts_dir("patcheval")
ARTIFACTS_DIR = RESULTS_DIR / "artifacts"

DEFAULT_CVE_IDS = ["CVE-2019-10787", "CVE-2022-0686", "CVE-2021-21330"]

HARNESS_SCRIPTS = (
    "prepare.sh", "fix-run.sh", "vul-run.sh", "unit_test.sh", "clean_git.sh", "check_git_changes.sh",
)

COPY_GLOBS = ("*.patch",)

DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.MULTILINE)
GIT_APPLY_RE = re.compile(r"git apply[^\n]*", re.MULTILINE)
WORKSPACE_PATCH_RE = re.compile(r"/workspace/(\S+\.patch)")
COMMIT_PATCH_RE = re.compile(r"^([0-9a-f]{7,40})\.patch$")


def image_for(cve_id: str) -> str:
    return f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"


def _docker_run(image: str, command: str, timeout: float, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c", command],
        capture_output=True, timeout=timeout, text=not binary,
    )


def fetch_workspace_files(image: str, timeout: float) -> dict[str, bytes]:
    names = [f"-name {shlex.quote(g)}" for g in (*COPY_GLOBS, *HARNESS_SCRIPTS)]
    result = _docker_run(
        image,
        f"cd /workspace && find . -maxdepth 1 -type f \\( {' -o '.join(names)} \\) -print0 "
        "| tar --null -T - -cf -",
        timeout, binary=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"tar failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace')[:300]}")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tar:
        for member in tar.getmembers():
            if member.isfile():
                extracted = tar.extractfile(member)
                if extracted is not None:
                    files[member.name.lstrip("./")] = extracted.read()
    return files


def probe_container(image: str, timeout: float) -> dict[str, str]:
    script = r"""
cd /workspace
repo=$(find . -mindepth 1 -maxdepth 1 -type d ! -name PoC_env | head -1 | sed 's|^\./||')
printf 'repo_dirname\t%s\n' "$repo"
printf 'has_poc_env\t%s\n' "$([ -d /workspace/PoC_env ] && echo true || echo false)"
find . -maxdepth 1 -type f -printf 'file\t%s\t%f\n' 2>/dev/null
printf 'poc_env_python\t%s\n' "$(ls -d /workspace/PoC_env/*/bin/python 2>/dev/null | head -1)"
if [ -n "$repo" ]; then
  cd "$repo"
  printf 'head_sha\t%s\n' "$(git rev-parse HEAD 2>/dev/null)"
  printf 'head_subject\t%s\n' "$(git log -1 --format=%s 2>/dev/null)"
  printf 'tracked_files\t%s\n' "$(git ls-files 2>/dev/null | wc -l)"
fi
"""
    result = _docker_run(image, script, timeout)
    probe: dict = {"workspace_listing": {}}
    for line in result.stdout.splitlines():
        key, _, value = line.partition("\t")
        if key == "file":
            size, _, name = value.partition("\t")
            probe["workspace_listing"][name.strip()] = int(size) if size.isdigit() else None
        elif key:
            probe[key] = value.strip()
    return probe


def patch_files(patch_text: str) -> list[str]:
    return sorted({m.group(2) for m in DIFF_FILE_RE.finditer(patch_text)})


def describe_patch(name: str, text: str) -> dict:
    return {
        "name": name,
        "bytes": len(text),
        "files": patch_files(text),
        "hunks": text.count("\n@@ ") + text.startswith("@@ "),
    }


def describe_script(name: str, text: str) -> dict:
    shebang_at = text.find("#!")
    malformed_prefix = text[:shebang_at] if shebang_at > 0 else ""
    body = text[shebang_at:] if shebang_at > 0 else text

    applies, commands = [], []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "set -e":
            continue
        if re.fullmatch(r"cd \S+", stripped):
            continue
        if stripped.startswith("git apply"):
            applies.extend(WORKSPACE_PATCH_RE.findall(stripped))
            continue
        commands.append(stripped)
    return {
        "name": name,
        "bytes": len(text),
        "applies": applies,
        "commands": commands,
        "malformed_prefix": malformed_prefix,
    }


def build_metadata(cve_id: str, record: dict, files: dict[str, bytes], probe: dict) -> dict:
    text = {name: blob.decode("utf-8", errors="replace") for name, blob in files.items()}
    patches = {n: t for n, t in text.items() if n.endswith(".patch")}
    scripts = {n: t for n, t in text.items() if n in HARNESS_SCRIPTS}

    commit_patches = [n for n in patches if COMMIT_PATCH_RE.match(n)]
    fix_run = describe_script("fix-run.sh", scripts["fix-run.sh"]) if "fix-run.sh" in scripts else None
    unit_test = describe_script("unit_test.sh", scripts["unit_test.sh"]) if "unit_test.sh" in scripts else None

    test_touched = set(patch_files(patches.get("test.patch", "")))
    fix_touched = set(patch_files(patches.get("fix.patch", "")))

    return {
        "cve_id": cve_id,
        "image": image_for(cve_id),
        "language": record.get("programming_language"),
        "repo": record.get("repo"),
        "repo_dirname": probe.get("repo_dirname"),
        "repo_dirname_matches_url": probe.get("repo_dirname") == repo_dirname(record.get("repo", "")),
        "head_sha": probe.get("head_sha"),
        "head_subject": probe.get("head_subject"),
        "tracked_files": int(probe["tracked_files"]) if probe.get("tracked_files", "").isdigit() else None,
        "has_poc_env": probe.get("has_poc_env") == "true",
        "poc_env_python": probe.get("poc_env_python") or None,
        "has_unit_test": unit_test is not None,
        "poc_apply_order": fix_run["applies"] if fix_run else [],
        "poc_command": " && ".join(fix_run["commands"]) if fix_run else None,
        "unit_test_apply_order": unit_test["applies"] if unit_test else [],
        "unit_test_command": " && ".join(unit_test["commands"]) if unit_test else None,
        "unit_test_malformed_prefix": (unit_test or {}).get("malformed_prefix") or None,
        "test_fix_overlap": sorted(test_touched & fix_touched),
        "ground_truth_fix_files": sorted(fix_touched),
        "poc_test_files": sorted(test_touched),
        "upstream_commit_patch": commit_patches[0] if commit_patches else None,
        "upstream_commit_sha": COMMIT_PATCH_RE.match(commit_patches[0]).group(1) if commit_patches else None,
        "patches": [describe_patch(n, patches[n]) for n in sorted(patches)],
        "scripts": [describe_script(n, scripts[n]) for n in sorted(scripts)],
        "other_files": [
            {"name": n, "bytes": size}
            for n, size in sorted(probe.get("workspace_listing", {}).items())
            if n not in text
        ],
    }


def extract_one_sync(cve_id: str, timeout: float) -> dict:
    t0 = time.monotonic()
    record = load_cve_record(cve_id)
    image = image_for(cve_id)
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=30).returncode != 0:
        return {"cve_id": cve_id, "status": "image_missing", "image": image,
                "duration_s": round(time.monotonic() - t0, 1)}

    files = fetch_workspace_files(image, timeout)
    probe = probe_container(image, timeout)
    metadata = build_metadata(cve_id, record, files, probe)

    out_dir = ARTIFACTS_DIR / cve_id
    (out_dir / "workspace").mkdir(parents=True, exist_ok=True)
    for name, blob in files.items():
        (out_dir / "workspace" / name).write_bytes(blob)
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    return {
        "cve_id": cve_id,
        "status": "ok",
        "language": metadata["language"],
        "n_files": len(files),
        "has_unit_test": metadata["has_unit_test"],
        "poc_apply_order": metadata["poc_apply_order"],
        "test_fix_overlap": metadata["test_fix_overlap"],
        "artifact_dir": str(out_dir),
        "duration_s": round(time.monotonic() - t0, 1),
    }


async def run_one(cve_id: str, timeout: float = 300.0) -> dict:
    try:
        return await asyncio.to_thread(extract_one_sync, cve_id, timeout)
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": repr(e)}


def main() -> None:
    parser = add_common_args(
        argparse.ArgumentParser(description="Extract PatchEval's own grading artifacts out of each CVE image, for study."),
        default_model=None, default_timeout=300.0, default_workers=4,
    )
    args = parser.parse_args()
    cve_ids = select_cve_ids(args, DEFAULT_CVE_IDS)

    if len(cve_ids) == 1:
        result = asyncio.run(run_one(cve_ids[0], args.timeout))
        print(json.dumps(result, indent=2))
        append_summary(RESULTS_DIR, result)
        return

    asyncio.run(run_batch(
        items=cve_ids,
        run_one=lambda cve_id: run_one(cve_id, args.timeout),
        results_dir=RESULTS_DIR,
        workers=args.workers,
        timeout=args.timeout,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", artifacts -> {ARTIFACTS_DIR}",
    ))


if __name__ == "__main__":
    main()
