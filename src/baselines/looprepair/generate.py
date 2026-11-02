import argparse
import asyncio
import json
import os
import re
import subprocess
import time
import traceback
from pathlib import Path

from src.benchmarks.vulnlocplus.loading import project_for
from src.harnesses.batch import append_summary, run_batch
from src.baselines.looprepair.config import MODEL, LOOPREPAIR_SRC, DEFAULT_TIMEOUT_S, run_dir

IMAGE = "looprepair-gen:latest"
BASE_URL = os.environ.get("LOOPREPAIR_BASE_URL", "https://openrouter.ai/api/v1" if "/" in MODEL else "")
PROVIDER = os.environ.get("LOOPREPAIR_PROVIDER", "")
RESULTS_DIR = run_dir("looprepair-pov")
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
GENERATED_PATCHES_DIR = RESULTS_DIR / "generated_patches/diff"
CVE_LIST_PATH = Path("resources/vulnlocplus.cves.discriminating.txt")

DOCKER_TIMEOUT_S = 300.0
HANG_BACKSTOP_S = 86400.0
DOCKER_EXEC_SLACK_S = 120.0
TIMEOUT_EXIT_CODE = 124
DEFAULT_WORKERS = 8

VALIDATION_LIMIT_MIN = 45
TEST_LIMIT_S = 30
PATCH_LIMIT = 10

ARTIFACTS = ("analysis/localization.json", "analysis/analysis.json", "candidates.json",
             "iterative.json", "report.json", "patches")

PATCH_HEADER_RE = re.compile(r"^(---|\+\+\+) ")


def docker(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, errors="replace", timeout=timeout)


def cve_ids() -> list[str]:
    return [line.strip() for line in CVE_LIST_PATH.read_text().splitlines() if line.strip()]


def api_key() -> str:
    key = os.environ.get("LOOPREPAIR_API_KEY") or os.environ.get("OPENROUTER_API_KEY" if "/" in MODEL else "OPENAI_API_KEY")
    if not key:
        raise RuntimeError("set LOOPREPAIR_API_KEY or OPENAI_API_KEY - scripts/baselines/looprepair/generate.sh does")
    return key


def model_env() -> list[str]:
    flags = ["-e", f"LOOPREPAIR_MODEL={MODEL}", "-e", f"LOOPREPAIR_API_KEY={api_key()}"]
    if BASE_URL:
        flags += ["-e", f"LOOPREPAIR_BASE_URL={BASE_URL}"]
    if PROVIDER:
        flags += ["-e", f"LOOPREPAIR_PROVIDER={PROVIDER}"]
    return flags


def repair_command(scenario: str, timeout: float) -> str:
    capped = f"timeout {int(timeout)} " if timeout else ""
    return (f"cd /looprepair/looprepair && {capped}python3.8 cli.py repair "
            f"{scenario}/bug.json --no-fuzzing --stop-early "
            f"--time-limit-minutes-validation {VALIDATION_LIMIT_MIN} "
            f"--time-limit-seconds-test {TEST_LIMIT_S} --patch-limit {PATCH_LIMIT}")


def copy_out(container: str, scenario: str, out_dir: Path) -> None:
    for artifact in ARTIFACTS:
        target = out_dir / artifact
        target.parent.mkdir(parents=True, exist_ok=True)
        docker(["cp", f"{container}:{scenario}/{artifact}", str(target)], DOCKER_TIMEOUT_S)


def report_error(out_dir: Path) -> str | None:
    path = out_dir / "report.json"
    if not path.exists():
        return None
    return (json.loads(path.read_text()).get("error") or {}).get("kind")


def candidate_locations(out_dir: Path) -> dict[int, str]:
    path = out_dir / "candidates.json"
    if not path.exists():
        return {}
    return {int(c["id"]): c["location"] for c in json.loads(path.read_text()) if "id" in c}


def export_patches(cve_id: str, out_dir: Path) -> list[dict]:
    project = project_for(cve_id)
    locations = candidate_locations(out_dir)
    rows = []
    for diff_path in sorted((out_dir / "patches").glob("*.diff")):
        candidate_id = int(diff_path.stem)
        location = locations.get(candidate_id, "")
        target_basename = Path(location.split(":")[0]).stem if location else None
        target_line = int(location.split(":")[1]) if location.count(":") >= 1 else None
        body = "".join(l for l in diff_path.read_text().splitlines(keepends=True) if not PATCH_HEADER_RE.match(l))
        name = f"{target_basename}_{target_line}_{candidate_id}.txt" if target_basename else f"{candidate_id}.txt"
        exported = GENERATED_PATCHES_DIR / project / cve_id / name
        exported.parent.mkdir(parents=True, exist_ok=True)
        exported.write_text(body)
        rows.append({"cve": cve_id, "project": project, "candidate_id": candidate_id,
                     "target_basename": target_basename, "target_line": target_line,
                     "fix_patch": body, "source_file": str(exported)})
    return rows


def generate_one_sync(cve_id: str, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    project = project_for(cve_id)
    scenario = f"/data/vulnloc/{project}/{cve_id}"
    container = f"looprepair-gen-{RESULTS_DIR.name}-{cve_id}".lower()
    out_dir = RESULTS_DIR / cve_id
    row = {"cve_id": cve_id, "project": project, "model": MODEL, "status": "error"}
    t0 = time.monotonic()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        docker(["rm", "-f", container], DOCKER_TIMEOUT_S)
        started = docker(["run", "-d", "--name", container,
                          *model_env(),
                          "-v", f"{Path.cwd() / LOOPREPAIR_SRC}:/looprepair",
                          IMAGE, "sleep", "infinity"], DOCKER_TIMEOUT_S)
        if started.returncode != 0:
            raise RuntimeError(started.stderr.strip()[-500:])
        proc = docker(["exec", container, "bash", "-c", repair_command(scenario, timeout)],
                      timeout + DOCKER_EXEC_SLACK_S if timeout else HANG_BACKSTOP_S)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "orchestrator.log").write_text(proc.stdout + proc.stderr)
        copy_out(container, scenario, out_dir)

        rows = export_patches(cve_id, out_dir)
        if rows:
            with open(PATCHES_PATH, "a") as f:
                for patch_row in rows:
                    f.write(json.dumps(patch_row) + "\n")
        row["n_candidates"] = len(candidate_locations(out_dir))
        row["n_patches"] = len(rows)
        row["localized"] = (out_dir / "analysis/localization.json").exists()
        row["report_error"] = report_error(out_dir)
        if proc.returncode == TIMEOUT_EXIT_CODE:
            row["status"] = "timeout"
            row["error"] = f"killed at the {int(timeout)}s wall clock"
        elif rows:
            row["status"] = "ok"
        elif not row["localized"]:
            row["status"] = "analysis_fail"
        else:
            row["status"] = "no_patch"
        return row
    except subprocess.TimeoutExpired as exc:
        row["status"] = "timeout"
        row["error"] = f"docker exec did not return within {exc.timeout}s"
        return row
    except Exception as exc:
        row["error"] = repr(exc)
        row["traceback"] = traceback.format_exc()
        return row
    finally:
        row["duration_s"] = round(time.monotonic() - t0, 1)
        docker(["rm", "-f", container], DOCKER_TIMEOUT_S)


async def generate_one(cve_id: str, timeout: float) -> dict:
    return await asyncio.to_thread(generate_one_sync, cve_id, timeout)


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Re-run LoopRepair's own pipeline under {MODEL}.")
    parser.add_argument("--cve", action="append", help="vulnerability id (repeatable)")
    parser.add_argument("--all", action="store_true", help=f"every id in {CVE_LIST_PATH}")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help="per-id wall clock in seconds; 0 lets LoopRepair run to completion")
    parser.add_argument("--heartbeat-interval", type=float, default=60.0)
    args = parser.parse_args()

    ids = args.cve or (cve_ids() if args.all else cve_ids()[:1])
    if args.limit:
        ids = ids[: args.limit]

    if len(ids) == 1:
        row = generate_one_sync(ids[0], args.timeout)
        append_summary(RESULTS_DIR, row)
        print(json.dumps(row, indent=2))
        return

    asyncio.run(run_batch(
        items=ids,
        run_one=lambda cve_id: generate_one(cve_id, args.timeout),
        results_dir=RESULTS_DIR,
        workers=args.workers,
        timeout=args.timeout + DOCKER_EXEC_SLACK_S if args.timeout else HANG_BACKSTOP_S,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", image {IMAGE}, model {MODEL}",
        done_msg=f"Patches: {PATCHES_PATH}",
    ))


if __name__ == "__main__":
    main()
