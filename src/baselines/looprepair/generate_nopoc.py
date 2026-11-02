import argparse
import asyncio
import json
import subprocess
import time
import traceback
from pathlib import Path

from src.baselines.looprepair.generate import IMAGE, LOOPREPAIR_SRC, MODEL, cve_ids, docker, model_env
from src.benchmarks.vulnlocplus.loading import project_for
from src.benchmarks.vulnlocplus.locations import crash_sites
from src.harnesses.batch import append_summary, run_batch
from src.baselines.looprepair.config import DEFAULT_TIMEOUT_S, run_dir

RESULTS_DIR = run_dir("looprepair-no-pov")
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
GENERATED_PATCHES_DIR = RESULTS_DIR / "generated_patches/diff"

DRIVERS = (Path("src/baselines/looprepair/generate_nopoc_in_container.py"),
           Path("src/baselines/looprepair/evaluate_in_container.py"))
DRIVER_DIR_IN_CONTAINER = "/looprepair-drivers"
LOOPREPAIR_SRC_IN_CONTAINER = "/looprepair-src"
OUT_IN_CONTAINER = "/tmp/nopoc"
ARTIFACTS = ("localization.json", "candidates.json", "result.json")
DOCKER_TIMEOUT_S = 300.0
DEFAULT_WORKERS = 8


def location_for(cve_id: str) -> str | None:
    site = crash_sites()[cve_id]
    if not site.get("file_path"):
        return None
    return f"/data/vulnloc/{project_for(cve_id)}/{cve_id}/src/{site['file_path']}:{site['line']}:0"


def export_patch(cve_id: str, location: str, candidate: dict) -> dict:
    file_path, line, _ = location.rsplit(":", 2)
    basename = Path(file_path).stem
    exported = GENERATED_PATCHES_DIR / project_for(cve_id) / cve_id / f"{basename}_{line}_{candidate['id']}.txt"
    exported.parent.mkdir(parents=True, exist_ok=True)
    exported.write_text(candidate["diff"])
    return {"cve": cve_id, "project": project_for(cve_id), "candidate_id": candidate["id"],
            "target_basename": basename, "target_line": int(line), "fix_patch": candidate["diff"],
            "source_file": str(exported)}


def generate_one_sync(cve_id: str, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    project = project_for(cve_id)
    row = {"cve_id": cve_id, "project": project, "model": MODEL, "status": "error"}
    t0 = time.monotonic()
    location = location_for(cve_id)
    if location is None:
        row["status"] = "no_location"
        row["duration_s"] = 0.0
        return row
    row["location"] = location
    container = f"looprepair-nopoc-{cve_id.lower()}"
    out_dir = RESULTS_DIR / cve_id
    try:
        docker(["rm", "-f", container], DOCKER_TIMEOUT_S)
        started = docker(["run", "-d", "--name", container,
                          *model_env(),
                          "-v", f"{Path.cwd() / LOOPREPAIR_SRC}:{LOOPREPAIR_SRC_IN_CONTAINER}",
                          IMAGE, "sleep", "infinity"], DOCKER_TIMEOUT_S)
        if started.returncode != 0:
            raise RuntimeError(started.stderr.strip()[-500:])
        docker(["exec", container, "mkdir", "-p", DRIVER_DIR_IN_CONTAINER], DOCKER_TIMEOUT_S)
        for driver in DRIVERS:
            docker(["cp", str(driver), f"{container}:{DRIVER_DIR_IN_CONTAINER}/{driver.name}"], DOCKER_TIMEOUT_S)
        proc = docker(["exec", container, "python3.8", f"{DRIVER_DIR_IN_CONTAINER}/{DRIVERS[0].name}",
                       f"/data/vulnloc/{project}/{cve_id}/bug.json", location, OUT_IN_CONTAINER], timeout)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "driver.log").write_text(proc.stdout + proc.stderr)
        for artifact in ARTIFACTS:
            docker(["cp", f"{container}:{OUT_IN_CONTAINER}/{artifact}", str(out_dir / artifact)], DOCKER_TIMEOUT_S)

        result_path = out_dir / "result.json"
        if not result_path.exists():
            raise RuntimeError("\n".join((proc.stdout + proc.stderr).strip().splitlines()[-5:]))
        result = json.loads(result_path.read_text())
        row["n_generated"] = result.get("n_generated")
        row["compile_statuses"] = [c["status"] for c in result["candidates"]]
        if result.get("error"):
            row["error"] = result["error"]
        elif result.get("n_generated") == 0:
            row["status"] = "no_function"
        elif result.get("first_build") is False:
            row["status"] = "build_fail"
        elif result["chosen"] is None:
            row["status"] = "no_compiling_patch"
        else:
            candidates = json.loads((out_dir / "candidates.json").read_text())
            chosen = next(c for c in candidates if c["id"] == result["chosen"])
            with open(PATCHES_PATH, "a") as f:
                f.write(json.dumps(export_patch(cve_id, location, chosen)) + "\n")
            row["chosen"] = result["chosen"]
            row["status"] = "ok"
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
    parser = argparse.ArgumentParser(
        description="LoopRepair's generation stage from bug.json's crash site, with no PoC: no crepair, "
                    "no crash test, no iteration; the first candidate that compiles is the patch.")
    parser.add_argument("--cve", action="append", help="vulnerability id (repeatable)")
    parser.add_argument("--all", action="store_true", help="every id in the discriminating working set")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="per-id seconds")
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
        timeout=args.timeout + DOCKER_TIMEOUT_S,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", image {IMAGE}, model {MODEL}, no PoC",
        done_msg=f"Patches: {PATCHES_PATH}",
    ))


if __name__ == "__main__":
    main()
