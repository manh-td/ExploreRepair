import argparse
import asyncio
import json
import os
import subprocess
import time
import traceback
from pathlib import Path

from src.benchmarks.vulnlocplus.loading import project_for
from src.benchmarks.vulnlocplus.locations import working_set as cve_ids
from src.baselines.looprepair.config import run_dir
from src.harnesses.results import REPO_ROOT
from src.harnesses.batch import append_summary, run_batch

IMAGE = "looprepair-prepped:latest"
DRIVER = Path(__file__).resolve().with_name("evaluate_in_container.py")
DRIVER_IN_CONTAINER = "/looprepair-src/evaluate_in_container.py"
RESULT_IN_CONTAINER = "/tmp/result.json"
CANDIDATE_IN_CONTAINER = "/tmp/candidate.diff"
RESULTS_DIR = run_dir()
GENERATED_PATCHES_DIR = Path(os.environ.get("LOOPREPAIR_PATCHES_DIR", RESULTS_DIR / "generated_patches/diff"))
PATCH_DIR_IN_CONTAINER = "/tmp/looprepair-patch"
FUZZER_RESULTS_ROOT = REPO_ROOT / "baselines" / "LoopRepair" / "fuzzer_results"
DOCKER_TIMEOUT_S = 300.0
DEFAULT_TIMEOUT_S = 3600.0
DEFAULT_WORKERS = 4


def docker(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, errors="replace", timeout=timeout)


def looprepair_patch_for(cve_id: str) -> Path | None:
    found = sorted((GENERATED_PATCHES_DIR / project_for(cve_id) / cve_id).glob("*.txt"))
    return found[0] if found else None


def verdicts(raw: dict) -> dict:
    vulnerable = raw.get("vulnerable") or {}
    patch = raw.get("looprepair_patch")
    golden = raw.get("golden")
    return {
        "asan_enabled": raw.get("asan_enabled"),
        "first_build": raw.get("first_build"),
        "vulnerable_passes": vulnerable.get("successful"),
        "oracle_discriminates": bool(raw.get("first_build")) and vulnerable.get("successful") is False,
        "looprepair_patch_is_repair": None if patch is None else patch.get("is-repair"),
        "looprepair_patch_applies": None if patch is None else patch.get("applies"),
        "golden_is_repair": None if golden is None else golden.get("is-repair"),
    }


class DriverFailed(RuntimeError):
    pass


def fuzzer_corpus_for(cve_id: str) -> Path | None:
    corpus = FUZZER_RESULTS_ROOT / project_for(cve_id) / cve_id / "concentrated_inputs"
    return corpus if corpus.is_dir() and any(corpus.iterdir()) else None


def run_driver(cve_id: str, out_dir: Path, *, looprepair_patch: Path | None = None, golden: str = "-",
               candidate: str | None = None, timeout: float = DEFAULT_TIMEOUT_S, name: str = "eval",
               fuzz_corpus: Path | None = None) -> dict:
    subject = f"/data/vulnloc/{project_for(cve_id)}/{cve_id}"
    container = f"looprepair-{name}-{cve_id.lower()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        docker(["rm", "-f", container], DOCKER_TIMEOUT_S)
        started = docker(["run", "-d", "--name", container, IMAGE, "sleep", "infinity"], DOCKER_TIMEOUT_S)
        if started.returncode != 0:
            raise DriverFailed(started.stderr.strip()[-500:])
        docker(["cp", str(DRIVER), f"{container}:{DRIVER_IN_CONTAINER}"], DOCKER_TIMEOUT_S)
        patch_arg = "-"
        if looprepair_patch is not None:
            docker(["exec", container, "mkdir", "-p", PATCH_DIR_IN_CONTAINER], DOCKER_TIMEOUT_S)
            patch_arg = f"{PATCH_DIR_IN_CONTAINER}/{looprepair_patch.name}"
            docker(["cp", str(looprepair_patch), f"{container}:{patch_arg}"], DOCKER_TIMEOUT_S)
        candidate_arg = ""
        if candidate is not None:
            local = out_dir / "candidate.diff"
            local.write_text(candidate)
            docker(["cp", str(local), f"{container}:{CANDIDATE_IN_CONTAINER}"], DOCKER_TIMEOUT_S)
            candidate_arg = f" {CANDIDATE_IN_CONTAINER}"
        fuzz_arg = ""
        if fuzz_corpus is not None:
            docker(["cp", str(fuzz_corpus), f"{container}:{subject}/"], DOCKER_TIMEOUT_S)
            fuzz_arg = " --fuzz"
        command = (f"cd /looprepair-src && python3.8 {DRIVER_IN_CONTAINER} {subject}/bug.json "
                   f"{patch_arg} {golden} {RESULT_IN_CONTAINER}{candidate_arg}{fuzz_arg}")
        proc = docker(["exec", container, "bash", "-c", command], timeout)
        (out_dir / "driver.log").write_text(proc.stdout + proc.stderr)
        got = docker(["exec", container, "cat", RESULT_IN_CONTAINER], DOCKER_TIMEOUT_S)
        if got.returncode != 0:
            raise DriverFailed("\n".join((proc.stdout + proc.stderr).strip().splitlines()[-5:]))
        raw = json.loads(got.stdout)
        (out_dir / "result.json").write_text(json.dumps(raw, indent=2))
        return raw
    finally:
        docker(["rm", "-f", container], DOCKER_TIMEOUT_S)


def evaluate_one_sync(cve_id: str, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    project = project_for(cve_id)
    row = {"cve_id": cve_id, "project": project, "status": "error",
           "name": RESULTS_DIR.name, "poc": False, "unittest": None, "type": "validation_fail"}
    t0 = time.monotonic()
    try:
        patch = looprepair_patch_for(cve_id)
        if patch is None:
            row["status"] = "no_patch"
            return row
        raw = run_driver(cve_id, RESULTS_DIR / cve_id / "evaluation", looprepair_patch=patch,
                         golden=f"/data/vulnloc/{project}/{cve_id}/dev-patch/fix.patch", timeout=timeout)
        row.update(verdicts(raw))
        row["poc"] = bool(row["looprepair_patch_is_repair"])
        row["type"] = "Repair Success" if row["poc"] else "validation_fail"
        row["status"] = "ok" if raw.get("first_build") else "build_fail"
        return row
    except subprocess.TimeoutExpired as exc:
        row["status"] = "timeout"
        row["error"] = f"timed out after {exc.timeout}s"
        return row
    except Exception as exc:
        row["error"] = str(exc) if isinstance(exc, DriverFailed) else repr(exc)
        row["traceback"] = traceback.format_exc()
        return row
    finally:
        row["duration_s"] = round(time.monotonic() - t0, 1)


async def evaluate_one(cve_id: str, timeout: float) -> dict:
    return await asyncio.to_thread(evaluate_one_sync, cve_id, timeout)


def main() -> None:
    parser = argparse.ArgumentParser(description="Grade VulnLoc+ CVEs with LoopRepair's own build and crash test.")
    parser.add_argument("--cve", action="append", help="CVE id (repeatable)")
    parser.add_argument("--all", action="store_true", help="the 35 retained VulnLoc+ vulnerabilities")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="per-CVE seconds")
    parser.add_argument("--heartbeat-interval", type=float, default=60.0)
    args = parser.parse_args()

    cve_list = args.cve or (cve_ids() if args.all else cve_ids()[:1])
    if args.limit:
        cve_list = cve_list[: args.limit]

    if len(cve_list) == 1:
        row = evaluate_one_sync(cve_list[0], args.timeout)
        append_summary(RESULTS_DIR, row, summary_name="evaluation_results.jsonl")
        print(json.dumps(row, indent=2))
        return

    asyncio.run(run_batch(
        items=cve_list,
        run_one=lambda cve_id: evaluate_one(cve_id, args.timeout),
        results_dir=RESULTS_DIR,
        summary_name="evaluation_results.jsonl",
        workers=args.workers,
        timeout=args.timeout,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", image {IMAGE}",
    ))


if __name__ == "__main__":
    main()
