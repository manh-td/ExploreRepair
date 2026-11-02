import asyncio
import json
import subprocess
import time
import traceback
from pathlib import Path

from dotenv import load_dotenv

from src.experiments.codex.agent import DEFAULT_MODEL, REASONING_EFFORT, TASK_SUFFIX, run_episode
from src.harnesses.batch import append_patch, append_summary
from src.harnesses.cve_task import load_cve_task
from src.harnesses.dataset import load_cve_record, repo_dirname
from src.harnesses.results import results_dir
from src.harnesses.docker import (
    get_split_diffs,
    resolve_repo_dirname,
    restore_and_stop,
    sanitize_container,
    start_editable_container,
)

load_dotenv()

RESULTS_DIR = results_dir("patcheval", "codex")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"

DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]


def _save_run_log(cve_id: str, task: str, duration_s: float, episode: dict) -> Path:
    run_dir = RESULTS_DIR / cve_id / "codex_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(json.dumps(
        {"cve_id": cve_id, "task": task, "duration_s": duration_s, **episode}, indent=2, default=str,
    ))
    return run_dir


async def run_one(cve_id: str, model: str = DEFAULT_MODEL) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    record = load_cve_record(cve_id)
    image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
    container_name = None
    dirname = None
    try:
        container_name = await asyncio.to_thread(start_editable_container, cve_id, image)
        dirname = await asyncio.to_thread(resolve_repo_dirname, container_name, repo_dirname(record["repo"]))
        await asyncio.to_thread(sanitize_container, container_name)
        print(f"{tag} container ready ({container_name})", flush=True)

        task = load_cve_task(record) + TASK_SUFFIX
        episode = await asyncio.to_thread(run_episode, task, container_name, f"/workspace/{dirname}", model)
        usage = episode["usage"]

        diffs = await asyncio.to_thread(get_split_diffs, container_name, dirname)
        fix_patch = diffs.fix_patch
        append_patch(PATCHES_PATH, cve_id, diffs)

        duration_s = round(time.monotonic() - t0, 1)
        run_dir = _save_run_log(cve_id, task, duration_s, episode)
        print(f"{tag} agent {episode['status']} after {episode['tool_calls']} tool calls, patch {len(fix_patch)} chars - {duration_s}s - log: {run_dir}", flush=True)
        return {
            "cve_id": cve_id,
            "status": "ok" if fix_patch.strip() else "no_patch",
            "patch_chars": len(fix_patch),
            "agent_status": episode["status"],
            "tool_calls": episode["tool_calls"],
            "reasoning_effort": REASONING_EFFORT,
            "input_tokens": usage.get("input_tokens"),
            "cached_input_tokens": usage.get("cached_input_tokens"),
            "output_tokens": usage.get("output_tokens"),
            "reasoning_output_tokens": usage.get("reasoning_output_tokens"),
            "duration_s": duration_s,
            "run_dir": str(run_dir),
        }
    except Exception as e:
        tb = traceback.format_exc()
        print(f"{tag} error:\n{tb}", flush=True)
        return {"cve_id": cve_id, "status": "error", "error": repr(e), "traceback": tb,
                "duration_s": round(time.monotonic() - t0, 1)}
    finally:
        if container_name and dirname:
            await asyncio.to_thread(restore_and_stop, container_name, dirname)
        elif container_name:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run this experiment on a single CVE")
    parser.add_argument("--cve", default=DEFAULT_CVE_IDS[0], help="CVE id to patch")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--no-summary", action="store_true", help="don't append a row to run_summary.jsonl")
    args = parser.parse_args()

    result = asyncio.run(run_one(args.cve, args.model))
    if not args.no_summary:
        append_summary(RESULTS_DIR, result)
    print(json.dumps(result, indent=2))
