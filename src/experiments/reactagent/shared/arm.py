import asyncio
import json
import subprocess
import time
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path

from src.experiments.reactagent.agent import run_episode
from src.harnesses.batch import append_patch
from src.harnesses.budget import agent_wall_limit
from src.harnesses.cve_task import load_cve_task
from src.harnesses.dataset import load_cve_record, repo_dirname
from src.harnesses.docker import (
    get_commit_sha,
    get_split_diffs,
    resolve_repo_dirname,
    restore_and_stop,
    sanitize_container,
    start_editable_container,
)

DEFAULT_TIMEOUT_S = 1800.0
REASONING_EFFORT = "medium"
MODEL_KWARGS = {"reasoning_effort": REASONING_EFFORT}


def guided_task(record: dict, guidance: str) -> str:
    task = load_cve_task(record)
    return f"{task}\n\n{guidance}" if guidance else task


async def run_guided_agent(cve_id: str, model: str, timeout: float, verbose: bool, results: Path, guidance: str, tools_for: Callable[[str], Sequence] | None = None) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    record = load_cve_record(cve_id)
    image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
    container_name = None
    dirname = None
    try:
        extra_tools = tuple(tools_for(cve_id)) if tools_for else ()
        container_name = await asyncio.to_thread(start_editable_container, cve_id, image, f"editable-{results.name}")
        dirname = await asyncio.to_thread(resolve_repo_dirname, container_name, repo_dirname(record["repo"]))
        await asyncio.to_thread(sanitize_container, container_name)
        base_sha = await asyncio.to_thread(get_commit_sha, container_name, dirname)
        print(f"{tag} container ready ({container_name})", flush=True)

        episode = await asyncio.to_thread(
            run_episode, cve_id, guided_task(record, guidance), container_name, dirname, model,
            results / cve_id / "reactagent_run", agent_wall_limit(timeout - (time.monotonic() - t0)),
            verbose, extra_tools, MODEL_KWARGS,
        )
        model_stats = episode.get("model_stats") or {}
        print(f"{tag} agent {episode['agent_status']} in {episode['steps']} steps, {model_stats}", flush=True)
        if episode["stderr_tail"]:
            print(f"{tag} agent error: {episode['stderr_tail']}", flush=True)

        diffs = await asyncio.to_thread(get_split_diffs, container_name, dirname, base_sha)
        append_patch(results / "patches.jsonl", cve_id, diffs)

        duration_s = round(time.monotonic() - t0, 1)
        print(f"{tag} patch {len(diffs.fix_patch)} chars, test {len(diffs.test_patch)} chars - {duration_s}s", flush=True)
        return {
            "cve_id": cve_id,
            "status": "ok" if diffs.fix_patch.strip() else "no_patch",
            "patch_chars": len(diffs.fix_patch),
            "test_chars": len(diffs.test_patch),
            "agent_status": episode["agent_status"],
            "agent_steps": episode["steps"],
            "reasoning_effort": REASONING_EFFORT,
            "extra_tools": [schema["function"]["name"] for schema, _ in extra_tools],
            "instance_cost": model_stats.get("instance_cost"),
            "tokens_sent": model_stats.get("tokens_sent"),
            "tokens_received": model_stats.get("tokens_received"),
            "api_calls": model_stats.get("api_calls"),
            "api_retries": model_stats.get("retries"),
            "summaries": episode.get("summaries"),
            "traj_path": episode.get("traj_path"),
            "agent_stderr_tail": episode.get("stderr_tail") or None,
            "duration_s": duration_s,
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


def main(results: Path, guidance: str, run_one, description: str) -> None:
    import argparse

    from dotenv import load_dotenv

    from src.agentcore.config import DEFAULT_MODEL
    from src.harnesses.batch import append_summary

    load_dotenv()
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--cve", default="CVE-2025-27154")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--print-task", action="store_true", help="print the task and exit, no container")
    parser.add_argument("--no-summary", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.print_task:
        print(guided_task(load_cve_record(args.cve), guidance))
        return
    result = asyncio.run(run_one(args.cve, args.model, args.timeout, verbose=not args.quiet))
    if not args.no_summary:
        append_summary(results, result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Print the unguided repair task for one CVE")
    parser.add_argument("--cve", default="CVE-2025-27154")
    print(guided_task(load_cve_record(parser.parse_args().cve), ""))
