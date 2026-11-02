import asyncio
import json
import subprocess
import time
import traceback

from src.experiments.reactagent.agent import run_episode
from src.experiments.reactagent.multi_agent.subagent import (
    MAX_SUBAGENTS,
    SUBAGENT_WALL_S,
    Subagents,
    subagent_suffix,
)
from src.experiments.reactagent.shared.arm import MODEL_KWARGS, REASONING_EFFORT, guided_task
from src.experiments.reactagent.structural.run_single import _tools
from src.harnesses.batch import append_patch
from src.harnesses.budget import EPISODE_TEARDOWN_MARGIN_S
from src.harnesses.dataset import load_cve_record, repo_dirname
from src.harnesses.docker import (
    get_commit_sha,
    get_split_diffs,
    resolve_repo_dirname,
    restore_and_stop,
    sanitize_container,
    start_editable_container,
)
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "multi-agent")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]
DEFAULT_TIMEOUT_S = 3000.0
MIN_TEAM_WALL_S = 60.0

GUIDANCE = f"""You are the lead of a team of engineers, and `spawn_subagent` is how you give them work. It \
hands a task you write to a fresh engineer agent in this same checkout and returns their report. Do not do \
the whole task alone: split it into sub-tasks and delegate them. How you split the work, and what each \
sub-agent is asked to do, is yours to decide.

- A sub-agent knows only what your prompt tells it. It has not seen this task, the location above, or \
anything you or another sub-agent found, so put in everything it needs and say what to report back.
- It has the same shell and code-graph tools you have (`graph_neighbors`, `search_code`), and it works in \
the same working tree: what it edits stays edited.
- Sub-agents run one at a time. You can start at most {MAX_SUBAGENTS}, and each has up to \
{SUBAGENT_WALL_S / 60:.0f} minutes.

The final state of the repository is yours to answer for. Read what each sub-agent reports and what it \
changed (`git diff`), and correct or redo it before you finish.

Do not run git commit, reset, checkout or stash."""


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    record = load_cve_record(cve_id)
    image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
    container_name = None
    dirname = None
    try:
        graph_tools = tuple(_tools(cve_id))
        container_name = await asyncio.to_thread(start_editable_container, cve_id, image, f"editable-{RESULTS_DIR.name}")
        dirname = await asyncio.to_thread(resolve_repo_dirname, container_name, repo_dirname(record["repo"]))
        await asyncio.to_thread(sanitize_container, container_name)
        base_sha = await asyncio.to_thread(get_commit_sha, container_name, dirname)
        print(f"{tag} container ready ({container_name})", flush=True)

        team_wall = max(MIN_TEAM_WALL_S, timeout - (time.monotonic() - t0) - EPISODE_TEARDOWN_MARGIN_S)
        team = Subagents(cve_id, container_name, dirname, model, RESULTS_DIR / cve_id,
                         time.monotonic() + team_wall, subagent_suffix(record), graph_tools, verbose)
        extra_tools = (*graph_tools, team.tool())
        episode = await asyncio.to_thread(
            run_episode, cve_id, guided_task(record, GUIDANCE), container_name, dirname, model,
            RESULTS_DIR / cve_id / "reactagent_run", team_wall, verbose, extra_tools, MODEL_KWARGS,
        )
        lead = episode.get("model_stats") or {}
        subs = team.usage()
        print(f"{tag} lead {episode['agent_status']} in {episode['steps']} steps, {len(team.calls)} sub-agents, "
              f"${(lead.get('instance_cost') or 0) + subs['cost']:.3f}", flush=True)
        if episode["stderr_tail"]:
            print(f"{tag} agent error: {episode['stderr_tail']}", flush=True)

        diffs = await asyncio.to_thread(get_split_diffs, container_name, dirname, base_sha)
        append_patch(PATCHES_PATH, cve_id, diffs)

        duration_s = round(time.monotonic() - t0, 1)
        print(f"{tag} patch {len(diffs.fix_patch)} chars, test {len(diffs.test_patch)} chars - {duration_s}s", flush=True)
        return {
            "cve_id": cve_id,
            "status": "ok" if diffs.fix_patch.strip() else "no_patch",
            "patch_chars": len(diffs.fix_patch),
            "test_chars": len(diffs.test_patch),
            "agent_status": episode["agent_status"],
            "agent_steps": episode["steps"],
            "team_steps": episode["steps"] + subs["steps"],
            "n_subagents": len(team.calls),
            "refused_spawns": team.refusals,
            "subagents": team.calls,
            "reasoning_effort": REASONING_EFFORT,
            "extra_tools": [schema["function"]["name"] for schema, _ in extra_tools],
            "lead_cost": lead.get("instance_cost"),
            "instance_cost": (lead.get("instance_cost") or 0) + subs["cost"],
            "tokens_sent": (lead.get("tokens_sent") or 0) + subs["tokens_sent"],
            "tokens_received": (lead.get("tokens_received") or 0) + subs["tokens_received"],
            "api_calls": (lead.get("api_calls") or 0) + subs["api_calls"],
            "api_retries": (lead.get("retries") or 0) + subs["retries"],
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


if __name__ == "__main__":
    import argparse

    from dotenv import load_dotenv

    from src.agentcore.config import DEFAULT_MODEL
    from src.harnesses.batch import append_summary

    load_dotenv()
    parser = argparse.ArgumentParser(description="A lead agent that delegates to sub-agents it prompts itself, on one CVE")
    parser.add_argument("--cve", default=DEFAULT_CVE_IDS[0])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--print-task", action="store_true", help="print the lead's task and exit, no container")
    parser.add_argument("--no-summary", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.print_task:
        print(guided_task(load_cve_record(args.cve), GUIDANCE))
        raise SystemExit(0)
    result = asyncio.run(run_one(args.cve, args.model, args.timeout, verbose=not args.quiet))
    if not args.no_summary:
        append_summary(RESULTS_DIR, result)
    print(json.dumps(result, indent=2))
