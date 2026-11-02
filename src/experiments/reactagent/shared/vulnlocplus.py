import argparse
import asyncio
import json
import time
import traceback
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from src.agentcore.config import DEFAULT_MODEL
from src.benchmarks.registry import get_benchmark
from src.benchmarks.vulnlocplus.evaluate import grade
from src.benchmarks.vulnlocplus.loading import project_for
from src.benchmarks.vulnlocplus.locations import locations
from src.experiments.reactagent.agent import run_episode
from src.experiments.reactagent.shared.arm import MODEL_KWARGS, REASONING_EFFORT
from src.harnesses.batch import add_common_args, append_patch, append_summary, run_batch, select_cve_ids
from src.harnesses.budget import agent_wall_limit
from src.harnesses.docker import get_commit_sha
from src.harnesses.jsonl import last_per_key, read_jsonl
from src.harnesses import results as recorded

BENCHMARK = "vulnlocplus"
DEFAULT_GRADE_WORKERS = 8
AGENT_TIMEOUT_S = 1800.0


def results_dir(approach: str) -> Path:
    return recorded.results_dir(BENCHMARK, approach)


async def batch_main(run_one, results: Path, patches_path: Path, default_timeout: float,
                     default_cve_ids: list[str], start_msg: str = "", takes_device: bool = False) -> None:
    parser = add_common_args(argparse.ArgumentParser(), default_model=DEFAULT_MODEL, default_timeout=default_timeout)
    if takes_device:
        parser.add_argument("--device", default=None, help="torch device for the embedding model")
    args = parser.parse_args()
    extra = {"device": args.device} if takes_device else {}
    if args.all and not args.cve:
        cve_ids = get_benchmark(BENCHMARK).cve_ids()[: args.limit or None]
    else:
        cve_ids = select_cve_ids(args, default_cve_ids)
    await run_batch(
        items=cve_ids,
        run_one=lambda cve_id: run_one(cve_id, args.model, args.timeout, **extra),
        results_dir=results,
        workers=args.workers,
        timeout=args.timeout,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", benchmark={BENCHMARK}, model={args.model}{start_msg}",
        done_msg=f"Patches: {patches_path}",
    )


def graph_tools_for(cve_id: str, device: str | None = None):
    from src.benchmarks.vulnlocplus.graphs import graph_key
    from src.experiments.reactagent.tools import graph_tools
    key = graph_key(cve_id)
    if not graph_tools.has_graph(key):
        raise RuntimeError(f"no graph for {key} - run scripts/benchmarks/vulnlocplus/graphs.sh first")
    return graph_tools.build_tools(key, device)


async def run_guided_agent(cve_id: str, model: str, timeout: float, verbose: bool, results: Path,
                           guidance: str, tools_for: Callable[[str], Sequence] | None = None) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    bench = get_benchmark(BENCHMARK)
    episode = None
    try:
        extra_tools = tuple(tools_for(cve_id)) if tools_for else ()
        episode = await asyncio.to_thread(bench.start, cve_id)
        await asyncio.to_thread(bench.sanitize, episode)
        base_sha = await asyncio.to_thread(get_commit_sha, episode.container, episode.repo_dir)
        print(f"{tag} container ready ({episode.container})", flush=True)

        task = bench.task_prompt(bench.load_record(cve_id))
        result = await asyncio.to_thread(
            run_episode, cve_id, f"{task}\n\n{guidance}" if guidance else task, episode.container,
            episode.repo_dir, model, results / cve_id / "reactagent_run",
            agent_wall_limit(timeout - (time.monotonic() - t0)), verbose, extra_tools, MODEL_KWARGS,
        )
        model_stats = result.get("model_stats") or {}
        print(f"{tag} agent {result['agent_status']} in {result['steps']} steps, {model_stats}", flush=True)
        diffs = await asyncio.to_thread(bench.extract_patch, episode, base_sha)
        append_patch(results / "patches.jsonl", cve_id, diffs)
        duration_s = round(time.monotonic() - t0, 1)
        print(f"{tag} patch {len(diffs.fix_patch)} chars, test {len(diffs.test_patch)} chars - {duration_s}s", flush=True)
        return {
            "cve_id": cve_id,
            "benchmark": BENCHMARK,
            "status": "ok" if diffs.fix_patch.strip() else "no_patch",
            "patch_chars": len(diffs.fix_patch),
            "test_chars": len(diffs.test_patch),
            "dropped_files": len(diffs.dropped_files),
            "agent_status": result["agent_status"],
            "agent_steps": result["steps"],
            "reasoning_effort": REASONING_EFFORT,
            "extra_tools": [schema["function"]["name"] for schema, _ in extra_tools],
            "instance_cost": model_stats.get("instance_cost"),
            "tokens_sent": model_stats.get("tokens_sent"),
            "tokens_received": model_stats.get("tokens_received"),
            "api_calls": model_stats.get("api_calls"),
            "api_retries": model_stats.get("retries"),
            "summaries": result.get("summaries"),
            "traj_path": result.get("traj_path"),
            "agent_stderr_tail": result.get("stderr_tail") or None,
            "duration_s": duration_s,
        }
    except Exception as e:
        tb = traceback.format_exc()
        print(f"{tag} error:\n{tb}", flush=True)
        return {"cve_id": cve_id, "benchmark": BENCHMARK, "status": "error", "error": repr(e), "traceback": tb,
                "duration_s": round(time.monotonic() - t0, 1)}
    finally:
        if episode is not None:
            await asyncio.to_thread(bench.teardown, episode)


def guided_main(results: Path, guidance: str, run_one, description: str) -> None:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--cve", default="CVE-2016-1838")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--timeout", type=float, default=AGENT_TIMEOUT_S)
    parser.add_argument("--print-task", action="store_true", help="print the task and exit, no container")
    parser.add_argument("--no-summary", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.print_task:
        bench = get_benchmark(BENCHMARK)
        task = bench.task_prompt(bench.load_record(args.cve))
        print(f"{task}\n\n{guidance}" if guidance else task)
        return
    result = asyncio.run(run_one(args.cve, args.model, args.timeout, verbose=not args.quiet))
    if not args.no_summary:
        append_summary(results, result)
    print(json.dumps(result, indent=2))


def aggregator_main(results: Path, run_one, description: str) -> None:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--cve", default="CVE-2016-1838")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--timeout", type=float, default=AGENT_TIMEOUT_S)
    parser.add_argument("--no-summary", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    result = asyncio.run(run_one(args.cve, args.model, args.timeout, verbose=not args.quiet))
    if not args.no_summary:
        append_summary(results, result)
    print(json.dumps(result, indent=2))


def hint_text(cve_id: str) -> str:
    hint = locations(cve_id)
    return ", ".join(f"{h['file_path']} line {h['start_line']}" for h in hint) if hint else "no location was given"


def evaluate_main(results: Path, patches_path: Path, name: str) -> None:
    parser = argparse.ArgumentParser(description=f"Grade {results.name}'s VulnLoc+ patches.")
    parser.add_argument("--workers", type=int, default=DEFAULT_GRADE_WORKERS)
    parser.add_argument("--cve", action="append")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    out_path = results / "evaluation_results.jsonl"
    patches = last_per_key(read_jsonl(patches_path), key="cve")
    done = {(row["cve_id"], row["name"]) for row in read_jsonl(out_path)} if out_path.exists() else set()
    pending = {cve_id: row["fix_patch"] for cve_id, row in patches.items()
               if (not args.cve or cve_id in args.cve) and (cve_id, name) not in done}
    if args.limit is not None:
        pending = dict(list(pending.items())[:args.limit])
    print(f"{len(patches)} patches, {len(patches) - len(pending)} already graded, {len(pending)} to grade")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a") as out, ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(grade, cve_id, patch, name, results / cve_id / "evaluation"): cve_id
                   for cve_id, patch in pending.items()}
        for future in as_completed(futures):
            row = future.result()
            out.write(json.dumps(row) + "\n")
            out.flush()
            print(f"{row['cve_id']}: {row['type']}{' (' + row['error'] + ')' if row.get('error') else ''}")
