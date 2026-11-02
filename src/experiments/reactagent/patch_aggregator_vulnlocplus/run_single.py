import asyncio
import json
import time
import traceback
from pathlib import Path

from dotenv import load_dotenv

from src.benchmarks.registry import get_benchmark
from src.experiments.reactagent.agent import run_episode
from src.experiments.reactagent.lesson_aggregator_vulnlocplus.run_single import SOURCES
from src.experiments.reactagent.patch_aggregator.run_single import attempts, render
from src.experiments.reactagent.shared.arm import MODEL_KWARGS, REASONING_EFFORT
from src.experiments.reactagent.shared.vulnlocplus import AGENT_TIMEOUT_S, BENCHMARK, aggregator_main, results_dir
from src.harnesses.batch import append_patch
from src.harnesses.budget import agent_wall_limit

load_dotenv()

RESULTS_DIR = results_dir("patch-aggregator")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_TIMEOUT_S = AGENT_TIMEOUT_S
DEFAULT_CVE_IDS = ["CVE-2016-1838"]
SOURCE_DIRS = list(SOURCES)


async def aggregate(cve_id: str, model: str, timeout: float, verbose: bool, results: Path, source_dirs: list[Path]) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    bench = get_benchmark(BENCHMARK)
    episode = None
    try:
        found = await asyncio.to_thread(attempts, cve_id, source_dirs)
        if not found:
            raise RuntimeError(f"no recorded attempts for {cve_id} in {[d.name for d in source_dirs]}")
        (results / cve_id).mkdir(parents=True, exist_ok=True)
        (results / cve_id / "attempts.json").write_text(json.dumps({"attempts": found}, indent=2))
        block = render(cve_id, found)
        print(f"{tag} {len(found)} attempts ({len(block)} chars)", flush=True)

        episode = await asyncio.to_thread(bench.start, cve_id)
        await asyncio.to_thread(bench.sanitize, episode)
        task = f"{bench.task_prompt(bench.load_record(cve_id))}{block}"
        result = await asyncio.to_thread(
            run_episode, cve_id, task, episode.container, episode.repo_dir, model,
            results / cve_id / "reactagent_run", agent_wall_limit(timeout - (time.monotonic() - t0)),
            verbose, (), MODEL_KWARGS,
        )
        model_stats = result.get("model_stats") or {}
        print(f"{tag} agent {result['agent_status']} in {result['steps']} steps, {model_stats}", flush=True)

        diffs = await asyncio.to_thread(bench.extract_patch, episode)
        append_patch(results / "patches.jsonl", cve_id, diffs)
        duration_s = round(time.monotonic() - t0, 1)
        print(f"{tag} patch saved ({len(diffs.fix_patch)} chars) - {duration_s}s", flush=True)
        return {
            "cve_id": cve_id,
            "benchmark": BENCHMARK,
            "status": "ok" if diffs.fix_patch.strip() else "no_patch",
            "patch_chars": len(diffs.fix_patch),
            "agent_status": result["agent_status"],
            "agent_steps": result["steps"],
            "reasoning_effort": REASONING_EFFORT,
            "n_attempts": len(found),
            "attempt_sources": [item["source"] for item in found],
            "block_chars": len(block),
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


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await aggregate(cve_id, model, timeout, verbose, RESULTS_DIR, SOURCE_DIRS)


if __name__ == "__main__":
    aggregator_main(RESULTS_DIR, run_one, "The Patch Aggregator on one VulnLoc+ CVE")
