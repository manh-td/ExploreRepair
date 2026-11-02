import asyncio
import json
import time
import traceback
from pathlib import Path

from dotenv import load_dotenv

from src.benchmarks.registry import get_benchmark
from src.experiments.reactagent.agent import run_episode
from src.experiments.reactagent.shared import distill
from src.experiments.reactagent.shared.arm import MODEL_KWARGS, REASONING_EFFORT
from src.experiments.reactagent.shared.vulnlocplus import AGENT_TIMEOUT_S, BENCHMARK, aggregator_main, hint_text, results_dir
from src.harnesses.batch import append_patch
from src.harnesses.budget import agent_wall_limit

load_dotenv()

RESULTS_DIR = results_dir("lesson-aggregator")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_TIMEOUT_S = AGENT_TIMEOUT_S
DEFAULT_CVE_IDS = ["CVE-2016-1838"]
SOURCES = {
    results_dir("structural"): "structure",
    results_dir("semantic"): "intent",
    results_dir("executable"): "execution",
}


async def aggregate(cve_id: str, model: str, timeout: float, verbose: bool, results: Path, sources: dict[Path, str]) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    bench = get_benchmark(BENCHMARK)
    episode = None
    try:
        found, usage = await asyncio.to_thread(distill.lessons, cve_id, model, sources, hint_text)
        if not found:
            raise RuntimeError(f"no recorded attempts to distil for {cve_id} in {[d.name for d in sources]}")
        (results / cve_id).mkdir(parents=True, exist_ok=True)
        (results / cve_id / "lessons.json").write_text(json.dumps({"lessons": found, "usage": usage}, indent=2))
        block = distill.render(found)
        print(f"{tag} {len(found)} lessons distilled ({len(block)} chars, ${usage['cost']:.3f})", flush=True)

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
            "n_lessons": len(found),
            "lesson_sources": [item["source"] for item in found],
            "lessons_chars": len(block),
            "distill_cost": round(usage["cost"], 6),
            "repair_cost": model_stats.get("instance_cost"),
            "instance_cost": (model_stats.get("instance_cost") or 0) + usage["cost"],
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
        return {"cve_id": cve_id, "benchmark": BENCHMARK, "status": "error", "error": repr(e), "traceback": tb, "duration_s": round(time.monotonic() - t0, 1)}
    finally:
        if episode is not None:
            await asyncio.to_thread(bench.teardown, episode)


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await aggregate(cve_id, model, timeout, verbose, RESULTS_DIR, SOURCES)


if __name__ == "__main__":
    aggregator_main(RESULTS_DIR, run_one, "The Lesson Aggregator on one VulnLoc+ CVE")
