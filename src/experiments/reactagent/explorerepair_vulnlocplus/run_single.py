import asyncio
import json
import time

from src.agentcore.utils.llm import build_client
from src.experiments.reactagent.direct_lessons_patches.run_single import render
from src.experiments.reactagent.explorerepair.distill import ROLES
from src.experiments.reactagent.lesson_aggregator_vulnlocplus.run_single import RESULTS_DIR as LESSON_AGGREGATOR
from src.experiments.reactagent.patch_aggregator_vulnlocplus.run_single import RESULTS_DIR as PATCH_AGGREGATOR
from src.experiments.reactagent.shared.distill import distill_attempt
from src.experiments.reactagent.shared.vulnlocplus import AGENT_TIMEOUT_S, aggregator_main, hint_text, results_dir, run_guided_agent
from src.harnesses.attempts import collect

RESULTS_DIR = results_dir("explorerepair")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_TIMEOUT_S = AGENT_TIMEOUT_S
DEFAULT_CVE_IDS = ["CVE-2016-1838"]


def lessons(cve_id: str, model: str) -> tuple[list[dict], dict]:
    usage = {"cost": 0.0, "prompt_tokens": 0, "completion_tokens": 0, "api_calls": 0, "retries": 0}
    client = build_client()
    out = []
    for attempt in collect(cve_id, [LESSON_AGGREGATOR, PATCH_AGGREGATOR]):
        lesson = distill_attempt(cve_id, attempt, attempt["source"], model, client, usage, hint_text, ROLES)
        out.append({"source": attempt["source"], "kind": ROLES[attempt["source"]][1], "lesson": lesson,
                    "diff": attempt["diff"]})
    return out, usage


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    t0 = time.monotonic()
    try:
        found, usage = await asyncio.to_thread(lessons, cve_id, model)
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": f"distill: {e!r}",
                "duration_s": round(time.monotonic() - t0, 1)}
    if not found:
        return {"cve_id": cve_id, "status": "error", "error": f"no recorded attempts in {list(ROLES)}",
                "duration_s": round(time.monotonic() - t0, 1)}
    (RESULTS_DIR / cve_id).mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / cve_id / "lessons.json").write_text(json.dumps({"lessons": found, "usage": usage}, indent=2))
    block = render(cve_id, found).strip()
    print(f"[{cve_id}] {len(found)} lessons and patches ({len(block)} chars, ${usage['cost']:.3f})", flush=True)

    result = await run_guided_agent(cve_id, model, timeout - (time.monotonic() - t0), verbose, RESULTS_DIR, block)
    repair_cost = result.get("instance_cost") or 0
    return {**result, "n_lessons": len(found), "lesson_sources": [item["source"] for item in found],
            "block_chars": len(block), "distill_cost": round(usage["cost"], 6), "repair_cost": repair_cost,
            "instance_cost": repair_cost + usage["cost"], "duration_s": round(time.monotonic() - t0, 1)}


if __name__ == "__main__":
    aggregator_main(RESULTS_DIR, run_one, "The final Aggregator on one VulnLoc+ CVE")
