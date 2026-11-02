import asyncio
import json
import time

from src.experiments.reactagent.direct_lessons_patches.run_single import render
from src.experiments.reactagent.explorerepair import distill
from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "explorerepair")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    t0 = time.monotonic()
    try:
        found, usage = await asyncio.to_thread(distill.lessons, cve_id, model)
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": f"distill: {e!r}",
                "duration_s": round(time.monotonic() - t0, 1)}
    if not found:
        return {"cve_id": cve_id, "status": "error", "error": f"no recorded attempts in {list(distill.ROLES)}",
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
    main(RESULTS_DIR, "", run_one, "The final Aggregator over the Lesson and Patch Aggregators' repairs, on one CVE")
