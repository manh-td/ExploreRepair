import asyncio
import json
import time
from pathlib import Path

from src.experiments.reactagent.shared import distill
from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "lesson-aggregator")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]

SOURCES = {
    results_dir("patcheval", "structural"): "structure",
    results_dir("patcheval", "semantic"): "intent",
    results_dir("patcheval", "executable"): "execution",
}


async def aggregate(cve_id: str, model: str, timeout: float, verbose: bool, results: Path,
                    sources: dict[Path, str]) -> dict:
    t0 = time.monotonic()
    try:
        found, usage = await asyncio.to_thread(distill.lessons, cve_id, model, sources)
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": f"distill: {e!r}",
                "duration_s": round(time.monotonic() - t0, 1)}
    if not found:
        return {"cve_id": cve_id, "status": "error",
                "error": f"no recorded attempts to distil in {[d.name for d in sources]}",
                "duration_s": round(time.monotonic() - t0, 1)}
    (results / cve_id).mkdir(parents=True, exist_ok=True)
    (results / cve_id / "lessons.json").write_text(json.dumps({"lessons": found, "usage": usage}, indent=2))
    block = distill.render(found).strip()
    print(f"[{cve_id}] {len(found)} lessons distilled ({len(block)} chars, ${usage['cost']:.3f})", flush=True)

    result = await run_guided_agent(cve_id, model, timeout - (time.monotonic() - t0), verbose, results, block)
    repair_cost = result.get("instance_cost") or 0
    return {**result, "n_lessons": len(found), "lesson_sources": [item["source"] for item in found],
            "lessons_chars": len(block), "distill_cost": round(usage["cost"], 6), "repair_cost": repair_cost,
            "instance_cost": repair_cost + usage["cost"], "duration_s": round(time.monotonic() - t0, 1)}


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await aggregate(cve_id, model, timeout, verbose, RESULTS_DIR, SOURCES)


if __name__ == "__main__":
    main(RESULTS_DIR, "", run_one, "The Lesson Aggregator over the three exploration agents' lessons, on one CVE")
