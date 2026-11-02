import asyncio
import json
import random
import time
from pathlib import Path

from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.harnesses.attempts import MAX_DIFF_CHARS, _clip, collect
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "patch-aggregator")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]
SOURCE_DIRS = [results_dir("patcheval", name) for name in ("structural", "semantic", "executable")]


def attempts(cve_id: str, source_dirs: list[Path]) -> list[dict]:
    return [{"source": a["source"], "diff": a["diff"]} for a in collect(cve_id, source_dirs)]


def render(cve_id: str, found: list[dict]) -> str:
    if not found:
        return ""
    ordered = list(found)
    random.Random(cve_id).shuffle(ordered)
    blocks = []
    for index, item in enumerate(ordered, start=1):
        parts = [f"### Attempt {index}"]
        parts.append(f"The change they made:\n```diff\n{_clip(item['diff'], MAX_DIFF_CHARS)}\n```")
        blocks.append("\n\n".join(parts))
    return (
        "\n\n# Earlier attempts at this vulnerability\n\n"
        f"{len(ordered)} engineers have already worked on this, independently and without seeing each other's "
        "work. Below is the change each of them made.\n\n"
        "None of them has been checked. Some may be correct, some partly correct, and possibly none - so do not "
        "assume the answer is in here, and do not pick one and submit it. Use them as evidence: where they "
        "converge, where they disagree, and what one addressed that the others missed. Where two attempts each "
        "address a different part of the problem, the fix may need both. Reach your own conclusion from the "
        "code itself; your patch is what gets graded.\n\n" + "\n\n".join(blocks) + "\n"
    )


async def aggregate(cve_id: str, model: str, timeout: float, verbose: bool, results: Path, source_dirs: list[Path]) -> dict:
    t0 = time.monotonic()
    found = await asyncio.to_thread(attempts, cve_id, source_dirs)
    if not found:
        return {"cve_id": cve_id, "status": "error",
                "error": f"no recorded attempts in {[d.name for d in source_dirs]}",
                "duration_s": round(time.monotonic() - t0, 1)}
    (results / cve_id).mkdir(parents=True, exist_ok=True)
    (results / cve_id / "attempts.json").write_text(json.dumps({"attempts": found}, indent=2))
    block = render(cve_id, found).strip()
    print(f"[{cve_id}] {len(found)} attempts ({len(block)} chars)", flush=True)

    result = await run_guided_agent(cve_id, model, timeout - (time.monotonic() - t0), verbose, results, block)
    return {**result, "n_attempts": len(found), "attempt_sources": [item["source"] for item in found], "block_chars": len(block), "duration_s": round(time.monotonic() - t0, 1)}


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await aggregate(cve_id, model, timeout, verbose, RESULTS_DIR, SOURCE_DIRS)


if __name__ == "__main__":
    main(RESULTS_DIR, "", run_one, "The Patch Aggregator over the three exploration agents' patches, on one CVE")
