import json
import random
import time
from pathlib import Path

from src.experiments.reactagent.lesson_aggregator.run_single import RESULTS_DIR as LESSON_AGGREGATOR, SOURCES
from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.harnesses.attempts import MAX_DIFF_CHARS, _clip, collect
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "direct-lessons-patches")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]

EXPLORERS = list(SOURCES)


def render(cve_id: str, attempts: list[dict]) -> str:
    ordered = list(attempts)
    random.Random(cve_id).shuffle(ordered)
    blocks = []
    for index, item in enumerate(ordered, start=1):
        parts = [f"### Attempt {index}"]
        if item.get("lesson"):
            parts.append(f"What they learned:\n{item['lesson']}")
        if item.get("diff"):
            parts.append(f"The change they made:\n```diff\n{_clip(item['diff'], MAX_DIFF_CHARS)}\n```")
        blocks.append("\n\n".join(parts))
    return (
        "\n\n# What earlier attempts learned, and what they changed\n\n"
        f"{len(ordered)} engineers worked on this independently, each with different context. For each, below "
        "is a summary of what they learned and the change they made.\n\n"
        "None of their changes has been checked. Some may be right, some partly right, and possibly none - so do "
        "not assume the answer is in here, and do not pick one and submit it. Use them as evidence: where they "
        "agree on the vulnerable code and its intent, where they disagree, and what one noticed or addressed that "
        "the others missed. Where two attempts each address a different part of the problem, the fix may need "
        "both. Reach your own conclusion from the code itself; your patch is what gets graded.\n\n"
        + "\n\n".join(blocks) + "\n"
    )


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False,
                  results_dir: Path = RESULTS_DIR) -> dict:
    t0 = time.monotonic()
    path = LESSON_AGGREGATOR / cve_id / "lessons.json"
    names = [d.name for d in EXPLORERS]
    lessons = {item["source"]: item["lesson"] for item in json.loads(path.read_text())["lessons"]
               if item["source"] in names} if path.exists() else {}
    diffs = {a["source"]: a["diff"] for a in collect(cve_id, EXPLORERS)}
    attempts = [{"source": s, "lesson": lessons.get(s), "diff": diffs.get(s)} for s in names
                if s in lessons or s in diffs]
    if not attempts:
        return {"cve_id": cve_id, "status": "error", "error": f"no recorded lessons or patches from {names}",
                "duration_s": round(time.monotonic() - t0, 1)}
    (results := results_dir / cve_id).mkdir(parents=True, exist_ok=True)
    (results / "attempts.json").write_text(json.dumps({"attempts": attempts}, indent=2))
    block = render(cve_id, attempts).strip()
    print(f"[{cve_id}] {len(lessons)} lessons, {len(diffs)} patches ({len(block)} chars)", flush=True)

    result = await run_guided_agent(cve_id, model, timeout - (time.monotonic() - t0), verbose, results_dir, block)
    return {**result, "n_lessons": len(lessons), "n_patches": len(diffs),
            "attempt_sources": [a["source"] for a in attempts], "block_chars": len(block),
            "duration_s": round(time.monotonic() - t0, 1)}


if __name__ == "__main__":
    main(RESULTS_DIR, "", run_one, "One agent over the three exploration agents' lessons plus their patches, on one CVE")
