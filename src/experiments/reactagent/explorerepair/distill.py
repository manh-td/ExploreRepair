import argparse
import json

from src.agentcore.config import DEFAULT_MODEL
from src.agentcore.utils.llm import build_client
from src.experiments.reactagent.lesson_aggregator.run_single import RESULTS_DIR as LESSON_AGGREGATOR
from src.experiments.reactagent.patch_aggregator.run_single import RESULTS_DIR as PATCH_AGGREGATOR
from src.experiments.reactagent.shared.distill import COMMON, distill_attempt
from src.harnesses.attempts import collect

ROLES = {
    LESSON_AGGREGATOR.name: (
        "three earlier engineers' written lessons - one on code structure, one on developer intent, one on "
        "running a proof of concept - but none of the changes they made",
        "a SYNTHESIS lesson",
        "Begin with \"Weighing three earlier engineers' lessons, the agent learned that ...\". Cover which of "
        "their conclusions it adopted and which it rejected, and why; what it checked in the code itself; and "
        "why it changed what it did.",
    ),
    PATCH_AGGREGATOR.name: (
        "three earlier engineers' changes, but none of their reasoning",
        "a SYNTHESIS lesson",
        "Begin with \"Weighing three earlier engineers' changes, the agent learned that ...\". Cover where the "
        "changes agreed and differed, which it built on and which it rejected, and why; what it checked in the "
        "code itself; and why it changed what it did.",
    ),
}


def lessons(cve_id: str, model: str) -> tuple[list[dict], dict]:
    usage = {"cost": 0.0, "prompt_tokens": 0, "completion_tokens": 0, "api_calls": 0, "retries": 0}
    client = build_client()
    out = []
    for attempt in collect(cve_id, [LESSON_AGGREGATOR, PATCH_AGGREGATOR]):
        lesson = distill_attempt(cve_id, attempt, attempt["source"], model, client, usage, roles=ROLES)
        out.append({"source": attempt["source"], "kind": ROLES[attempt["source"]][1], "lesson": lesson,
                    "diff": attempt["diff"]})
    return out, usage


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Print the final Aggregator's two input lessons for one CVE")
    parser.add_argument("--cve", default="CVE-2025-27154")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--prompts", action="store_true")
    args = parser.parse_args()
    if args.prompts:
        for source, (context, kind, instruction) in ROLES.items():
            print("=" * 100 + f"\n{source}  (context: {context})\n" + "=" * 100)
            print(f"{COMMON}\n\nFrom this attempt, write {kind}. {instruction}\n")
        raise SystemExit(0)
    found, usage = lessons(args.cve, args.model)
    for item in found:
        print(f"--- {item['source']}\n{item['lesson']}\n")
    print(json.dumps(usage, indent=2))
