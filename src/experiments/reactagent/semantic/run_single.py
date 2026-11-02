from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.experiments.reactagent.shared.intent_questions import CITE_NOTE, STAGES
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "semantic")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]


def _question(prompt: str) -> str:
    cuts = [i for i in (prompt.find(f"\n{CITE_NOTE}"), prompt.find("\n{CITE_NOTE}")) if i != -1]
    return prompt[:min(cuts)].strip() if cuts else prompt.strip()

GUIDANCE = (
    "Before you edit anything, work out what this code is meant to do. Answer the parts below in "
    "order, each building on the ones before it, citing file:line for what you read; say plainly "
    "where you could not establish something rather than filling the gap. Only then make the fix, "
    "and make it restore the rules you found.\n\n"
    + "\n\n".join(_question(stage.prompt) for stage in STAGES)
)

async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await run_guided_agent(cve_id, model, timeout, verbose, RESULTS_DIR, GUIDANCE)

if __name__ == "__main__":
    main(RESULTS_DIR, GUIDANCE, run_one, "The Intent agent (semantic evidence) on one CVE")
