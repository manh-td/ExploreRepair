from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "single-agent")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]
GUIDANCE = ""


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await run_guided_agent(cve_id, model, timeout, verbose, RESULTS_DIR, GUIDANCE)


if __name__ == "__main__":
    main(RESULTS_DIR, GUIDANCE, run_one, "The Single Agent baseline on one CVE")
