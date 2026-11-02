from src.experiments.reactagent.executable.run_single import GUIDANCE
from src.experiments.reactagent.shared.vulnlocplus import AGENT_TIMEOUT_S, guided_main, results_dir, run_guided_agent

RESULTS_DIR = results_dir("executable")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_TIMEOUT_S = AGENT_TIMEOUT_S
DEFAULT_CVE_IDS = ["CVE-2016-1838"]


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await run_guided_agent(cve_id, model, timeout, verbose, RESULTS_DIR, GUIDANCE)


if __name__ == "__main__":
    guided_main(RESULTS_DIR, GUIDANCE, run_one, "The PoV agent on one VulnLoc+ CVE")
