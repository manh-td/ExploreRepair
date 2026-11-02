from src.experiments.reactagent.shared.vulnlocplus import AGENT_TIMEOUT_S, graph_tools_for, guided_main, results_dir, run_guided_agent
from src.experiments.reactagent.structural.run_single import GUIDANCE

RESULTS_DIR = results_dir("structural")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_TIMEOUT_S = AGENT_TIMEOUT_S
DEFAULT_CVE_IDS = ["CVE-2016-1838"]


async def run_one(cve_id: str, model: str, timeout: float, device: str | None = None,
                  verbose: bool = False) -> dict:
    return await run_guided_agent(cve_id, model, timeout, verbose, RESULTS_DIR, GUIDANCE,
                                  lambda cve: graph_tools_for(cve, device))


if __name__ == "__main__":
    guided_main(RESULTS_DIR, GUIDANCE, run_one, "The Code Knowledge Graph agent on one VulnLoc+ CVE")
