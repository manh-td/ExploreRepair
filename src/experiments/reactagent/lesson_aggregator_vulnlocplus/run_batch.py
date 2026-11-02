import asyncio

from src.experiments.reactagent.lesson_aggregator_vulnlocplus.run_single import DEFAULT_CVE_IDS, DEFAULT_TIMEOUT_S, PATCHES_PATH, RESULTS_DIR, run_one
from src.experiments.reactagent.shared.vulnlocplus import batch_main

if __name__ == "__main__":
    asyncio.run(batch_main(run_one, RESULTS_DIR, PATCHES_PATH, DEFAULT_TIMEOUT_S, DEFAULT_CVE_IDS))
