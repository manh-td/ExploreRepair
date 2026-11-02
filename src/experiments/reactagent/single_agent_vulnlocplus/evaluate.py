from src.experiments.reactagent.single_agent_vulnlocplus.run_single import PATCHES_PATH, RESULTS_DIR
from src.experiments.reactagent.shared.vulnlocplus import evaluate_main

NAME = "single-agent"

if __name__ == "__main__":
    evaluate_main(RESULTS_DIR, PATCHES_PATH, NAME)
