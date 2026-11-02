from src.experiments.reactagent.semantic_vulnlocplus.run_single import PATCHES_PATH, RESULTS_DIR
from src.experiments.reactagent.shared.vulnlocplus import evaluate_main

NAME = "semantic"

if __name__ == "__main__":
    evaluate_main(RESULTS_DIR, PATCHES_PATH, NAME)
