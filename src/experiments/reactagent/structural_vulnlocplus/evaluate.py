from src.experiments.reactagent.structural_vulnlocplus.run_single import PATCHES_PATH, RESULTS_DIR
from src.experiments.reactagent.shared.vulnlocplus import evaluate_main

NAME = "structural"

if __name__ == "__main__":
    evaluate_main(RESULTS_DIR, PATCHES_PATH, NAME)
