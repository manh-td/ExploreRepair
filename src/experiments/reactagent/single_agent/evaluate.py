from src.evaluation.evaluate_batch import main
from src.experiments.reactagent.single_agent.run_single import PATCHES_PATH, RESULTS_DIR

NAME = "single-agent"


if __name__ == "__main__":
    main(results_dir=RESULTS_DIR, patches_path=PATCHES_PATH, name=NAME)
