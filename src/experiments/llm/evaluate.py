from src.evaluation.evaluate_batch import main
from src.experiments.llm.run_single import RESULTS_DIR, PATCHES_PATH

NAME = "llm"


if __name__ == "__main__":
    main(results_dir=RESULTS_DIR, patches_path=PATCHES_PATH, name=NAME)
