from src.evaluation.evaluate_batch import main
from src.experiments.reactagent.direct_lessons_patches.run_single import PATCHES_PATH, RESULTS_DIR

NAME = "direct-lessons-patches"


if __name__ == "__main__":
    main(results_dir=RESULTS_DIR, patches_path=PATCHES_PATH, name=NAME)
