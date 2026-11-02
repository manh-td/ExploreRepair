from src.evaluation.evaluate_batch import main
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "intentfix")
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
NAME = "intentfix"

if __name__ == "__main__":
    main(results_dir=RESULTS_DIR, patches_path=PATCHES_PATH, name=NAME)
