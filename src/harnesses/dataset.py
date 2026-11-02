import json
from functools import lru_cache
from pathlib import Path

DATASET_PATH = Path("benchmarks/PatchEval/patcheval/datasets/input.json")
ALL_PATCHEVAL_CVES_PATH = Path("resources/patcheval.cves.txt")
ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH = Path("resources/patcheval.cves.with-unit-test.txt")


@lru_cache(maxsize=1)
def _dataset_index() -> dict[str, dict]:
    return {item["cve_id"]: item for item in json.loads(DATASET_PATH.read_text())}


def load_cve_record(cve_id: str) -> dict:
    try:
        return _dataset_index()[cve_id]
    except KeyError:
        raise ValueError(f"{cve_id} not found in {DATASET_PATH}") from None


def repo_dirname(repo_url: str) -> str:
    return repo_url.rstrip("/").rsplit("/", 1)[-1]
