from __future__ import annotations

import subprocess
import typing as t

from src.benchmarks.base import Benchmark, Episode, UnsupportedFlag
from src.harnesses.cve_task import load_cve_task
from src.harnesses.dataset import (ALL_PATCHEVAL_CVES_PATH,
                                   ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH,
                                   load_cve_record, repo_dirname)
from src.harnesses.docker import (StagedDiffs, get_split_diffs, resolve_repo_dirname,
                                  restore_and_stop, sanitize_container,
                                  start_editable_container)

IMAGE_TEMPLATE = "ghcr.io/anonymous2578-data/{cve_lower}:latest"


class PatchEvalBenchmark:
    name = "patcheval"

    def __init__(self, with_unit_tests: bool = True) -> None:
        self.with_unit_tests = with_unit_tests

    def cve_ids(self) -> list[str]:
        path = (ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH if self.with_unit_tests
                else ALL_PATCHEVAL_CVES_PATH)
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]

    def load_record(self, cve_id: str) -> dict:
        return load_cve_record(cve_id)

    def locations(self, cve_id: str) -> list[dict]:
        return list(self.load_record(cve_id).get("vul_func") or [])

    def image_for(self, cve_id: str) -> str:
        return IMAGE_TEMPLATE.format(cve_lower=cve_id.lower())

    def start(self, cve_id: str) -> Episode:
        image = self.image_for(cve_id)
        container = start_editable_container(cve_id, image, "editable")
        repo_dir = resolve_repo_dirname(container, repo_dirname(self.load_record(cve_id)["repo"]))
        return Episode(cve_id=cve_id, container=container, repo_dir=repo_dir, image=image)

    def sanitize(self, episode: Episode) -> None:
        sanitize_container(episode.container)

    def task_prompt(self, record: dict, **flags: t.Any) -> str:
        kind = flags.pop("kind", "cve")
        if kind != "cve":
            raise UnsupportedFlag(f"unknown task kind for patcheval: {kind!r}")
        return load_cve_task(record, decisive=flags.pop("decisive", False),
                             cve_context=flags.pop("cve_context", False))

    def extract_patch(self, episode: Episode) -> StagedDiffs:
        return get_split_diffs(episode.container, episode.repo_dir)

    def teardown(self, episode: Episode) -> None:
        if episode.repo_dir:
            restore_and_stop(episode.container, episode.repo_dir)
        else:
            subprocess.run(["docker", "rm", "-f", episode.container],
                           capture_output=True, timeout=30)

    def evaluate(self, cve_id: str, patch: str, name: str = "patch") -> dict:
        from src.evaluation.evaluate import evaluate_patch
        return evaluate_patch(cve_id, name, patch)
