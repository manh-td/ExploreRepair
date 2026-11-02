from __future__ import annotations

import typing as t

from src.benchmarks.base import Episode
from src.benchmarks.vulnlocplus import container as vulnlocplus_container
from src.benchmarks.vulnlocplus.evaluate import grade
from src.benchmarks.vulnlocplus.images import image_for
from src.benchmarks.vulnlocplus.loading import load_record
from src.benchmarks.vulnlocplus.locations import locations, working_set
from src.benchmarks.vulnlocplus.task import build_task
from src.harnesses.docker import StagedDiffs


class VulnlocplusBenchmark:

    name = "vulnlocplus"

    def cve_ids(self) -> list[str]:
        return working_set()

    def load_record(self, cve_id: str) -> dict:
        return load_record(cve_id)

    def locations(self, cve_id: str) -> list[dict]:
        return locations(cve_id)

    def image_for(self, cve_id: str) -> str:
        return image_for(cve_id)

    def start(self, cve_id: str) -> Episode:
        episode = vulnlocplus_container.start(cve_id)
        return Episode(cve_id=cve_id, container=episode.container, repo_dir=episode.repo_dirname,
                       image=episode.image, extra={"vulnlocplus": episode})

    def sanitize(self, episode: Episode) -> None:
        vulnlocplus_container.sanitize(episode.extra["vulnlocplus"])

    def task_prompt(self, record: dict, **flags: t.Any) -> str:
        return build_task(record["cve_id"], **flags)

    def extract_patch(self, episode: Episode, base_sha: str | None = None) -> StagedDiffs:
        return vulnlocplus_container.extract_patch(episode.extra["vulnlocplus"], base_sha)

    def teardown(self, episode: Episode) -> None:
        vulnlocplus_container.teardown(episode.extra["vulnlocplus"])

    def evaluate(self, cve_id: str, patch: str, name: str = "patch") -> dict:
        return grade(cve_id, patch, name)


if __name__ == "__main__":
    import json

    from src.benchmarks.base import Benchmark
    from src.benchmarks.registry import get_benchmark

    bench = get_benchmark("vulnlocplus")
    sample = bench.cve_ids()[0]
    print(json.dumps({
        "name": bench.name,
        "cve_ids": len(bench.cve_ids()),
        "sample": sample,
        "image_for": bench.image_for(sample),
        "locations": bench.locations(sample),
        "prompt_chars": len(bench.task_prompt(bench.load_record(sample))),
        "isinstance_Benchmark": isinstance(bench, Benchmark),
    }, indent=2))
