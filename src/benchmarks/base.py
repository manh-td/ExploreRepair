from __future__ import annotations

import typing as t
from dataclasses import dataclass, field

from src.harnesses.docker import StagedDiffs

RESULT_VOCABULARY = ("Repair Success", "validation_fail", "compilation_fail", "apply_fail")


@dataclass
class Episode:
    cve_id: str
    container: str
    repo_dir: str
    image: str = ""
    extra: dict = field(default_factory=dict)


@t.runtime_checkable
class Benchmark(t.Protocol):

    name: str

    def cve_ids(self) -> list[str]:
        pass

    def load_record(self, cve_id: str) -> dict:
        pass

    def locations(self, cve_id: str) -> list[dict]:
        pass

    def image_for(self, cve_id: str) -> str:
        ...

    def start(self, cve_id: str) -> Episode:
        pass

    def sanitize(self, episode: Episode) -> None:
        pass

    def task_prompt(self, record: dict, **flags: t.Any) -> str:
        pass

    def extract_patch(self, episode: Episode) -> StagedDiffs:
        ...

    def teardown(self, episode: Episode) -> None:
        ...

    def evaluate(self, cve_id: str, patch: str, name: str = "patch") -> dict:
        pass


class UnsupportedFlag(ValueError):
    pass


if __name__ == "__main__":
    from src.benchmarks.registry import get_benchmark, list_benchmarks

    print(f"registered: {', '.join(list_benchmarks())}\n")
    for name in list_benchmarks():
        bench = get_benchmark(name)
        cve_ids = bench.cve_ids()
        sample = cve_ids[0]
        locations = bench.locations(sample)
        print(f"{name}:")
        print(f"  cve_ids()        {len(cve_ids)} CVEs, first {sample}")
        print(f"  image_for()      {bench.image_for(sample)}")
        print(f"  locations()      {len(locations)} entr(y/ies)")
        if locations:
            first = locations[0]
            keys = sorted(first)
            print(f"    keys           {keys}")
            print(f"    first          {first['file_path']}:{first['start_line']}-{first['end_line']}")
            assert {"file_path", "start_line", "end_line"} <= set(keys), name
        print(f"  task_prompt()    {len(bench.task_prompt(bench.load_record(sample)))} chars")
        print(f"  isinstance(Benchmark) {isinstance(bench, Benchmark)}")
        print()
