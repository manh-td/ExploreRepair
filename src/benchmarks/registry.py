from __future__ import annotations

import argparse
import os
import typing as t

from src.benchmarks.base import Benchmark

DEFAULT = "patcheval"


def _patcheval(**kwargs: t.Any) -> Benchmark:
    from src.benchmarks.patcheval.adapter import PatchEvalBenchmark
    return PatchEvalBenchmark(**kwargs)


def _vulnlocplus(**kwargs: t.Any) -> Benchmark:
    from src.benchmarks.vulnlocplus.adapter import VulnlocplusBenchmark
    return VulnlocplusBenchmark(**kwargs)


BENCHMARKS = {"patcheval": _patcheval, "vulnlocplus": _vulnlocplus}


def list_benchmarks() -> list[str]:
    return sorted(BENCHMARKS)


def get_benchmark(name: str | None = None, **kwargs: t.Any) -> Benchmark:
    name = name or os.environ.get("BENCHMARK") or DEFAULT
    try:
        return BENCHMARKS[name](**kwargs)
    except KeyError:
        raise ValueError(f"unknown benchmark {name!r}; known: {', '.join(list_benchmarks())}") from None


def add_benchmark_arg(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--benchmark", default=os.environ.get("BENCHMARK", DEFAULT),
                        choices=list_benchmarks(),
                        help=f"which benchmark to run against (default {DEFAULT})")
    return parser


if __name__ == "__main__":
    for name in list_benchmarks():
        try:
            bench = get_benchmark(name)
            print(f"{name:12s} ok    {len(bench.cve_ids())} CVEs")
        except Exception as exc:
            print(f"{name:12s} ERROR {exc!r}")
