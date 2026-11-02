import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from src.benchmarks.vulnlocplus.images import image_for, leaks, repo_dirname, repo_path
from src.harnesses.docker import (StagedDiffs, _diff_of_paths, _staged_paths, is_test_path, is_vendored_path,
                                  start_editable_container)

C_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"})


class LeakDetected(AssertionError):
    pass


@dataclass
class VulnlocplusEpisode:
    cve_id: str
    container: str
    repo_dirname: str
    image: str


def start(cve_id: str, name_suffix: str = "editable") -> VulnlocplusEpisode:
    image = image_for(cve_id)
    container = start_editable_container(cve_id, image, name_suffix, network="none")
    return VulnlocplusEpisode(cve_id=cve_id, container=container, repo_dirname=repo_dirname(cve_id), image=image)


def sanitize(episode: VulnlocplusEpisode) -> None:
    hits = leaks(episode.container, episode.cve_id, scan_filesystem=False)
    if hits:
        raise LeakDetected(f"{episode.cve_id}: {hits}")


def split_c_paths(paths: list[str]) -> tuple[list[str], list[str], list[str]]:
    test = [p for p in paths if is_test_path(p)]
    source = [p for p in paths if p not in test and not is_vendored_path(p)
              and Path(p).suffix.lower() in C_SOURCE_SUFFIXES]
    kept = set(source) | set(test)
    return source, test, [p for p in paths if p not in kept]


def extract_patch(episode: VulnlocplusEpisode, base_sha: str | None = None) -> StagedDiffs:
    source, test, dropped = split_c_paths(_staged_paths(episode.container, episode.repo_dirname, base_sha))
    return StagedDiffs(
        fix_patch=_diff_of_paths(episode.container, episode.repo_dirname, source, base_sha),
        test_patch=_diff_of_paths(episode.container, episode.repo_dirname, test, base_sha),
        dropped_files=dropped,
    )


def teardown(episode: VulnlocplusEpisode) -> None:
    subprocess.run(["docker", "rm", "-f", episode.container], capture_output=True, timeout=60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Start a baked VulnLoc+ episode, verify it is clean, tear it down.")
    parser.add_argument("--cve", required=True)
    args = parser.parse_args()

    episode = start(args.cve)
    try:
        sanitize(episode)
        probe = subprocess.run(["docker", "exec", episode.container, "bash", "-c",
                                f"cd {repo_path(args.cve)} && pwd -P && git log --oneline | head -3 && git status --short | head"],
                               capture_output=True, text=True)
        print(json.dumps({"cve_id": args.cve, "container": episode.container, "image": episode.image,
                          "repo": repo_path(args.cve), "leak_check": "clean",
                          "probe": probe.stdout.splitlines()}, indent=2))
    finally:
        teardown(episode)


if __name__ == "__main__":
    main()
