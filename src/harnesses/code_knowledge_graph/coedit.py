import subprocess
from collections import Counter
from itertools import combinations
from pathlib import Path

GIT_TIMEOUT_S = 900
MAX_COMMITS = 5000
MAX_FILES_PER_COMMIT = 30
MIN_WEIGHT = 2


def _log(repo: Path, sha: str, max_commits: int) -> str:
    result = subprocess.run(
        ["git", "log", sha, "--first-parent", "--no-merges", "--name-only",
         f"--max-count={max_commits}", "--pretty=format:%x00", "--"],
        cwd=repo, capture_output=True, text=True, timeout=GIT_TIMEOUT_S,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git log {sha} failed: {result.stderr.strip()[-300:]}")
    return result.stdout


def co_edit_edges(
    repo: Path,
    sha: str,
    paths: set[str],
    max_commits: int = MAX_COMMITS,
    max_files_per_commit: int = MAX_FILES_PER_COMMIT,
    min_weight: int = MIN_WEIGHT,
) -> tuple[list[dict], dict]:
    counts: Counter = Counter()
    commits = 0
    skipped = 0
    for chunk in _log(Path(repo), sha, max_commits).split("\0"):
        touched = {line.strip() for line in chunk.splitlines() if line.strip()}
        touched &= paths
        if len(touched) < 2:
            continue
        commits += 1
        if len(touched) > max_files_per_commit:
            skipped += 1
            continue
        counts.update(combinations(sorted(touched), 2))

    edges = [
        {"source": f"file:{a}", "target": f"file:{b}", "kind": "co_edit", "weight": weight}
        for (a, b), weight in sorted(counts.items())
        if weight >= min_weight
    ]
    return edges, {
        "co_edit_commits": commits,
        "co_edit_skipped_commits": skipped,
        "co_edit_pairs_seen": len(counts),
    }


def add_co_edit(graph: dict, repo: Path, sha: str, **kwargs) -> dict:
    paths = {node["path"] for node in graph["nodes"] if node["kind"] == "file"}
    edges, stats = co_edit_edges(repo, sha, paths, **kwargs)
    graph["edges"] += edges
    graph["stats"].update(stats)
    graph["stats"]["co_edit_edges"] = len(edges)
    return graph
