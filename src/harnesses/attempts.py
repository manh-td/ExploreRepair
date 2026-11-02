import json
import re
from pathlib import Path

MAX_DIFF_CHARS = 8000
MIN_THOUGHT_CHARS = 40


def _patches(results_dir: Path) -> dict[str, str]:
    path = results_dir / "patches.jsonl"
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            out[row["cve"]] = row.get("fix_patch") or ""
    return out


_PATCH_CACHE: dict[str, dict[str, str]] = {}

def _patch_for(results_dir: Path, cve_id: str) -> str:
    key = str(results_dir)
    if key not in _PATCH_CACHE:
        _PATCH_CACHE[key] = _patches(results_dir)
    return _PATCH_CACHE[key].get(cve_id, "")


def _trajectory(results_dir: Path, cve_id: str) -> dict | None:
    path = results_dir / cve_id / "reactagent_run" / f"{cve_id}.traj.json"
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _reasoning(trajectory: dict) -> list[str]:
    steps = []
    for message in trajectory.get("messages") or []:
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if not isinstance(content, str):
            continue
        text = re.sub(r"^Thought:\s*", "", content.strip())
        if len(text) >= MIN_THOUGHT_CHARS:
            steps.append(text)
    return steps


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


def collect(cve_id: str, source_dirs: list[Path]) -> list[dict]:
    attempts = []
    for results_dir in source_dirs:
        trajectory = _trajectory(results_dir, cve_id)
        diff = _patch_for(results_dir, cve_id)
        if trajectory is None or not diff.strip():
            continue
        reasoning = _reasoning(trajectory)
        closing = (trajectory.get("output") or "").strip()
        if reasoning and closing and (closing in reasoning[-1] or reasoning[-1] in closing):
            closing = ""
        attempts.append({
            "source": results_dir.name,
            "reasoning": reasoning,
            "diff": diff,
            "closing": closing,
            "steps": trajectory.get("steps"),
        })
    return attempts


if __name__ == "__main__":
    import argparse

    from src.harnesses.results import results_dir

    parser = argparse.ArgumentParser(description="Show the recorded exploration attempts for one CVE")
    parser.add_argument("--cve", default="CVE-2022-24825")
    args = parser.parse_args()

    found = collect(args.cve, [results_dir("patcheval", name) for name in ("structural", "semantic", "executable")])
    print(f"{len(found)} attempts")
    for a in found:
        print(f"  {a['source']:12} {len(a['reasoning']):2d} reasoning steps, {len(a['diff']):6d} diff chars")
