import json
from collections.abc import Sequence
from pathlib import Path

from src.agentcore.agent import Session
from src.agentcore.config import CONTEXT_LIMIT_TOKENS, DEFAULT_MODEL, SYSTEM_PROMPT
from src.harnesses.budget import (
    AGENT_OBSERVATION_LIMIT_CHARS,
    AGENT_STEP_LIMIT,
    BASH_COMMAND_TIMEOUT_S,
)

TASK_SUFFIX = """

You have a real bash shell, already inside the checked-out repository. Use it directly (cat, ls,
grep, sed, your own editor invocations). Do not `pip install`, `git clone`, or otherwise fetch a
separate copy of the target repo: that copy isn't the one being graded, and every command spent on
it is a step burned from your budget for nothing.

Your edits to the working tree are the deliverable. Do not print a diff and stop - change the files.
"""


def build_session(container_name: str, repo_dirname: str, model: str, verbose: bool = False,
                  extra_tools: Sequence[tuple[dict, object]] = (),
                  model_kwargs: dict | None = None) -> Session:
    return Session(
        cwd=f"/workspace/{repo_dirname}",
        container=container_name,
        model=model,
        max_steps=AGENT_STEP_LIMIT,
        context_limit=CONTEXT_LIMIT_TOKENS,
        system_prompt=SYSTEM_PROMPT,
        verbose=verbose,
        tool_context={
            "timeout": BASH_COMMAND_TIMEOUT_S,
            "output_limit": AGENT_OBSERVATION_LIMIT_CHARS,
        },
        extra_tools=extra_tools,
        model_kwargs=model_kwargs,
    )


def run_turn(session: Session, task: str, timeout: float) -> dict:
    opening = session.turns == 0
    turn = session.send(task + TASK_SUFFIX if opening else task, wall_time_s=timeout)
    return _report(turn)


def run_episode(cve_id: str, task: str, container_name: str, repo_dirname: str, model: str,
                output_dir: Path, timeout: float, verbose: bool = False,
                extra_tools: Sequence[tuple[dict, object]] = (),
                model_kwargs: dict | None = None) -> dict:
    session = build_session(container_name, repo_dirname, model, verbose, extra_tools, model_kwargs)
    episode = session.send(task + TASK_SUFFIX, wall_time_s=timeout)

    traj_path = output_dir / f"{cve_id}.traj.json"
    traj_path.parent.mkdir(parents=True, exist_ok=True)
    traj_path.write_text(json.dumps(episode, indent=2, default=str))

    return {**_report(episode), "traj_path": str(traj_path)}


def tool_call_counts(messages: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for message in messages:
        if message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            name = (call.get("function") or {}).get("name", "")
            counts[name] = counts.get(name, 0) + 1
    return counts


def _report(episode: dict) -> dict:
    usage = episode["usage"]
    return {
        "returncode": 0 if episode["status"] == "done" else 1,
        "agent_status": episode["status"],
        "steps": episode["steps"],
        "model_stats": {
            "instance_cost": usage["cost"],
            "tokens_sent": usage["prompt_tokens"],
            "tokens_received": usage["completion_tokens"],
            "api_calls": usage["api_calls"],
            "retries": usage["retries"],
        },
        "summaries": len(episode["summaries"]),
        "messages": episode["messages"],
        "stdout_tail": (episode["output"] or "")[-2000:],
        "stderr_tail": episode["error"],
    }


if __name__ == "__main__":
    import argparse

    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser(description="Run one agentcore episode in a container")
    parser.add_argument("--container", required=True, help="name of an already-running container")
    parser.add_argument("--repo-dir", required=True, help="repo directory name under /workspace")
    parser.add_argument("--task", required=True)
    parser.add_argument("--cve", default="demo", help="label used for the trajectory filename")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--output-dir", type=Path, default=Path("workspace/reactagent-agent-demo"))
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--quiet", action="store_true", help="don't echo each step")
    args = parser.parse_args()

    episode = run_episode(args.cve, args.task, args.container, args.repo_dir, args.model,
                          args.output_dir, args.timeout, verbose=not args.quiet)
    print(json.dumps({k: v for k, v in episode.items() if k != "messages"}, indent=2))
