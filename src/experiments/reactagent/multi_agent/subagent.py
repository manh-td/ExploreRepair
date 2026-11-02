import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from src.agentcore.config import DEFAULT_MODEL
from src.experiments.reactagent.agent import build_session
from src.experiments.reactagent.shared.arm import MODEL_KWARGS
from src.harnesses.attempts import _clip
from src.harnesses.cve_task import _env_hint, _network_hint

MAX_SUBAGENTS = 5
SUBAGENT_WALL_S = 1800.0
MIN_SUBAGENT_S = 120.0
REPORT_CHARS = 6000
SUBAGENT_DIR = "subagents"

SPAWN_SCHEMA = {
    "type": "function",
    "function": {
        "name": "spawn_subagent",
        "description": (
            "Hand a task to a fresh engineer agent and get back its final report. The sub-agent works in "
            "this same repository checkout with the same tools you have, so the files it edits stay "
            "edited. It knows nothing except the prompt you write: it has not seen your task, the "
            "vulnerable location, or anything you or an earlier sub-agent found. It runs to completion "
            "before you continue, and it cannot start sub-agents of its own."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "The whole task for the sub-agent: the goal, the files and lines "
                                   "involved, what is already known, and what to report back.",
                },
            },
            "required": ["prompt"],
        },
    },
}


def subagent_suffix(record: dict) -> str:
    return (
        "\n\nYou are in a real bash shell, already inside the checked-out repository. The lead engineer "
        "who wrote the task above shares this working tree with you, so any file you change stays "
        "changed. Do not run git commit, reset, checkout or stash."
        f"{_env_hint(record)}{_network_hint()}"
        "\n\nWhen you are done, reply with no tool calls and a report for the lead: what you found, "
        "citing file:line, what you changed, and what you left unchecked. Only that final message "
        "reaches them."
    )


def closing_report(messages: list[dict]) -> str:
    replies = []
    for message in reversed(messages):
        if message.get("role") != "assistant":
            continue
        if message.get("tool_calls"):
            break
        if (message.get("content") or "").strip():
            replies.append(message["content"].strip())
    return "\n\n".join(reversed(replies))


@dataclass
class Subagents:
    cve_id: str
    container: str
    dirname: str
    model: str
    run_dir: Path
    deadline: float
    suffix: str
    tools: Sequence[tuple[dict, object]] = ()
    verbose: bool = False
    calls: list[dict] = field(default_factory=list)
    refusals: int = 0

    def _refusal(self) -> str | None:
        if len(self.calls) >= MAX_SUBAGENTS:
            return f"REFUSED: all {MAX_SUBAGENTS} sub-agents are used up. Finish the task yourself."
        if self.deadline - time.monotonic() < MIN_SUBAGENT_S:
            return "REFUSED: the run is almost out of time. Finish the task yourself now."
        return None

    def spawn(self, prompt: str) -> str:
        refusal = self._refusal()
        if refusal:
            self.refusals += 1
            return refusal
        n = len(self.calls) + 1
        if self.verbose:
            print(f"\n>>> [{self.cve_id}] sub-agent {n}: {prompt[:300]}", flush=True)

        t0 = time.monotonic()
        session = build_session(self.container, self.dirname, self.model, self.verbose, self.tools, MODEL_KWARGS)
        episode = session.send(prompt + self.suffix,
                               wall_time_s=min(SUBAGENT_WALL_S, self.deadline - time.monotonic()))

        traj_path = self.run_dir / SUBAGENT_DIR / f"{n:02d}.traj.json"
        traj_path.parent.mkdir(parents=True, exist_ok=True)
        traj_path.write_text(json.dumps({"prompt": prompt, **episode}, indent=2, default=str))
        usage = episode["usage"]
        report = closing_report(episode["messages"])
        self.calls.append({
            "n": n, "status": episode["status"], "steps": episode["steps"],
            "elapsed_s": round(time.monotonic() - t0, 1), "prompt_chars": len(prompt),
            "report_chars": len(report), "error": episode["error"] or None,
            "cost": usage["cost"], "tokens_sent": usage["prompt_tokens"],
            "tokens_received": usage["completion_tokens"], "api_calls": usage["api_calls"],
            "retries": usage["retries"], "traj_path": str(traj_path),
        })
        if self.verbose:
            print(f"<<< [{self.cve_id}] sub-agent {n}: {episode['status']} in {episode['steps']} steps", flush=True)

        report = (report or episode["error"]
                  or "(no final report - it stopped before writing one; check `git diff` for what it changed)")
        return (f"[sub-agent {n} of at most {MAX_SUBAGENTS} finished: {episode['status']} after "
                f"{episode['steps']} steps]\n{_clip(report, REPORT_CHARS)}")

    def tool(self) -> tuple[dict, object]:
        def spawn_subagent(prompt: str) -> str:
            return self.spawn(prompt)

        return SPAWN_SCHEMA, spawn_subagent

    def usage(self) -> dict:
        return {key: sum(call[key] or 0 for call in self.calls)
                for key in ("cost", "tokens_sent", "tokens_received", "api_calls", "retries", "steps")}


if __name__ == "__main__":
    import argparse

    from dotenv import load_dotenv

    from src.harnesses.dataset import load_cve_record

    load_dotenv()
    parser = argparse.ArgumentParser(description="Show the spawn_subagent tool, or run one sub-agent in a container")
    parser.add_argument("--cve", default="CVE-2025-27154")
    parser.add_argument("--container", default="", help="name of an already-running container")
    parser.add_argument("--repo-dir", default="", help="repo directory name under /workspace")
    parser.add_argument("--prompt", default="Say which file holds this project's version number, and stop.")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--results-dir", type=Path, default=Path("workspace/multi-agent-demo"))
    args = parser.parse_args()

    suffix = subagent_suffix(load_cve_record(args.cve))
    if not args.container:
        print(json.dumps(SPAWN_SCHEMA, indent=2))
        print(f"\n--- a sub-agent is sent the lead's prompt followed by ---{suffix}")
        print(f"\n--- limits: {MAX_SUBAGENTS} sub-agents, {SUBAGENT_WALL_S:.0f}s each ---")
        raise SystemExit(0)

    team = Subagents(args.cve, args.container, args.repo_dir, args.model, args.results_dir / args.cve,
                     time.monotonic() + SUBAGENT_WALL_S, suffix, verbose=True)
    print("\n" + team.spawn(args.prompt))
    print(json.dumps(team.calls, indent=2))
