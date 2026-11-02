import os
import re

TOOLS_PACKAGE = "src.agentcore.tools"

DEFAULT_MODEL = os.environ.get("AGENTCORE_MODEL", os.environ.get("MODEL", "gpt-5.6-luna"))
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
REQUEST_TIMEOUT_S = 120.0

MODEL_KWARGS = {"reasoning_effort": "none"}
NON_REASONING_MODELS = ("gpt-4o",)

PRICING = {
    "gpt-5.6-luna": (0.2, 1.2),
    "gpt-4o-mini": (0.15, 0.6),
    "qwen/qwen3.7-plus": (0.32, 1.28),
    "deepseek/deepseek-v4.1-flash": (0.04, 1.0),
}

MAX_ATTEMPTS = 6
RETRY_BASE_DELAY_S = 2.0
RETRY_MAX_DELAY_S = 60.0

CONTEXT_ERROR = re.compile(
    r"context[_ ]length|maximum context|too many tokens|reduce the length|prompt is too long",
    re.IGNORECASE,
)

MAX_STEPS = 50
WALL_TIME_LIMIT_S = 3600.0
MAX_TOTAL_TOKENS = 0
MAX_COST_USD = 0.0

MAX_NUDGES = 3
NUDGE_PROMPT = """You replied without calling a tool. You have {steps_left} steps and about \
{minutes_left} minutes left. If the task is not finished, keep working with the tools. If it is \
finished, reply once more with no tool calls to end the episode."""

CONTEXT_LIMIT_TOKENS = 120_000
KEEP_RECENT_STEPS = 3
STUB_CHARS = 400
CHARS_PER_TOKEN = 4
ELISION_PREFIX = "[compacted:"

SUMMARIZE_ON_DROP = True
SUMMARY_MODEL = ""
SUMMARY_MAX_CHARS = 1200
SUMMARY_ID_PREFIX = "sum_"
SUMMARY_PROMPT = """Summarise this portion of an agent's working transcript for its own future \
reference. Keep, in this order: what it was trying to establish, what the commands actually showed \
(file paths, symbol names, error text, exit codes), and anything still unresolved. Drop pleasantries \
and repeated output. Write at most {max_chars} characters of plain prose, no headings."""

OUTPUT_LIMIT_CHARS = 30_000
HEAD_SHARE = 0.6
COMMAND_TIMEOUT_S = 600
KILL_GRACE_S = 5
DOCKER_CLIENT_SLACK_S = 15
TIMEOUT_EXIT_CODE = 124

CVE_IMAGE = "ghcr.io/anonymous2578-data/{slug}:latest"
CONTAINER_WORKDIR = "/workspace"

ARGS_PREVIEW_CHARS = 200
OBSERVATION_PREVIEW_CHARS = 300
OBSERVATION_INDENT = " " * 7

SYSTEM_PROMPT = """You are an autonomous engineering agent working in a real shell.

Work in a Thought - Action - Observation loop. Each turn: write the Thought as one or two
sentences, then call the tools. Their output is the Observation you see next turn.

The Thought is where you plan, not where you narrate. Use it to say what you now believe, what
that changes about your plan, and what would show you are wrong.

- Ground every claim in an Observation. Never guess.
- Let Observations correct you: when one contradicts the plan, say so and change the plan.
- An empty, truncated or unhelpful Observation is evidence of nothing. Narrow the command or try another approach rather than building on it.
- Prefer one focused command over a chain of speculative ones.
- Never end a turn without completing the task.
- Reply with no tool calls only once the task is done. That ends the episode for good.
"""


if __name__ == "__main__":
    import json

    groups = {
        "tools": ["TOOLS_PACKAGE"],
        "provider": ["DEFAULT_MODEL", "OPENROUTER_BASE_URL", "REQUEST_TIMEOUT_S", "MODEL_KWARGS"],
        "retry": ["MAX_ATTEMPTS", "RETRY_BASE_DELAY_S", "RETRY_MAX_DELAY_S"],
        "episode caps": ["MAX_STEPS", "WALL_TIME_LIMIT_S", "MAX_TOTAL_TOKENS", "MAX_COST_USD"],
        "nudges": ["MAX_NUDGES", "NUDGE_PROMPT"],
        "compaction": ["CONTEXT_LIMIT_TOKENS", "KEEP_RECENT_STEPS", "STUB_CHARS", "CHARS_PER_TOKEN"],
        "summaries": ["SUMMARIZE_ON_DROP", "SUMMARY_MODEL", "SUMMARY_MAX_CHARS", "SUMMARY_ID_PREFIX"],
        "bash tool": ["OUTPUT_LIMIT_CHARS", "HEAD_SHARE", "COMMAND_TIMEOUT_S", "KILL_GRACE_S", "DOCKER_CLIENT_SLACK_S", "TIMEOUT_EXIT_CODE"],
        "containers": ["CVE_IMAGE", "CONTAINER_WORKDIR"],
        "logging": ["ARGS_PREVIEW_CHARS", "OBSERVATION_PREVIEW_CHARS"],
    }
    for group, names in groups.items():
        print(f"\n--- {group} ---")
        for name in names:
            print(f"  {name:24} {json.dumps(globals()[name], default=str)}")

    print(f"\n--- SYSTEM_PROMPT ({len(SYSTEM_PROMPT)} chars, ~{len(SYSTEM_PROMPT) // CHARS_PER_TOKEN} tokens) ---")
    print(SYSTEM_PROMPT)
