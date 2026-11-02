import json
import time
from collections.abc import Sequence

from src.agentcore.config import (
    ARGS_PREVIEW_CHARS,
    CONTEXT_ERROR,
    CONTEXT_LIMIT_TOKENS,
    CONTAINER_WORKDIR,
    CVE_IMAGE,
    DEFAULT_MODEL,
    MAX_COST_USD,
    MAX_NUDGES,
    MAX_STEPS,
    MAX_TOTAL_TOKENS,
    MODEL_KWARGS,
    NUDGE_PROMPT,
    OBSERVATION_INDENT,
    OBSERVATION_PREVIEW_CHARS,
    SUMMARIZE_ON_DROP,
    SUMMARY_MODEL,
    SYSTEM_PROMPT,
    WALL_TIME_LIMIT_S,
)
from src.agentcore.utils.budget import budget_status
from src.agentcore.utils.compact import compact, estimate_tokens
from src.agentcore.utils.dispatch import discover, dispatch
from src.agentcore.utils.llm import BadRequestError, build_client, complete, price
from src.agentcore.utils.summary import SummaryStore

class Session:
    def __init__(self, cwd: str = ".", container: str = "", model: str = DEFAULT_MODEL,
                 max_steps: int = MAX_STEPS, wall_time_s: float = WALL_TIME_LIMIT_S,
                 max_tokens: int = MAX_TOTAL_TOKENS, max_cost: float = MAX_COST_USD,
                 context_limit: int = CONTEXT_LIMIT_TOKENS,
                 system_prompt: str = SYSTEM_PROMPT, verbose: bool = True,
                 tool_context: dict | None = None,
                 extra_tools: Sequence[tuple[dict, object]] = (),
                 model_kwargs: dict | None = None,
                 default_tools: Sequence[str] | None = None):
        self.client = build_client()
        self.tools = discover()
        if default_tools is not None:
            self.tools = {name: tool for name, tool in self.tools.items() if name in default_tools}
        for schema, fn in extra_tools:
            self.tools[schema["function"]["name"]] = (schema, fn)
        self.summaries = SummaryStore()
        self.context = {"cwd": cwd, "container": container, "summaries": self.summaries,
                        **(tool_context or {})}
        self.model = model
        self.max_steps = max_steps
        self.wall_time_s = wall_time_s
        self.max_tokens = max_tokens
        self.max_cost = max_cost
        self.context_limit = context_limit
        self.verbose = verbose
        self.kwargs = dict(MODEL_KWARGS if model_kwargs is None else model_kwargs)
        self.messages = [{"role": "system", "content": system_prompt}]
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "cost": 0.0, "api_calls": 0,
                      "retries": 0}
        self.turns = 0

    def send(self, task: str, wall_time_s: float | None = None,
             max_steps: int | None = None) -> dict:
        self.turns += 1
        self.messages.append({"role": "user", "content": task})
        return self._loop(
            max_steps if max_steps is not None else self.max_steps,
            wall_time_s if wall_time_s is not None else self.wall_time_s,
        )

    def _loop(self, max_steps: int, wall_time_s: float) -> dict:
        client, tools, summaries = self.client, self.tools, self.summaries
        schemas = [schema for schema, _ in tools.values()]
        context, kwargs, model = self.context, self.kwargs, self.model
        messages, usage = self.messages, self.usage
        context_limit, verbose = self.context_limit, self.verbose
        max_tokens, max_cost = self.max_tokens, self.max_cost
        started = time.monotonic()
        status, output, error, step = "", "", "", 0
        nudges, nudges_in_row = 0, 0

        while True:
            step += 1
            status = budget_status(step, started, usage, max_steps, wall_time_s, max_tokens, max_cost)
            if status:
                step -= 1
                break

            messages, compacted = compact(messages, context_limit, store=summaries,
                                          client=client if SUMMARIZE_ON_DROP else None,
                                          model=SUMMARY_MODEL or model)
            if compacted and verbose:
                print(f"    [compacted history to ~{estimate_tokens(messages)} tokens]", flush=True)

            try:
                response = complete(client, model, messages, schemas, kwargs, usage, verbose)
            except BadRequestError as e:
                if not CONTEXT_ERROR.search(str(e)):
                    status, error, step = "error", repr(e), step - 1
                    break
                messages, _ = compact(messages, context_limit // 2, keep_recent=1, store=summaries,
                                      client=client if SUMMARIZE_ON_DROP else None,
                                      model=SUMMARY_MODEL or model)
                if verbose:
                    print(f"    [context rejected, compacted to ~{estimate_tokens(messages)} tokens]", flush=True)
                try:
                    response = complete(client, model, messages, schemas, kwargs, usage, verbose)
                except Exception as e2:
                    status, error, step = "error", repr(e2), step - 1
                    break
            except Exception as e:
                status, error, step = "error", repr(e), step - 1
                break

            if response.usage:
                sent = response.usage.prompt_tokens or 0
                received = response.usage.completion_tokens or 0
                usage["prompt_tokens"] += sent
                usage["completion_tokens"] += received
                reported = float(getattr(response.usage, "cost", 0.0) or 0.0)
                usage["cost"] += reported or price(model, sent, received)
            usage["api_calls"] += 1

            message = response.choices[0].message
            calls = message.tool_calls or []
            reasoning = getattr(message, "reasoning_items", None)
            messages.append({
                "role": "assistant",
                "content": message.content or "",
                **({"tool_calls": [{"id": c.id, "type": "function", "function": {"name": c.function.name, "arguments": c.function.arguments}} for c in calls]} if calls else {}),
                **({"reasoning_items": reasoning} if reasoning else {}),
            })
            if verbose and message.content:
                print(f"\n[{step}] {message.content.strip()}", flush=True)

            if not calls:
                content = (message.content or "").strip()
                if (content and nudges_in_row) or nudges_in_row >= MAX_NUDGES or step >= max_steps:
                    status, output = "done", content
                    break
                nudges, nudges_in_row = nudges + 1, nudges_in_row + 1
                minutes_left = max(0, int((wall_time_s - (time.monotonic() - started)) // 60))
                messages.append({"role": "user", "content": NUDGE_PROMPT.format(
                    steps_left=max_steps - step, minutes_left=minutes_left)})
                if verbose:
                    print(f"    [no tool call, nudged {nudges_in_row}/{MAX_NUDGES}]", flush=True)
                continue
            nudges_in_row = 0

            for call in calls:
                if verbose:
                    print(f"    -> {call.function.name}({call.function.arguments[:ARGS_PREVIEW_CHARS]})", flush=True)
                observation = dispatch(tools, call.function.name, call.function.arguments, context)
                if verbose:
                    preview = observation[:OBSERVATION_PREVIEW_CHARS].replace("\n", "\n" + OBSERVATION_INDENT)
                    print(f"{OBSERVATION_INDENT}{preview}", flush=True)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": observation})

        self.messages = messages
        return {
            "status": status,
            "output": output,
            "error": error,
            "steps": step,
            "nudges": nudges,
            "elapsed_s": round(time.monotonic() - started, 1),
            "usage": dict(usage),
            "summaries": {i: summaries.text(i) for i in summaries.ids()},
            "messages": messages,
        }


def run(task: str, cwd: str = ".", container: str = "", model: str = DEFAULT_MODEL,
        max_steps: int = MAX_STEPS, wall_time_s: float = WALL_TIME_LIMIT_S,
        max_tokens: int = MAX_TOTAL_TOKENS, max_cost: float = MAX_COST_USD,
        context_limit: int = CONTEXT_LIMIT_TOKENS,
        system_prompt: str = SYSTEM_PROMPT, verbose: bool = True,
        tool_context: dict | None = None,
        extra_tools: Sequence[tuple[dict, object]] = ()) -> dict:
    session = Session(cwd, container, model, max_steps, wall_time_s, max_tokens, max_cost,
                      context_limit, system_prompt, verbose, tool_context, extra_tools)
    return session.send(task)


if __name__ == "__main__":
    import argparse
    import subprocess

    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser(description="Run one agent episode")
    parser.add_argument("--task", default="What is this repository for? Answer in two sentences.")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--cwd", default="",
                        help=f"working directory (default: . locally, {CONTAINER_WORKDIR} in a container)")
    parser.add_argument("--cve", default="", help="spin up this CVE's container and work inside it")
    parser.add_argument("--steps", type=int, default=MAX_STEPS)
    parser.add_argument("--timeout", type=float, default=WALL_TIME_LIMIT_S, help="wall-clock cap in seconds")
    parser.add_argument("--max-tokens", type=int, default=MAX_TOTAL_TOKENS, help="0 disables")
    parser.add_argument("--max-cost", type=float, default=MAX_COST_USD, help="USD; 0 disables, OpenRouter only")
    parser.add_argument("--context-tokens", type=int, default=CONTEXT_LIMIT_TOKENS, help="compact the history once it exceeds this")
    parser.add_argument("--output", default="", help="write the full episode here as JSON")
    parser.add_argument("--demo-compaction", action="store_true", help="compact a synthetic history and check the tool-call pairing invariant")
    parser.add_argument("--selftest", action="store_true", help="exercise the retry path against a stub provider, no API calls")
    args = parser.parse_args()

    container = ""
    if args.cve:
        slug = args.cve.lower()
        image = CVE_IMAGE.format(slug=slug)
        container = f"{slug}_agentcore_demo"
        if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
            raise SystemExit(f"image not pulled locally: {image}\nrun: bash scripts/download/patcheval_images.sh")
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        subprocess.run(["docker", "run", "-d", "--name", container, "--network", "none", image, "sleep", "infinity"], check=True, capture_output=True)
        print(f"started {container}")

    try:
        cwd = args.cwd or (CONTAINER_WORKDIR if container else ".")
        episode = run(args.task, cwd=cwd, container=container, model=args.model, max_steps=args.steps,
                      wall_time_s=args.timeout, max_tokens=args.max_tokens, max_cost=args.max_cost,
                      context_limit=args.context_tokens)
    finally:
        if container:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
            print(f"\nremoved {container}")

    print(f"\n=== {episode['status']} in {episode['steps']} steps / {episode['elapsed_s']}s ===")
    if episode["error"]:
        print(episode["error"])
    print(json.dumps(episode["usage"]))
    print(f"\n{episode['output']}")
    if args.output:
        with open(args.output, "w") as f:
            json.dump(episode, f, indent=2, default=str)
