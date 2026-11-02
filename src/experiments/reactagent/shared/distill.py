import argparse
import json
from pathlib import Path

from src.agentcore.utils.llm import build_client, complete, price
from src.experiments.reactagent.shared.arm import MODEL_KWARGS
from src.harnesses.attempts import _clip, collect
from src.harnesses.dataset import load_cve_record

MAX_REASONING_CHARS = 8000
MAX_DIFF_CHARS = 6000
MAX_LESSON_WORDS = 250

LESSON_TOOL = {
    "type": "function",
    "function": {
        "name": "record_lesson",
        "description": "Record the lesson. Only this text reaches the final engineer.",
        "parameters": {"type": "object", "properties": {"lesson": {"type": "string"}}, "required": ["lesson"]},
    },
}

COMMON = f"""You turn one engineer's attempt at repairing a security vulnerability into a short lesson for \
the engineer who will write the final fix. You are shown what that engineer was asked to focus on, the \
location hint they were given, their step-by-step reasoning, and the change they made.

Nobody has checked whether their change is correct. Do not say it is right or wrong, and do not say it \
fixed anything - say what they concluded and what they did.

Write at most {MAX_LESSON_WORDS} words, and call record_lesson with it. Name files, functions and lines. \
Quote at most a line or two of code; do not reproduce the diff. End with what they changed, and what they \
left uncertain or never checked."""

ROLES = {
    "structure": (
        "a static code graph of the repository, and an instruction to analyse the vulnerability's structural "
        "context before editing",
        "a STRUCTURE lesson",
        "Begin with \"From the code structure, the agent learned that ...\". Cover the path from entry point to "
        "the vulnerable code, the callers and callees that matter, sibling code paths that share the flaw or "
        "guard it differently, and where in that structure the fix has to sit.",
    ),
    "intent": (
        "an instruction to establish what the code is meant to do - its contract, who reaches it with what "
        "trust, what it acts on, the rules it should keep - before editing",
        "a DEVELOPER-INTENT lesson",
        "Begin with \"From the developers' intent in this codebase, the agent learned that ...\". Cover what "
        "the code is meant to do and what governs it, which party is untrusted and what it controls, the "
        "conventions sibling code follows, and the specific rule the vulnerable code breaks.",
    ),
    "execution": (
        "an instruction to analyse the vulnerability, prove it with a proof-of-concept test it ran, and only "
        "then fix it",
        "an EXECUTION lesson",
        "Begin with \"From running the code, the agent learned that ...\". Cover how the vulnerability was "
        "triggered - entry point and input - what the PoC showed when it ran before and after the fix, and "
        "which behaviour was observed as opposed to only assumed.",
    ),
}


def _hint_text(cve_id: str) -> str:
    hint = load_cve_record(cve_id).get("vul_func") or []
    return (", ".join(f"{h['file_path']} lines {h['start_line']}-{h['end_line']}" for h in hint)
            or "no location was given")


def distill_attempt(cve_id: str, attempt: dict, role: str, model: str, client, usage: dict,
                    hint_text=_hint_text, roles: dict = ROLES) -> str:
    context, kind, instruction = roles[role]
    reasoning = "\n".join(f"- {step}" for step in attempt["reasoning"])
    brief = (
        f"What the engineer was asked to focus on: {context}.\n"
        f"Location hint they were given: {hint_text(cve_id)}.\n\n"
        f"Their reasoning, step by step:\n{_clip(reasoning, MAX_REASONING_CHARS)}\n\n"
        + (f"What they said when they stopped:\n{attempt['closing']}\n\n" if attempt["closing"] else "")
        + f"The change they made:\n```diff\n{_clip(attempt['diff'], MAX_DIFF_CHARS)}\n```"
    )
    messages = [{"role": "system", "content": f"{COMMON}\n\nFrom this attempt, write {kind}. {instruction}"},
                {"role": "user", "content": brief}]
    response = complete(client, model, messages, [LESSON_TOOL], dict(MODEL_KWARGS), usage, verbose=False)
    usage["api_calls"] += 1
    if response.usage is not None:
        usage["prompt_tokens"] += response.usage.prompt_tokens
        usage["completion_tokens"] += response.usage.completion_tokens
        usage["cost"] += price(model, response.usage.prompt_tokens, response.usage.completion_tokens)
    message = response.choices[0].message
    for call in message.tool_calls or []:
        if call.function.name == "record_lesson":
            return (json.loads(call.function.arguments or "{}").get("lesson") or "").strip()
    return (message.content or "").strip()


def lessons(cve_id: str, model: str, sources: dict[Path, str],
            hint_text=_hint_text) -> tuple[list[dict], dict]:
    usage = {"cost": 0.0, "prompt_tokens": 0, "completion_tokens": 0, "api_calls": 0, "retries": 0}
    client = build_client()
    out = []
    role_of = {d.name: role for d, role in sources.items()}
    for attempt in collect(cve_id, list(sources)):
        role = role_of[attempt["source"]]
        lesson = distill_attempt(cve_id, attempt, role, model, client, usage, hint_text)
        if lesson:
            out.append({"source": attempt["source"], "kind": ROLES[role][1], "lesson": lesson})
    return out, usage


def render(found: list[dict]) -> str:
    if not found:
        return ""
    body = "\n\n".join(f"### Lesson {i}\n{item['lesson']}" for i, item in enumerate(found, start=1))
    return (
        "\n\n# What earlier attempts learned\n\n"
        f"{len(found)} engineers worked on this independently, each with different context. What each of "
        "them learned is summarised below.\n\n"
        "None of their changes has been checked. Some may be right, some partly right, and possibly none - so "
        "do not assume the answer is in here. Use the lessons as evidence: where they agree on the vulnerable "
        "code and its intent, where they disagree, and what one noticed that the others missed. Reach your "
        f"own conclusion from the code itself; your patch is what gets graded.\n\n{body}\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Print the lesson-distillation system prompt for each exploration agent")
    parser.parse_args()
    for role, (context, kind, instruction) in ROLES.items():
        print("=" * 100 + f"\n{role}  (context: {context})\n" + "=" * 100)
        print(f"{COMMON}\n\nFrom this attempt, write {kind}. {instruction}\n")
