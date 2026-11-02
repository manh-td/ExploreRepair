import re

from src.agentcore.config import (
    CHARS_PER_TOKEN,
    CONTEXT_LIMIT_TOKENS,
    ELISION_PREFIX,
    KEEP_RECENT_STEPS,
    STUB_CHARS,
)
from src.agentcore.utils.summary import summarise


def estimate_tokens(messages: list) -> int:
    total = 0
    for message in messages:
        total += len(message.get("content") or "")
        for call in message.get("tool_calls") or []:
            total += len(str(call.get("function", {})))
    return total // CHARS_PER_TOKEN


def fits(messages: list, limit: int = CONTEXT_LIMIT_TOKENS) -> bool:
    return estimate_tokens(messages) <= limit


def _steps(messages: list) -> list[list[int]]:
    groups: list[list[int]] = []
    for i, message in enumerate(messages):
        if message.get("role") == "assistant":
            groups.append([i])
        elif message.get("role") == "tool" and groups:
            groups[-1].append(i)
    return groups


def _is_note(message: dict) -> bool:
    return message.get("role") == "system" and str(message.get("content", "")).startswith(ELISION_PREFIX)


def compact(messages: list, limit: int = CONTEXT_LIMIT_TOKENS, keep_recent: int = KEEP_RECENT_STEPS,
            store=None, client=None, model: str = "") -> tuple[list, bool]:
    if fits(messages, limit):
        return messages, False

    working = [dict(m) for m in messages]
    changed = False

    def stub(index: int) -> bool:
        content = working[index].get("content") or ""
        if len(content) <= STUB_CHARS:
            return False
        working[index]["content"] = f"{content[:STUB_CHARS]}\n[... {len(content) - STUB_CHARS} characters elided ...]"
        return True

    groups = _steps(working)
    for group in groups[: max(0, len(groups) - keep_recent)]:
        for index in group[1:]:
            changed |= stub(index)
        if fits(working, limit):
            return working, changed

    dropped, removed = 0, []
    for message in working:
        if _is_note(message):
            found = re.search(r"\d+", message["content"])
            dropped += int(found.group()) if found else 0
    while not fits(working, limit):
        groups = _steps(working)
        if len(groups) <= keep_recent:
            break
        oldest = [working[i] for i in groups[0]]
        for index in sorted(groups[0], reverse=True):
            working.pop(index)
        removed.extend(oldest)
        dropped += 1
        changed = True

    if not fits(working, limit):
        for index, message in enumerate(working):
            if message.get("role") == "tool":
                changed |= stub(index)

    if dropped:
        previous = [m["content"] for m in working if _is_note(m)]
        working = [m for m in working if not _is_note(m)]
        body = f"{dropped} earlier step(s) dropped to fit the context window."

        if removed and store is not None and client is not None:
            text = summarise(removed, client, model)
            if text:
                summary_id = store.add(removed, text)
                body += f" Summary {summary_id}: {text}"
        earlier = [i for note in previous for i in re.findall(r"sum_\d+", note)]
        if earlier:
            body += f" Earlier summaries: {', '.join(dict.fromkeys(earlier))}."
        body += " Call expand_summary(summary_id) for the originals, or re-run a tool."

        note = {"role": "system", "content": f"{ELISION_PREFIX} {body}]"}
        first_step = next((i for i, m in enumerate(working) if m.get("role") == "assistant"), len(working))
        working.insert(first_step, note)
    return working, changed


if __name__ == "__main__":
    history = [
        {"role": "system", "content": "You are an autonomous engineering agent."},
        {"role": "user", "content": "Find and fix the vulnerability."},
    ]
    for n in range(1, 41):
        history.append({
            "role": "assistant",
            "content": f"Step {n}: I will inspect the next candidate file.",
            "tool_calls": [{"id": f"call_{n}", "type": "function", "function": {"name": "bash", "arguments": f'{{"command": "cat file_{n}.py"}}'}}],
        })
        history.append({"role": "tool", "tool_call_id": f"call_{n}", "content": f"line of output {n}\n" * 400})

    def check(messages: list) -> str:
        open_ids, orphans = set(), []
        for message in messages:
            for call in message.get("tool_calls") or []:
                open_ids.add(call["id"])
            if message.get("role") == "tool" and message["tool_call_id"] not in open_ids:
                orphans.append(message["tool_call_id"])
        return f"ORPHANED tool messages: {orphans}" if orphans else "every tool_call_id is paired"

    print(f"--- fits() is the criterion compact() works to ---")
    for limit in (200_000, 72_000, 10_000):
        print(f"    fits(history, {limit:>7}) -> {fits(history, limit)}")

    print(f"\n--- before: {len(history)} messages, ~{estimate_tokens(history)} tokens ---")
    print(f"    {check(history)}")

    for limit in (60_000, 20_000, 4_000, 800):
        compacted, changed = compact(history, limit)
        note = next((m["content"] for m in compacted if _is_note(m)), "(none)")
        print(f"\n--- limit {limit:>6} -> ~{estimate_tokens(compacted):>6} tokens, "
              f"{len(compacted):>3} messages, {len(_steps(compacted)):>2} steps kept, changed={changed} ---")
        print(f"    {check(compacted)}")
        print(f"    fits: {fits(compacted, limit)}")
        print(f"    note: {note}")

    print("\n--- the original list is never mutated in place ---")
    print(f"    still {len(history)} messages, ~{estimate_tokens(history)} tokens")

    print("\n--- the newest steps survive, the oldest are stubbed then dropped ---")
    for message in compact(history, 4_000)[0]:
        if message.get("role") == "tool":
            print(f"    {message['tool_call_id']:>9}: {len(message['content']):>6} chars")
