from src.agentcore.config import (
    SUMMARY_ID_PREFIX,
    SUMMARY_MAX_CHARS,
    SUMMARY_PROMPT,
)


class SummaryStore:
    def __init__(self):
        self._originals: dict[str, list] = {}
        self._texts: dict[str, str] = {}

    def add(self, messages: list, text: str) -> str:
        summary_id = f"{SUMMARY_ID_PREFIX}{len(self._originals) + 1}"
        self._originals[summary_id] = [dict(m) for m in messages]
        self._texts[summary_id] = text
        return summary_id

    def text(self, summary_id: str) -> str:
        return self._texts.get(summary_id, "")

    def ids(self) -> list[str]:
        return list(self._originals)

    def expand(self, summary_id: str) -> str:
        original = self._originals.get(summary_id)
        if original is None:
            return f"ERROR: unknown summary id {summary_id!r}. Available: {', '.join(self._originals) or '(none)'}"
        lines = []
        for message in original:
            role = message.get("role", "?")
            for call in message.get("tool_calls") or []:
                function = call.get("function", {})
                lines.append(f"[{role} called {function.get('name')}({function.get('arguments')})]")
            if message.get("content"):
                lines.append(f"[{role}] {message['content']}")
        return "\n".join(lines) or "(the dropped steps had no content)"


def render(messages: list) -> str:
    lines = []
    for message in messages:
        for call in message.get("tool_calls") or []:
            function = call.get("function", {})
            lines.append(f"{message.get('role')} called {function.get('name')}({function.get('arguments')})")
        if message.get("content"):
            lines.append(f"{message.get('role')}: {message['content']}")
    return "\n".join(lines)


def summarise(messages: list, client, model: str, max_chars: int = SUMMARY_MAX_CHARS) -> str:
    transcript = render(messages)
    if not transcript.strip():
        return ""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SUMMARY_PROMPT.format(max_chars=max_chars)},
                {"role": "user", "content": transcript},
            ],
        )
        return (response.choices[0].message.content or "").strip()[:max_chars]
    except Exception as e:
        return f"(summary unavailable: {type(e).__name__})"


if __name__ == "__main__":
    from dotenv import load_dotenv

    from src.agentcore.config import DEFAULT_MODEL
    from src.agentcore.utils.llm import build_client

    load_dotenv()
    messages = [
        {"role": "assistant", "content": "Looking for the parser entry point.",
         "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "bash", "arguments": '{"command": "ls src"}'}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": "parser.py\nconfig.py\nmain.py"},
    ]

    store = SummaryStore()
    summary_id = store.add(messages, summarise(messages, build_client(), DEFAULT_MODEL))

    print("id:", summary_id)
    print("text:", store.text(summary_id))
    print("expand:")
    print(store.expand(summary_id))
    print(store.ids())
