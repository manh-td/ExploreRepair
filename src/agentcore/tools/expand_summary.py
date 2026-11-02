def expand_summary(summary_id: str, summaries=None) -> str:
    if summaries is None:
        return "ERROR: no summaries exist in this episode"
    return summaries.expand(summary_id)


TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "expand_summary",
        "description": (
            "Retrieve the full original steps behind a summary shown in a [compacted: ...] note. "
            "Use it when the summary is too vague to act on and re-running the commands would be "
            "more expensive than reading what they already returned."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "summary_id": {
                    "type": "string",
                    "description": "The id from the compaction note, e.g. 'sum_1'",
                },
            },
            "required": ["summary_id"],
        },
    },
}
