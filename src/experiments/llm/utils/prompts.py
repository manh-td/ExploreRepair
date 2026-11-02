LANGUAGE_TAGS = {"Python": "python", "JavaScript": "javascript", "Go": "go"}

SYSTEM_PROMPT = (
    "You are a security engineer. You will be given the exact function(s) that contain a "
    "security vulnerability - no CVE description or CWE is provided, identifying the actual "
    "issue is part of the task. Return complete, corrected replacements for each function."
)


def build_user_prompt(record: dict) -> str:
    lang_tag = LANGUAGE_TAGS.get(record.get("programming_language", ""), "")

    functions_block = "\n\n".join(
        f"### {f['id']}\n"
        f"File: {f['file_path']} (lines {f['start_line']}-{f['end_line']})\n"
        f"```{lang_tag}\n{f['snippet']}\n```"
        for f in record["vul_func"]
    )

    return f"""The function(s) below contain a security vulnerability. Identify it and fix it.

Vulnerable function(s):

{functions_block}

For each function above, return its complete fixed source (not a diff), keeping
the original signature and indentation. Respond with ONLY a JSON array, no other
text, in this exact format:
[
  {{"id": "<function id>", "patch": "<complete fixed function source>"}}
]
"""


if __name__ == "__main__":
    import argparse

    from src.harnesses.dataset import load_cve_record

    parser = argparse.ArgumentParser(description="Show the single-shot prompt for one CVE")
    parser.add_argument("--cve", default="CVE-2025-27154")
    args = parser.parse_args()

    print(SYSTEM_PROMPT)
    print("\n---\n")
    print(build_user_prompt(load_cve_record(args.cve)))
