import json
import os
import re

from src.agentcore.config import DEFAULT_MODEL
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def _extract_json_array(text: str) -> list | None:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _openai_usage(response) -> dict:
    usage = response.usage
    if usage is None:
        return {}
    return {
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens,
    }


def _anthropic_usage(response) -> dict:
    usage = response.usage
    if usage is None:
        return {}
    return {
        "prompt_tokens": usage.input_tokens,
        "completion_tokens": usage.output_tokens,
        "total_tokens": usage.input_tokens + usage.output_tokens,
    }


def _chat_completion_with_temperature_fallback(client, **kwargs):
    try:
        return client.chat.completions.create(**kwargs, temperature=1)
    except Exception as e:
        if "temperature" not in str(e).lower():
            raise
        return client.chat.completions.create(**kwargs)


def generate_patches(
    model: str, system_prompt: str, user_prompt: str, max_tokens: int = 8000
) -> tuple[dict[str, str], dict]:
    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    if openrouter_key:
        from openai import OpenAI

        client = OpenAI(api_key=openrouter_key, base_url=OPENROUTER_BASE_URL)
        response = _chat_completion_with_temperature_fallback(
            client,
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = response.choices[0].message.content
        usage = _openai_usage(response)
    elif model.startswith("claude"):
        import anthropic

        client = anthropic.Anthropic()
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=1,
        )
        content = response.content[0].text
        usage = _anthropic_usage(response)
    else:
        from openai import OpenAI

        client = OpenAI()
        response = _chat_completion_with_temperature_fallback(
            client,
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = response.choices[0].message.content
        usage = _openai_usage(response)

    items = _extract_json_array(content or "")
    if not items:
        return {}, usage
    patches = {item["id"]: item["patch"] for item in items if isinstance(item, dict) and "id" in item and "patch" in item}
    return patches, usage


if __name__ == "__main__":
    import argparse

    from dotenv import load_dotenv

    from src.harnesses.dataset import load_cve_record
    from src.experiments.llm.utils.prompts import SYSTEM_PROMPT, build_user_prompt

    load_dotenv()
    parser = argparse.ArgumentParser(description="Ask the model for one CVE's patched functions")
    parser.add_argument("--cve", default="CVE-2025-27154")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    patches, usage = generate_patches(args.model, SYSTEM_PROMPT, build_user_prompt(load_cve_record(args.cve)))
    print(json.dumps({"usage": usage, "patched_ids": list(patches)}, indent=2))
    for fid, code in patches.items():
        print(f"\n### {fid}\n{code}")
