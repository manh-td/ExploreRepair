import json
import os
import sys
import tempfile

from openai_codex import ApprovalMode, Codex, CodexConfig, Sandbox
from src.agentcore.config import DEFAULT_MODEL

REASONING_EFFORT = "medium"

DISABLED_FEATURES = [
    "shell_tool", "unified_exec", "apps", "plugins", "browser_use", "browser_use_external",
    "computer_use", "image_generation", "multi_agent", "view_image", "skill_search",
    "tool_suggest", "memories", "goals", "shell_snapshot", "in_app_browser",
    "multi_agent_v2", "sleep_tool",
]

TASK_SUFFIX = """

You have a `bash` tool that runs commands directly inside the checked-out repository - it's
already your current working directory, no other tools are available, so use bash the way you
would in a real shell (cat, ls, grep, sed, your own editor invocations, etc.).

Your edits to the working tree are the deliverable. Do not print a diff and stop - change the files.
"""


def _config_overrides(container_name: str, cwd: str) -> tuple[str, ...]:
    mcp_args = ["-B", "-m", "src.experiments.codex.utils.bash_mcp", "--container", container_name, "--cwd", cwd]
    return (
        *(f"features.{name}=false" for name in DISABLED_FEATURES),
        "include_apply_patch_tool=false",
        'web_search="disabled"',
        f"mcp_servers.patcheval.command={json.dumps(sys.executable)}",
        f"mcp_servers.patcheval.args={json.dumps(mcp_args)}",
        f"mcp_servers.patcheval.cwd={json.dumps(os.getcwd())}",
        "mcp_servers.patcheval.tool_timeout_sec=900",
        'mcp_servers.patcheval.default_tools_approval_mode="approve"',
    )


def _item_to_dict(item) -> dict:
    return item.model_dump(mode="json", by_alias=True) if hasattr(item, "model_dump") else {"repr": repr(item)}


def _provider_overrides(model: str) -> tuple[str, ...]:
    if "/" not in model:
        return ()
    return (
        'model_provider="openrouter"',
        'model_providers.openrouter.name="OpenRouter"',
        'model_providers.openrouter.base_url="https://openrouter.ai/api/v1"',
        'model_providers.openrouter.env_key="OPENROUTER_API_KEY"',
        'model_providers.openrouter.wire_api="responses"',
        'model_providers.openrouter.requires_openai_auth=false',
        'model_providers.openrouter.supports_websockets=false',
    )


def run_episode(task: str, container_name: str, cwd: str, model: str = DEFAULT_MODEL,
                effort: str = REASONING_EFFORT) -> dict:
    with tempfile.TemporaryDirectory(prefix="codex_home_") as home, tempfile.TemporaryDirectory(prefix="codex_cwd_") as host_cwd:
        overrides = _config_overrides(container_name, cwd) + _provider_overrides(model)
        config = CodexConfig(config_overrides=overrides, env={**os.environ, "CODEX_HOME": home})
        with Codex(config) as codex:
            if not _provider_overrides(model):
                codex.login_api_key(os.environ["OPENAI_API_KEY"])
            thread = codex.thread_start(
                model=model, cwd=host_cwd, ephemeral=True, approval_mode=ApprovalMode.deny_all,
                sandbox=Sandbox.read_only,
            )
            result = thread.run(task, effort=effort)
    items = [_item_to_dict(item) for item in result.items]
    usage = result.usage.total.model_dump() if result.usage else {}
    return {
        "status": str(result.status.value if hasattr(result.status, "value") else result.status),
        "error": _item_to_dict(result.error) if result.error else None,
        "final_response": result.final_response,
        "duration_ms": result.duration_ms,
        "tool_calls": sum(1 for i in items if i.get("type") == "mcpToolCall"),
        "usage": usage,
        "items": items,
    }


if __name__ == "__main__":
    import argparse

    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser(description="Run one Codex SDK episode in a container")
    parser.add_argument("--container", required=True, help="name of an already-running container")
    parser.add_argument("--cwd", default="/workspace", help="working directory inside the container")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--task", required=True)
    args = parser.parse_args()

    episode = run_episode(args.task + TASK_SUFFIX, args.container, args.cwd, args.model)
    for item in episode["items"]:
        print(json.dumps(item, default=str)[:400])
    print(json.dumps({k: v for k, v in episode.items() if k != "items"}, indent=2, default=str))
