import json
import os
from pathlib import Path
import sys
import time


def install() -> None:
    import litellm
    import minisweagent.environments as environments
    from minisweagent.agents.enhanced import EnhancedAgent
    from minisweagent.agents.default import LimitsExceeded
    from minisweagent.models.litellm_tool_model import LitellmToolModel
    from minisweagent.tools.base import ToolManager
    from src.harnesses.docker import sanitize_container
    from src.agentcore.config import PRICING

    litellm.register_model({
        f"openrouter/{name}": {
            "input_cost_per_token": rates[0] / 1e6,
            "output_cost_per_token": rates[1] / 1e6,
            "litellm_provider": "openrouter", "mode": "chat", "supports_reasoning": True,
        }
        for name, rates in PRICING.items() if "/" in name
    })

    original_environment = environments.get_environment
    original_query = EnhancedAgent.query
    original_model_query = LitellmToolModel._query
    original_schemas = ToolManager.get_all_schemas

    def schemas(self):
        result = original_schemas(self)
        for schema in result:
            function = schema.get("function", {})
            if function.get("strict"):
                function.setdefault("parameters", {}).setdefault("additionalProperties", False)
        return result

    def model_query(self, messages, **kwargs):
        response = original_model_query(self, messages, **kwargs)
        if len(response.choices) > 1:
            first = response.choices[0]
            calls = [call for choice in response.choices for call in (choice.message.tool_calls or [])]
            first.message.content = "\n".join(c.message.content for c in response.choices if c.message.content)
            if calls:
                first.message.tool_calls = calls
                first.finish_reason = "tool_calls"
            response.choices = [first]
        return response

    def query(self):
        if time.monotonic() >= getattr(self.env, "_explorerepair_deadline", float("inf")):
            raise LimitsExceeded("ExploreRepair per-CVE wall-time budget exhausted")
        return original_query(self)

    def environment(config, *, default_type=""):
        if config.get("environment_class", default_type) != "docker":
            return original_environment(config, default_type=default_type)
        config = dict(config)
        config["run_args"] = ["--rm", "--network", "none"]
        env = original_environment(config, default_type=default_type)
        try:
            if not env.container_id:
                raise RuntimeError("EvoRepair did not provide a container to sanitize")
            sanitize_container(env.container_id)
        except BaseException:
            env.cleanup()
            raise
        instance = str(config["image"]).rsplit("/", 1)[-1].split(":", 1)[0].upper()
        output = Path(os.environ["EXPLOREREPAIR_EVOREPAIR_OUTPUT"])
        budget_path = output / "budgets" / f"{instance}.json"
        used = json.loads(budget_path.read_text())["duration_s"] if budget_path.exists() else 0.0
        started = time.monotonic()
        env._explorerepair_deadline = started + max(0, float(os.environ["EXPLOREREPAIR_EVOREPAIR_BUDGET"]) - used)
        original_cleanup = env.cleanup
        original_execute = env.execute
        recorded = False

        def execute(command, cwd="", *, timeout=None):
            remaining = env._explorerepair_deadline - time.monotonic()
            if remaining <= 0:
                raise LimitsExceeded("ExploreRepair per-CVE wall-time budget exhausted")
            return original_execute(command, cwd, timeout=max(1, min(timeout or env.config.timeout, int(remaining))))

        def cleanup():
            nonlocal recorded
            try:
                if not recorded:
                    duration = used + time.monotonic() - started
                    budget_path.parent.mkdir(parents=True, exist_ok=True)
                    budget_path.write_text(json.dumps({"duration_s": duration}))
                    recorded = True
            finally:
                original_cleanup()

        env.execute = execute
        env.cleanup = cleanup
        return env

    ToolManager.get_all_schemas = schemas
    LitellmToolModel._query = model_query
    EnhancedAgent.query = query
    environments.get_environment = environment


if os.environ.get("EXPLOREREPAIR_EVOREPAIR") == "1":
    try:
        install()
    except BaseException as error:
        print(f"Cannot install EvoRepair restrictions: {type(error).__name__}: {error}", file=sys.stderr)
        os._exit(1)
