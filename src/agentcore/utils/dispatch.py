import importlib
import inspect
import json
import pkgutil

from src.agentcore.config import TOOLS_PACKAGE


def discover(package: str = TOOLS_PACKAGE) -> dict[str, tuple[dict, object]]:
    module = importlib.import_module(package)
    tools = {}
    for info in pkgutil.iter_modules(module.__path__):
        loaded = importlib.import_module(f"{package}.{info.name}")
        schema = getattr(loaded, "TOOL_SCHEMA", None)
        if schema is None:
            continue
        name = schema["function"]["name"]
        fn = getattr(loaded, name, None)
        if fn is None:
            raise AttributeError(f"{loaded.__name__}.TOOL_SCHEMA names {name!r} but defines no such function")
        tools[name] = (schema, fn)
    return tools


def dispatch(tools: dict, name: str, arguments: str, context: dict) -> str:
    if name not in tools:
        return f"ERROR: unknown tool {name!r}. Available: {', '.join(tools) or '(none)'}"
    schema, fn = tools[name]

    try:
        args = json.loads(arguments or "{}")
    except json.JSONDecodeError as e:
        return f"ERROR: {name}: arguments were not valid JSON: {e}"
    if not isinstance(args, dict):
        return f"ERROR: {name}: arguments must be an object, got {type(args).__name__}"

    declared = set(schema["function"].get("parameters", {}).get("properties", {}))
    args = {k: v for k, v in args.items() if k in declared}
    accepted = inspect.signature(fn).parameters
    args.update({k: v for k, v in context.items() if k in accepted})

    try:
        result = fn(**args)
    except TypeError as e:
        return f"ERROR: invalid arguments for {name}: {str(e).replace(fn.__qualname__, name)}"
    except Exception as e:
        return f"ERROR: {name} failed: {type(e).__name__}: {e}"
    return result if isinstance(result, str) else json.dumps(result, default=str)


if __name__ == "__main__":
    tools = discover()
    print(f"--- discovered {len(tools)} tool(s) in {TOOLS_PACKAGE} ---")
    for name, (schema, _) in tools.items():
        declared = sorted(schema["function"].get("parameters", {}).get("properties", {}))
        print(f"  {name:12} model may pass: {declared}")

    context = {"cwd": ".", "container": ""}
    print("\n--- calls ---")
    for arguments in ['{"command": "echo hi"}', '{"command": "wc -l < .gitignore"}']:
        print(f"  {arguments:34} -> {dispatch(tools, 'bash', arguments, context)!r}")

    print("\n--- never raises: every failure is an observation ---")
    for label, name, arguments in [
        ("unknown tool", "missing", "{}"),
        ("malformed JSON", "bash", "{not json"),
        ("arguments are not an object", "bash", '["echo hi"]'),
        ("missing required argument", "bash", "{}"),
        ("hallucinated argument is dropped", "bash", '{"command": "echo hi", "shell": "zsh"}'),
        ("model cannot redirect its own shell", "bash", '{"command": "pwd", "container": "evil"}'),
        ("the tool's own error text passes through", "bash", '{"command": "ls /nope"}'),
    ]:
        print(f"  {label:38} -> {dispatch(tools, name, arguments, context)!r}")
