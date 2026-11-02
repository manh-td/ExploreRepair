import time


def budget_status(step: int, started: float, usage: dict, max_steps: int, wall_time_s: float,
                  max_tokens: int, max_cost: float) -> str:
    if step > max_steps:
        return "step_limit"
    if time.monotonic() - started >= wall_time_s:
        return "time_limit"
    if max_tokens and usage["prompt_tokens"] + usage["completion_tokens"] >= max_tokens:
        return "token_limit"
    if max_cost and usage["cost"] >= max_cost:
        return "cost_limit"
    return ""


if __name__ == "__main__":
    now = time.monotonic()
    empty = {"prompt_tokens": 0, "completion_tokens": 0, "cost": 0.0}
    for label, args in [
        ("nothing reached", (1, now, empty, 50, 3600.0, 0, 0.0)),
        ("step limit", (51, now, empty, 50, 3600.0, 0, 0.0)),
        ("wall clock", (1, now - 4000, empty, 50, 3600.0, 0, 0.0)),
        ("token cap", (1, now, {**empty, "prompt_tokens": 999}, 50, 3600.0, 500, 0.0)),
        ("cost cap", (1, now, {**empty, "cost": 1.5}, 50, 3600.0, 0, 1.0)),
        ("caps of 0 are disabled", (1, now, {**empty, "prompt_tokens": 10**9, "cost": 999.0}, 50, 3600.0, 0, 0.0)),
    ]:
        print(f"  {label:24} -> {budget_status(*args) or '(keep going)'}")
