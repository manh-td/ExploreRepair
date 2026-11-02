import os
import random
import time
from types import SimpleNamespace

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    BadRequestError,
    InternalServerError,
    OpenAI,
    RateLimitError,
)

from src.agentcore.config import (
    MAX_ATTEMPTS,
    MODEL_KWARGS,
    NON_REASONING_MODELS,
    OPENROUTER_BASE_URL,
    PRICING,
    REQUEST_TIMEOUT_S,
    RETRY_BASE_DELAY_S,
    RETRY_MAX_DELAY_S,
)

PER_MILLION = 1_000_000


def build_client() -> OpenAI:
    if os.environ.get("OPENROUTER_API_KEY"):
        return OpenAI(api_key=os.environ["OPENROUTER_API_KEY"], base_url=OPENROUTER_BASE_URL)
    return OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))


def rates(model: str) -> tuple[float, float]:
    matches = [key for key in PRICING if model.startswith(key)]
    return PRICING[max(matches, key=len)] if matches else (0.0, 0.0)


def price(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    rate_in, rate_out = rates(model)
    return (prompt_tokens * rate_in + completion_tokens * rate_out) / PER_MILLION


class Unusable(RuntimeError):
    pass


def _retry_after(error: Exception) -> float | None:
    headers = getattr(getattr(error, "response", None), "headers", {}) or {}
    try:
        return float(headers.get("retry-after"))
    except (TypeError, ValueError):
        return None


def backoff_delay(attempt: int, retry_after: float | None = None) -> float:
    if retry_after is not None:
        return min(retry_after, RETRY_MAX_DELAY_S)
    return min(RETRY_BASE_DELAY_S * 2**attempt, RETRY_MAX_DELAY_S) * (0.5 + random.random())


def _to_responses_input(messages: list) -> list:
    items = []
    for m in messages:
        if m["role"] == "tool":
            items.append({"type": "function_call_output", "call_id": m["tool_call_id"], "output": m["content"]})
            continue
        items.extend(m.get("reasoning_items") or [])
        if m.get("content"):
            items.append({"role": m["role"], "content": m["content"]})
        for call in m.get("tool_calls") or []:
            items.append({"type": "function_call", "call_id": call["id"],
                          "name": call["function"]["name"], "arguments": call["function"]["arguments"]})
    return items


def _to_chat_response(response) -> SimpleNamespace:
    text = "".join(part.text for item in response.output if item.type == "message"
                   for part in item.content if getattr(part, "text", None))
    calls = [SimpleNamespace(id=item.call_id, function=SimpleNamespace(name=item.name, arguments=item.arguments))
             for item in response.output if item.type == "function_call"]
    usage = response.usage and SimpleNamespace(prompt_tokens=response.usage.input_tokens,
                                               completion_tokens=response.usage.output_tokens)
    reasoning = [item.model_dump(exclude_none=True) for item in response.output if item.type == "reasoning"]
    message = SimpleNamespace(content=text or None, tool_calls=calls or None, reasoning_items=reasoning or None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


def _create(client: OpenAI, model: str, messages: list, schemas: list, kwargs: dict):
    kwargs = dict(kwargs)
    effort = kwargs.pop("reasoning_effort", None)
    if model.startswith(NON_REASONING_MODELS):
        effort = None
    if effort in (None, "none"):
        return client.chat.completions.create(
            model=model, messages=messages, tools=schemas, tool_choice="auto",
            timeout=REQUEST_TIMEOUT_S, **kwargs, **({} if effort is None else {"reasoning_effort": effort}),
        )
    response = client.responses.create(
        model=model, input=_to_responses_input(messages),
        tools=[{"type": "function", **schema["function"]} for schema in schemas],
        tool_choice="auto", reasoning={"effort": effort}, store=False,
        include=["reasoning.encrypted_content"], timeout=REQUEST_TIMEOUT_S, **kwargs,
    )
    return _to_chat_response(response)


def complete(client: OpenAI, model: str, messages: list, schemas: list, kwargs: dict,
             usage: dict, verbose: bool = True):
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = _create(client, model, messages, schemas, kwargs)
            choices = getattr(response, "choices", None) or []
            if not choices or getattr(choices[0], "message", None) is None:
                raise Unusable(f"no message in response: {getattr(response, 'error', '')}")
            return response

        except BadRequestError as e:
            rejected = next((k for k in kwargs if k in str(e)), "")
            if not rejected:
                raise
            if verbose:
                print(f"    [provider rejected {rejected}, retrying without it]", flush=True)
            kwargs.pop(rejected)
            continue

        except (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError, Unusable) as e:
            error = e
        except APIStatusError as e:
            if e.status_code < 500 and e.status_code != 429:
                raise
            error = e

        usage["retries"] += 1
        if attempt == MAX_ATTEMPTS - 1:
            raise error
        delay = backoff_delay(attempt, _retry_after(error))
        if verbose:
            print(f"    [{type(error).__name__}, retrying in {delay:.1f}s "
                  f"({attempt + 1}/{MAX_ATTEMPTS - 1})]", flush=True)
        time.sleep(delay)


if __name__ == "__main__":
    import httpx

    def stub(status: int, headers: dict | None = None) -> httpx.Response:
        request = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
        return httpx.Response(status, headers=headers or {}, request=request)

    class FlakyClient:
        def __init__(self, failures: list):
            self.failures, self.calls = failures, 0
            self.chat = type("chat", (), {"completions": self})()

        def create(self, **_):
            self.calls += 1
            if self.failures:
                raise self.failures.pop(0)
            return type("r", (), {"choices": [type("c", (), {"message": "ok"})()], "usage": None})()

    print("--- backoff is exponential with jitter, so parallel workers do not collide ---")
    print(f"    attempts 0..5: {[round(backoff_delay(i), 1) for i in range(MAX_ATTEMPTS)]}")
    print(f"    retry-after header wins: {backoff_delay(0, retry_after=7.0)}")

    for label, failures in [
        ("rate limit twice, then success",
         [RateLimitError("429", response=stub(429, {"retry-after": "1"}), body=None)] * 2),
        ("connection reset, then success", [APIConnectionError(request=stub(500).request)]),
        ("provider 503, then success", [InternalServerError("503", response=stub(503), body=None)]),
        ("200 with no choices, then success", [Unusable("empty")]),
        ("rejected parameter is dropped, not retried",
         [BadRequestError("Unsupported parameter: 'reasoning_effort'", response=stub(400), body=None)]),
    ]:
        print(f"\n--- {label} ---")
        usage, client, started = {"retries": 0}, FlakyClient(list(failures)), time.monotonic()
        complete(client, "stub-model", [], [], dict(MODEL_KWARGS), usage)
        print(f"    calls={client.calls} retries={usage['retries']} waited={time.monotonic() - started:.1f}s")

    print(f"\n--- all {MAX_ATTEMPTS} attempts fail: the error is raised, run() turns it into status=error ---")
    usage = {"retries": 0}
    try:
        complete(FlakyClient([InternalServerError("503", response=stub(503), body=None)] * MAX_ATTEMPTS),
                 "stub-model", [], [], {}, usage)
    except Exception as e:
        print(f"    raised {type(e).__name__} after {usage['retries']} retries")

    print("\n--- a 4xx that is not a rate limit is not retried ---")
    usage = {"retries": 0}
    try:
        complete(FlakyClient([APIStatusError("401", response=stub(401), body=None)]),
                 "stub-model", [], [], {}, usage)
    except Exception as e:
        print(f"    raised {type(e).__name__} immediately, retries={usage['retries']}")
