import os

from openai import OpenAI

from src.agentcore.utils.llm import price, rates
from src.baselines.intentfix.config import TEMPERATURE


def create_llm(interface_class: type, model: str):
    class CompatibleInterface(interface_class):
        def __init__(self):
            if "/" in model:
                self.model = model
                self.model_name = model
                self.temperature = TEMPERATURE
                self.client_type = "openai"
                self.api_key_type = "main"
                self.client = OpenAI(api_key=os.environ.get("OPENROUTER_API_KEY", ""),
                                     base_url="https://openrouter.ai/api/v1")
                self.total_tokens = self.input_tokens = self.output_tokens = 0
                self.total_cost = 0.0
                with self._key_usage_lock:
                    self._key_usage_counter["main"] += 1
            else:
                super().__init__(model=model, temperature=TEMPERATURE)
            if self.client_type == "openai":
                original_create = self.client.chat.completions.create
                temperature_supported = True

                def create(**kwargs):
                    nonlocal temperature_supported
                    if temperature_supported:
                        kwargs.setdefault("temperature", self.temperature)
                    try:
                        return original_create(**kwargs)
                    except Exception as error:
                        if not temperature_supported or "temperature" not in str(error).lower():
                            raise
                        temperature_supported = False
                        kwargs.pop("temperature", None)
                        return original_create(**kwargs)

                self.client.chat.completions.create = create

        def _update_cost(self, tokens):
            if rates(self.model) != (0.0, 0.0):
                self.total_cost = price(self.model, self.input_tokens, self.output_tokens)
            else:
                super()._update_cost(tokens)

    return CompatibleInterface()
