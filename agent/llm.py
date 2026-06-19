from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Literal

from anthropic import Anthropic
from openai import OpenAI
from pydantic import BaseModel, Field, ValidationError

from config import LLMConfig


PhaseName = Literal["recon", "enumeration", "foothold", "privesc", "flag_capture"]


class Action(BaseModel):
    phase: PhaseName
    reasoning: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)


class LLMError(RuntimeError):
    """Base error for planner LLM failures."""


class InvalidLLMResponse(LLMError):
    """Raised when a provider response cannot be validated as an action."""


class ProviderResponse(BaseModel):
    text: str
    rejected_tool_use: bool = False


class BaseLLMProvider(ABC):
    def __init__(self, config: LLMConfig):
        self.config = config

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        """Return raw model text without executing any tool calls."""


class OpenAICompatibleProvider(BaseLLMProvider):
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not config.api_key:
            raise LLMError("Missing OpenAI-compatible API key")
        kwargs: dict[str, Any] = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self.client = OpenAI(**kwargs)

    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        message = response.choices[0].message
        if getattr(message, "tool_calls", None):
            return ProviderResponse(text="", rejected_tool_use=True)
        return ProviderResponse(text=message.content or "")


class AnthropicProvider(BaseLLMProvider):
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not config.api_key:
            raise LLMError("Missing Anthropic API key")
        self.client = Anthropic(api_key=config.api_key)

    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        response = self.client.messages.create(
            model=self.config.model,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        parts: list[str] = []
        for block in response.content:
            block_type = getattr(block, "type", "")
            if block_type == "tool_use":
                return ProviderResponse(text="", rejected_tool_use=True)
            if block_type == "text":
                parts.append(getattr(block, "text", ""))
        return ProviderResponse(text="\n".join(parts))


class LLMClient:
    """Direct provider client that validates planner JSON actions."""

    def __init__(self, config: LLMConfig):
        self.config = config
        if config.provider in {"openai", "ollama"}:
            self.provider: BaseLLMProvider = OpenAICompatibleProvider(config)
        elif config.provider == "anthropic":
            self.provider = AnthropicProvider(config)
        else:
            raise LLMError(f"Unsupported LLM provider: {config.provider}")

    def complete_action(self, system_prompt: str, user_prompt: str, retries: int = 3) -> Action:
        prompt = user_prompt
        last_error = ""
        for attempt in range(1, retries + 1):
            response = self.provider.complete(system_prompt, prompt)
            if response.rejected_tool_use:
                last_error = "Model attempted tool use. Expedition33 requires JSON text only."
            else:
                try:
                    return self._parse_action(response.text)
                except InvalidLLMResponse as exc:
                    last_error = str(exc)

            prompt = self._retry_prompt(user_prompt, last_error, attempt)

        raise InvalidLLMResponse(f"LLM failed to return a valid action after {retries} attempts: {last_error}")

    def _retry_prompt(self, original_prompt: str, error: str, attempt: int) -> str:
        return (
            f"{original_prompt}\n\n"
            f"Your previous response was invalid on attempt {attempt}: {error}\n"
            "Return exactly one JSON object and no surrounding commentary. "
            "Do not emit tool calls or tool-use blocks."
        )

    def _parse_action(self, text: str) -> Action:
        payload = _extract_json(text)
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise InvalidLLMResponse(f"Response was not valid JSON: {exc}") from exc
        try:
            return Action.model_validate(data)
        except ValidationError as exc:
            raise InvalidLLMResponse(f"Response did not match action schema: {exc}") from exc


def _extract_json(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        raise InvalidLLMResponse("Response was empty")
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", stripped, re.DOTALL | re.IGNORECASE)
    if fenced:
        fenced_text = fenced.group(1).strip()
        first = fenced_text.find("{")
        last = fenced_text.rfind("}")
        if first != -1 and last != -1 and last > first:
            return fenced_text[first : last + 1]

    first = stripped.find("{")
    last = stripped.rfind("}")
    if first != -1 and last != -1 and last > first:
        candidate = stripped[first : last + 1]
        return candidate

    raise InvalidLLMResponse("Response did not contain a JSON object")
