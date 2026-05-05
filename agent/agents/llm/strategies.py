"""LLM provider strategies for the explanation agent."""

import os
from abc import ABC, abstractmethod

from langchain_core.language_models import BaseChatModel


class LLMStrategy(ABC):
    """Abstract strategy: builds a LangChain chat model."""

    @abstractmethod
    def build(self) -> BaseChatModel: ...

    @property
    @abstractmethod
    def label(self) -> str:
        """Human-readable provider/model label for logging."""
        ...


class OpenAIStrategy(LLMStrategy):
    """ChatGPT via the OpenAI API."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        temperature: float = 0.3,
        max_tokens: int = 1000,
        timeout: float = 30.0,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self._api_key:
            raise ValueError("OpenAI API key required (set OPENAI_API_KEY env var)")

    @property
    def label(self) -> str:
        return f"OpenAI/{self.model}"

    def build(self) -> BaseChatModel:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            request_timeout=self.timeout,
            api_key=self._api_key,
        )


class AnthropicStrategy(LLMStrategy):
    """Claude via the Anthropic API."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-5",
        temperature: float = 0.3,
        max_tokens: int = 1000,
        timeout: float = 30.0,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise ValueError("Anthropic API key required (set ANTHROPIC_API_KEY env var)")

    @property
    def label(self) -> str:
        return f"Anthropic/{self.model}"

    def build(self) -> BaseChatModel:
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            timeout=self.timeout,
            api_key=self._api_key,
        )


class GeminiStrategy(LLMStrategy):
    """Gemini via Google Generative AI."""

    def __init__(
        self,
        model: str = "gemini-2.0-flash",
        temperature: float = 0.3,
        max_tokens: int = 1000,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self._api_key:
            raise ValueError("Google API key required (set GOOGLE_API_KEY env var)")

    @property
    def label(self) -> str:
        return f"Gemini/{self.model}"

    def build(self) -> BaseChatModel:
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model=self.model,
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
            google_api_key=self._api_key,
        )


class VLLMStrategy(LLMStrategy):
    """Local vLLM server (Gemma or any HF model) via the OpenAI-compatible endpoint."""

    def __init__(
        self,
        model: str = "gemma4",
        base_url: str = "http://localhost:11434/v1",
        temperature: float = 0.3,
        max_tokens: int = 1000,
        timeout: float = 60.0,
        api_key: str = "EMPTY",
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._api_key = api_key

    @property
    def label(self) -> str:
        return f"vLLM/{self.model}@{self.base_url}"

    def build(self) -> BaseChatModel:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=self.model,
            base_url=self.base_url,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            request_timeout=self.timeout,
            api_key=self._api_key,
        )


_PROVIDERS: dict[str, type[LLMStrategy]] = {
    "openai": OpenAIStrategy,
    "anthropic": AnthropicStrategy,
    "gemini": GeminiStrategy,
    "vllm": VLLMStrategy,
}


def create_strategy(provider: str, **kwargs: object) -> LLMStrategy:
    """Instantiate a strategy by provider name.

    Args:
        provider: one of ``"openai"``, ``"anthropic"``, ``"gemini"``, ``"vllm"``
        **kwargs: forwarded to the chosen strategy constructor
    """
    key = provider.lower()
    cls = _PROVIDERS.get(key)
    if cls is None:
        raise ValueError(f"Unknown LLM provider '{provider}'. Choose from: {list(_PROVIDERS)}")
    return cls(**kwargs)  # type: ignore[arg-type]
