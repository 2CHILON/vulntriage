"""Abstract base class for LLM providers."""
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Abstract base for LLM providers."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """
        Request completion from the LLM.

        Args:
            system: System prompt (instructions to the model).
            user: User prompt (the actual query).

        Returns:
            Raw text response from the LLM.

        Raises:
            ProviderError: On any error (network, timeout, invalid response).
        """
        pass
