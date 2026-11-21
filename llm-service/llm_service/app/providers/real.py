"""Real LLM provider stub (not implemented in this phase)."""
from llm_service.app.providers.base import LLMProvider


class RealProvider(LLMProvider):
    """
    Real LLM provider stub.

    To implement: replace NotImplementedError with actual vendor API calls.
    """

    def __init__(self, api_key: str, model: str, timeout: int) -> None:
        """
        Initialize RealProvider.

        Args:
            api_key: API key for the LLM vendor.
            model: Model identifier (e.g., "gpt-4", "claude-3-sonnet").
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, system: str, user: str) -> str:
        """
        Request completion from a real LLM provider.

        Args:
            system: System prompt.
            user: User prompt.

        Returns:
            Raw text response from the LLM.

        Raises:
            NotImplementedError: This is a stub; real provider swap is in Phase 3 follow-up.
        """
        # TODO(REAL-LLM): call the vendor API here
        # TODO(REAL-LLM): never log api_key
        # TODO(REAL-LLM): map vendor errors to ProviderError
        raise NotImplementedError(
            "RealProvider is not implemented in Phase 3. "
            "Use LLM_PROVIDER=mock for testing, or implement a real provider following the TODO markers in llm-service/app/providers/real.py"
        )
