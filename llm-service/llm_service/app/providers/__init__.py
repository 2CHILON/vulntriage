"""LLM provider factory and base exception."""


class ProviderError(Exception):
    """Raised when provider initialization or operation fails."""

    pass


def get_provider(settings):
    """
    Factory function to create an LLM provider based on settings.

    Args:
        settings: Settings instance with llm_provider, llm_api_key, llm_model, llm_timeout_seconds.

    Returns:
        An LLMProvider instance (MockProvider or RealProvider).

    Raises:
        ProviderError: If provider name is unknown or required config is missing.
    """
    provider_name = settings.llm_provider.lower()

    if provider_name == "mock":
        from llm_service.app.providers.mock import MockProvider

        return MockProvider()

    if provider_name == "real":
        # TODO(REAL-LLM): add more real providers as needed (openai, anthropic, etc.)
        if not settings.llm_api_key:
            raise ProviderError(
                "LLM_API_KEY must be set to use the 'real' provider"
            )
        from llm_service.app.providers.real import RealProvider

        return RealProvider(
            api_key=settings.llm_api_key,
            model=settings.llm_model,
            timeout=settings.llm_timeout_seconds,
        )

    valid_providers = ["mock", "real"]
    raise ProviderError(
        f"Unknown LLM_PROVIDER '{provider_name}'. Valid choices: {valid_providers}"
    )
