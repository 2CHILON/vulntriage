"""Tests for provider factory."""
import pytest

from llm_service.app.config import Settings
from llm_service.app.providers import ProviderError, get_provider
from llm_service.app.providers.mock import MockProvider
from llm_service.app.providers.real import RealProvider


class TestProviderFactory:
    """Test get_provider factory function."""

    def test_factory_mock_provider(self):
        """Factory returns MockProvider for 'mock'."""
        settings = Settings()
        settings.llm_provider = "mock"

        provider = get_provider(settings)

        assert isinstance(provider, MockProvider)

    def test_factory_real_provider_with_key(self):
        """Factory returns RealProvider when LLM_PROVIDER=real and key is set."""
        settings = Settings()
        settings.llm_provider = "real"
        settings.llm_api_key = "sk-test-key"
        settings.llm_model = "gpt-4"

        provider = get_provider(settings)

        assert isinstance(provider, RealProvider)

    def test_factory_real_provider_without_key_fails(self):
        """Factory raises ProviderError if real provider requested without API key."""
        settings = Settings()
        settings.llm_provider = "real"
        settings.llm_api_key = ""

        with pytest.raises(ProviderError) as exc_info:
            get_provider(settings)

        assert "LLM_API_KEY" in str(exc_info.value)

    def test_factory_unknown_provider_fails(self):
        """Factory raises ProviderError for unknown provider name."""
        settings = Settings()
        settings.llm_provider = "unknown-provider"

        with pytest.raises(ProviderError) as exc_info:
            get_provider(settings)

        assert "unknown-provider" in str(exc_info.value).lower()
        assert "valid" in str(exc_info.value).lower()

    def test_factory_case_insensitive(self):
        """Factory is case-insensitive for provider name."""
        settings = Settings()
        settings.llm_provider = "MOCK"

        provider = get_provider(settings)

        assert isinstance(provider, MockProvider)

    def test_factory_mixed_case(self):
        """Factory handles mixed case."""
        settings = Settings()
        settings.llm_provider = "Mock"

        provider = get_provider(settings)

        assert isinstance(provider, MockProvider)
