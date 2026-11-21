"""Tests for secret redaction (API keys not leaked)."""
import logging

from llm_service.app.analyzer import analyze
from llm_service.app.config import Settings
from llm_service.app.providers.base import LLMProvider
from llm_service.app.schemas import AnalyzeRequest, Finding


class BrokenProvider(LLMProvider):
    """Provider that always fails."""

    def __init__(self):
        self.call_count = 0

    def complete(self, system: str, user: str) -> str:
        self.call_count += 1
        raise Exception("Provider error")


class TestSecretRedaction:
    """Test that API keys and secrets are not leaked in responses or logs."""

    def test_api_key_not_in_response(self):
        """API key from settings is not in HTTP response."""
        fake_provider = BrokenProvider()
        settings = Settings()
        settings.llm_api_key = "sk-test-SECRET-123"
        settings.llm_max_retries = 0  # No retries, fail fast

        request = AnalyzeRequest(finding=Finding(id="f1", source="trivy"))

        response = analyze(request, fake_provider, settings)

        # Serialize response as it would be sent over HTTP
        response_dict = response.model_dump(mode="json")
        response_str = str(response_dict)

        # Secret should NOT appear anywhere in the response
        assert "sk-test-SECRET-123" not in response_str
        assert "SECRET" not in response_str

    def test_api_key_not_in_logs(self, caplog):
        """API key is not logged."""
        fake_provider = BrokenProvider()
        settings = Settings()
        settings.llm_api_key = "sk-test-SECRET-456"
        settings.llm_max_retries = 0

        with caplog.at_level(logging.INFO):
            request = AnalyzeRequest(finding=Finding(id="f1", source="trivy"))
            analyze(request, fake_provider, settings)

        # Check all log records for the secret
        for record in caplog.records:
            assert "sk-test-SECRET-456" not in record.message
            assert "SECRET" not in record.message
