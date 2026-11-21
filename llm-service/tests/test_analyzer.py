"""Tests for the analyzer module."""
import json

from llm_service.app.analyzer import analyze, _build_user_prompt, _strip_markdown_fences
from llm_service.app.config import Settings
from llm_service.app.providers.base import LLMProvider
from llm_service.app.schemas import (
    AnalyzeRequest,
    ContextInput,
    Finding,
)


class FakeProvider(LLMProvider):
    """Fake provider for testing."""

    def __init__(self, response: str, raise_on_call: Exception = None):
        self.response = response
        self.raise_on_call = raise_on_call
        self.call_count = 0

    def complete(self, system: str, user: str) -> str:
        self.call_count += 1
        if self.raise_on_call:
            raise self.raise_on_call
        return self.response


class TestAnalyzer:
    """Test analyzer function."""

    def test_analyze_valid_json(self):
        """Valid JSON response passes validation."""
        result_json = json.dumps(
            {
                "exploitable": True,
                "confidence": 0.95,
                "reasoning": "SQL injection vulnerability",
                "suggested_fix": "Use parameterized queries",
                "priority": "critical",
            }
        )
        fake_provider = FakeProvider(response=result_json)
        settings = Settings()
        settings.llm_max_retries = 1

        request = AnalyzeRequest(
            finding=Finding(id="f1", source="trivy", severity="critical", cve="CVE-2024-1234")
        )

        response = analyze(request, fake_provider, settings)

        assert response.status == "ok"
        assert response.result.exploitable is True
        assert response.result.confidence == 0.95
        assert fake_provider.call_count == 1

    def test_analyze_json_with_markdown_fences(self):
        """JSON wrapped in markdown fences passes."""
        result_json = json.dumps(
            {
                "exploitable": False,
                "confidence": 0.4,
                "reasoning": "No real exploit path found",
                "suggested_fix": "Monitor for future CVEs",
                "priority": "low",
            }
        )
        fake_provider = FakeProvider(response=f"```json\n{result_json}\n```")
        settings = Settings()
        settings.llm_max_retries = 1

        request = AnalyzeRequest(
            finding=Finding(id="f2", source="semgrep", severity="low")
        )

        response = analyze(request, fake_provider, settings)

        assert response.status == "ok"
        assert response.result.exploitable is False

    def test_analyze_invalid_json_then_valid_on_retry(self):
        """Invalid JSON first, valid on retry succeeds with 2 provider calls."""
        valid_json = json.dumps(
            {
                "exploitable": True,
                "confidence": 0.8,
                "reasoning": "Exploitable after retry",
                "suggested_fix": "Update",
                "priority": "high",
            }
        )

        class RetryProvider(LLMProvider):
            def __init__(self):
                self.call_count = 0

            def complete(self, system: str, user: str) -> str:
                self.call_count += 1
                if self.call_count == 1:
                    return "not valid json"
                return valid_json

        fake_provider = RetryProvider()
        settings = Settings()
        settings.llm_max_retries = 1

        request = AnalyzeRequest(
            finding=Finding(id="f3", source="trivy")
        )

        response = analyze(request, fake_provider, settings)

        assert response.status == "ok"
        assert fake_provider.call_count == 2

    def test_analyze_always_invalid_gives_analysis_failed(self):
        """Always invalid JSON gives analysis_failed after max retries."""
        fake_provider = FakeProvider(response="always invalid json")
        settings = Settings()
        settings.llm_max_retries = 1

        request = AnalyzeRequest(
            finding=Finding(id="f4", source="trivy")
        )

        response = analyze(request, fake_provider, settings)

        assert response.status == "analysis_failed"
        assert response.result is None
        assert fake_provider.call_count == 2  # 1 attempt + 1 retry

    def test_analyze_validation_error_then_valid_on_retry(self):
        """Invalid schema first, valid on retry succeeds."""
        invalid_json = json.dumps(
            {
                "exploitable": "not a bool",  # Invalid
                "confidence": 0.8,
                "reasoning": "test",
                "suggested_fix": "fix",
                "priority": "high",
            }
        )
        valid_json = json.dumps(
            {
                "exploitable": True,
                "confidence": 0.8,
                "reasoning": "Now valid",
                "suggested_fix": "fix",
                "priority": "high",
            }
        )

        class RetryProvider(LLMProvider):
            def __init__(self):
                self.call_count = 0

            def complete(self, system: str, user: str) -> str:
                self.call_count += 1
                if self.call_count == 1:
                    return invalid_json
                return valid_json

        fake_provider = RetryProvider()
        settings = Settings()
        settings.llm_max_retries = 1

        request = AnalyzeRequest(
            finding=Finding(id="f5", source="trivy")
        )

        response = analyze(request, fake_provider, settings)

        assert response.status == "ok"
        assert fake_provider.call_count == 2

    def test_analyze_provider_exception_gives_analysis_failed(self):
        """Provider raising exception gives analysis_failed."""
        fake_provider = FakeProvider(
            response="",
            raise_on_call=TimeoutError("LLM timeout"),
        )
        settings = Settings()
        settings.llm_max_retries = 1

        request = AnalyzeRequest(
            finding=Finding(id="f6", source="trivy")
        )

        response = analyze(request, fake_provider, settings)

        assert response.status == "analysis_failed"
        assert fake_provider.call_count == 2

    def test_analyze_context_truncated(self):
        """Context longer than MAX_CONTEXT_CHARS is truncated."""
        result_json = json.dumps(
            {
                "exploitable": True,
                "confidence": 0.9,
                "reasoning": "Exploitable",
                "suggested_fix": "fix",
                "priority": "high",
            }
        )

        class CapturingProvider(LLMProvider):
            def __init__(self):
                self.last_user_prompt = None

            def complete(self, system: str, user: str) -> str:
                self.last_user_prompt = user
                return result_json

        fake_provider = CapturingProvider()
        settings = Settings()
        settings.max_context_chars = 50

        long_code = "x" * 1000
        request = AnalyzeRequest(
            finding=Finding(id="f7", source="trivy"),
            context=ContextInput(code_snippet=long_code),
        )

        response = analyze(request, fake_provider, settings)

        assert response.status == "ok"
        # Check that the prompt contains truncated code
        assert len(fake_provider.last_user_prompt) < len(long_code) + 200


class TestBuildUserPrompt:
    """Test _build_user_prompt function."""

    def test_build_user_prompt_minimal(self):
        """Minimal finding builds prompt."""
        request = AnalyzeRequest(
            finding=Finding(id="f1", source="trivy"),
            context=None,
        )
        prompt = _build_user_prompt(request, 1000)

        assert "f1" in prompt
        assert "trivy" in prompt
        assert "FINDING:" in prompt

    def test_build_user_prompt_with_all_fields(self):
        """All finding fields appear in prompt."""
        request = AnalyzeRequest(
            finding=Finding(
                id="f1",
                source="semgrep",
                severity="high",
                file="app.py",
                line=42,
                cwe="CWE-89",
                cve="CVE-2024-1234",
                description="SQL injection",
            ),
            context=None,
        )
        prompt = _build_user_prompt(request, 1000)

        assert "f1" in prompt
        assert "semgrep" in prompt
        assert "high" in prompt
        assert "app.py" in prompt
        assert "42" in prompt
        assert "CWE-89" in prompt
        assert "CVE-2024-1234" in prompt
        assert "SQL injection" in prompt

    def test_build_user_prompt_with_code_context(self):
        """Code snippet is wrapped in untrusted delimiters."""
        request = AnalyzeRequest(
            finding=Finding(id="f1", source="trivy"),
            context=ContextInput(code_snippet="def foo(): pass"),
        )
        prompt = _build_user_prompt(request, 1000)

        assert "<<<UNTRUSTED_CODE_START>>>" in prompt
        assert "def foo(): pass" in prompt
        assert "<<<UNTRUSTED_CODE_END>>>" in prompt

    def test_build_user_prompt_with_dependency_context(self):
        """Dependency usage is wrapped in untrusted delimiters."""
        request = AnalyzeRequest(
            finding=Finding(id="f1", source="trivy"),
            context=ContextInput(dependency_usage="requests==2.25.0"),
        )
        prompt = _build_user_prompt(request, 1000)

        assert "<<<UNTRUSTED_DEPENDENCY_START>>>" in prompt
        assert "requests==2.25.0" in prompt
        assert "<<<UNTRUSTED_DEPENDENCY_END>>>" in prompt

    def test_build_user_prompt_context_truncation(self):
        """Context is truncated to MAX_CONTEXT_CHARS."""
        long_code = "x" * 2000
        request = AnalyzeRequest(
            finding=Finding(id="f1", source="trivy"),
            context=ContextInput(code_snippet=long_code),
        )
        prompt = _build_user_prompt(request, 100)

        # Prompt should contain truncated code (100 chars), not full 2000
        assert len(prompt) < len(long_code) + 500


class TestStripMarkdownFences:
    """Test _strip_markdown_fences function."""

    def test_strip_json_fences(self):
        """Strip ```json fences."""
        text = '```json\n{"key": "value"}\n```'
        result = _strip_markdown_fences(text)
        assert result == '{"key": "value"}'

    def test_strip_generic_fences(self):
        """Strip generic ``` fences."""
        text = '```\n{"key": "value"}\n```'
        result = _strip_markdown_fences(text)
        assert result == '{"key": "value"}'

    def test_no_fences(self):
        """Plain JSON without fences passes through."""
        text = '{"key": "value"}'
        result = _strip_markdown_fences(text)
        assert result == '{"key": "value"}'

    def test_strip_with_whitespace(self):
        """Strip fences and whitespace."""
        text = "  ```json\n  {\"key\": \"value\"}  \n```  "
        result = _strip_markdown_fences(text)
        assert result == '{"key": "value"}'
