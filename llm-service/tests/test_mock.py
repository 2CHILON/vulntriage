"""Tests for MockProvider."""
import json

from llm_service.app.providers.mock import MockProvider


class TestMockProvider:
    """Test MockProvider determinism and logic."""

    def test_mock_provider_deterministic(self):
        """Same input gives identical output twice."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'Finding: {"id": "f1", "source": "trivy", "severity": "critical", "cve": "CVE-2024-1234"}'

        response1 = provider.complete(system, user)
        response2 = provider.complete(system, user)

        assert response1 == response2
        assert json.loads(response1) == json.loads(response2)

    def test_mock_provider_critical_with_cve_exploitable(self):
        """Critical severity + CVE = exploitable true."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'severity="critical", "cve": "CVE-2024-1234"'

        response = provider.complete(system, user)
        result = json.loads(response)

        assert result["exploitable"] is True
        assert result["confidence"] > 0.9
        assert result["priority"] == "critical"
        assert result["reasoning"].startswith("MOCK PROVIDER")

    def test_mock_provider_critical_without_cve_not_exploitable(self):
        """Critical severity without CVE = exploitable false."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'severity="critical"'

        response = provider.complete(system, user)
        result = json.loads(response)

        assert result["exploitable"] is False
        assert result["confidence"] > 0.0
        assert result["priority"] == "critical"

    def test_mock_provider_high_with_cwe_exploitable(self):
        """High severity + CWE = exploitable true."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'severity="high", "cwe": "CWE-89"'

        response = provider.complete(system, user)
        result = json.loads(response)

        assert result["exploitable"] is True
        assert result["confidence"] > 0.75
        assert result["priority"] == "high"

    def test_mock_provider_low_not_exploitable(self):
        """Low severity = exploitable false."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'severity="low", "cve": "CVE-2024-1234"'

        response = provider.complete(system, user)
        result = json.loads(response)

        assert result["exploitable"] is False
        assert result["priority"] == "low"

    def test_mock_provider_medium_exploitability(self):
        """Medium severity without CVE/CWE = exploitable false."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'severity="medium"'

        response = provider.complete(system, user)
        result = json.loads(response)

        assert result["exploitable"] is False
        assert result["priority"] == "medium"
        assert result["confidence"] > 0.5

    def test_mock_provider_reasoning_format(self):
        """Reasoning starts with MOCK PROVIDER prefix."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'severity="critical", "cve": "CVE-2024-1234"'

        response = provider.complete(system, user)
        result = json.loads(response)

        assert result["reasoning"].startswith("MOCK PROVIDER – not a real analysis:")

    def test_mock_provider_valid_priority_values(self):
        """All responses have valid priority values."""
        provider = MockProvider()
        system = "You are a security analyst."
        valid_priorities = ["critical", "high", "medium", "low"]

        for severity in ["critical", "high", "medium", "low", "note"]:
            user = f'severity="{severity}"'
            response = provider.complete(system, user)
            result = json.loads(response)
            assert result["priority"] in valid_priorities

    def test_mock_provider_confidence_in_range(self):
        """All responses have confidence between 0 and 1."""
        provider = MockProvider()
        system = "You are a security analyst."

        for severity in ["critical", "high", "medium", "low", "note"]:
            user = f'severity="{severity}"'
            response = provider.complete(system, user)
            result = json.loads(response)
            assert 0.0 <= result["confidence"] <= 1.0

    def test_mock_provider_valid_json(self):
        """Response is always valid JSON matching schema."""
        provider = MockProvider()
        system = "You are a security analyst."
        user = 'Finding: id="f1", source="trivy"'

        response = provider.complete(system, user)

        # Should parse without error
        result = json.loads(response)

        # Should have all required fields
        assert "exploitable" in result
        assert "confidence" in result
        assert "reasoning" in result
        assert "suggested_fix" in result
        assert "priority" in result
