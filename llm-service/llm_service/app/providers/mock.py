"""Mock LLM provider for testing without network calls."""
import json
import re

from llm_service.app.providers.base import LLMProvider


class MockProvider(LLMProvider):
    """
    Deterministic mock provider for testing.

    Rule: severity critical or high AND (cve or cwe present) gives exploitable true;
    otherwise false. Confidence and priority derive from severity.
    """

    def complete(self, system: str, user: str) -> str:
        """
        Return a deterministic mock JSON response.

        Args:
            system: System prompt (ignored).
            user: User prompt containing the finding.

        Returns:
            JSON string matching AnalysisResult schema.
        """
        # Parse the user prompt to extract severity and presence of cve/cwe
        severity = self._extract_severity(user)
        has_cve_or_cwe = self._has_cve_or_cwe(user)

        # Determine exploitability
        exploitable = (severity in ("critical", "high")) and has_cve_or_cwe

        # Map severity to confidence and priority
        confidence_map = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.65,
            "low": 0.40,
            "note": 0.20,
        }
        confidence = confidence_map.get(severity, 0.5)

        priority_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "note": "low",
        }
        priority = priority_map.get(severity, "medium")

        result = {
            "exploitable": exploitable,
            "confidence": confidence,
            "reasoning": f"MOCK PROVIDER – not a real analysis: severity={severity}, has_cve_or_cwe={has_cve_or_cwe}",
            "suggested_fix": "No real fix available from mock provider",
            "priority": priority,
        }

        return json.dumps(result)

    @staticmethod
    def _extract_severity(user: str) -> str:
        """Extract severity from user prompt. Handles both JSON and plain formats."""
        severity_keywords = ["critical", "high", "medium", "low", "note"]
        for sev in severity_keywords:
            # Format 1: "severity": "critical" or 'Severity: "critical"'
            if f'severity": "{sev}"' in user or f'Severity: "{sev}"' in user:
                return sev
            # Format 2: severity="critical"
            if f'severity="{sev}"' in user:
                return sev
        return "medium"

    @staticmethod
    def _has_cve_or_cwe(user: str) -> bool:
        """Check if user prompt contains non-empty cve or cwe (CVE-XXXX or CWE-XXXX pattern)."""
        # Look for CVE-XXXX pattern (e.g., CVE-2024-1234)
        if re.search(r'CVE-\d{4}-\d+', user, re.IGNORECASE):
            return True
        # Look for CWE-XXXX pattern (e.g., CWE-89)
        if re.search(r'CWE-\d+', user, re.IGNORECASE):
            return True
        return False


