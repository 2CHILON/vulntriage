"""Tests for Pydantic schemas."""
import pytest
from pydantic import ValidationError

from llm_service.app.schemas import (
    AnalysisResult,
    AnalyzeRequest,
    AnalyzeResponse,
    ContextInput,
    Finding,
)


class TestFinding:
    """Test Finding schema."""

    def test_finding_valid_minimal(self):
        """Finding with only id and source."""
        f = Finding(id="f1", source="trivy")
        assert f.id == "f1"
        assert f.source == "trivy"
        assert f.severity is None

    def test_finding_valid_full(self):
        """Finding with all fields."""
        f = Finding(
            id="f1",
            source="semgrep",
            severity="high",
            file="app.py",
            line=42,
            cwe="CWE-89",
            cve="CVE-2024-1234",
            description="SQL injection",
        )
        assert f.id == "f1"
        assert f.severity == "high"

    def test_finding_rejects_extra_field(self):
        """Finding rejects unknown extra fields."""
        with pytest.raises(ValidationError):
            Finding(id="f1", source="trivy", unknown_field="value")


class TestContextInput:
    """Test ContextInput schema."""

    def test_context_valid_empty(self):
        """Empty context is valid."""
        c = ContextInput()
        assert c.code_snippet is None
        assert c.dependency_usage is None

    def test_context_valid_partial(self):
        """Partial context is valid."""
        c = ContextInput(code_snippet="def foo(): pass")
        assert c.code_snippet == "def foo(): pass"
        assert c.dependency_usage is None

    def test_context_rejects_extra_field(self):
        """Context rejects unknown extra fields."""
        with pytest.raises(ValidationError):
            ContextInput(code_snippet="code", unknown_field="value")


class TestAnalysisResult:
    """Test AnalysisResult schema."""

    def test_analysis_result_valid(self):
        """Valid AnalysisResult."""
        r = AnalysisResult(
            exploitable=True,
            confidence=0.95,
            reasoning="This is exploitable",
            suggested_fix="Update package",
            priority="critical",
        )
        assert r.exploitable is True
        assert r.confidence == 0.95
        assert r.priority == "critical"

    def test_analysis_result_confidence_above_1_rejected(self):
        """Confidence > 1.0 is rejected."""
        with pytest.raises(ValidationError):
            AnalysisResult(
                exploitable=True,
                confidence=1.01,
                reasoning="test",
                suggested_fix="fix",
                priority="high",
            )

    def test_analysis_result_confidence_below_0_rejected(self):
        """Confidence < 0.0 is rejected."""
        with pytest.raises(ValidationError):
            AnalysisResult(
                exploitable=False,
                confidence=-0.1,
                reasoning="test",
                suggested_fix="fix",
                priority="low",
            )

    def test_analysis_result_confidence_boundaries(self):
        """Confidence 0.0 and 1.0 are valid."""
        r1 = AnalysisResult(
            exploitable=False,
            confidence=0.0,
            reasoning="test",
            suggested_fix="fix",
            priority="low",
        )
        assert r1.confidence == 0.0

        r2 = AnalysisResult(
            exploitable=True,
            confidence=1.0,
            reasoning="test",
            suggested_fix="fix",
            priority="critical",
        )
        assert r2.confidence == 1.0

    def test_analysis_result_empty_reasoning_rejected(self):
        """Empty reasoning is rejected."""
        with pytest.raises(ValidationError):
            AnalysisResult(
                exploitable=True,
                confidence=0.9,
                reasoning="",
                suggested_fix="fix",
                priority="high",
            )

    def test_analysis_result_whitespace_only_reasoning_rejected(self):
        """Whitespace-only reasoning is rejected."""
        with pytest.raises(ValidationError):
            AnalysisResult(
                exploitable=True,
                confidence=0.9,
                reasoning="   ",
                suggested_fix="fix",
                priority="high",
            )

    def test_analysis_result_invalid_priority_rejected(self):
        """Invalid priority is rejected."""
        with pytest.raises(ValidationError):
            AnalysisResult(
                exploitable=True,
                confidence=0.9,
                reasoning="test",
                suggested_fix="fix",
                priority="urgent",
            )

    def test_analysis_result_rejects_extra_field(self):
        """Extra fields are rejected."""
        with pytest.raises(ValidationError):
            AnalysisResult(
                exploitable=True,
                confidence=0.9,
                reasoning="test",
                suggested_fix="fix",
                priority="high",
                extra_field="value",
            )


class TestAnalyzeRequest:
    """Test AnalyzeRequest schema."""

    def test_analyze_request_valid(self):
        """Valid AnalyzeRequest."""
        req = AnalyzeRequest(
            finding=Finding(id="f1", source="trivy", severity="high"),
            context=ContextInput(code_snippet="code"),
        )
        assert req.finding.id == "f1"
        assert req.context.code_snippet == "code"

    def test_analyze_request_no_context(self):
        """AnalyzeRequest without context."""
        req = AnalyzeRequest(finding=Finding(id="f1", source="trivy"))
        assert req.finding.id == "f1"
        assert req.context is None

    def test_analyze_request_rejects_extra_field(self):
        """Extra fields are rejected."""
        with pytest.raises(ValidationError):
            AnalyzeRequest(
                finding=Finding(id="f1", source="trivy"),
                extra_field="value",
            )


class TestAnalyzeResponse:
    """Test AnalyzeResponse schema."""

    def test_analyze_response_ok(self):
        """Valid AnalyzeResponse with status ok."""
        result = AnalysisResult(
            exploitable=True,
            confidence=0.9,
            reasoning="test",
            suggested_fix="fix",
            priority="high",
        )
        resp = AnalyzeResponse(
            finding_id="f1",
            status="ok",
            result=result,
            error=None,
            provider="mock",
            prompt_version="v1",
        )
        assert resp.status == "ok"
        assert resp.result.exploitable is True

    def test_analyze_response_analysis_failed(self):
        """Valid AnalyzeResponse with status analysis_failed."""
        resp = AnalyzeResponse(
            finding_id="f1",
            status="analysis_failed",
            result=None,
            error="Provider timeout",
            provider="mock",
            prompt_version="v1",
        )
        assert resp.status == "analysis_failed"
        assert resp.error == "Provider timeout"
        assert resp.result is None

    def test_analyze_response_rejects_extra_field(self):
        """Extra fields are rejected."""
        with pytest.raises(ValidationError):
            AnalyzeResponse(
                finding_id="f1",
                status="ok",
                result=None,
                error=None,
                provider="mock",
                prompt_version="v1",
                extra_field="value",
            )
