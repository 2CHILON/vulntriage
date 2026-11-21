"""Pydantic v2 schemas for LLM service."""
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class Finding(BaseModel):
    """Finding input for analysis."""

    id: str
    source: str
    severity: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    description: Optional[str] = None

    model_config = {"extra": "forbid"}


class ContextInput(BaseModel):
    """Optional code context."""

    code_snippet: Optional[str] = None
    dependency_usage: Optional[str] = None

    model_config = {"extra": "forbid"}


class AnalyzeRequest(BaseModel):
    """Request to analyze a finding."""

    finding: Finding
    context: Optional[ContextInput] = None

    model_config = {"extra": "forbid"}


class AnalysisResult(BaseModel):
    """Result of LLM analysis."""

    exploitable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1)
    suggested_fix: str
    priority: Literal["critical", "high", "medium", "low"]

    @field_validator("reasoning")
    @classmethod
    def reasoning_not_empty(cls, v: str) -> str:
        """Ensure reasoning is non-empty after stripping."""
        if not v or not v.strip():
            raise ValueError("reasoning must be non-empty")
        return v

    model_config = {"extra": "forbid"}


class AnalyzeResponse(BaseModel):
    """Response from the analyze endpoint."""

    finding_id: str
    status: Literal["ok", "analysis_failed"]
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None
    provider: str
    prompt_version: str

    model_config = {"extra": "forbid"}
