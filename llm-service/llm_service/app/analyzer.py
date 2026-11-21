"""LLM-based vulnerability analysis."""
import json
import logging
from pathlib import Path

from pydantic import ValidationError

from llm_service.app.schemas import AnalyzeRequest, AnalysisResult, AnalyzeResponse

logger = logging.getLogger(__name__)

PROMPT_VERSION = "v1"


def _load_prompt() -> str:
    """Load the system prompt from analyze_v1.txt."""
    prompt_path = Path(__file__).parent / "prompts" / "analyze_v1.txt"
    return prompt_path.read_text()


SYSTEM_PROMPT = _load_prompt()


def analyze(request: AnalyzeRequest, provider, settings) -> AnalyzeResponse:
    """
    Analyze a finding using the LLM provider.

    Args:
        request: AnalyzeRequest with finding and optional context.
        provider: LLMProvider instance (mock or real).
        settings: Settings instance with max_context_chars, llm_max_retries, etc.

    Returns:
        AnalyzeResponse with status, result, and error.
    """
    finding_id = request.finding.id
    provider_name = settings.llm_provider

    # Build user prompt with finding metadata and untrusted code blocks
    user_prompt = _build_user_prompt(request, settings.max_context_chars)

    # Retry logic: attempt up to llm_max_retries+1 times
    max_attempts = settings.llm_max_retries + 1
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                f"Finding {finding_id}: LLM provider {provider_name} attempt {attempt}/{max_attempts}"
            )

            # Call the provider
            raw_response = provider.complete(SYSTEM_PROMPT, user_prompt)

            # Strip optional markdown code fences
            raw_response = _strip_markdown_fences(raw_response)

            # Parse JSON
            try:
                result_dict = json.loads(raw_response)
            except json.JSONDecodeError as e:
                logger.warning(
                    f"Finding {finding_id}: JSON parse failed on attempt {attempt}: {e}"
                )
                if attempt < max_attempts:
                    continue
                return AnalyzeResponse(
                    finding_id=finding_id,
                    status="analysis_failed",
                    result=None,
                    error="LLM returned invalid JSON",
                    provider=provider_name,
                    prompt_version=PROMPT_VERSION,
                )

            # Validate against schema
            try:
                result = AnalysisResult(**result_dict)
                logger.info(f"Finding {finding_id}: analysis succeeded")
                return AnalyzeResponse(
                    finding_id=finding_id,
                    status="ok",
                    result=result,
                    error=None,
                    provider=provider_name,
                    prompt_version=PROMPT_VERSION,
                )
            except ValidationError as e:
                logger.warning(
                    f"Finding {finding_id}: validation failed on attempt {attempt}: {e}"
                )
                if attempt < max_attempts:
                    continue
                return AnalyzeResponse(
                    finding_id=finding_id,
                    status="analysis_failed",
                    result=None,
                    error="LLM response did not match schema",
                    provider=provider_name,
                    prompt_version=PROMPT_VERSION,
                )

        except Exception as e:
            # Provider raised an exception (timeout, network, etc.)
            logger.warning(
                f"Finding {finding_id}: provider exception on attempt {attempt}: {type(e).__name__}"
            )
            if attempt < max_attempts:
                continue
            return AnalyzeResponse(
                finding_id=finding_id,
                status="analysis_failed",
                result=None,
                error="Provider error",
                provider=provider_name,
                prompt_version=PROMPT_VERSION,
            )

    # This should not be reached, but handle it gracefully
    return AnalyzeResponse(
        finding_id=finding_id,
        status="analysis_failed",
        result=None,
        error="Max retries exceeded",
        provider=provider_name,
        prompt_version=PROMPT_VERSION,
    )


def _build_user_prompt(request: AnalyzeRequest, max_context_chars: int) -> str:
    """
    Build the user prompt from finding and context.

    Args:
        request: AnalyzeRequest.
        max_context_chars: Maximum characters for context.

    Returns:
        Formatted user prompt with untrusted blocks.
    """
    finding = request.finding
    context = request.context

    lines = [
        "FINDING:",
        f"  ID: {finding.id}",
        f"  Source: {finding.source}",
    ]

    if finding.severity:
        lines.append(f'  Severity: "{finding.severity}"')
    if finding.file:
        lines.append(f"  File: {finding.file}")
    if finding.line is not None:
        lines.append(f"  Line: {finding.line}")
    if finding.cwe:
        lines.append(f"  CWE: {finding.cwe}")
    if finding.cve:
        lines.append(f"  CVE: {finding.cve}")
    if finding.description:
        lines.append(f"  Description: {finding.description}")

    lines.append("")
    lines.append("Provide your analysis:")

    if context:
        if context.code_snippet:
            truncated_snippet = context.code_snippet[:max_context_chars]
            lines.append("")
            lines.append("<<<UNTRUSTED_CODE_START>>>")
            lines.append(truncated_snippet)
            lines.append("<<<UNTRUSTED_CODE_END>>>")

        if context.dependency_usage:
            truncated_deps = context.dependency_usage[:max_context_chars]
            lines.append("")
            lines.append("<<<UNTRUSTED_DEPENDENCY_START>>>")
            lines.append(truncated_deps)
            lines.append("<<<UNTRUSTED_DEPENDENCY_END>>>")

    return "\n".join(lines)


def _strip_markdown_fences(text: str) -> str:
    """
    Strip optional markdown code fences from response.

    Handles:
    - ```json ... ```
    - ```json\n ... \n```
    - ``` ... ```
    """
    text = text.strip()
    if text.startswith("```"):
        # Remove opening fence (up to and including first newline after ```)
        lines = text.split("\n")
        if lines[0].startswith("```"):
            text = "\n".join(lines[1:])
        # Remove closing fence
        if text.endswith("```"):
            text = text[:-3]
    return text.strip()
