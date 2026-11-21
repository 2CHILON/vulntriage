"""FastAPI LLM analysis service."""
import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from llm_service.app.analyzer import analyze
from llm_service.app.config import get_settings
from llm_service.app.providers import ProviderError, get_provider
from llm_service.app.schemas import AnalyzeRequest, AnalyzeResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="VulnTriage LLM Service", version="0.1.0")

# Global provider, initialized at startup
_provider = None
_settings = None


@app.on_event("startup")
def startup_event():
    """Initialize provider at startup."""
    global _provider, _settings
    _settings = get_settings()
    try:
        _provider = get_provider(_settings)
        logger.info(f"LLM provider initialized: {_settings.llm_provider}")
    except ProviderError as e:
        logger.error(f"Failed to initialize LLM provider: {e}")
        raise


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "ok", "provider": _settings.llm_provider}


@app.post("/analyze")
def analyze_finding(request: AnalyzeRequest):
    """
    Analyze a finding for exploitability.

    Args:
        request: AnalyzeRequest with finding and optional context.

    Returns:
        AnalyzeResponse with analysis result or error.
        Always returns HTTP 200; check status field in body for analysis_failed.
    """
    try:
        response: AnalyzeResponse = analyze(request, _provider, _settings)
        return JSONResponse(
            status_code=200,
            content=response.model_dump(mode="json"),
        )
    except Exception as e:
        # Should not happen (analyze catches all exceptions), but handle gracefully
        logger.error(f"Unexpected error in /analyze: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"},
        )
