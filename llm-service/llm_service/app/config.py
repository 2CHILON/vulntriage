"""Configuration from environment variables."""
import os


class Settings:
    """LLM service configuration."""

    def __init__(self) -> None:
        self.llm_provider = os.environ.get("LLM_PROVIDER", "mock")
        self.llm_api_key = os.environ.get("LLM_API_KEY", "")
        # TODO(REAL-LLM)
        self.llm_model = os.environ.get("LLM_MODEL", "")
        # TODO(REAL-LLM)
        self.llm_timeout_seconds = int(os.environ.get("LLM_TIMEOUT_SECONDS", "30"))
        self.llm_max_retries = int(os.environ.get("LLM_MAX_RETRIES", "1"))
        self.max_context_chars = int(os.environ.get("MAX_CONTEXT_CHARS", "8000"))


def get_settings() -> Settings:
    """Return Settings instance."""
    return Settings()
