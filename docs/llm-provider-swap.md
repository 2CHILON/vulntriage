# LLM Provider Swap Guide

This guide explains how to swap from the mock LLM provider (used in Phase 3) to a real provider (OpenAI, Anthropic, etc.) in Phase 4 or later.

## Current State

**Phase 3** ships with:
- **Mock Provider** (`llm-service/app/providers/mock.py`): Deterministic, no network calls, safe for testing
- **Real Provider Stub** (`llm-service/app/providers/real.py`): NotImplementedError; TODO markers show where to add real API calls

## Finding All TODO(REAL-LLM) Locations

Every place that needs changes to support a real provider is marked with `TODO(REAL-LLM)`.

**Find all markers:**
```bash
grep -rn "TODO(REAL-LLM)" llm-service deploy docs .env.example
```

**Current locations (Phase 3):**
- `llm-service/app/config.py` – LLM_API_KEY, LLM_MODEL settings
- `llm-service/app/providers/__init__.py` – Factory registration for new providers
- `llm-service/app/providers/real.py` – Complete method implementation, error handling, logging
- `.env.example` – Placeholder env vars

## Steps to Implement a Real Provider

### 1. Update `.env.example`

```bash
# Replace TODO(REAL-LLM) placeholders with real settings
LLM_PROVIDER=openai  # or "anthropic", etc.
LLM_API_KEY=sk-your-key-here
LLM_MODEL=gpt-4-turbo  # or "claude-3-sonnet", etc.
```

### 2. Create `.env` for local development

```bash
cp .env.example .env
# Edit .env with your real API key and provider name
```

### 3. Implement `RealProvider.complete()`

**In `llm-service/app/providers/real.py`:**

```python
def complete(self, system: str, user: str) -> str:
    """Call the vendor API here."""
    # TODO(REAL-LLM): call the vendor API here
    # Example for OpenAI:
    import openai
    response = openai.ChatCompletion.create(
        model=self.model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        timeout=self.timeout,
    )
    return response.choices[0].message.content
    # TODO(REAL-LLM): never log api_key
    # TODO(REAL-LLM): map vendor errors to ProviderError
```

### 4. Add Vendor SDK to requirements.txt

```bash
# Add the appropriate SDK (e.g., openai, anthropic)
openai==1.X.X  # Pin exact version
```

### 5. Update Provider Factory

**In `llm-service/app/providers/__init__.py`:**

```python
# TODO(REAL-LLM): add more real providers as needed (openai, anthropic, etc.)
if provider_name == "openai":
    from llm_service.app.providers.openai_provider import OpenAIProvider
    return OpenAIProvider(...)
```

### 6. Test with Real Provider

```bash
# Install vendor SDK
pip install -r requirements.txt

# Run tests (should still pass, but now hitting real API)
PYTHONPATH=.. python -m pytest -v

# Manual test
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @testdata/llm/sample-request.json
```

## Important: Code Context Redaction (Phase 4)

**⚠️ WARNING:** The code context in this phase is **NOT REDACTED**. It's treated as untrusted data for prompt injection, but secrets/credentials may appear in plain text in the LLM API calls.

**Phase 4** will implement:
- Secret detection and redaction before sending to LLM
- Safe logging and error handling
- Audit trails for sensitive processing

**Until Phase 4 is complete:** Only use the real provider with **sample code or non-sensitive repositories**. Do not analyze production code with embedded secrets or credentials.

## Error Handling

Implement these error cases in `RealProvider.complete()`:

```python
try:
    # API call here
    # TODO(REAL-LLM): map vendor errors to ProviderError
except TimeoutError as e:
    raise ProviderError(f"LLM provider timeout: {e}")
except AuthenticationError as e:
    raise ProviderError("LLM provider authentication failed")
except Exception as e:
    raise ProviderError(f"LLM provider error: {e}")
```

## Logging Security

**Never log:**
- API keys or tokens
- Full code context
- Full LLM responses (may contain sensitive inferences)

**Safe to log:**
- Finding ID, provider name, attempt number
- Status (ok, analysis_failed)
- Generic error messages

```python
# ✅ GOOD
logger.info(f"Finding {finding_id}: LLM provider {provider} attempt {attempt}")

# ❌ BAD
logger.debug(f"API key: {api_key}")  # TODO(REAL-LLM): never log api_key
logger.debug(f"Full code: {code_snippet}")
logger.debug(f"LLM response: {raw_response}")
```

## Switching Between Providers

To switch from mock → real (or real → different real):

```bash
# Edit .env
LLM_PROVIDER=openai
LLM_API_KEY=sk-...

# Restart service
docker compose down
docker compose up -d llm-service
```

The app will re-initialize the provider on startup.

## Fallback Strategy

For robustness, consider:
- Primary provider: real (OpenAI, Anthropic)
- Fallback provider: mock (always available, deterministic)

```python
# In get_provider():
try:
    real_provider = RealProvider(...)
    return real_provider
except ProviderError:
    logger.warning("Real provider failed, falling back to mock")
    return MockProvider()
```

---

**Next:** Phase 4 adds secret redaction, audit logging, and production hardening.
