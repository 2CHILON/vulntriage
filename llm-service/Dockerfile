FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY llm-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY llm-service/llm_service ./llm_service

# Create non-root user
RUN useradd -m -u 1000 llmuser && chown -R llmuser:llmuser /app
USER llmuser

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Run uvicorn
CMD ["uvicorn", "llm_service.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
