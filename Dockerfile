# syntax=docker/dockerfile:1
# Production Dockerfile for Dependency Upgrade Risk Agent (Cloud Run)
# Uses astral-sh/uv for ultra-fast, reproducible dependency installation

FROM ghcr.io/astral-sh/uv:0.6.14 AS uv_bin

FROM python:3.12-slim

# Copy uv binary into image
COPY --from=uv_bin /uv /uvx /bin/

# Set working directory
WORKDIR /app

# Enable bytecode compilation and unbuffered stdout for Cloud Logging
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV HOME=/app
ENV UV_CACHE_DIR=/app/.cache/uv
ENV PATH="/app/.venv/bin:$PATH"

# Security: Create non-root system user with /app as home
RUN addgroup --system appgroup && adduser --system --ingroup appgroup --home /app appuser

# Copy pyproject and lockfile first for layer caching
COPY pyproject.toml uv.lock README.md /app/

# Install production dependencies only
RUN uv sync --frozen --no-install-project --no-dev

# Copy application source code
COPY src /app/src

# Install project package
RUN uv sync --frozen --no-dev

# Create cache directory and chown entire app to appuser
RUN mkdir -p /app/.cache/uv && chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Cloud Run defaults to PORT environment variable (default 8080)
EXPOSE 8080

# Execute FastAPI webhook application with uvicorn directly from virtualenv
CMD ["sh", "-c", "uvicorn risk_agent.webhook.app:app --host 0.0.0.0 --port ${PORT:-8080}"]
