# ==============================================================================
# HamiCard (حامی‌کارت) Production Dockerfile
# Baseline: BL-HAMICARD-PRD-V1 | Python 3.13 Slim
# ==============================================================================

FROM python:3.13-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final runtime image
FROM python:3.13-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH \
    PYTHONPATH=.

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m appuser

# Copy installed packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source code and strip dev/experimental PoC artifacts from release image
COPY --chown=appuser:appuser src ./src
COPY --chown=appuser:appuser db ./db
RUN rm -f src/static/auth_poc* src/static/index.html

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["python", "-m", "src.api.release_entrypoint"]

