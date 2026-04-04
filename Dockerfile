# ── PIP — PrivEsc Intelligence Platform ──────────────────────────────────────
# Multi-stage build: lean runtime image (~180MB) from a full build stage.
#
# Build:   docker build -t pip-toolkit:2.0.0 .
# Run CLI: docker run --rm -it --network host pip-toolkit:2.0.0 scan --mode deep
# Run API: docker run --rm -p 8443:8443 -e PIP_JWT_SECRET=<secret> pip-toolkit:2.0.0 serve
#
# IMPORTANT: When running against a local target, mount the host PID/proc
# namespace with extreme caution and only in authorised test environments:
#   docker run --rm -it --pid=host --network=host pip-toolkit:2.0.0 scan

# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for Docker layer caching
COPY requirements.txt requirements-dev.txt pyproject.toml ./

# Install runtime dependencies into a prefix directory
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="PIP — PrivEsc Intelligence Platform"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.description="Next-generation Linux privilege escalation intelligence toolkit."
LABEL org.opencontainers.image.url="https://github.com/yourusername/pip-toolkit"
LABEL org.opencontainers.image.licenses="MIT"

# Runtime system packages (curl needed for IMDS checks, less for paging)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    procps \
    less \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Create non-root user for API server mode
# (CLI scan mode may still need elevated access depending on target)
RUN useradd --system --create-home --shell /bin/bash pip

WORKDIR /app

# Copy application source
COPY pip.py        ./pip.py
COPY pip/          ./pip/
COPY plugins/      ./plugins/
COPY data/         ./data/
COPY docs/         ./docs/

# Default output directory — mount a volume here for persistent reports
RUN mkdir -p /output && chown pip:pip /output
VOLUME ["/output"]

# Environment configuration
ENV PIP_JWT_SECRET=""
ENV PIP_API_KEYS=""
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose API port
EXPOSE 8443

# Entrypoint: route to pip.py with whatever command is passed
ENTRYPOINT ["python", "pip.py"]

# Default command: show help
CMD ["--help"]

# ── Health check for API mode ─────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8443/health || exit 1

# ── Usage examples (in comments, not executed) ────────────────────────────────
# CLI scan:
#   docker run --rm -it pip-toolkit:2.0.0 scan --mode deep --output /output
#
# API server:
#   docker run -d -p 8443:8443 \
#     -e PIP_JWT_SECRET=my-secret \
#     -v $(pwd)/reports:/output \
#     pip-toolkit:2.0.0 serve --host 0.0.0.0 --port 8443
#
# Sync knowledge base:
#   docker run --rm pip-toolkit:2.0.0 update
