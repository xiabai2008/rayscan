# ─────────────────────────────────────────────────────────────
# Builder stage: installs dev dependencies and builds the wheel
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Build backend must be available locally for --no-isolation builds
RUN pip install --no-cache-dir --upgrade pip setuptools wheel build

# Copy only what is required to build the distribution
COPY pyproject.toml README.md ./
COPY wvs ./wvs

# Install dev dependencies in the builder (tests / lint tooling) and build a wheel.
# The wheel carries [project.dependencies] only, so the runtime stage stays lean.
RUN pip install --no-cache-dir ".[dev]" \
    && python -m build --wheel --no-isolation

# ─────────────────────────────────────────────────────────────
# Runtime stage: only runtime deps + non-root execution
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install the wheel built by the builder. This pulls [project.dependencies]
# (requests / httpx / flask / beautifulsoup4 / lxml / pyyaml / colorama / aiohttp / rich)
# and NOT the dev tooling (ruff / mypy / pytest / ...).
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -rf /tmp/*.whl

# Run as an unprivileged user for least-privilege execution
RUN useradd --create-home --uid 1000 --shell /bin/sh rayscan

USER rayscan

# Default command: help
ENTRYPOINT ["python", "-m", "wvs"]
CMD ["--help"]
