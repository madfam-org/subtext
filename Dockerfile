# Subtext API Dockerfile — multi-stage production build.
#
# Why two stages:
#   - Stage 1 builds wheels for every dep into a clean prefix the runtime
#     stage can copy. Keeps the runtime image small (no gcc, no build headers).
#   - Runtime installs only the system libs the Python packages need at
#     execution (libsndfile for soundfile, ffmpeg for librosa, etc.).
#
# Why NOT install .[dev]:
#   - The dev extra pulls pytest/ruff/mypy/pre-commit — none of which run
#     inside the container. They bloat the image and slow builds.
#   - Earlier versions tried `pip install -e ".[dev]"` before copying src/,
#     which fails because editable mode needs the package directory on disk.

# ══════════════════════════════════════════════════════════════
# Stage 1: Build wheels
# ══════════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy everything needed for the install up front. pyproject is the
# only thing that determines dep resolution; src is what the package
# actually installs.
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package and its runtime deps (NOT the dev extra) into the
# system site-packages so we can copy the whole tree to the runtime stage.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# ══════════════════════════════════════════════════════════════
# Stage 2: Runtime
# ══════════════════════════════════════════════════════════════
FROM python:3.11-slim AS runtime

WORKDIR /app

# Runtime system deps:
#   - ffmpeg: librosa backends for mp3/wav/etc.
#   - libsndfile1: soundfile I/O.
#   - curl: health-check probe.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ffmpeg \
    libsndfile1 \
    && rm -rf /var/lib/apt/lists/*

# Bring over the Python packages + console scripts from the builder.
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Application source lives alongside the installed package. The install
# in the builder stage already wired everything up; this is just the
# in-repo view for debugging + for packages that resolve via importlib.
COPY src/ ./src/

# Non-root for prod.
RUN useradd --create-home --shell /bin/bash --uid 1001 appuser && \
    chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "subtext.api:app", "--host", "0.0.0.0", "--port", "8000"]
