# Multi-stage Docker build for DMARRSS
# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY pyproject.toml ./
COPY src/ ./src/

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Stage 2: Runtime
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash dmarrss

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/dmarrss /usr/local/bin/dmarrss

# Copy application
COPY --chown=dmarrss:dmarrss src/ /app/src/
COPY --chown=dmarrss:dmarrss config/ /app/config/
COPY --chown=dmarrss:dmarrss scripts/ /app/scripts/
COPY --chown=dmarrss:dmarrss pyproject.toml /app/

# Create data directories
RUN mkdir -p /app/data/raw /app/data/state /app/data/models /app/data/training /app/data/reputation && \
    chown -R dmarrss:dmarrss /app/data

# Switch to non-root user
USER dmarrss

# Set Python path
ENV PYTHONPATH=/app/src:$PYTHONPATH

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/status || exit 1

# Default command: run daemon
CMD ["dmarrss", "run"]
