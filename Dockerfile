# =============================================================================
# USecVisLib Docker Image
# Universal Security Visualization Library - API and CLI
# =============================================================================

FROM python:3.12-slim

# Labels
LABEL maintainer="VulnEx"
LABEL description="Universal Security Visualization Library - API and CLI"
LABEL version="0.1.5"

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
# - graphviz: Required for graph rendering (dot executable)
# - fonts: For proper text rendering in visualizations
# - libcairo2, libpango: Required for cairosvg (SVG to PNG conversion)
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz \
    fonts-dejavu-core \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy setup.py, README, and source code
COPY setup.py .
COPY README.md .
COPY src/ ./src/
COPY api/ ./api/
COPY templates/ ./templates/
COPY tests/ ./tests/
COPY assets/ ./assets/

# Install the package in editable mode
RUN pip install --no-cache-dir -e .

# Create directory for temporary files and fix ownership
RUN mkdir -p /app/tmp && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command: Run the API server
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
