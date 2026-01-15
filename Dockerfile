# =============================================================================
# USecVisLib Docker Image
# Universal Security Visualization Library - API and CLI
# =============================================================================

FROM python:3.12-slim

# Labels
LABEL maintainer="VulnEx"
LABEL description="Universal Security Visualization Library - API and CLI"
LABEL version="0.3.3"

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
# - graphviz: Required for graph rendering (dot executable)
# - fonts: For proper text rendering in visualizations
# - libcairo2, libpango: Required for cairosvg (SVG to PNG conversion)
# - nodejs, npm: Required for mermaid-cli
# - chromium: Required for mermaid-cli puppeteer
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz \
    fonts-dejavu-core \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    nodejs \
    npm \
    chromium \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install mermaid-cli globally with extended timeouts for large package
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
RUN npm config set fetch-timeout 600000 && \
    npm config set fetch-retries 5 && \
    npm install -g @mermaid-js/mermaid-cli

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy setup.py, README, and source code
# NOTE: Ensure git submodules are initialized before building:
#   git submodule update --init --recursive
COPY setup.py .
COPY README.md .
COPY src/ ./src/
COPY api/ ./api/
COPY templates/ ./templates/
COPY tests/ ./tests/
COPY assets/ ./assets/
COPY puppeteer-config.json .

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
