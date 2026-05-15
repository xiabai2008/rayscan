FROM python:3.11-slim

WORKDIR /app

# Install system deps for optional tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

# Install the project
COPY . .
RUN pip install --no-cache-dir -e .

# Default command: help
ENTRYPOINT ["python", "-m", "wvs"]
CMD ["--help"]
