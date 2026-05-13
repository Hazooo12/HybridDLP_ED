# Detection Engine (L3) Dockerfile
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Ho_Chi_Minh \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tesseract-ocr \
    tesseract-ocr-vie \
    libtesseract-dev \
    libleptonica-dev \
    libmagic1 \
    yara \
    libyara-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy worker code
COPY . ./

# Create necessary directories
RUN mkdir -p logs ml_models database dataset \
    && python -c "from pathlib import Path; [Path(d).mkdir(parents=True, exist_ok=True) for d in ['logs', 'ml_models', 'database', 'dataset']]"

# Set working directory
WORKDIR /app

# Environment variables
ENV LOG_LEVEL=INFO

# Run worker
CMD ["python", "worker.py"]
