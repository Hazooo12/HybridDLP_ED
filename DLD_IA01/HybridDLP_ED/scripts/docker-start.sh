#!/bin/bash
# Docker startup script for HybridDLP

set -e

echo "[START] Starting HybridDLP Docker Services..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "[FAIL] Docker is not running. Please start Docker first."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "[FAIL] docker-compose is not installed. Please install docker-compose first."
    exit 1
fi

# Build images
echo " Building Docker images..."
docker-compose build

# Start services
echo "▶️  Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 5

# Check Worker
echo "[SEARCH] Checking Worker..."
if docker ps | grep -q hybrid-dlp-worker; then
    echo "[OK] Worker is running"
else
    echo "[WARN]  Worker may not be ready yet"
fi

# Check Dashboard
echo "[SEARCH] Checking Dashboard..."
sleep 3
if curl -f http://localhost:8501/_stcore/health > /dev/null 2>&1; then
    echo "[OK] Dashboard is accessible at http://localhost:8501"
else
    echo "[WARN]  Dashboard may not be ready yet"
fi

echo ""
echo " HybridDLP is starting up!"
echo ""
echo "[CHART] Dashboard: http://localhost:8501"
echo "[DOC] View logs: docker-compose logs -f"
echo " Stop: docker-compose down"
echo ""
