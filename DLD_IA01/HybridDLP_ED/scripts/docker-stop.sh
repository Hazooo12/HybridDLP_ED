#!/bin/bash
# Docker stop script for HybridDLP

set -e

echo " Stopping HybridDLP Docker Services..."

# Stop services
docker-compose down

echo "[OK] All services stopped"
