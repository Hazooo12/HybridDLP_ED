#!/bin/bash
# Setup ML models script

set -e

echo " Setting up ML models..."

cd worker

# Create directories
mkdir -p ml_models dataset/sensitive dataset/normal

# Collect dataset
echo "[CHART] Collecting dataset..."
python scripts/collect_dataset.py

# Train model
echo " Training ML model..."
python scripts/train_model.py

echo "[OK] ML models setup completed!"
echo "   Models location: worker/ml_models/"
