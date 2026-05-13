#!/bin/bash
# Script để train UEBA model
# Sử dụng: ./train.sh

cd "$(dirname "$0")/.."

echo "=== Generating Synthetic Data ==="
python -m ML.generate_synthetic_data \
    --output synthetic_events.jsonl \
    --normal 10000 \
    --anomalous 50

echo ""
echo "=== Training UEBA Model ==="
python -m ML.train_ueba \
    --cert-dir Dataset \
    --synthetic synthetic_events.jsonl \
    --output worker/ml_models/ueba_iso_forest.pkl \
    --contamination 0.01 \
    --n-estimators 100

echo ""
echo "=== Training Complete ==="
echo "Model saved to: worker/ml_models/ueba_iso_forest.pkl"
