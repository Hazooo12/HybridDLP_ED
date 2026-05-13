"""
Train UEBA Model using CERT Insider Threat Dataset + Synthetic Data
Uses Isolation Forest for unsupervised anomaly detection
Theo mô tả trong ML_DEVELOPMENT_PLAN.md
"""
import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator
import argparse
from datetime import datetime
import logging
import joblib
import random

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .cert_dataset_loader import CERTDatasetLoader
from .feature_extractor import EventFeatureExtractor


def load_jsonl_events_streaming(jsonl_path: Path, limit: Optional[int] = None, sample_ratio: Optional[float] = None) -> Iterator[Dict[str, Any]]:
    """
    Load events from JSONL file in streaming mode (memory efficient)
    Yields events one by one instead of loading all into memory
    
    Args:
        jsonl_path: Path to JSONL file
        limit: Maximum number of events to load (None = all)
        sample_ratio: Sample ratio (0.1 = 10%, None = no sampling)
    """
    if not jsonl_path.exists():
        logger.warning(f"JSONL file not found: {jsonl_path}")
        return
    
    logger.info(f"Streaming JSONL file: {jsonl_path}")
    if sample_ratio:
        logger.info(f"  Using sampling ratio: {sample_ratio*100:.1f}%")
    
    count = 0
    loaded = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if limit and count >= limit:
                break
            
            # Apply sampling
            if sample_ratio and random.random() > sample_ratio:
                continue
            
            try:
                event = json.loads(line.strip())
                yield event
                loaded += 1
                count += 1
                
                if loaded % 100000 == 0:
                    logger.info(f"  Streamed {loaded:,} events...")
            except json.JSONDecodeError:
                continue
    
    logger.info(f"[OK] Streamed {loaded:,} events from {jsonl_path}")


def load_jsonl_events(jsonl_path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Load events from JSONL file (TOÀN BỘ nếu limit=None)
    
    Args:
        jsonl_path: Path to JSONL file
        limit: Maximum number of events to load (None = load toàn bộ)
    """
    events = []
    if not jsonl_path.exists():
        logger.warning(f"JSONL file not found: {jsonl_path}")
        return events
    
    logger.info(f"Reading JSONL file: {jsonl_path}")
    line_count = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            line_count += 1
            try:
                event = json.loads(line.strip())
                events.append(event)
            except json.JSONDecodeError:
                continue
            
            # Log progress for large files (every 100k lines)
            if (i + 1) % 100000 == 0:
                logger.info(f"  Read {i + 1:,} lines, loaded {len(events):,} events...")
    
    logger.info(f"[OK] Loaded {len(events):,} events from {jsonl_path} (total lines: {line_count:,})")
    return events


def train_ueba_model(
    cert_data_dir: Optional[Path] = None,
    synthetic_data_path: Optional[Path] = None,
    agent_events_path: Optional[Path] = None,
    output_model_path: Optional[Path] = None,
    contamination: float = 0.01,
    n_estimators: int = 100,
    max_samples: int = 256,
    max_events_per_file: Optional[int] = None,
    sample_ratio: Optional[float] = None
) -> None:
    """
    Train Isolation Forest model for UEBA
    Theo ML_DEVELOPMENT_PLAN.md: Sử dụng Isolation Forest với contamination=0.01
    
    Args:
        cert_data_dir: Directory containing CERT dataset files
        synthetic_data_path: Path to synthetic events JSONL file
        agent_events_path: Path to real agent events JSONL file
        output_model_path: Path to save trained model
        contamination: Expected proportion of anomalies (default: 0.01 = 1%)
        n_estimators: Number of trees in Isolation Forest
        max_samples: Maximum samples per tree
        max_events_per_file: Maximum events to load per CERT file (None = all, use for large files)
        sample_ratio: Sample ratio for very large datasets (0.1 = 10%, None = no sampling)
    """
    # Default output path
    if output_model_path is None:
        output_model_path = Path(__file__).parent.parent / "worker" / "ml_models" / "ueba_iso_forest.pkl"
    
    output_model_path = Path(output_model_path)
    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    
    # OPTIMIZED: Extract features on-the-fly (không lưu toàn bộ events vào memory)
    logger.info("=" * 60)
    logger.info("OPTIMIZED TRAINING: Processing in chunks to save memory")
    logger.info("=" * 60)
    
    feature_extractor = EventFeatureExtractor()
    features_list = []
    event_history_buffer = []  # Sliding window buffer
    max_buffer_size = 1000  # Keep last 1000 events for frequency features
    
    total_processed = 0
    
    # 1. Process CERT dataset in chunks (MEMORY EFFICIENT)
    if cert_data_dir:
        cert_path = Path(cert_data_dir)
        logger.info(f"Processing CERT dataset from: {cert_path.absolute()}")
        
        if max_events_per_file:
            logger.info(f"[WARN]  Using limit: {max_events_per_file:,} events per file (to save memory)")
        else:
            logger.info("[WARN]  Processing TOÀN BỘ CERT dataset (may use a lot of memory)")
        
        cert_loader = CERTDatasetLoader(cert_path)
        
        # Process CERT events in chunks
        chunk_size = 10000
        cert_count = 0
        
        for cert_event in cert_loader.load_cert_events_streaming(limit=max_events_per_file, chunk_size=chunk_size):
            # Apply sampling if needed
            if sample_ratio and random.random() > sample_ratio:
                continue
            
            # Update event history buffer
            event_history_buffer.append(cert_event)
            if len(event_history_buffer) > max_buffer_size:
                event_history_buffer.pop(0)
            
            # Extract features on-the-fly
            feature_extractor.event_history = event_history_buffer[:-1]  # Exclude current event
            try:
                features = feature_extractor.extract(cert_event)
                features_list.append(features)
                cert_count += 1
                total_processed += 1
                
                if cert_count % 50000 == 0:
                    logger.info(f"  Processed {cert_count:,} CERT events, {len(features_list):,} features extracted...")
            except Exception as e:
                logger.debug(f"Error extracting features: {e}")
                continue
        
        logger.info(f"[OK] Processed {cert_count:,} CERT events")
    
    # 2. Process synthetic data in chunks
    if synthetic_data_path and Path(synthetic_data_path).exists():
        logger.info(f"Processing synthetic data from: {synthetic_data_path}")
        synthetic_count = 0
        
        for synthetic_event in load_jsonl_events_streaming(Path(synthetic_data_path), sample_ratio=sample_ratio):
            event_history_buffer.append(synthetic_event)
            if len(event_history_buffer) > max_buffer_size:
                event_history_buffer.pop(0)
            
            feature_extractor.event_history = event_history_buffer[:-1]
            try:
                features = feature_extractor.extract(synthetic_event)
                features_list.append(features)
                synthetic_count += 1
                total_processed += 1
                
                if synthetic_count % 50000 == 0:
                    logger.info(f"  Processed {synthetic_count:,} synthetic events...")
            except Exception as e:
                logger.debug(f"Error extracting features: {e}")
                continue
        
        logger.info(f"[OK] Processed {synthetic_count:,} synthetic events")
    
    # 3. Process agent events in chunks
    if agent_events_path and Path(agent_events_path).exists():
        logger.info(f"Processing agent events from: {agent_events_path}")
        agent_count = 0
        
        for agent_event in load_jsonl_events_streaming(Path(agent_events_path), sample_ratio=sample_ratio):
            event_history_buffer.append(agent_event)
            if len(event_history_buffer) > max_buffer_size:
                event_history_buffer.pop(0)
            
            feature_extractor.event_history = event_history_buffer[:-1]
            try:
                features = feature_extractor.extract(agent_event)
                features_list.append(features)
                agent_count += 1
                total_processed += 1
            except Exception as e:
                logger.debug(f"Error extracting features: {e}")
                continue
        
        logger.info(f"[OK] Processed {agent_count:,} agent events")
    
    if len(features_list) == 0:
        logger.error("No features extracted! Please check data sources.")
        return
    
    logger.info(f"[OK] Total features extracted: {len(features_list):,} from {total_processed:,} events")
    
    if len(features_list) == 0:
        logger.error("No features extracted! Check event format.")
        return
    
    # Convert to numpy array
    X = np.array(features_list)
    logger.info(f"Feature matrix shape: {X.shape}")
    logger.info(f"Feature names: {feature_extractor.get_feature_names()}")
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    logger.info(f"Training Isolation Forest (contamination={contamination}, n_estimators={n_estimators})...")
    model = IsolationForest(
        contamination=contamination,
        n_estimators=n_estimators,
        max_samples=max_samples,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)
    
    # Predict on training data to see distribution
    predictions = model.predict(X_scaled)
    anomaly_count = np.sum(predictions == -1)
    logger.info(f"Detected {anomaly_count} anomalies ({anomaly_count/len(predictions)*100:.2f}%) in training data")
    
    # Save model and scaler
    model_data = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_extractor.get_feature_names(),
        'trained_at': datetime.now().isoformat(),
        'n_samples': len(X),
        'contamination': contamination
    }
    
    joblib.dump(model_data, output_model_path)
    logger.info(f"Model saved to {output_model_path}")
    logger.info("Training completed!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train UEBA model using CERT + Synthetic data")
    parser.add_argument(
        "--cert-dir",
        type=str,
        help="Directory containing CERT dataset files (Dataset folder)"
    )
    parser.add_argument(
        "--synthetic",
        type=str,
        help="Path to synthetic events JSONL file"
    )
    parser.add_argument(
        "--agent-events",
        type=str,
        help="Path to real agent events JSONL file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output model path (default: worker/ml_models/ueba_iso_forest.pkl)"
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.01,
        help="Expected proportion of anomalies (default: 0.01)"
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of trees in Isolation Forest (default: 100)"
    )
    parser.add_argument(
        "--max-events-per-file",
        type=int,
        default=None,
        help="Maximum events per CERT file (for large files, e.g., 1000000)"
    )
    parser.add_argument(
        "--sample-ratio",
        type=float,
        default=None,
        help="Sample ratio for very large datasets (0.1 = 10%%, 0.01 = 1%%)"
    )
    
    args = parser.parse_args()
    
    train_ueba_model(
        cert_data_dir=Path(args.cert_dir) if args.cert_dir else None,
        synthetic_data_path=Path(args.synthetic) if args.synthetic else None,
        agent_events_path=Path(args.agent_events) if args.agent_events else None,
        output_model_path=Path(args.output) if args.output else None,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        max_events_per_file=args.max_events_per_file,
        sample_ratio=args.sample_ratio
    )
