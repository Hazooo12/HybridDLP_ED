"""
Train UEBA Model using CERT Insider Threat Dataset + Synthetic Data
Uses Isolation Forest for unsupervised anomaly detection
"""
import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse
from datetime import datetime
from loguru import logger
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

from .feature_extractor import EventFeatureExtractor


class CERTDatasetLoader:
    """
    Load and convert CERT Insider Threat Dataset to agent event format
    """
    
    def __init__(self, cert_data_dir: Path):
        """
        Initialize CERT dataset loader
        
        Args:
            cert_data_dir: Directory containing CERT dataset files
        """
        self.cert_data_dir = Path(cert_data_dir)
    
    def load_cert_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Load CERT dataset and convert to agent event format
        
        Note: This is a simplified converter. In production, you would need
        to map CERT's specific fields (logon.csv, file.csv, email.csv, http.csv)
        to your agent's event format.
        
        Args:
            limit: Maximum number of events to load (None = all)
        
        Returns:
            List of events in agent format
        """
        events = []
        
        # CERT dataset structure (example):
        # - logon.csv: user, pc, date, time, activity, logon_type
        # - file.csv: user, pc, date, time, filename, activity
        # - email.csv: user, pc, date, time, to, cc, bcc, size, attachment
        # - http.csv: user, pc, date, time, url, content
        
        # Check if CERT files exist
        logon_file = self.cert_data_dir / "logon.csv"
        file_file = self.cert_data_dir / "file.csv"
        email_file = self.cert_data_dir / "email.csv"
        http_file = self.cert_data_dir / "http.csv"
        
        if not any([logon_file.exists(), file_file.exists(), email_file.exists(), http_file.exists()]):
            logger.warning(f"CERT dataset files not found in {self.cert_data_dir}")
            logger.info("Expected files: logon.csv, file.csv, email.csv, http.csv")
            return events
        
        # Load file events (most relevant for DLP)
        if file_file.exists():
            try:
                df = pd.read_csv(file_file, nrows=limit)
                logger.info(f"Loading {len(df)} file events from CERT dataset")
                
                for _, row in df.iterrows():
                    # Convert CERT file event to agent format
                    event = self._convert_cert_file_event(row)
                    if event:
                        events.append(event)
            except Exception as e:
                logger.error(f"Error loading CERT file.csv: {e}")
        
        # Load email events (for exfiltration detection)
        if email_file.exists():
            try:
                df = pd.read_csv(email_file, nrows=limit)
                logger.info(f"Loading {len(df)} email events from CERT dataset")
                
                for _, row in df.iterrows():
                    event = self._convert_cert_email_event(row)
                    if event:
                        events.append(event)
            except Exception as e:
                logger.error(f"Error loading CERT email.csv: {e}")
        
        # Load HTTP events (for network upload detection)
        if http_file.exists():
            try:
                df = pd.read_csv(http_file, nrows=limit)
                logger.info(f"Loading {len(df)} HTTP events from CERT dataset")
                
                for _, row in df.iterrows():
                    event = self._convert_cert_http_event(row)
                    if event:
                        events.append(event)
            except Exception as e:
                logger.error(f"Error loading CERT http.csv: {e}")
        
        logger.info(f"Total CERT events loaded: {len(events)}")
        return events
    
    def _convert_cert_file_event(self, row: pd.Series) -> Optional[Dict[str, Any]]:
        """Convert CERT file.csv row to agent event format"""
        try:
            # CERT format: user, pc, date, time, filename, activity
            user = str(row.get('user', 'unknown'))
            date = str(row.get('date', ''))
            time = str(row.get('time', ''))
            filename = str(row.get('filename', ''))
            activity = str(row.get('activity', '')).lower()
            
            # Parse datetime
            try:
                dt = datetime.strptime(f"{date} {time}", "%m/%d/%Y %H:%M:%S")
                dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
            except:
                dt = datetime.now()
            
            # Map activity to event type
            if 'copy' in activity or 'read' in activity:
                event_type = "file_copy"
            elif 'write' in activity or 'create' in activity:
                event_type = "file_copy"
            else:
                event_type = "file_copy"  # Default
            
            pc = str(row.get('pc', ''))
            
            event = {
                "ts": dt.isoformat(),
                "timestamp": dt.isoformat(),
                "type": event_type,
                "event_type": event_type,
                "user": user,
                "source": "cert_dataset",
                "device": {
                    "host_name": pc if pc else None
                },
                "context": {
                    "user": user,
                    "process_name": "explorer.exe",
                    "active_window": "File Explorer"
                },
                "object": {
                    "path": filename,
                    "size_bytes": 0  # CERT doesn't provide size
                },
                "operation": {
                    "op_type": "copy" if "copy" in activity else "read"
                },
                "metrics": {
                    "entropy": 3.5  # Default
                }
            }
            
            return event
        except Exception as e:
            logger.debug(f"Error converting CERT file event: {e}")
            return None
    
    def _convert_cert_email_event(self, row: pd.Series) -> Optional[Dict[str, Any]]:
        """Convert CERT email.csv row to agent event format"""
        try:
            user = str(row.get('user', 'unknown'))
            date = str(row.get('date', ''))
            time = str(row.get('time', ''))
            size = int(row.get('size', 0))
            to_email = str(row.get('to', ''))
            attachment = str(row.get('attachment', ''))
            pc = str(row.get('pc', ''))
            
            # Extract domain from email address
            dest_domain = ''
            if '@' in to_email:
                dest_domain = to_email.split('@')[1].lower()
            elif to_email:
                dest_domain = to_email.lower()
            
            # Parse datetime
            try:
                dt = datetime.strptime(f"{date} {time}", "%m/%d/%Y %H:%M:%S")
                dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
            except:
                dt = datetime.now()
            
            event = {
                "ts": dt.isoformat(),
                "timestamp": dt.isoformat(),
                "type": "clipboard_paste",  # Email as clipboard paste to external
                "event_type": "clipboard_paste",
                "user": user,
                "source": "cert_dataset",
                "device": {
                    "host_name": pc if pc else None
                },
                "context": {
                    "user": user,
                    "process_name": "outlook.exe",
                    "active_window": "Outlook",
                    "dest_domain": dest_domain
                },
                "clipboard": {
                    "content_type": "Text",
                    "content": f"Email content {size} bytes",
                    "content_len": size,
                    "dest_app": "outlook.exe",
                    "dest_domain": dest_domain,
                    "snapshot_linked": True
                },
                "object": {
                    "path": attachment if attachment else None,
                    "size_bytes": size if attachment else 0
                },
                "operation": {
                    "op_type": "paste"
                },
                "metrics": {
                    "entropy": 4.0
                }
            }
            
            return event
        except Exception as e:
            logger.debug(f"Error converting CERT email event: {e}")
            return None
    
    def _convert_cert_http_event(self, row: pd.Series) -> Optional[Dict[str, Any]]:
        """Convert CERT http.csv row to agent event format"""
        try:
            import re
            from urllib.parse import urlparse
            
            user = str(row.get('user', 'unknown'))
            date = str(row.get('date', ''))
            time = str(row.get('time', ''))
            url = str(row.get('url', ''))
            content = str(row.get('content', ''))
            pc = str(row.get('pc', ''))
            
            # Extract domain from URL
            dest_domain = ''
            try:
                parsed = urlparse(url)
                dest_domain = parsed.netloc.lower() if parsed.netloc else ''
            except:
                # Fallback: extract domain manually
                if '://' in url:
                    dest_domain = url.split('://')[1].split('/')[0].lower()
            
            # Determine if upload (POST) or download (GET)
            is_upload = any(keyword in url.lower() for keyword in ['upload', 'post', 'send', 'submit'])
            op_type = "upload" if is_upload else "download"
            
            # Parse datetime
            try:
                dt = datetime.strptime(f"{date} {time}", "%m/%d/%Y %H:%M:%S")
                dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
            except:
                dt = datetime.now()
            
            event = {
                "ts": dt.isoformat(),
                "timestamp": dt.isoformat(),
                "type": "network_upload" if is_upload else "network_download",
                "event_type": "network_upload" if is_upload else "network_download",
                "user": user,
                "source": "cert_dataset",
                "device": {
                    "host_name": pc if pc else None
                },
                "context": {
                    "user": user,
                    "process_name": "chrome.exe",
                    "active_window": "Browser",
                    "dest_domain": dest_domain
                },
                "object": {
                    "path": url,
                    "dst_path": url
                },
                "network": {
                    "dest_url": url,
                    "dest_domain": dest_domain,
                    "method": "POST" if is_upload else "GET",
                    "external_dst": True if dest_domain and not dest_domain.endswith('.company.com') else False
                },
                "content": {
                    "sample": content[:1000] if content else None,  # Limit sample size
                    "sample_len": len(content) if content else 0
                },
                "operation": {
                    "op_type": op_type
                },
                "metrics": {
                    "entropy": 4.5
                }
            }
            
            return event
        except Exception as e:
            logger.debug(f"Error converting CERT http event: {e}")
            return None


def load_jsonl_events(jsonl_path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Load events from JSONL file"""
    events = []
    if not jsonl_path.exists():
        logger.warning(f"JSONL file not found: {jsonl_path}")
        return events
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            try:
                event = json.loads(line.strip())
                events.append(event)
            except json.JSONDecodeError:
                continue
    
    logger.info(f"Loaded {len(events)} events from {jsonl_path}")
    return events


def train_ueba_model(
    cert_data_dir: Optional[Path] = None,
    synthetic_data_path: Optional[Path] = None,
    agent_events_path: Optional[Path] = None,
    output_model_path: Optional[Path] = None,
    contamination: float = 0.01,
    n_estimators: int = 100,
    max_samples: int = 256
) -> None:
    """
    Train Isolation Forest model for UEBA
    
    Args:
        cert_data_dir: Directory containing CERT dataset files
        synthetic_data_path: Path to synthetic events JSONL file
        agent_events_path: Path to real agent events JSONL file
        output_model_path: Path to save trained model
        contamination: Expected proportion of anomalies (default: 0.01 = 1%)
        n_estimators: Number of trees in Isolation Forest
        max_samples: Maximum samples per tree
    """
    from config import WorkerConfig
    
    if output_model_path is None:
        output_model_path = WorkerConfig.ML_MODELS_DIR / "ueba_iso_forest.pkl"
    
    output_model_path = Path(output_model_path)
    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Load events from all sources
    all_events = []
    
    # 1. Load CERT dataset
    if cert_data_dir:
        cert_loader = CERTDatasetLoader(Path(cert_data_dir))
        cert_events = cert_loader.load_cert_events(limit=50000)  # Limit for training speed
        all_events.extend(cert_events)
        logger.info(f"Loaded {len(cert_events)} events from CERT dataset")
    
    # 2. Load synthetic data
    if synthetic_data_path and Path(synthetic_data_path).exists():
        synthetic_events = load_jsonl_events(Path(synthetic_data_path))
        all_events.extend(synthetic_events)
        logger.info(f"Loaded {len(synthetic_events)} events from synthetic data")
    
    # 3. Load real agent events (if available)
    if agent_events_path and Path(agent_events_path).exists():
        agent_events = load_jsonl_events(Path(agent_events_path), limit=10000)
        all_events.extend(agent_events)
        logger.info(f"Loaded {len(agent_events)} events from agent")
    
    if len(all_events) == 0:
        logger.error("No events loaded! Please provide at least one data source.")
        return
    
    logger.info(f"Total events for training: {len(all_events)}")
    
    # Extract features
    logger.info("Extracting features...")
    feature_extractor = EventFeatureExtractor()
    features_list = []
    
    for i, event in enumerate(all_events):
        if i % 1000 == 0:
            logger.info(f"Processing event {i}/{len(all_events)}")
        
        try:
            # Use recent events for frequency calculation
            recent_events = all_events[max(0, i-100):i] if i > 0 else []
            feature_extractor.event_history = recent_events
            
            features = feature_extractor.extract(event)
            features_list.append(features)
        except Exception as e:
            logger.debug(f"Error extracting features from event {i}: {e}")
            continue
    
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
    
    # Print feature importance (if available)
    logger.info("Training completed!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train UEBA model using CERT + Synthetic data")
    parser.add_argument(
        "--cert-dir",
        type=str,
        help="Directory containing CERT dataset files (logon.csv, file.csv, email.csv, http.csv)"
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
    
    args = parser.parse_args()
    
    train_ueba_model(
        cert_data_dir=Path(args.cert_dir) if args.cert_dir else None,
        synthetic_data_path=Path(args.synthetic) if args.synthetic else None,
        agent_events_path=Path(args.agent_events) if args.agent_events else None,
        output_model_path=Path(args.output) if args.output else None,
        contamination=args.contamination,
        n_estimators=args.n_estimators
    )
