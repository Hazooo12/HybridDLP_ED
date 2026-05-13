"""
Behavioral ML Analyzer - Real-time UEBA anomaly detection
"""
import numpy as np
from typing import Dict, Any, Optional
from pathlib import Path
import joblib
from loguru import logger

from .feature_extractor import EventFeatureExtractor


def _normalize_anomaly_raw(raw_score: float) -> float:
    """
    Normalize IsolationForest raw decision score to [0,10] (cùng thang risk score).
    """
    from config import WorkerConfig
    method = (WorkerConfig.ML_ANOMALY_NORM_METHOD or "percentile").lower()
    if method == "minmax":
        lo = float(WorkerConfig.ML_ANOMALY_MIN)
        hi = float(WorkerConfig.ML_ANOMALY_MAX)
    else:
        lo = float(WorkerConfig.ML_ANOMALY_P5)
        hi = float(WorkerConfig.ML_ANOMALY_P95)
    if hi <= lo:
        lo, hi = -1.0, 1.0
    x = min(max(float(raw_score), lo), hi)
    return max(0.0, min(10.0, (x - lo) / (hi - lo) * 10.0))


class BehavioralMLAnalyzer:
    """
    Load trained Isolation Forest model and predict anomaly scores
    """
    
    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize ML analyzer
        
        Args:
            model_path: Path to trained Isolation Forest model (.pkl file)
        """
        if model_path is None:
            from config import WorkerConfig
            model_path = WorkerConfig.ML_MODELS_DIR / "ueba_iso_forest.pkl"
        
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.feature_extractor = EventFeatureExtractor()
        self.is_loaded = False
        if not self.model_path.exists():
            logger.warning(f"UEBA model not found at {self.model_path}. Anomaly detection disabled.")
    
    def load_model(self) -> bool:
        """Load Isolation Forest model from disk"""
        try:
            model_data = joblib.load(self.model_path)
            
            # Handle both old format (direct model) and new format (dict with model + scaler)
            if isinstance(model_data, dict):
                self.model = model_data['model']
                self.scaler = model_data.get('scaler')
                self.feature_names = model_data.get('feature_names', [])
            else:
                # Old format: direct model
                self.model = model_data
                self.scaler = None
                self.feature_names = []
            
            self.is_loaded = True
            logger.info(f"UEBA model loaded from {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load UEBA model: {e}")
            self.is_loaded = False
            return False
    
    def predict(self, event: Dict[str, Any], event_history: Optional[list] = None) -> Dict[str, Any]:
        """
        Predict anomaly score for an event
        
        Args:
            event: Event dictionary
            event_history: List of recent events for frequency calculations
        
        Returns:
            Dictionary with:
            - anomaly_score: float [0, 10] (higher = more anomalous)
            - is_anomaly: bool
            - features: numpy array
        """
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        if not self.is_loaded or self.model is None:
            return {
                'anomaly_score': 0.0,
                'is_anomaly': False,
                'features': None,
                'error': 'Model not loaded'
            }
        
        try:
            # Update feature extractor with event history
            if event_history:
                self.feature_extractor.event_history = event_history
            
            # Extract features
            features = self.feature_extractor.extract(event)
            features_2d = features.reshape(1, -1)  # Shape: (1, n_features)
            
            # Scale features if scaler is available
            if self.scaler is not None:
                features_2d = self.scaler.transform(features_2d)
            
            # Predict anomaly score
            # Isolation Forest returns: -1 (anomaly) to 1 (normal)
            raw_score = self.model.decision_function(features_2d)[0]
            
            # Calibrated to [0,10] with configured normalization policy.
            anomaly_score = _normalize_anomaly_raw(raw_score)
            
            # Threshold: score > threshold is considered anomaly (configurable)
            from config import WorkerConfig
            threshold = WorkerConfig.ML_ANOMALY_THRESHOLD
            is_anomaly = anomaly_score > threshold
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': is_anomaly,
                'features': features,
                'raw_score': float(raw_score)
            }
        
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return {
                'anomaly_score': 0.0,
                'is_anomaly': False,
                'features': None,
                'error': str(e)
            }
    
    def is_available(self) -> bool:
        """Check if model is loaded and available"""
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        return self.is_loaded and self.model is not None

