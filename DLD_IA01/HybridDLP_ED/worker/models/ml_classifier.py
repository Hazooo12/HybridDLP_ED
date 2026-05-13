"""
ML Classifier với Lazy Loading
"""
import joblib
from pathlib import Path
from typing import Dict, Optional, Any
from loguru import logger
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


class MLClassifier:
    """ML Classifier với Lazy Loading"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.loaded = False
        self._warned = False  # Log thiếu model chỉ 1 lần duy nhất
    
    def _lazy_load(self):
        """Lazy load model chỉ khi cần"""
        if not self.loaded:
            try:
                model_path = WorkerConfig.ML_MODEL_PATH
                vectorizer_path = WorkerConfig.ML_VECTORIZER_PATH
                
                if not model_path.exists() or not vectorizer_path.exists():
                    if not self._warned:
                        # DEBUG thay vì WARNING — đây là trạng thái bình thường khi chưa train
                        # UEBA (ueba_iso_forest.pkl) vẫn hoạt động độc lập với classifier này
                        logger.debug(
                            f"Text ML classifier not trained yet "
                            f"(classifier.pkl={model_path.exists()}, "
                            f"vectorizer.pkl={vectorizer_path.exists()}). "
                            f"System will use YARA + UEBA instead."
                        )
                        self._warned = True
                    return False
                
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                self.loaded = True
                logger.info("ML model loaded (lazy)")
                return True
            except Exception as e:
                logger.error(f"Error loading ML model: {e}")
                return False
        return True
    
    def classify(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Phân loại text với ML
        
        Args:
            text: Text cần phân loại
        
        Returns:
            {
                'is_sensitive': True/False,
                'confidence': 0.85,
                'class': 'sensitive'
            }
        """
        if not text or not text.strip():
            return None
        
        if not self._lazy_load():
            return None
        
        try:
            # Vectorize text
            text_vector = self.vectorizer.transform([text])
            
            # Predict
            prediction = self.model.predict(text_vector)[0]
            probability = self.model.predict_proba(text_vector)[0]
            
            confidence = max(probability)
            is_sensitive = (prediction == 'sensitive' and 
                          confidence >= WorkerConfig.ML_CONFIDENCE_THRESHOLD)
            
            return {
                'is_sensitive': is_sensitive,
                'confidence': float(confidence),
                'class': prediction,
                'probabilities': {
                    'sensitive': float(probability[0]) if len(probability) > 0 else 0,
                    'normal': float(probability[1]) if len(probability) > 1 else 0
                }
            }
        except Exception as e:
            logger.error(f"ML classification error: {e}")
            return None
    
    def is_loaded(self) -> bool:
        """Kiểm tra model đã load chưa"""
        return self.loaded
