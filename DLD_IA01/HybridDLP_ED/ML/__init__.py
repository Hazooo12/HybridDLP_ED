"""
ML Module for UEBA (User and Entity Behavior Analytics)
Tích hợp với L3 Detection Engine

DESIGN: ML-FIRST APPROACH
- Semantic classification (not keyword matching)
- Behavioral anomaly detection (not hard thresholds)
- Probabilistic risk scoring (not binary)
- Learnable baselines (not static rules)

Classes:
- MLContentAnalyzer: Main ML pipeline
- TextVectorizer: Text embedding
- SemanticClassifier: Category classification
- BehavioralBaseline: User behavior learning
- FragmentSimilarityEngine: Document reconstruction
- ContentAggregationTracker: Fragmented exfil detection
"""

from .content_fingerprint import (
    MLContentAnalyzer,
    TextVectorizer,
    SemanticClassifier,
    BehavioralBaseline,
    FragmentSimilarityEngine,
    MLAnalysisResult,
    quick_ml_analyze
)

from .content_aggregation_tracker import (
    ContentAggregationTracker,
    AggregationConfig,
    ContentFragment,
    DocumentAssembly,
    AggregationAlert
)

__all__ = [
    # Core ML
    'MLContentAnalyzer',
    'TextVectorizer',
    'SemanticClassifier',
    'BehavioralBaseline',
    'FragmentSimilarityEngine',
    'MLAnalysisResult',
    'quick_ml_analyze',
    
    # Tracker
    'ContentAggregationTracker',
    'AggregationConfig',
    'ContentFragment',
    'DocumentAssembly',
    'AggregationAlert',
]
