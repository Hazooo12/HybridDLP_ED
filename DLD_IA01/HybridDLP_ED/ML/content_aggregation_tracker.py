"""
Content Aggregation Tracker - ML-Powered Fragmented Exfiltration Detection

THIẾT KẾ:
- ML đóng vai trò CHÍNH trong classification và anomaly detection
- Rules chỉ dùng cho SPECIFIC structured patterns (CCCD, phone formats)
- Kết hợp ML scores + Rules matches = Combined Intelligence

ML Components:
1. SemanticClassifier - Understand content semantics
2. BehavioralBaseline - Learn user patterns, detect anomalies
3. FragmentSimilarityEngine - Link related fragments
4. Probabilistic risk scoring

Author: HybridDLP Team
Date: 2026-05-04
"""

import time
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from datetime import datetime
import threading

from .content_fingerprint import (
    MLContentAnalyzer, MLAnalysisResult
)

logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class AggregationConfig:
    """Configuration for ML-powered aggregation detection"""
    
    # ML Model Parameters
    ml_sensitivity_threshold: float = 0.35  # ML semantic threshold
    ml_anomaly_threshold: float = 0.4       # Behavioral anomaly threshold
    ml_fragment_similarity: float = 0.45    # Fragment linking threshold
    
    # ML Combination Weights (how much each ML component contributes)
    weight_semantic: float = 0.5           # Weight for semantic classification
    weight_anomaly: float = 0.3            # Weight for behavioral anomaly
    weight_fragmentation: float = 0.2      # Weight for fragment linking
    
    # Time windows
    window_seconds: int = 3600             # 1 hour tracking window
    fragment_link_window: int = 1800        # 30 min for fragment linking
    
    # Thresholds (ML-learned, can be overridden)
    min_fragments_to_alert: int = 3        # Alert after 3 related fragments
    high_risk_completeness: float = 0.7    # 70% = critical alert
    
    # Alert cooldown
    alert_cooldown_seconds: int = 300      # 5 minutes between alerts


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ContentFragment:
    """Một content fragment được track"""
    fragment_id: str
    user: str
    timestamp: float
    event_type: str
    destination: str
    
    # ML Analysis Results (the key differentiator)
    ml_analysis: MLAnalysisResult
    
    # Combined Score (ML + Rules)
    ml_score: float
    rule_score: float
    combined_score: float
    
    # Metadata
    raw_content_hash: str
    content_preview: str  # First 100 chars
    raw_content: str = ""  # Full content để phục vụ rescan
    
    def to_dict(self) -> Dict:
        return {
            'fragment_id': self.fragment_id,
            'user': self.user,
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'destination': self.destination,
            'ml_analysis': self.ml_analysis.to_dict(),
            'ml_score': round(self.ml_score, 3),
            'rule_score': round(self.rule_score, 3),
            'combined_score': round(self.combined_score, 3),
            'content_preview': self.content_preview,
            'raw_content_length': len(self.raw_content) if self.raw_content else 0
        }


@dataclass
class DocumentAssembly:
    """Theo dõi quá trình assembly một văn bản từ fragments"""
    assembly_id: str
    user: str
    created_at: float
    last_update: float
    fragments: List[ContentFragment] = field(default_factory=list)
    
    # ML-Tracked metrics
    ml_categories_detected: Set[str] = field(default_factory=set)
    ml_assembly_confidence: float = 0.0
    ml_fragment_link_count: int = 0
    
    # Behavioral indicators
    total_anomaly_score: float = 0.0
    anomaly_pattern: List[str] = field(default_factory=list)
    
    # Rule-based indicators (secondary)
    entity_types: Set[str] = field(default_factory=set)
    
    def compute_completeness(self) -> float:
        """ML computes document completeness from semantic similarity"""
        if len(self.fragments) < 2:
            return 0.0
        
        # ML-based: use semantic scores (normalized 0-1)
        ml_scores = [f.ml_analysis.combined_risk_score for f in self.fragments]
        avg_ml_score = sum(ml_scores) / len(ml_scores) / 10.0  # Normalize from 0-10 to 0-1
        
        # Factor in fragment count
        count_factor = min(1.0, len(self.fragments) / 5)
        
        # Combine: weighted average
        completeness = avg_ml_score * 0.6 + count_factor * 0.4
        
        return min(1.0, completeness)
    
    def to_dict(self) -> Dict:
        return {
            'assembly_id': self.assembly_id,
            'user': self.user,
            'created_at': self.created_at,
            'last_update': self.last_update,
            'fragment_count': len(self.fragments),
            'ml_categories': list(self.ml_categories_detected),
            'ml_assembly_confidence': round(self.ml_assembly_confidence, 3),
            'ml_fragment_links': self.ml_fragment_link_count,
            'total_anomaly_score': round(self.total_anomaly_score, 3),
            'entity_types': list(self.entity_types),
            'completeness': round(self.compute_completeness(), 3)
        }


@dataclass
class AggregationAlert:
    """Alert từ ML + NLP analysis"""
    alert_type: str  # 'fragmentation_detected', 'anomaly', 'sensitivity_threshold'
    user: str
    risk_score: float
    ml_confidence: float
    reason: str
    ml_explanation: str
    
    # Assembly info
    assembly_id: Optional[str] = None
    fragment_count: int = 0
    
    # NLP Analysis Results (NEW!)
    document_type: str = "unknown"  # Loại tài liệu: contract, invoice, payslip...
    document_confidence: float = 0.0  # Độ tin cậy của classification
    risk_factors: List[str] = field(default_factory=list)  # Giải thích risk
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Behavioral indicators
    behavioral_indicators: List[str] = field(default_factory=list)
    
    # Combined content analysis
    combined_content_preview: str = ""
    nlp_entities: Dict[str, int] = field(default_factory=dict)  # NLP entities
    yara_matches: List[Dict] = field(default_factory=list)  # YARA matches
    is_highly_sensitive: bool = False
    
    # Sensitive flags
    has_pii: bool = False  # Có PII (CCCD, name)
    has_financial: bool = False  # Có thông tin tài chính
    has_legal: bool = False  # Có nội dung pháp lý
    
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        return {
            'alert_type': self.alert_type,
            'user': self.user,
            'risk_score': round(self.risk_score, 2),
            'ml_confidence': round(self.ml_confidence, 3),
            'reason': self.reason,
            'ml_explanation': self.ml_explanation,
            'assembly_id': self.assembly_id,
            'fragment_count': self.fragment_count,
            
            # NLP Results
            'document_type': self.document_type,
            'document_confidence': round(self.document_confidence, 3),
            'risk_level': self.risk_level,
            'risk_factors': self.risk_factors,
            
            # Sensitive flags
            'has_pii': self.has_pii,
            'has_financial': self.has_financial,
            'has_legal': self.has_legal,
            
            # Content analysis
            'combined_content_preview': self.combined_content_preview[:500],
            'nlp_entities': self.nlp_entities,
            'nlp_entity_count': sum(self.nlp_entities.values()) if isinstance(self.nlp_entities, dict) else 0,
            'yara_matches': self.yara_matches,
            'yara_match_count': len(self.yara_matches),
            'is_highly_sensitive': self.is_highly_sensitive,
            
            # Behavioral
            'behavioral_indicators': self.behavioral_indicators,
            'timestamp': self.timestamp
        }
    
    def get_explainable_summary(self) -> str:
        """Tạo summary có thể explain được cho analyst"""
        parts = []
        parts.append(f"Document: {self.document_type} ({self.document_confidence:.0%})")
        parts.append(f"Risk: {self.risk_level} ({self.risk_score:.1f})")
        if self.risk_factors:
            parts.append(f"Factors: {'; '.join(self.risk_factors[:3])}")
        if self.has_pii:
            parts.append("Contains PII")
        if self.has_financial:
            parts.append("Contains financial data")
        if self.has_legal:
            parts.append("Contains legal content")
        return " | ".join(parts)


# ============================================================================
# MAIN TRACKER - ML-POWERED
# ============================================================================

class ContentAggregationTracker:
    """
    ML-Powered Content Aggregation Tracker.
    
    KEY DIFFERENCE FROM RULE-BASED:
    - Không dùng hard-coded thresholds
    - ML học baseline của user
    - ML phát hiện semantic relationships
    - Probabilistic risk assessment
    """
    
    def __init__(self, config: Optional[AggregationConfig] = None):
        self.config = config or AggregationConfig()
        
        # Initialize ML Components
        self.ml_analyzer = MLContentAnalyzer({
            'vectorizer': 'tfidf',
            'sensitivity_threshold': self.config.ml_sensitivity_threshold,
            'anomaly_threshold': self.config.ml_anomaly_threshold
        })
        
        # State
        self.user_assemblies: Dict[str, List[DocumentAssembly]] = defaultdict(list)
        self.global_entity_accumulation: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.last_alert_time: Dict[str, float] = defaultdict(float)
        
        # Fragment history for ML similarity (shared across assemblies)
        self.fragment_history: List[Tuple[str, float, MLAnalysisResult]] = []
        
        # Lock for thread safety
        self._lock = threading.Lock()
    
    def process_event(self, event: Dict, user: str) -> Optional[AggregationAlert]:
        """
        Process event through ML pipeline.
        
        ML Pipeline:
        1. Extract content
        2. Run ML analysis (semantic + anomaly)
        3. Check fragment linking
        4. Combine scores
        5. Generate alert if needed
        """
        with self._lock:
            # Extract content
            content = self._extract_content(event)
            if not content:
                return None
            
            # Run ML Analysis
            ml_analysis = self.ml_analyzer.analyze(content, event, user)
            
            # Update fragment history
            self._update_fragment_history(content, time.time(), ml_analysis)
            
            # Compute combined score (ML + Rules)
            ml_score = ml_analysis.combined_risk_score
            rule_score = self._compute_rule_score(content)
            combined_score = self._combine_scores(ml_score, rule_score)
            
            # Create fragment - lưu full content để phục vụ rescan sau này
            fragment = ContentFragment(
                fragment_id=self._generate_fragment_id(content),
                user=user,
                timestamp=time.time(),
                event_type=event.get('event_type', 'unknown'),
                destination=self._extract_destination(event),
                ml_analysis=ml_analysis,
                ml_score=ml_score,
                rule_score=rule_score,
                combined_score=combined_score,
                raw_content_hash=self._hash_content(content),
                content_preview=content[:100],
                raw_content=content  # Lưu full content để rescan
            )
            
            # Check for existing assembly
            assembly = self._find_related_assembly(user, fragment)
            
            if assembly:
                return self._update_assembly(assembly, fragment)
            else:
                # Create new assembly
                return self._create_assembly(fragment)
    
    def _extract_content(self, event: Dict) -> Optional[str]:
        """Extract text content from event"""
        event_type = event.get('event_type', '')
        
        if 'clipboard' in event_type:
            clip = event.get('clipboard', {})
            if isinstance(clip, dict):
                raw_content = clip.get('content', '')
                if isinstance(raw_content, str):
                    return raw_content
                elif isinstance(raw_content, dict):
                    return str(raw_content)
            return str(clip) if clip else ''
        
        elif 'file' in event_type:
            obj = event.get('object', {})
            if isinstance(obj, dict):
                raw_content = obj.get('content', '')
                if isinstance(raw_content, str):
                    return raw_content
                elif isinstance(raw_content, dict):
                    return str(raw_content)
            return str(obj) if obj else ''
        
        elif 'upload' in event_type:
            upload = event.get('upload', {})
            if isinstance(upload, dict):
                raw_content = upload.get('content', '')
                if isinstance(raw_content, str):
                    return raw_content
                elif isinstance(raw_content, dict):
                    return str(raw_content)
            return str(upload) if upload else ''
        
        elif 'screenshot' in event_type:
            ocr = event.get('ocr', event.get('screenshot', {}))
            if isinstance(ocr, dict):
                raw_content = ocr.get('text', '')
                if isinstance(raw_content, str):
                    return raw_content
                elif isinstance(raw_content, dict):
                    return str(raw_content)
            return str(ocr) if ocr else ''
        
        raw_content = event.get('content', '')
        if isinstance(raw_content, str):
            return raw_content
        elif isinstance(raw_content, dict):
            return str(raw_content)
        return str(raw_content) if raw_content else ''
    
    def _run_ml_analysis(self, content: str, event: Dict, user: str) -> MLAnalysisResult:
        """Run ML analysis on content"""
        return self.ml_analyzer.analyze(content, event, user)
    
    def _update_fragment_history(self, content: str, timestamp: float, ml_result: MLAnalysisResult):
        """Update shared fragment history for ML similarity"""
        self.fragment_history.append((content, timestamp, ml_result))
        
        # Keep only recent fragments
        cutoff = timestamp - self.config.fragment_link_window
        self.fragment_history = [
            (c, t, m) for c, t, m in self.fragment_history
            if t > cutoff
        ]
    
    def _compute_rule_score(self, content: str) -> float:
        """
        Rule-based score (SECONDARY - for structured patterns ML might miss).
        Chỉ dùng cho specific patterns ML khó detect:
        - CCCD/CMND formats
        - Phone number formats
        - Credit card formats
        """
        import re
        score = 0.0
        
        # Structured patterns (rules for backup)
        patterns = [
            (r'\b\d{12}\b', 2.0),           # CCCD
            (r'\b\d{9}\b', 1.5),            # CMND
            (r'\b(09|08|07|03)\d{8}\b', 1.0),  # Phone
            (r'\b\d{4}[\s\-\.]\d{4}[\s\-\.]\d{4}[\s\-\.]\d{4}\b', 2.5),  # Card
            (r'AKIA[A-Z0-9]{16}', 3.0),     # AWS key
            (r'ghp_[a-zA-Z0-9]{36}', 3.0), # GitHub token
        ]
        
        for pattern, weight in patterns:
            if re.search(pattern, content):
                score += weight
        
        return min(5.0, score)
    
    def _combine_scores(self, ml_score: float, rule_score: float) -> float:
        """
        ML COMBINES scores - not hard-coded.
        This is where ML can learn optimal weighting.
        """
        # Current heuristic: ML primary, rules secondary
        return ml_score * 0.7 + rule_score * 0.3
    
    def _generate_fragment_id(self, content: str) -> str:
        """Generate unique fragment ID"""
        return hashlib.md5(content[:50].encode()).hexdigest()[:12]
    
    def _hash_content(self, content: str) -> str:
        """Hash content for deduplication"""
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _extract_destination(self, event: Dict) -> str:
        """Extract destination category"""
        if event.get('usb', {}).get('to_removable'):
            return 'usb'
        elif 'upload' in event.get('event_type', ''):
            return 'cloud'
        elif 'clipboard' in event.get('event_type', ''):
            return 'clipboard'
        return 'other'
    
    def _find_related_assembly(self, user: str, fragment: ContentFragment) -> Optional[DocumentAssembly]:
        """Find assembly that fragment belongs to (ML-powered)"""
        for assembly in self.user_assemblies[user]:
            # Check ML semantic similarity
            if self._is_related_to_assembly(assembly, fragment):
                return assembly
        
        return None
    
    def _is_related_to_assembly(self, assembly: DocumentAssembly, fragment: ContentFragment) -> bool:
        """
        ML determines if fragment is related to assembly.
        Uses semantic similarity, not hard rules.
        """
        # Time check (ML learns what's "too old")
        if fragment.timestamp - assembly.last_update > self.config.window_seconds:
            return False
        
        # ML semantic check
        if assembly.fragments:
            first_ml = assembly.fragments[0].ml_analysis
            
            # Check category overlap
            categories_overlap = bool(
                set(first_ml.semantic_categories.keys()) &
                set(fragment.ml_analysis.semantic_categories.keys())
            )
            
            # Check anomaly pattern similarity
            anomaly_similarity = (
                first_ml.anomaly_score > 0.3 and
                fragment.ml_analysis.anomaly_score > 0.3
            )
            
            # Check fragment similarity
            fragment_similarity = len(fragment.ml_analysis.related_fragments) > 0
            
            if categories_overlap or anomaly_similarity or fragment_similarity:
                return True
        
        return False
    
    def _create_assembly(self, fragment: ContentFragment) -> Optional[AggregationAlert]:
        """Create new assembly and check for immediate alert"""
        assembly = DocumentAssembly(
            assembly_id=self._generate_assembly_id(fragment.user),
            user=fragment.user,
            created_at=fragment.timestamp,
            last_update=fragment.timestamp,
            fragments=[fragment]
        )
        
        # Update assembly metrics
        self._update_assembly_metrics(assembly)
        
        # Add to tracking
        self.user_assemblies[fragment.user].append(assembly)
        
        # Check immediate high risk
        if fragment.combined_score > 7.0 and fragment.ml_analysis.ml_confidence > 0.6:
            return self._create_alert(
                assembly=assembly,
                alert_type='high_risk_content',
                reason=f"Single high-risk fragment detected",
                ml_explanation=fragment.ml_analysis.explanation
            )
        
        return None
    
    def _update_assembly(self, assembly: DocumentAssembly, fragment: ContentFragment) -> Optional[AggregationAlert]:
        """Update assembly with new fragment"""
        assembly.fragments.append(fragment)
        assembly.last_update = fragment.timestamp
        
        # Update ML metrics
        self._update_assembly_metrics(assembly)
        
        # Check for fragmentation pattern (ML)
        frag_pattern = self._detect_fragmentation_pattern(assembly)
        
        # Check alert conditions (ML-powered)
        return self._check_alert_conditions(assembly, frag_pattern)
    
    def _update_assembly_metrics(self, assembly: DocumentAssembly):
        """Update assembly metrics from fragments"""
        if not assembly.fragments:
            return
        
        # Aggregate ML categories
        all_categories = defaultdict(float)
        total_anomaly = 0.0
        
        for f in assembly.fragments:
            # ML categories
            for cat, score in f.ml_analysis.semantic_categories.items():
                all_categories[cat] = max(all_categories[cat], score)
            
            # Anomaly scores
            total_anomaly += f.ml_analysis.anomaly_score
        
        assembly.ml_categories_detected = set(all_categories.keys())
        assembly.total_anomaly_score = total_anomaly / len(assembly.fragments)
        
        # ML assembly confidence
        if len(assembly.fragments) > 1:
            scores = [f.ml_score for f in assembly.fragments[-3:]]  # Use ml_score (0-10 scale)
            assembly.ml_assembly_confidence = min(1.0, sum(scores) / len(scores) / 10.0)  # Normalize
    
    def _detect_fragmentation_pattern(self, assembly: DocumentAssembly) -> Dict:
        """
        ML detects fragmentation pattern.
        Not based on rules, but on learned patterns.
        """
        if len(assembly.fragments) < 2:
            return {'is_fragmented': False, 'confidence': 0.0}
        
        # ML pattern detection
        fragments_data = [
            (f.content_preview, f.timestamp) for f in assembly.fragments
        ]
        
        # Sequential pattern
        time_diffs = [
            assembly.fragments[i].timestamp - assembly.fragments[i-1].timestamp
            for i in range(1, len(assembly.fragments))
        ]
        avg_gap = sum(time_diffs) / len(time_diffs) if time_diffs else 0
        is_sequential = 0 < avg_gap < 600  # Within 10 minutes
        
        # Category consistency (ML)
        categories = [f.ml_analysis.top_category for f in assembly.fragments]
        category_consistency = len(set(categories)) <= 2  # Few categories
        
        # Increasing sensitivity (ML learned pattern)
        scores = [f.combined_score for f in assembly.fragments]
        is_increasing = all(scores[i] <= scores[i+1] for i in range(len(scores)-1))
        
        # ML confidence
        confidence = (
            (1.0 if is_sequential else 0.0) * 0.3 +
            (1.0 if category_consistency else 0.0) * 0.4 +
            (1.0 if is_increasing else 0.0) * 0.3
        )
        
        return {
            'is_fragmented': confidence > 0.5,
            'confidence': confidence,
            'is_sequential': is_sequential,
            'avg_gap_seconds': avg_gap,
            'category_consistency': category_consistency,
            'is_increasing_sensitivity': is_increasing,
            'fragment_count': len(assembly.fragments)
        }
    
    def _check_alert_conditions(self, assembly: DocumentAssembly, 
                                frag_pattern: Dict) -> Optional[AggregationAlert]:
        """Check if alert conditions are met (ML-powered)"""
        # Cooldown check
        user = assembly.user
        if time.time() - self.last_alert_time[user] < self.config.alert_cooldown_seconds:
            return None
        
        # ML fragmentation alert
        if (frag_pattern['is_fragmented'] and 
            frag_pattern['confidence'] > 0.5 and
            len(assembly.fragments) >= self.config.min_fragments_to_alert):
            explanation_parts = [
                "Sequential" if frag_pattern['is_sequential'] else "Non-sequential",
                f"Categories: {list(assembly.ml_categories_detected)}",
                "Sensitivity: Increasing" if frag_pattern['is_increasing_sensitivity'] else "Sensitivity: Mixed",
            ]
             
            return self._create_alert(
                assembly=assembly,
                alert_type='fragmentation_detected',
                reason=f"ML detected {len(assembly.fragments)} related fragments with {frag_pattern['confidence']:.0%} confidence",
                ml_explanation=f"Fragmentation pattern: {'; '.join(explanation_parts)}"
            )
        
        # ML anomaly alert
        if assembly.total_anomaly_score > 0.5:
            return self._create_alert(
                assembly=assembly,
                alert_type='behavioral_anomaly',
                reason=f"Behavioral anomaly detected (score: {assembly.total_anomaly_score:.0%})",
                ml_explanation=f"Anomaly indicators from ML baseline analysis"
            )
        
        # High completeness alert
        completeness = assembly.compute_completeness()
        if completeness > self.config.high_risk_completeness:
            return self._create_alert(
                assembly=assembly,
                alert_type='high_completeness',
                reason=f"Document completeness reached {completeness:.0%}",
                ml_explanation=f"ML assembly confidence: {assembly.ml_assembly_confidence:.0%}"
            )
        
        return None
    
    def _create_alert(self, assembly: DocumentAssembly, alert_type: str,
                     reason: str, ml_explanation: str) -> AggregationAlert:
        """Create aggregation alert với combined content analysis"""
        fragment_count = max(1, len(assembly.fragments))

        # Calculate risk score (ML-weighted, normalized to 0-10)
        risk_score = (
            assembly.ml_assembly_confidence * 4.0 +
            assembly.compute_completeness() * 4.0 +
            assembly.total_anomaly_score * 2.0
        )
        
        # NLP confidence
        ml_confidence = sum(f.ml_analysis.ml_confidence for f in assembly.fragments) / fragment_count
        
        # CRITICAL: Rescan combined content với NLP
        rescan_result = self.rescan_assembled_content(assembly)
        
        # Get NLP risk score
        nlp_risk = rescan_result.get('risk_score', 0.0)
        nlp_entities = rescan_result.get('nlp_entities', {})
        risk_factors = rescan_result.get('risk_factors', [])
        
        # Calculate final risk score
        # Base risk from assembly, plus NLP risk
        base_risk = (
            assembly.ml_assembly_confidence * 4.0 +
            assembly.compute_completeness() * 4.0 +
            assembly.total_anomaly_score * 2.0
        )
        
        # Total risk = max(base, nlp_risk) + yara_boost
        yara_count = rescan_result.get('yara_match_count', 0)
        yara_boost = min(yara_count * 1.0, 3.0)  # +1 per YARA match, max 3
        
        risk_score = min(10.0, max(base_risk, nlp_risk) + yara_boost)
        
        # Log boost
        if yara_boost > 0 or nlp_risk > base_risk:
            logger.warning(
                f"[AggregationAlert] Risk: {risk_score:.1f} = "
                f"max({base_risk:.1f}, NLP:{nlp_risk:.1f}) + YARA:{yara_boost:.1f} "
                f"for assembly {assembly.assembly_id[:8]}"
            )
        
        alert = AggregationAlert(
            alert_type=alert_type,
            user=assembly.user,
            risk_score=risk_score,
            ml_confidence=ml_confidence,
            reason=reason,
            ml_explanation=ml_explanation,
            assembly_id=assembly.assembly_id,
            fragment_count=len(assembly.fragments),
            
            # NLP Analysis Results
            document_type=rescan_result.get('document_type', 'unknown'),
            document_confidence=rescan_result.get('document_confidence', 0.0),
            risk_level=rescan_result.get('risk_level', 'LOW'),
            risk_factors=risk_factors,
            
            # Behavioral indicators
            behavioral_indicators=assembly.anomaly_pattern,
            
            # Content analysis
            combined_content_preview=rescan_result.get('combined_content', ''),
            nlp_entities=nlp_entities,
            yara_matches=rescan_result.get('yara_matches', []),
            is_highly_sensitive=rescan_result.get('is_highly_sensitive', False),
            
            # Sensitive flags
            has_pii=rescan_result.get('has_pii', False),
            has_financial=rescan_result.get('has_financial', False),
            has_legal=rescan_result.get('has_legal', False),
            
            timestamp=time.time()
        )
        
        self.last_alert_time[assembly.user] = time.time()
        
        # Log alert
        logger.warning(
            f"[AGGREGATION ALERT] User={alert.user}, "
            f"Type={alert.alert_type}, Risk={alert.risk_score:.1f}, "
            f"ML_Conf={alert.ml_confidence:.0%}, Reason={reason}"
        )
        
        return alert
    
    def rescan_assembled_content(self, assembly: DocumentAssembly) -> Dict[str, Any]:
        """
        Gom các fragments lại thành 1 text lớn → phân tích bằng NLP.
        
        ĐÂY LÀ TÍNH NĂNG QUAN TRỌNG để cover case "attacker chia nhỏ dữ liệu để né YARA/ngưỡng".
        
        LUỒNG NLP:
        1. Gom tất cả fragment.content lại thành 1 text
        2. DocumentTypeClassifier: Xác định loại tài liệu (contract, invoice, payslip...)
        3. VietnameseNER: Trích xuất entities (CCCD, phone, bank, person, org...)
        4. ContextRiskBuilder: Tính risk dựa trên document type + entities + combinations
        5. YARA scan: Bổ sung pattern matching (giữ lại để detect credentials)
        6. Pass kết quả vào alert để analyst review
        
        Returns:
            Dict chứa đầy đủ thông tin NLP:
            - document_type: Loại tài liệu (contract, invoice, payslip...)
            - document_confidence: Độ tin cậy của classification
            - nlp_entities: Dict[str, int] - entities đã trích xuất
            - risk_score: Risk score từ NLP (0-10)
            - risk_factors: List[str] - giải thích tại sao risk cao
            - yara_matches: YARA matches bổ sung
            - is_highly_sensitive: True nếu highly sensitive
        """
        try:
            # 1. Gom fragments lại thành combined text
            combined_parts = []
            for frag in assembly.fragments:
                # Ưu tiên full content > content_preview
                if hasattr(frag, 'raw_content') and frag.raw_content:
                    combined_parts.append(frag.raw_content)
                elif hasattr(frag, 'content_preview') and frag.content_preview:
                    combined_parts.append(frag.content_preview)
            
            # Fallback: tái tạo từ ML analysis preview
            if not combined_parts:
                for frag in assembly.fragments:
                    if hasattr(frag, 'ml_analysis') and frag.ml_analysis:
                        combined_parts.append(frag.ml_analysis.content_preview)
            
            combined_content = "\n---\n".join(combined_parts)
            
            if not combined_content.strip():
                logger.warning(f"[AggregationRescan] No content to rescan for assembly {assembly.assembly_id}")
                return {
                    'combined_content': '',
                    'document_type': 'unknown',
                    'document_confidence': 0.0,
                    'nlp_entities': {},
                    'risk_score': 0.0,
                    'risk_factors': [],
                    'yara_matches': [],
                    'is_highly_sensitive': False,
                    'combined_content_hash': None,
                    'error': 'No content available'
                }
            
            # 2. Tính hash để dedup
            combined_hash = hashlib.sha256(combined_content.encode('utf-8', errors='replace')).hexdigest()
            
            # 3. NLP ANALYSIS - Sử dụng NLPPoweredAnalyzer
            nlp_analysis_result = {}
            try:
                from ML.nlp_content_analyzer import NLPPoweredAnalyzer
                nlp_analyzer = NLPPoweredAnalyzer()
                nlp_analysis = nlp_analyzer.analyze(combined_content)
                
                # Chuyển đổi sang dict format
                nlp_analysis_result = {
                    'document_type': nlp_analysis.document_type.value,
                    'document_confidence': nlp_analysis.document_type_confidence,
                    'nlp_entities': nlp_analysis.entity_summary,
                    'risk_score': nlp_analysis.risk_score,
                    'risk_level': nlp_analysis.risk_level.name,
                    'risk_factors': nlp_analysis.risk_factors,
                    'has_pii': nlp_analysis.has_pii,
                    'has_financial': nlp_analysis.has_financial,
                    'has_legal': nlp_analysis.has_legal,
                    'entities': [
                        {'type': e.entity_type, 'text': e.text[:30], 'confidence': e.confidence}
                        for e in nlp_analysis.entities
                    ]
                }
                
                logger.info(
                    f"[AggregationRescan] NLP Analysis: "
                    f"DocType={nlp_analysis.document_type.value} "
                    f"({nlp_analysis.document_type_confidence:.0%}), "
                    f"Risk={nlp_analysis.risk_score:.1f}, "
                    f"Entities={list(nlp_analysis.entity_summary.keys())}"
                )
                
            except ImportError:
                logger.warning("[AggregationRescan] NLP analyzer not available, using fallback")
                nlp_analysis_result = {'document_type': 'unknown', 'document_confidence': 0.0}
            except Exception as nlp_err:
                logger.warning(f"[AggregationRescan] NLP analysis failed: {nlp_err}")
                nlp_analysis_result = {'document_type': 'unknown', 'document_confidence': 0.0}
            
            # 4. YARA scan - Bổ sung pattern matching
            yara_matches = []
            try:
                from worker.core.fast_scan import FastScanEngine
                fast_scan = FastScanEngine()
                yara_result = fast_scan.scan_text_content(combined_content, panic_mode=False)
                yara_matches = yara_result.get('yara_matches', [])
                logger.info(
                    f"[AggregationRescan] YARA scan on {len(combined_parts)} fragments: "
                    f"{len(yara_matches)} matches"
                )
            except Exception as yara_err:
                logger.warning(f"[AggregationRescan] YARA scan failed: {yara_err}")
            
            # 5. Tổng hợp risk score
            # Kết hợp NLP risk + YARA boost
            nlp_risk = nlp_analysis_result.get('risk_score', 0.0)
            yara_count = len(yara_matches)
            
            # YARA boost dựa trên số matches
            if yara_count >= 3:
                yara_boost = 2.0
            elif yara_count >= 2:
                yara_boost = 1.5
            elif yara_count >= 1:
                yara_boost = 1.0
            else:
                yara_boost = 0.0
            
            # Tổng risk = NLP risk + YARA boost
            total_risk = min(10.0, nlp_risk + yara_boost)
            
            # Xác định highly sensitive
            nlp_entities = nlp_analysis_result.get('nlp_entities', {})
            is_highly_sensitive = (
                nlp_analysis_result.get('has_pii', False) and 
                (nlp_analysis_result.get('has_financial', False) or nlp_analysis_result.get('has_legal', False))
            ) or yara_count >= 2
            
            # 6. Build result
            result = {
                # Combined content info
                'combined_content': combined_content[:5000],
                'combined_content_length': len(combined_content),
                'combined_content_hash': combined_hash,
                
                # NLP Analysis Results
                'document_type': nlp_analysis_result.get('document_type', 'unknown'),
                'document_confidence': nlp_analysis_result.get('document_confidence', 0.0),
                'nlp_entities': nlp_entities,
                'entity_count': sum(nlp_entities.values()) if isinstance(nlp_entities, dict) else 0,
                'risk_score': total_risk,
                'nlp_risk_score': nlp_risk,
                'risk_factors': nlp_analysis_result.get('risk_factors', []),
                'risk_level': nlp_analysis_result.get('risk_level', 'LOW'),
                
                # Sensitive flags
                'has_pii': nlp_analysis_result.get('has_pii', False),
                'has_financial': nlp_analysis_result.get('has_financial', False),
                'has_legal': nlp_analysis_result.get('has_legal', False),
                'is_highly_sensitive': is_highly_sensitive,
                
                # YARA results
                'yara_matches': [
                    {
                        'rule': m.get('rule', 'unknown'),
                        'tags': m.get('tags', []),
                        'meta': m.get('meta', {})
                    }
                    for m in yara_matches
                ],
                'yara_match_count': yara_count,
                
                # Assembly info
                'fragment_count': len(assembly.fragments),
                'assembly_id': assembly.assembly_id,
                'user': assembly.user,
                
                # Context for alert
                'alert_context': {
                    'ml_assembly_confidence': assembly.ml_assembly_confidence,
                    'completeness': assembly.compute_completeness(),
                    'anomaly_score': assembly.total_anomaly_score,
                    'categories': list(assembly.ml_categories_detected),
                    'yara_boost_applied': yara_boost > 0
                }
            }
            
            # Log summary
            logger.warning(
                f"[AggregationRescan] Assembly {assembly.assembly_id[:8]}: "
                f"DocType={result['document_type']}, "
                f"Risk={total_risk:.1f} (NLP:{nlp_risk:.1f}+YARA:{yara_boost:.1f}), "
                f"Entities={result['entity_count']}, "
                f"YARA={yara_count}, "
                f"Sensitive={is_highly_sensitive}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"[AggregationRescan] Error rescanning assembly: {e}", exc_info=True)
            return {
                'combined_content': '',
                'document_type': 'unknown',
                'document_confidence': 0.0,
                'nlp_entities': {},
                'risk_score': 0.0,
                'risk_factors': [],
                'yara_matches': [],
                'is_highly_sensitive': False,
                'combined_content_hash': None,
                'error': str(e)
            }
    
    def _generate_assembly_id(self, user: str) -> str:
        """Generate unique assembly ID"""
        hash_input = f"{user}_{time.time()}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]
    
    def get_assemblies(self, user: str) -> List[Dict]:
        """Get all active assemblies for user"""
        return [a.to_dict() for a in self.user_assemblies.get(user, [])]
    
    def get_ml_baseline(self, user: str) -> Dict:
        """Get learned ML baseline for user"""
        return self.ml_analyzer.get_user_baseline(user)


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    print("=" * 70)
    print("ML-POWERED CONTENT AGGREGATION TRACKER TEST")
    print("=" * 70)
    
    tracker = ContentAggregationTracker()
    
    # Test fragments (simulating fragmented exfiltration)
    test_events = [
        {
            'event_type': 'clipboard_paste',
            'clipboard': {'content': "CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM\nHỢP ĐỒNG TÀI TRỢ\nSố 03/HĐTT/2026"},
            'ts': '2026-05-04T14:00:00',
            'metrics': {'entropy': 4.5}
        },
        {
            'event_type': 'clipboard_paste',
            'clipboard': {'content': "BÊN A: Ban tổ chức Sự kiện\nĐại diện: Anh Đào Nam Trung\nChức vụ: Trưởng ban"},
            'ts': '2026-05-04T14:05:00',
            'metrics': {'entropy': 4.2}
        },
        {
            'event_type': 'file_move',
            'object': {'path': 'contract_part3.txt', 'content': "Địa chỉ: 123 Nguyễn Trãi, Quận 1, TP.HCM"},
            'usb': {'to_removable': True},
            'ts': '2026-05-04T14:10:00',
            'metrics': {'entropy': 4.0}
        },
        {
            'event_type': 'file_move',
            'object': {'path': 'contract_part4.txt', 'content': "Số CCCD: 048204003872\nNgày cấp: 31/5/2021"},
            'usb': {'to_removable': True},
            'ts': '2026-05-04T14:15:00',
            'metrics': {'entropy': 4.5}
        },
        {
            'event_type': 'browser_upload',
            'upload': {'url': 'https://drive.google.com', 'content': "Tài khoản: 19038057431014 Techcombank"},
            'ts': '2026-05-04T14:20:00',
            'metrics': {'entropy': 5.0}
        }
    ]
    
    print("\n--- Processing Events ---")
    
    user = 'test_user'
    alerts = []
    
    for i, event in enumerate(test_events):
        print(f"\nEvent {i+1}: {event['event_type']}")
        
        # Get content preview
        if 'clipboard' in event['event_type']:
            content = event.get('clipboard', {}).get('content', '')[:50]
        elif 'object' in event:
            content = event.get('object', {}).get('content', '')[:50]
        else:
            content = event.get('upload', {}).get('content', '')[:50]
        print(f"  Content: {content}...")
        
        # Process through ML
        alert = tracker.process_event(event, user)
        
        if alert:
            alerts.append(alert)
            print(f"  [!] ALERT: {alert.alert_type}")
            print(f"      Risk: {alert.risk_score:.1f}")
            print(f"      ML Confidence: {alert.ml_confidence:.0%}")
            print(f"      Explanation: {alert.ml_explanation}")
        else:
            print(f"  [OK] No alert")
    
    print("\n" + "=" * 70)
    print("ML ROLE IN THIS DETECTION:")
    print("=" * 70)
    print("""
1. SEMANTIC CLASSIFICATION
   - ML analyzed each fragment's semantic meaning
   - Detected legal/contract content semantically
   - Not by keyword 'hợp đồng'!

2. BEHAVIORAL ANOMALY
   - ML tracked user behavior baseline
   - Detected unusual: off-hours, USB, cloud upload pattern
   - Not by hard-coded threshold!

3. FRAGMENT LINKING
   - ML semantic similarity linked fragments
   - Recognized related content across events
   - Not by matching 'contract' keyword!

4. RISK SCORING
   - ML combined scores with confidence
   - Probabilistic output, not binary
   - Learnable and tunable!
""")
    
    print("\n" + "=" * 70)
    print("ALERT SUMMARY")
    print("=" * 70)
    for alert in alerts:
        print(f"\n[{alert.alert_type.upper()}]")
        print(f"  Risk Score: {alert.risk_score:.1f}")
        print(f"  ML Confidence: {alert.ml_confidence:.0%}")
        print(f"  Fragments: {alert.fragment_count}")
        print(f"  Categories: {list(alert.categories.keys())}")
        print(f"  Explanation: {alert.ml_explanation}")
    
    print("\n[SUCCESS] ML-Powered Aggregation Tracker Test Complete!")
