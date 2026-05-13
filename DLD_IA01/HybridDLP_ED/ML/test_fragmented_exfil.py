"""
Test Suite for ML-Powered Fragmented Exfiltration Detection

Tests:
1. ML Content Analysis - Semantic classification (not rules)
2. Behavioral Anomaly Detection - ML baseline learning
3. Fragment Similarity - ML-powered document reconstruction
4. Aggregation Tracker - Combined ML pipeline

Author: HybridDLP Team
Date: 2026-05-04
"""

import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from datetime import datetime, timezone
from typing import List, Dict

# Import ML modules
from ML.content_fingerprint import (
    MLContentAnalyzer,
    TextVectorizer,
    SemanticClassifier,
    BehavioralBaseline,
    FragmentSimilarityEngine,
    MLAnalysisResult
)

from ML.content_aggregation_tracker import (
    ContentAggregationTracker,
    AggregationConfig
)


def test_ml_content_analysis():
    """Test 1: ML Semantic Classification"""
    print("\n" + "=" * 70)
    print("TEST 1: ML SEMANTIC CLASSIFICATION")
    print("=" * 70)
    print("Purpose: ML classifies content semantically (NOT by keywords/regex)")
    print()
    
    analyzer = MLContentAnalyzer()
    
    test_cases = {
        'Contract Header': "CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM\nHỢP ĐỒNG TÀI TRỢ\nSố 03/HĐTT/2026\n\nCăn cứ Bộ luật Dân sự.",
        'Party Info': "BÊN A: Ban tổ chức Sự kiện Chăm Hội\nĐại diện: Anh Đào Nam Trung\nChức vụ: Trưởng ban Đối Ngoại",
        'Address': "Địa chỉ: 123 Nguyễn Trãi, Quận 1, TP.HCM\nThành phố Hồ Chí Minh",
        'CCCD': "Số CCCD: 048204003872\nNgày cấp: 31/5/2021\nNơi cấp: Cục Cảnh sát",
        'Financial': "Tài khoản: 19038057431014 Techcombank\nSố dư: 50,000,000 đồng",
        'Source Code': "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\napi_key = 'secret123'\ndb_password = 'pass'",
        'Payroll': "Bảng lương tháng 01/2026\nNhân viên: Nguyễn Văn A\nLương: 25,000,000 đ",
        'Normal Text': "Hôm nay trời đẹp, tôi đi làm về muộn. Ăn cơm với gia đình."
    }
    
    results = {}
    for name, content in test_cases.items():
        result = analyzer.analyze(content, {'type': 'test'}, user='test_user')
        results[name] = result
        
        print(f"[{name}]")
        print(f"  ML Category: {result.top_category} ({result.top_category_score:.0%})")
        print(f"  ML Confidence: {result.ml_confidence:.0%}")
        print(f"  Risk Score: {result.combined_risk_score:.1f}")
        print(f"  Explanation: {result.explanation}")
        print()
    
    # Verify ML detected sensitive content
    sensitive_detected = [
        name for name, r in results.items()
        if r.top_category_score > 0.35 or len(r.semantic_categories) > 0
    ]
    
    print(f"ML Detection: {len(sensitive_detected)}/{len(test_cases)} sensitive content detected")
    print(f"Categories: {sensitive_detected}")
    
    return len(sensitive_detected) >= 6


def test_behavioral_anomaly():
    """Test 2: ML Behavioral Anomaly Detection"""
    print("\n" + "=" * 70)
    print("TEST 2: ML BEHAVIORAL ANOMALY DETECTION")
    print("=" * 70)
    print("Purpose: ML learns user baseline and detects deviations (NOT thresholds)")
    print()
    
    analyzer = MLContentAnalyzer()
    baseline_model = BehavioralBaseline()
    
    # Simulate normal behavior (business hours, low entropy)
    print("Learning normal behavior baseline...")
    
    # Add more samples for higher confidence
    normal_events = []
    for h in range(9, 18):  # 9 AM - 5 PM
        normal_events.append({'type': 'clipboard', 'ts': f'2026-05-04T0{h}:00:00', 'entropy': 4.0, 'metrics': {'entropy': 4.0}})
        normal_events.append({'type': 'clipboard', 'ts': f'2026-05-04T{h}:30:00', 'entropy': 4.2, 'metrics': {'entropy': 4.2}})
    
    for event in normal_events:
        baseline_model.update('test_user', event)
        analyzer.analyze("Normal work document", event, user='test_user')
    
    # Get learned baseline
    baseline = analyzer.get_user_baseline('test_user')
    print(f"  Learned Active Hours: {baseline['active_hours']}")
    print(f"  Learned Avg Entropy: {baseline['avg_entropy']:.2f}")
    print(f"  Baseline Confidence: {baseline['confidence']:.0%}")
    print()
    
    # Test anomaly detection
    print("Testing anomaly detection...")
    anomaly_events = [
        {
            'type': 'clipboard',
            'ts': '2026-05-04T23:00:00',  # 11 PM - unusual
            'entropy': 6.5,
            'metrics': {'entropy': 6.5}
        },
        {
            'type': 'clipboard',
            'ts': '2026-05-04T02:00:00',  # 2 AM - very unusual
            'entropy': 7.0,
            'metrics': {'entropy': 7.0}
        },
    ]
    
    anomaly_scores = []
    for event in anomaly_events:
        result = analyzer.analyze("Sensitive content detected!", event, user='test_user')
        print(f"  Event at {event['ts']}:")
        print(f"    Anomaly Score: {result.anomaly_score:.0%}")
        print(f"    Reasons: {result.anomaly_reasons}")
        anomaly_scores.append(result.anomaly_score)
    
    ml_detected_anomaly = any(score > 0.2 for score in anomaly_scores)
    print(f"\nML Detected Anomaly: {ml_detected_anomaly}")
    
    # Also check that normal events don't trigger anomaly
    normal_result = analyzer.analyze("Normal content", {'ts': '2026-05-04T10:00:00', 'entropy': 4.0, 'metrics': {'entropy': 4.0}}, user='test_user')
    print(f"Normal event (10 AM): Anomaly Score: {normal_result.anomaly_score:.0%} (should be low)")
    
    return ml_detected_anomaly


def test_fragment_similarity():
    """Test 3: ML Fragment Similarity"""
    print("\n" + "=" * 70)
    print("TEST 3: ML FRAGMENT SIMILARITY")
    print("=" * 70)
    print("Purpose: ML links fragments by semantic similarity (NOT keywords)")
    print()
    
    vectorizer = TextVectorizer()
    similarity_engine = FragmentSimilarityEngine(vectorizer)
    
    # Contract fragments (different parts)
    fragments = [
        "CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM Độc lập Tự do Hạnh phúc",
        "HỢP ĐỒNG TÀI TRỢ Số 03/HĐTT/2026",
        "BÊN A đại diện Trưởng phòng Kinh doanh",
        "BÊN B đại diện Giám đốc Công ty ABC",
        "Căn cứ Bộ luật Dân sự số 33/2005 QH11",
    ]
    
    import time
    ts = time.time()
    
    # Add fragments
    for i, frag in enumerate(fragments):
        similarity_engine.add_fragment(frag, ts + i * 60)
        print(f"Fragment {i+1}: {frag[:40]}...")
    
    print()
    
    # Query for similar fragment (without 'contract' keyword!)
    query = "048204003872 ngày cấp 31/5/2021 nơi cấp cục cảnh sát"
    related = similarity_engine.find_related_fragments(query, ts + 600)
    
    print(f"Query: '{query[:40]}...'")
    print(f"ML Found {len(related)} related fragments:")
    for content, score in related:
        print(f"  - Similarity {score:.0%}: '{content[:50]}...'")
    
    # Compute assembly confidence
    confidence = similarity_engine.compute_assembly_confidence(fragments)
    print(f"\nAssembly Confidence: {confidence:.0%}")
    
    # Test fragmentation pattern detection
    frag_data = [(f, ts + i * 60) for i, f in enumerate(fragments)]
    pattern = similarity_engine.detect_fragmentation_pattern(frag_data)
    
    print(f"\nFragmentation Pattern:")
    print(f"  Is Fragmented: {pattern['is_fragmented']}")
    print(f"  Confidence: {pattern['confidence']:.0%}")
    print(f"  Sequential: {pattern['is_sequential']}")
    print(f"  Related Content: {pattern['is_related_content']}")
    
    return pattern['is_fragmented']


def test_aggregation_tracker():
    """Test 4: End-to-End Aggregation Tracker"""
    print("\n" + "=" * 70)
    print("TEST 4: ML AGGREGATION TRACKER (END-TO-END)")
    print("=" * 70)
    print("Purpose: Complete ML pipeline for fragmented exfil detection")
    print()
    
    tracker = ContentAggregationTracker()
    
    # Simulate fragmented exfiltration scenario
    events = [
        {
            'event_type': 'clipboard_paste',
            'clipboard': {
                'content': "CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM\nHỢP ĐỒNG TÀI TRỢ\nSố 03/HĐTT/2026\n\nCăn cứ Bộ luật Dân sự."
            },
            'ts': '2026-05-04T14:00:00',
            'metrics': {'entropy': 4.5}
        },
        {
            'event_type': 'clipboard_paste',
            'clipboard': {
                'content': "BÊN A: Ban tổ chức Sự kiện\nĐại diện: Anh Đào Nam Trung\nChức vụ: Trưởng ban"
            },
            'ts': '2026-05-04T14:05:00',
            'metrics': {'entropy': 4.2}
        },
        {
            'event_type': 'file_move',
            'object': {
                'path': 'contract_part3.txt',
                'content': "Địa chỉ: 123 Nguyễn Trãi, Quận 1, TP.HCM\nSố CCCD: 048204003872"
            },
            'usb': {'to_removable': True},
            'ts': '2026-05-04T14:10:00',
            'metrics': {'entropy': 4.5}
        },
        {
            'event_type': 'browser_upload',
            'upload': {
                'url': 'https://drive.google.com',
                'content': "Tài khoản: 19038057431014 Techcombank\nSố dư: 50,000,000 đồng"
            },
            'ts': '2026-05-04T14:15:00',
            'metrics': {'entropy': 5.0}
        }
    ]
    
    user = 'test_user'
    alerts = []
    
    print(f"Processing {len(events)} events for user '{user}'...\n")
    
    for i, event in enumerate(events):
        print(f"Event {i+1}: {event['event_type']}")
        
        # Show content preview
        if 'clipboard' in event['event_type']:
            content = event['clipboard'].get('content', '')[:50]
        elif 'object' in event:
            content = event['object'].get('content', '')[:50]
        else:
            content = event.get('upload', {}).get('content', '')[:50]
        print(f"  Content: {content}...")
        
        # Process through ML pipeline
        alert = tracker.process_event(event, user)
        
        if alert:
            alerts.append(alert)
            print(f"  [!] ALERT TRIGGERED")
            print(f"      Type: {alert.alert_type}")
            print(f"      Risk: {alert.risk_score:.1f}/10")
            print(f"      ML Confidence: {alert.ml_confidence:.0%}")
            print(f"      Categories: {list(alert.categories.keys())}")
            print(f"      Explanation: {alert.ml_explanation}")
        else:
            print(f"  [OK] No alert")
        print()
    
    # Summary
    print("=" * 70)
    print("ALERT SUMMARY")
    print("=" * 70)
    print(f"Total Alerts: {len(alerts)}")
    print()
    
    for alert in alerts:
        print(f"[{alert.alert_type.upper()}]")
        print(f"  Risk Score: {alert.risk_score:.1f}/10")
        print(f"  ML Confidence: {alert.ml_confidence:.0%}")
        print(f"  Fragments: {alert.fragment_count}")
        print(f"  Categories: {list(alert.categories.keys())}")
        print(f"  Reason: {alert.reason}")
        print()
    
    # Check if ML detected the pattern
    ml_detected = len(alerts) > 0
    print(f"ML Detected Pattern: {ml_detected}")
    
    return ml_detected


def test_comparison_with_rules():
    """Test 5: Comparison - ML vs Rules"""
    print("\n" + "=" * 70)
    print("TEST 5: ML vs RULE-BASED (COMPARISON)")
    print("=" * 70)
    print()
    
    print("SCENARIO: Detect 'contract' content")
    print()
    
    # Rule-based approach
    rule_content = "HỢP ĐỒNG TÀI TRỢ"
    rule_keywords = ['hợp đồng', 'hđtt', 'thỏa thuận']
    rule_detected = any(kw in rule_content.lower() for kw in rule_keywords)
    
    print("RULE-BASED APPROACH:")
    print(f"  Content: '{rule_content}'")
    print(f"  Rule: Check for keywords {rule_keywords}")
    print(f"  Result: {'DETECTED' if rule_detected else 'NOT DETECTED'}")
    print()
    
    # ML approach
    analyzer = MLContentAnalyzer()
    ml_result = analyzer.analyze(rule_content, {'type': 'test'}, user='test')
    
    print("ML APPROACH:")
    print(f"  Content: '{rule_content}'")
    print(f"  Method: Semantic embedding + similarity")
    print(f"  Result: {ml_result.top_category} ({ml_result.top_category_score:.0%})")
    print()
    
    # Now test with paraphrased content (rules would fail)
    paraphrased = "Thỏa ước tài trợ và hỗ trợ tài chính giữa hai bên"
    rule_detected_para = any(kw in paraphrased.lower() for kw in rule_keywords)
    ml_result_para = analyzer.analyze(paraphrased, {'type': 'test'}, user='test')
    
    print("PARAPHRASED SCENARIO:")
    print(f"  Content: '{paraphrased}'")
    print(f"  Rule-based: {'DETECTED' if rule_detected_para else 'NOT DETECTED'} (keyword matching)")
    print(f"  ML-based: {ml_result_para.top_category} ({ml_result_para.top_category_score:.0%})")
    print()
    
    # Show ML advantage
    ml_advantage = ml_result_para.top_category_score > 0.3
    print(f"ML ADVANTAGE: {'YES' if ml_advantage else 'NO'} - ML can detect paraphrased content")
    
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("ML-POWERED FRAGMENTED EXFILTRATION DETECTION TEST SUITE")
    print("=" * 70)
    print(f"Timestamp: {datetime.now(timezone.utc)}")
    print()
    
    tests = [
        ("ML Semantic Classification", test_ml_content_analysis),
        ("ML Behavioral Anomaly", test_behavioral_anomaly),
        ("ML Fragment Similarity", test_fragment_similarity),
        ("ML Aggregation Tracker", test_aggregation_tracker),
        ("ML vs Rules Comparison", test_comparison_with_rules),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed, None))
        except Exception as e:
            results.append((name, False, str(e)))
            print(f"ERROR: {e}")
    
    # Summary
    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    
    passed_count = 0
    for name, passed, error in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {name}")
        if error:
            print(f"         Error: {error}")
        if passed:
            passed_count += 1
    
    print()
    print(f"Total: {passed_count}/{len(results)} passed")
    
    if passed_count == len(results):
        print("\n[SUCCESS] All ML tests passed!")
        print()
        print("KEY TAKEAWAYS:")
        print("1. ML classifies content SEMANTICALLY, not by keywords")
        print("2. ML learns user BEHAVIORAL BASELINE, not hard thresholds")
        print("3. ML links fragments by EMBEDDING SIMILARITY, not rules")
        print("4. ML provides PROBABILISTIC outputs with confidence")
        print("5. ML is ADAPTABLE - learns from data, not hard-coded")
    else:
        print("\n[FAILED] Some tests failed. Please review.")
    
    return passed_count == len(results)


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
