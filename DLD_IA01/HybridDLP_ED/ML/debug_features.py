"""
Debug script để xem features được extract như thế nào
"""
import numpy as np
from pathlib import Path
import sys
from datetime import datetime, timezone

# Import ML modules
ML_DIR = Path(__file__).parent
sys.path.insert(0, str(ML_DIR.parent))

from ML.feature_extractor import EventFeatureExtractor
from ML.test_model import create_test_event

def debug_features():
    """Debug feature extraction cho test events"""
    
    print("=" * 80)
    print("DEBUG FEATURE EXTRACTION")
    print("=" * 80)
    
    extractor = EventFeatureExtractor()
    feature_names = extractor.get_feature_names()
    
    # Test scenarios
    test_scenarios = [
        ("Normal Event", "normal"),
        ("Anomalous: Off-hours + ChatGPT", "anomalous_off_hours"),
        ("Anomalous: USB Bulk Copy", "anomalous_usb_bulk")
    ]
    
    # Create event history for anomalous scenarios
    event_history_off_hours = []
    for i in range(20):  # Increased from 10 to 20
        hist_event = create_test_event("anomalous_off_hours")
        hist_dt = datetime.now(timezone.utc).replace(hour=2, minute=20+i)
        hist_event["ts"] = hist_dt.isoformat()
        hist_event["timestamp"] = hist_dt.isoformat()
        event_history_off_hours.append(hist_event)
    
    event_history_usb = []
    for i in range(5):
        hist_event = create_test_event("anomalous_usb_bulk")
        hist_dt = datetime.now(timezone.utc).replace(hour=23, minute=40+i)
        hist_event["ts"] = hist_dt.isoformat()
        hist_event["timestamp"] = hist_dt.isoformat()
        event_history_usb.append(hist_event)
    
    for scenario_name, event_type in test_scenarios:
        print(f"\n{'='*80}")
        print(f"SCENARIO: {scenario_name}")
        print(f"{'='*80}")
        
        event = create_test_event(event_type)
        
        # Update extractor with event history for anomalous scenarios
        if event_type == "anomalous_off_hours":
            extractor.event_history = event_history_off_hours
        elif event_type == "anomalous_usb_bulk":
            extractor.event_history = event_history_usb
        else:
            extractor.event_history = []
        
        # Extract features
        features = extractor.extract(event)
        
        print(f"\nEvent Type: {event.get('type')} / {event.get('event_type')}")
        print(f"Timestamp: {event.get('ts')}")
        print(f"\nExtracted Features ({len(features)} features):")
        print("-" * 80)
        
        for i, (name, value) in enumerate(zip(feature_names, features)):
            print(f"  {i+1:2d}. {name:35s} = {value:8.4f}")
        
        # Highlight key features
        print(f"\nKey Features Analysis:")
        print("-" * 80)
        
        # Temparol
        is_off_hours_idx = feature_names.index('is_off_hours')
        hour_of_day_idx = feature_names.index('hour_of_day')
        print(f"  is_off_hours: {features[is_off_hours_idx]:.4f} (1.0 = off-hours)")
        print(f"  hour_of_day:  {features[hour_of_day_idx]:.4f} (normalized hour)")
        
        # Frequency
        clipboard_pastes_idx = feature_names.index('clipboard_pastes_last_10m')
        usb_bytes_idx = feature_names.index('bytes_transferred_usb_last_1h')
        file_ops_idx = feature_names.index('file_operations_last_1h')
        print(f"  clipboard_pastes_last_10m: {features[clipboard_pastes_idx]:.4f}")
        print(f"  bytes_transferred_usb_last_1h: {features[usb_bytes_idx]:.4f}")
        print(f"  file_operations_last_1h: {features[file_ops_idx]:.4f}")
        
        # Quantitative
        entropy_idx = feature_names.index('entropy_value')
        content_size_idx = feature_names.index('content_size_log')
        print(f"  entropy_value: {features[entropy_idx]:.4f} (normalized)")
        print(f"  content_size_log: {features[content_size_idx]:.4f}")
        
        # Contextual
        dest_category_idx = feature_names.index('dest_app_category')
        source_type_idx = feature_names.index('source_type')
        operation_type_idx = feature_names.index('operation_type')
        print(f"  dest_app_category: {features[dest_category_idx]:.4f} (0=Local, 1=Browser, 2=Chat, 3=Cloud, 4=USB)")
        print(f"  source_type: {features[source_type_idx]:.4f} (0=File, 1=Clipboard Text, 2=Image, 3=Network)")
        print(f"  operation_type: {features[operation_type_idx]:.4f} (0=Copy, 1=Move, 2=Delete, 3=Print, 4=Upload)")
        
        # Check if features look anomalous
        print(f"\nAnomaly Indicators:")
        print("-" * 80)
        anomaly_score = 0.0
        
        if features[is_off_hours_idx] > 0.5:
            print(f"  [WARN]  Off-hours activity detected")
            anomaly_score += 0.2
        
        if features[clipboard_pastes_idx] > 0.5:
            print(f"  [WARN]  High clipboard paste frequency")
            anomaly_score += 0.2
        
        if features[usb_bytes_idx] > 0.1:
            print(f"  [WARN]  USB transfer detected")
            anomaly_score += 0.3
        
        if features[entropy_idx] > 0.8:
            print(f"  [WARN]  High entropy (encrypted/sensitive)")
            anomaly_score += 0.2
        
        if features[dest_category_idx] > 0.4:  # Browser, Chat, Cloud, USB
            print(f"  [WARN]  External destination")
            anomaly_score += 0.1
        
        print(f"\n  Estimated Anomaly Score (heuristic): {anomaly_score * 100:.2f}/100")
    
    print(f"\n{'='*80}")
    print("CONCLUSION")
    print(f"{'='*80}")
    print("Nếu features không khác biệt nhiều giữa normal và anomalous,")
    print("model sẽ không phân biệt được. Cần:")
    print("1. Kiểm tra feature extraction logic")
    print("2. Train với nhiều data hơn")
    print("3. Điều chỉnh threshold")


if __name__ == "__main__":
    debug_features()
