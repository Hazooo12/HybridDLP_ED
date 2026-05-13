"""
Feature Extractor for UEBA - Transform events into ML features
Theo mô tả trong ML_DEVELOPMENT_PLAN.md
"""
import numpy as np
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import re
import logging

# Setup logging
logger = logging.getLogger(__name__)


class EventFeatureExtractor:
    """
    Extract numerical features from events for ML models
    
    Features theo ML_DEVELOPMENT_PLAN.md:
    1. Temparol Features: is_off_hours, is_weekend, hour_of_day, day_of_week
    2. Frequency/Velocity Features: clipboard_pastes_last_10m, bytes_transferred_usb_last_1h, file_operations_last_1h
    3. Quantitative Features: entropy_value, content_size, file_count
    4. Contextual/Categorical Features: dest_app_category, source_type, operation_type
    """
    
    def __init__(self, event_history: Optional[List[Dict[str, Any]]] = None):
        """
        Initialize feature extractor
        
        Args:
            event_history: List of recent events for frequency calculations (sliding window)
        """
        self.event_history = event_history or []
        self.feature_names = [
            # Temparol (4)
            'is_off_hours', 'is_weekend', 'hour_of_day', 'day_of_week',
            # Frequency (3)
            'clipboard_pastes_last_10m', 'bytes_transferred_usb_last_1h', 'file_operations_last_1h',
            # Quantitative (3)
            'entropy_value', 'content_size_log', 'file_count',
            # Contextual (3)
            'dest_app_category', 'source_type', 'operation_type'
        ]
        
        # Feature weights for important cases (higher weight = more important)
        # These will be used to create weighted composite features
        self.feature_weights = {
            'is_off_hours': 1.5,  # Off-hours activity is suspicious
            'entropy_value': 2.0,  # High entropy = encrypted/sensitive data
            'dest_app_category': 2.5,  # External destinations (ChatGPT, USB) are high risk
            'bytes_transferred_usb_last_1h': 2.0,  # USB transfers are high risk
            'clipboard_pastes_last_10m': 1.5,  # Bulk paste activity is suspicious
        }
    
    def extract(self, event: Dict[str, Any]) -> np.ndarray:
        """
        Extract feature vector from single event
        
        Returns:
            numpy array of shape (13,) with feature values
        """
        features = []
        
        # 1. Temparol Features
        ts_str = event.get('ts') or event.get('timestamp', '')
        dt = self._parse_timestamp(ts_str)
        
        if dt:
            hour = dt.hour
            day_of_week = dt.weekday()  # 0=Monday, 6=Sunday
            features.extend([
                1.0 if (hour < 8 or hour >= 18) else 0.0,  # is_off_hours
                1.0 if day_of_week >= 5 else 0.0,  # is_weekend (Sat=5, Sun=6)
                hour / 23.0,  # hour_of_day normalized [0, 1]
                day_of_week / 6.0  # day_of_week normalized [0, 1]
            ])
        else:
            features.extend([0.0, 0.0, 0.5, 0.5])  # Default values
        
        # 2. Frequency Features (from event history)
        features.extend(self._calculate_frequency_features(event, dt))
        
        # 3. Quantitative Features
        features.extend(self._extract_quantitative_features(event))
        
        # 4. Contextual Features
        features.extend(self._extract_contextual_features(event))
        
        # Apply feature weights to important features
        features_array = np.array(features, dtype=np.float32)
        features_array = self._apply_feature_weights(features_array)
        
        return features_array
    
    def _apply_feature_weights(self, features: np.ndarray) -> np.ndarray:
        """
        Apply weights to important features to emphasize high-risk cases
        
        Args:
            features: Feature array of shape (13,)
        
        Returns:
            Weighted feature array
        """
        weighted_features = features.copy()
        
        # Apply weights to important features
        # is_off_hours (index 0)
        if features[0] > 0:  # Only weight if off-hours
            weighted_features[0] = min(1.0, features[0] * self.feature_weights['is_off_hours'])
        
        # entropy_value (index 7)
        if features[7] > 0.7:  # Only weight high entropy
            weighted_features[7] = min(1.0, features[7] * self.feature_weights['entropy_value'])
        
        # dest_app_category (index 10) - High weight for external destinations
        if features[10] > 0.25:  # Browser (0.25), Chat (0.5), Cloud (0.75), USB (1.0)
            weighted_features[10] = min(1.0, features[10] * self.feature_weights['dest_app_category'])
        
        # bytes_transferred_usb_last_1h (index 5)
        if features[5] > 0:  # Any USB transfer
            weighted_features[5] = min(1.0, features[5] * self.feature_weights['bytes_transferred_usb_last_1h'])
        
        # clipboard_pastes_last_10m (index 4) - Bulk paste activity
        if features[4] > 0.1:  # More than 10 pastes
            weighted_features[4] = min(1.0, features[4] * self.feature_weights['clipboard_pastes_last_10m'])
        
        return weighted_features
    
    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime"""
        if not ts_str:
            return None
        
        try:
            if isinstance(ts_str, str):
                # ISO8601 format: "2026-03-04T06:11:33.414327+00:00" or "2026-03-04T06:11:33Z"
                ts_str = ts_str.replace('Z', '+00:00')
                return datetime.fromisoformat(ts_str)
            return None
        except Exception as e:
            logger.debug(f"Error parsing timestamp {ts_str}: {e}")
            return None
    
    def _calculate_frequency_features(self, current_event: Dict[str, Any], current_dt: Optional[datetime]) -> List[float]:
        """
        Calculate frequency features using sliding window from event history
        Theo ML_DEVELOPMENT_PLAN.md:
        - clipboard_pastes_last_10m: Số lần paste trong 10 phút qua
        - bytes_transferred_usb_last_1h: Tổng dung lượng copy ra USB trong 1 giờ
        - file_operations_last_1h: Số lần file operations trong 1 giờ
        
        Returns:
            [clipboard_pastes_last_10m, bytes_transferred_usb_last_1h, file_operations_last_1h]
        """
        if not current_dt:
            return [0.0, 0.0, 0.0]
        
        clipboard_count = 0
        usb_bytes = 0
        file_ops = 0
        
        # Time windows. Names are kept for backward-compatible model features, but
        # the actual durations are configurable for live demos.
        try:
            from worker.config import WorkerConfig
            clipboard_window_sec = int(getattr(WorkerConfig, "UEBA_CLIPBOARD_SPIKE_WINDOW_SEC", 120))
            transfer_window_sec = int(getattr(WorkerConfig, "UEBA_EXTERNAL_SPIKE_WINDOW_SEC", 120))
        except Exception:
            clipboard_window_sec = 120
            transfer_window_sec = 120
        window_10m = current_dt.timestamp() - max(1, clipboard_window_sec)
        window_1h = current_dt.timestamp() - max(1, transfer_window_sec)
        
        # Also check current event for frequency features
        current_event_type = (current_event.get('type') or current_event.get('event_type', '')).lower()
        
        # Check current event for USB operations
        if current_dt.timestamp() >= window_1h:
            obj = current_event.get('object', {})
            dst_path = str(obj.get('dst_path', '')).lower()
            usb_info = current_event.get('usb', {})
            
            is_usb_op = (
                usb_info.get('to_removable', False) or 
                'usb' in current_event_type or
                'usb' in dst_path or 
                'removable' in dst_path or 
                any(letter in dst_path for letter in ['f:', 'e:', 'g:', 'h:'])
            )
            
            if is_usb_op:
                size = current_event.get('size') or obj.get('size_bytes') or 0
                usb_bytes += size
            
            # File operations count
            if any(op in current_event_type for op in ['file_copy', 'file_move', 'file_delete', 'file_write', 'usb_copy']):
                file_ops += 1
        
        # Check clipboard paste in current event (last 10m)
        if current_dt.timestamp() >= window_10m:
            if ('clipboard' in current_event_type and 'paste' in current_event_type) or \
               (current_event_type == 'clipboard_paste'):
                clipboard_count += 1
        
        # Check event history
        if not self.event_history:
            # Normalize and return even without history
            return [
                min(clipboard_count / 100.0, 1.0),
                min(usb_bytes / (1024 * 1024 * 1024), 1.0),
                min(file_ops / 1000.0, 1.0)
            ]
        
        for hist_event in self.event_history:
            hist_ts_str = hist_event.get('ts') or hist_event.get('timestamp', '')
            hist_dt = self._parse_timestamp(hist_ts_str)
            if not hist_dt:
                continue
            
            hist_ts = hist_dt.timestamp()
            event_type = (hist_event.get('type') or hist_event.get('event_type', '')).lower()
            
            # Clipboard pastes in last 10 minutes
            if hist_ts >= window_10m:
                # Check clipboard paste events
                if ('clipboard' in event_type and 'paste' in event_type) or \
                   (event_type == 'clipboard_paste'):
                    clipboard_count += 1
            
            # USB transfers in last 1 hour
            if hist_ts >= window_1h:
                # Check for USB operations
                obj = hist_event.get('object', {})
                dst_path = str(obj.get('dst_path', '')).lower()
                usb_info = hist_event.get('usb', {})
                
                # Check USB copy/move operations
                is_usb_op = (
                    usb_info.get('to_removable', False) or 
                    'usb' in event_type or
                    'usb' in dst_path or 
                    'removable' in dst_path or 
                    any(letter in dst_path for letter in ['f:', 'e:', 'g:', 'h:'])
                )
                
                if is_usb_op:
                    size = hist_event.get('size') or obj.get('size_bytes') or 0
                    usb_bytes += size
                
                # File operations count (including USB copy)
                if any(op in event_type for op in ['file_copy', 'file_move', 'file_delete', 'file_write', 'usb_copy']):
                    file_ops += 1
        
        # Normalize: clipboard_count (0-100), usb_bytes (0-1GB), file_ops (0-1000)
        return [
            min(clipboard_count / 100.0, 1.0),  # Normalize to [0, 1]
            min(usb_bytes / (1024 * 1024 * 1024), 1.0),  # Normalize GB to [0, 1]
            min(file_ops / 1000.0, 1.0)  # Normalize to [0, 1]
        ]
    
    def _extract_quantitative_features(self, event: Dict[str, Any]) -> List[float]:
        """
        Extract quantitative features: entropy, content_size, file_count
        
        Returns:
            [entropy_value, content_size_log, file_count]
        """
        # Entropy
        entropy = event.get('metrics', {}).get('entropy', 0.0)
        if entropy == 0:
            # Try to calculate from content
            content = event.get('clipboard', {}).get('content', '') or event.get('content', {}).get('sample', '')
            if content:
                entropy = self._calculate_entropy(str(content))
        
        # Content size
        size_bytes = event.get('size') or event.get('object', {}).get('size_bytes') or 0
        if size_bytes == 0:
            content = event.get('clipboard', {}).get('content', '') or event.get('content', {}).get('sample', '')
            if content:
                size_bytes = len(str(content).encode('utf-8'))
            else:
                # Try content_len
                size_bytes = event.get('clipboard', {}).get('content_len', 0) or event.get('content', {}).get('sample_len', 0)
        
        # Log scale for content size (handle 0)
        content_size_log = np.log1p(size_bytes) / 20.0  # Normalize: log(1+bytes)/20 -> roughly [0, 1]
        
        # File count (for bulk operations)
        file_list = event.get('clipboard', {}).get('file_list', []) or event.get('file_list', [])
        file_count = len(file_list) if isinstance(file_list, list) else 0
        
        return [
            min(entropy / 8.0, 1.0),  # Normalize entropy [0, 8] -> [0, 1]
            float(content_size_log),
            min(file_count / 50.0, 1.0)  # Normalize file_count [0, 50] -> [0, 1]
        ]
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        text = str(text)
        if len(text) == 0:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            p = count / text_len
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _extract_contextual_features(self, event: Dict[str, Any]) -> List[float]:
        """
        Extract contextual features: dest_app_category, source_type, operation_type
        Theo ML_DEVELOPMENT_PLAN.md:
        - dest_app_category: 0: Local App, 1: Browser, 2: Chat App, 3: Cloud Sync
        
        Returns:
            [dest_app_category, source_type, operation_type]
        """
        # Destination app category
        # 0: Local App, 1: Browser, 2: Chat App, 3: Cloud Sync, 4: USB/External
        dest_app = (event.get('clipboard', {}).get('dest_app', '') or 
                   event.get('context', {}).get('process_name', '') or '').lower()
        dest_domain = (event.get('clipboard', {}).get('dest_domain', '') or 
                      event.get('context', {}).get('dest_domain', '') or '').lower()
        dest_window = (event.get('clipboard', {}).get('dest_window_title', '') or 
                      event.get('context', {}).get('active_window', '') or '').lower()
        
        obj = event.get('object', {})
        dst_path = str(obj.get('dst_path', '')).lower()
        network = event.get('network', {})
        network_domain = str(network.get('dest_domain', '')).lower()
        
        dest_category = 0.0  # Default: Local App
        
        # USB/External (check first - highest priority)
        usb_info = event.get('usb', {})
        event_type = (event.get('type') or event.get('event_type', '')).lower()
        if (usb_info.get('to_removable', False) or 
            'usb' in event_type or
            'usb' in dst_path or 'removable' in dst_path or 
            any(letter in dst_path for letter in ['f:', 'e:', 'g:', 'h:'])):
            dest_category = 4.0
        # Cloud Sync
        elif any(cloud in dst_path or cloud in dest_domain or cloud in network_domain 
                for cloud in ['onedrive', 'dropbox', 'google drive', 'drive.google.com', 'dropbox.com']):
            dest_category = 3.0
        # Chat App (check multiple sources)
        elif any(app in dest_app or app in dest_window or app in dest_domain 
                for app in ['chatgpt', 'discord', 'slack', 'teams', 'zalo', 'chat.openai.com', 'openai.com']):
            dest_category = 2.0
        # Browser
        elif dest_app in ['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe'] or network_domain:
            dest_category = 1.0
        
        dest_category = dest_category / 4.0  # Normalize to [0, 1]
        
        # Source type
        # 0: File, 1: Clipboard Text, 2: Clipboard Image, 3: Network
        source_type = 0.0  # Default: File
        event_type = (event.get('type') or event.get('event_type', '')).lower()
        if 'clipboard' in event_type:
            content_type = (event.get('clipboard', {}).get('content_type', '') or '').lower()
            if 'image' in content_type or 'filelist' in content_type:
                source_type = 2.0
            else:
                source_type = 1.0
        elif 'network' in event_type or 'upload' in event_type or 'download' in event_type:
            source_type = 3.0
        
        source_type = source_type / 3.0  # Normalize to [0, 1]
        
        # Operation type
        # 0: Copy, 1: Move, 2: Delete, 3: Print, 4: Upload
        op_type = (event.get('operation', {}).get('op_type', '') or event.get('event_type', '') or '').lower()
        operation_type = 0.0  # Default: Copy
        if 'move' in op_type:
            operation_type = 1.0
        elif 'delete' in op_type:
            operation_type = 2.0
        elif 'print' in op_type:
            operation_type = 3.0
        elif 'upload' in op_type or 'network' in op_type:
            operation_type = 4.0
        
        operation_type = operation_type / 4.0  # Normalize to [0, 1]
        
        return [dest_category, source_type, operation_type]
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return self.feature_names.copy()
