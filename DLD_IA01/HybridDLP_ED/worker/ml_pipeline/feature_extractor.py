"""
Feature Extractor for UEBA - Transform events into ML features
"""
import numpy as np
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import re
from loguru import logger


class EventFeatureExtractor:
    """
    Extract numerical features from events for ML models
    
    Features:
    - Temparol: is_off_hours, is_weekend, hour_of_day, day_of_week
    - Frequency: clipboard_pastes_last_10m, bytes_transferred_usb_last_1h, file_operations_last_1h
    - Quantitative: entropy_value, content_size, file_count
    - Contextual: dest_app_category, source_type, operation_type
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
        
        return np.array(features, dtype=np.float32)
    
    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime"""
        if not ts_str:
            return None
        
        try:
            if isinstance(ts_str, (int, float)):
                return datetime.fromtimestamp(float(ts_str))
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
        
        Returns:
            [clipboard_pastes_last_10m, bytes_transferred_usb_last_1h, file_operations_last_1h]
        """
        if not current_dt or not self.event_history:
            return [0.0, 0.0, 0.0]
        
        clipboard_count = 0
        usb_bytes = 0
        file_ops = 0
        
        # Time windows
        window_10m = current_dt.timestamp() - 600  # 10 minutes
        window_1h = current_dt.timestamp() - 3600   # 1 hour
        
        for hist_event in self.event_history:
            hist_ts_str = hist_event.get('ts') or hist_event.get('timestamp', '')
            hist_dt = self._parse_timestamp(hist_ts_str)
            if not hist_dt:
                continue
            
            hist_ts = hist_dt.timestamp()
            event_type = str(
                hist_event.get('type')
                or (hist_event.get('operation', {}) or {}).get('op_type')
                or ''
            ).lower()
            
            # Clipboard pastes in last 10 minutes
            if hist_ts >= window_10m:
                if 'clipboard' in event_type and 'paste' in event_type:
                    clipboard_count += 1
            
            # USB transfers in last 1 hour
            if hist_ts >= window_1h:
                # Check for USB operations
                obj = hist_event.get('object', {}) or {}
                dst_path = str(
                    obj.get('dst_path')
                    or hist_event.get('dst_path')
                    or hist_event.get('Dest_Path')
                    or ''
                ).lower()
                dst_vol = str(
                    obj.get('dest_volume_type')
                    or obj.get('volume_type')
                    or hist_event.get('Dest_Volume_Type')
                    or ''
                ).lower()
                is_external_dst = (
                    ('usb' in dst_path) or
                    ('removable' in dst_path) or
                    ('removable' in dst_vol) or
                    any(letter in dst_path for letter in ['f:', 'e:', 'g:', 'h:'])
                )
                if is_external_dst:
                    size = (
                        hist_event.get('size')
                        or obj.get('size')
                        or obj.get('size_bytes')
                        or hist_event.get('File_Size')
                        or 0
                    )
                    usb_bytes += size
                
                # File operations count
                if (
                    event_type in ['file_copy', 'file_move', 'file_delete', 'file_modified', 'file_created']
                    or 'file_' in event_type
                ):
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
            content = (
                event.get('clipboard', {}).get('content', '')
                or event.get('clipboard', {}).get('text_file', '')
                or (event.get('content', {}) or {}).get('sample', '')
                or event.get('content', '')
            )
            if content:
                entropy = self._calculate_entropy(str(content))
        
        # Content size
        obj = event.get('object', {}) or {}
        size_bytes = (
            event.get('size')
            or obj.get('size')
            or obj.get('size_bytes')
            or event.get('File_Size')
            or 0
        )
        if size_bytes == 0:
            content = (
                event.get('clipboard', {}).get('content', '')
                or event.get('clipboard', {}).get('text_file', '')
                or (event.get('content', {}) or {}).get('sample', '')
                or event.get('content', '')
            )
            if content:
                size_bytes = len(str(content).encode('utf-8'))
        
        # Log scale for content size (handle 0)
        content_size_log = np.log1p(size_bytes) / 20.0  # Normalize: log(1+bytes)/20 -> roughly [0, 1]
        
        # File count (for bulk operations)
        file_list = event.get('clipboard', {}).get('file_list', []) or event.get('file_list', [])
        file_count = len(file_list) if isinstance(file_list, list) else 0
        if file_count == 0:
            metrics = event.get('metrics', {}) or {}
            file_count = (
                metrics.get('file_count_10s')
                or metrics.get('file_count')
                or event.get('File_Count_10s')
                or event.get('File_Count')
                or event.get('clipboard', {}).get('file_count')
                or 0
            )
        
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
        
        Returns:
            [dest_app_category, source_type, operation_type]
        """
        # Destination app category
        # 0: Local App, 1: Browser, 2: Chat App, 3: Cloud Sync, 4: USB/External
        clipboard = event.get('clipboard', {}) or {}
        network = event.get('network', {}) or {}
        context = event.get('context', {}) or {}
        operation = event.get('operation', {}) or {}
        dest_app = (
            clipboard.get('dest_app')
            or context.get('fg_app')
            or context.get('fg_process')
            or operation.get('tool')
            or ''
        ).lower()
        dest_domain = (
            clipboard.get('dest_domain')
            or network.get('dest_domain')
            or context.get('dest_domain')
            or ''
        ).lower()
        dest_window = (
            clipboard.get('dest_window_title')
            or clipboard.get('active_window_title')
            or context.get('window_title')
            or ''
        ).lower()
        
        obj = event.get('object', {}) or {}
        dst_path = str(obj.get('dst_path', '')).lower()
        
        dest_category = 0.0  # Default: Local App
        
        # USB/External
        if 'usb' in dst_path or 'removable' in dst_path or any(letter in dst_path for letter in ['f:', 'e:', 'g:', 'h:']):
            dest_category = 4.0
        # Cloud Sync
        elif any(cloud in dst_path or cloud in dest_domain for cloud in ['onedrive', 'dropbox', 'google drive', 'drive.google.com', 'box.com', 'icloud', 'mega.nz']):
            dest_category = 3.0
        # Chat App
        elif any(app in dest_app or app in dest_window or app in dest_domain for app in ['chatgpt', 'discord', 'slack', 'teams', 'zalo', 'gmail', 'outlook', 'telegram', 'whatsapp']):
            dest_category = 2.0
        # Browser
        elif any(b in dest_app for b in ['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe']):
            dest_category = 1.0
        
        dest_category = dest_category / 4.0  # Normalize to [0, 1]
        
        # Source type
        # 0: File, 1: Clipboard Text, 2: Clipboard Image, 3: Network
        source_type = 0.0  # Default: File
        event_type = str(event.get('type') or '').lower()
        op_type = str((event.get('operation', {}) or {}).get('op_type') or '').lower()
        if 'clipboard' in event_type or 'clipboard' in op_type:
            content_type = (clipboard.get('content_type', '') or '').lower()
            if 'image' in content_type or 'filelist' in content_type:
                source_type = 2.0
            else:
                source_type = 1.0
        elif 'network' in event_type or 'upload' in event_type or 'upload' in op_type:
            source_type = 3.0
        
        source_type = source_type / 3.0  # Normalize to [0, 1]
        
        # Operation type
        # 0: Copy, 1: Move, 2: Delete, 3: Print, 4: Upload
        op_type = str((event.get('operation', {}) or {}).get('op_type', '') or event.get('event_type', '') or event.get('type', '')).lower()
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

