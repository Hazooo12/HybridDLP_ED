"""
Report Generator - Chuyển đổi event + detection results thành REPORT FIELDS format
Theo yêu cầu trong "Trường và Kịch bản demo.txt"
"""
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from loguru import logger


class ReportGenerator:
    """Generator cho REPORT FIELDS theo format chuẩn"""
    
    def __init__(self):
        pass
    
    def generate_report(
        self,
        event: Dict[str, Any],
        fast_scan_result: Dict[str, Any],
        deep_analysis_result: Dict[str, Any],
        risk_result: Dict[str, Any],
        file_path: Path
    ) -> Dict[str, Any]:
        """
        Tạo report fields từ event + detection results
        
        Args:
            event: Event từ agent (có thể đã có report fields từ L1)
            fast_scan_result: Kết quả từ FastScanEngine
            deep_analysis_result: Kết quả từ DeepAnalysisEngine
            risk_result: Kết quả từ RiskScoringEngine
            file_path: Đường dẫn file đang xử lý
        
        Returns:
            Dict với tất cả REPORT FIELDS theo format chuẩn
        """
        report = {}
        
        # ========== A) Event mapping ==========
        report['Event_Type'] = self._get_event_type(event)
        report['Operation_Type'] = self._get_operation_type(event)
        report['Timestamp'] = self._get_timestamp(event)
        
        # ========== B) File attributes ==========
        # Check nếu là clipboard event (không có file path)
        is_clipboard = (
            'clipboard' in str(file_path).lower() or
            'clipboard' in event.get('type', '').lower() or
            'clipboard' in event.get('source', '').lower() or
            'clipboard' in (event.get('operation', {}).get('op_type', '') or '').lower()
        )
        
        is_special_event = str(file_path).startswith('special_event://')
        
        if is_clipboard:
            # Clipboard event - không có file
            content = event.get('content', {}) or {}
            clipboard = event.get('clipboard', {}) or {}
            text_content = clipboard.get('text_file') or content.get('sample') or ''
            
            report['File_Name'] = f"Clipboard Content ({len(text_content)} chars)"
            report['File_Extension'] = '.txt'  # Clipboard text
            report['File_Size'] = len(text_content.encode('utf-8')) if text_content else 0
            report['File_Path'] = 'clipboard://clipboard_content'
            report['File_Hash'] = clipboard.get('content_hash') or event.get('hash_sha256')
            report['File_Signature'] = 'text/plain'
        elif is_special_event:
            # Special event (proc_start, etc) - không có file
            event_type = event.get('type', 'special_event')
            report['File_Name'] = f"Event: {event_type}"
            report['File_Extension'] = ''
            report['File_Size'] = 0
            report['File_Path'] = str(file_path)
            report['File_Hash'] = event.get('hash_sha256')
            report['File_Signature'] = ''
        else:
            # File event - có path
            target_path = event.get('dst_path') or event.get('object', {}).get('dst_path') or event.get('path') or event.get('object', {}).get('path') or str(file_path)
            target_path_obj = Path(target_path)
            
            report['File_Name'] = target_path_obj.name if target_path_obj else None
            # File_Extension phải là string (không None)
            report['File_Extension'] = self._get_extension(target_path_obj) or event.get('ext') or event.get('object', {}).get('ext') or target_path_obj.suffix.lower() if target_path_obj else ''
            report['File_Size'] = event.get('size') or event.get('object', {}).get('size')
            report['File_Path'] = target_path
            report['File_Hash'] = event.get('hash_sha256') or event.get('object', {}).get('hash_sha256')
            report['File_Signature'] = event.get('signature') or event.get('object', {}).get('signature')
        report['File_Sensitivity'] = self._calculate_sensitivity(
            event, fast_scan_result, deep_analysis_result, risk_result
        )
        
        # ========== C) Source/Destination ==========
        if is_clipboard:
            # Clipboard event
            clipboard = event.get('clipboard', {}) or {}
            ctx = event.get('context', {}) or {}
            window_title = ctx.get('window_title') or clipboard.get('active_window_title') or 'Unknown'
            
            report['Source_Path'] = 'clipboard'
            report['Dest_Path'] = window_title  # Destination app
            report['Dest_Volume_Type'] = None
        elif is_special_event:
            # Special event
            report['Source_Path'] = 'event_source'
            report['Dest_Path'] = event.get('object', {}).get('dst_path') or None
            report['Dest_Volume_Type'] = self._get_dest_volume_type(event)
        else:
            # File event
            source_path = event.get('path') or event.get('object', {}).get('path') or str(file_path)
            report['Source_Path'] = source_path
            report['Dest_Path'] = event.get('dst_path') or event.get('object', {}).get('dst_path')
            report['Dest_Volume_Type'] = self._get_dest_volume_type(event)
        
        # ========== D) Process info ==========
        # Best-effort từ context, không phải attribution kernel
        ctx = event.get('context', {}) or {}
        actor = event.get('actor', {}) or {}
        operation = event.get('operation', {}) or {}
        
        report['Process_Name'] = (
            operation.get('tool') or
            actor.get('process') or
            ctx.get('fg_app') or
            ctx.get('fg_process') or
            None
        )
        report['Process_ID'] = actor.get('pid') or ctx.get('fg_pid')
        report['Command_Line'] = actor.get('cmdline') or ctx.get('fg_cmdline')
        
        # ========== E) Advanced metrics / before-after ==========
        metrics = event.get('metrics', {}) or {}
        flags = event.get('flags', {}) or {}
        
        # File_Count phải là int (không None)
        report['File_Count'] = int(metrics.get('file_count') or event.get('File_Count') or 0)
        report['Entropy_Value'] = metrics.get('entropy') or event.get('Entropy_Value')
        report['Password_Flag'] = flags.get('password_protected') or event.get('Password_Flag') or fast_scan_result.get('is_encrypted_zip')
        
        # Before/After fields
        report['Original_File_Size'] = event.get('Original_File_Size')
        report['New_File_Size'] = report['File_Size']
        report['File_Hash_Before'] = event.get('File_Hash_Before')
        report['File_Hash_After'] = report['File_Hash']
        
        # Extension changes (chỉ khi moved/renamed)
        if report['Event_Type'] in ['Move', 'Rename']:
            report['Old_Extension'] = (
                event.get('old_ext') or
                event.get('object', {}).get('old_ext') or
                event.get('Old_Extension')
            )
            report['New_Extension'] = (
                event.get('new_ext') or
                event.get('object', {}).get('new_ext') or
                event.get('New_Extension') or
                report['File_Extension']
            )
        else:
            report['Old_Extension'] = None
            report['New_Extension'] = None
        
        # ========== Additional detection fields (không trong spec nhưng hữu ích) ==========
        report['_detection'] = {
            'yara_matches': fast_scan_result.get('yara_matches', []),
            'nlp_analysis': fast_scan_result.get('nlp_analysis', {}),
            'risk_score': risk_result.get('total_score', 0),
            'action': risk_result.get('action', 'log'),
            'is_sensitive_ml': deep_analysis_result.get('is_sensitive', False),
            'nlp_is_sensitive': deep_analysis_result.get('nlp_is_sensitive', False),
            'nlp_risk_score': deep_analysis_result.get('nlp_risk_score'),
            'ocr_text_length': len(deep_analysis_result.get('ocr_text', '')) if deep_analysis_result.get('ocr_text') else 0
        }
        
        return report
    
    def _get_event_type(self, event: Dict[str, Any]) -> str:
        """Map event type sang Event_Type: Create, Modify, Delete, Move, Rename"""
        # Nếu đã có từ L1, dùng luôn
        if event.get('Event_Type'):
            return event['Event_Type']
        
        # Map từ type field
        event_type = event.get('type', '').lower()
        if 'created' in event_type:
            return 'Create'
        elif 'modified' in event_type:
            return 'Modify'
        elif 'deleted' in event_type:
            return 'Delete'
        elif 'moved' in event_type:
            # Check nếu là rename (same dir, different name)
            src_path = event.get('path') or event.get('object', {}).get('path')
            dst_path = event.get('dst_path') or event.get('object', {}).get('dst_path')
            if src_path and dst_path:
                try:
                    src = Path(src_path)
                    dst = Path(dst_path)
                    if src.parent == dst.parent and src.name != dst.name:
                        return 'Rename'
                except Exception:
                    pass
            return 'Move'
        
        return 'Modify'  # default
    
    def _get_operation_type(self, event: Dict[str, Any]) -> str:
        """Map sang Operation_Type: Create, Overwrite, Delete, Move, Modify"""
        # Nếu đã có từ L1, dùng luôn
        if event.get('Operation_Type'):
            return event['Operation_Type']
        
        # Map từ operation.op_type
        op_type = event.get('operation', {}).get('op_type', '')
        if 'create' in op_type.lower():
            return 'Create'
        elif 'delete' in op_type.lower():
            return 'Delete'
        elif 'move' in op_type.lower():
            return 'Move'
        elif 'modify' in op_type.lower():
            # Check nếu có dst_path => Overwrite
            if event.get('dst_path') or event.get('object', {}).get('dst_path'):
                return 'Overwrite'
            return 'Modify'
        
        return 'Modify'  # default
    
    def _get_timestamp(self, event: Dict[str, Any]) -> str:
        """Convert timestamp sang ISO UTC string"""
        # Nếu đã có từ L1, dùng luôn
        if event.get('Timestamp'):
            return event['Timestamp']
        
        # Convert từ ts (unix float hoặc ISO string)
        ts = event.get('ts')
        if ts is None:
            return datetime.now(timezone.utc).isoformat()
        
        if isinstance(ts, str):
            # Đã là ISO string
            return ts
        elif isinstance(ts, (int, float)):
            # Unix timestamp
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            return dt.isoformat()
        
        return datetime.now(timezone.utc).isoformat()
    
    def _get_extension(self, file_path: Path) -> Optional[str]:
        """Lấy extension từ file path (lowercase)"""
        if not file_path:
            return None
        ext = file_path.suffix.lower()
        return ext if ext else None
    
    def _calculate_sensitivity(
        self,
        event: Dict[str, Any],
        fast_scan_result: Dict[str, Any],
        deep_analysis_result: Dict[str, Any],
        risk_result: Dict[str, Any]
    ) -> str:
        """
        Tính File_Sensitivity: Normal, Sensitive, Highly Sensitive
        Dựa trên:
        - YARA matches (PII patterns)
        - ML classification
        - Risk score
        - File location
        """
        # Nếu đã có từ L1 và không có detection results, giữ nguyên
        if event.get('File_Sensitivity') and not fast_scan_result.get('yara_matches') and not deep_analysis_result.get('is_sensitive'):
            return event['File_Sensitivity']
        
        # Check YARA matches (high-risk patterns)
        yara_matches = fast_scan_result.get('yara_matches', [])
        high_risk_patterns = ['id', 'cmnd', 'cccd', 'credit', 'card', 'bank', 'api_key']
        has_high_risk_pattern = any(
            any(pattern in match.get('rule', '').lower() for pattern in high_risk_patterns)
            for match in yara_matches
        )
        
        # Check ML classification
        is_sensitive_ml = deep_analysis_result.get('is_sensitive', False)
        ml_confidence = deep_analysis_result.get('ml_result', {}).get('confidence', 0) if deep_analysis_result.get('ml_result') else 0
        
        # Check risk score
        risk_score = risk_result.get('total_score', 0)
        
        # Check file location
        file_path = event.get('path') or event.get('object', {}).get('path') or ''
        path_lower = str(file_path).lower()
        sensitive_locations = ['finance', 'hr', 'customer', 'payroll', 'confidential', 'secret', 'private']
        is_sensitive_location = any(loc in path_lower for loc in sensitive_locations)
        
        # Decision logic
        if has_high_risk_pattern or (is_sensitive_ml and ml_confidence > 0.8) or risk_score >= 7.0:
            if is_sensitive_location:
                return 'Highly Sensitive'
            return 'Sensitive'
        elif is_sensitive_ml or risk_score >= 4.0 or len(yara_matches) > 0:
            return 'Sensitive'
        elif is_sensitive_location:
            return 'Sensitive'
        else:
            return 'Normal'
    
    def _get_dest_volume_type(self, event: Dict[str, Any]) -> Optional[str]:
        """Lấy Dest_Volume_Type từ event"""
        # Nếu đã có từ L1, dùng luôn
        if event.get('Dest_Volume_Type'):
            return event['Dest_Volume_Type']
        
        # Lấy từ dst_path
        dst_path = event.get('dst_path') or event.get('object', {}).get('dst_path')
        if not dst_path:
            return None
        
        # Extract drive letter
        try:
            drive = Path(dst_path).drive
            if drive:
                # Map drive letter to volume type (best-effort)
                # Trong thực tế cần gọi Windows API, nhưng đây là approximation
                return self._infer_volume_type_from_drive(drive)
        except Exception:
            pass
        
        return None
    
    def _infer_volume_type_from_drive(self, drive: str) -> str:
        """Infer volume type từ drive letter (best-effort)"""
        # Đây là approximation, trong thực tế cần gọi Windows API
        # Fixed drives thường là C:, D:, E: (nếu không phải removable)
        # Removable thường là F:, G:, etc. (nhưng không chắc chắn)
        # Network drives thường là mapped drives
        # Tạm thời return None, để L1 xử lý chính xác hơn
        return None
