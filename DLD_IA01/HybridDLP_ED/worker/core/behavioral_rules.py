"""
Behavioral Rules Engine - Phát hiện hành vi tuồn dữ liệu dựa trên điều kiện từ event fields
Theo yêu cầu trong Noteupdate.txt
"""
from typing import Dict, Any, List, Optional, Tuple
from loguru import logger
import re
from datetime import datetime, time
from pathlib import Path
from .config_provider import get_config_provider


class BehavioralRule:
    """Một rule phát hiện hành vi"""
    
    def __init__(self, name: str, description: str, severity: str = "high"):
        self.name = name
        self.description = description
        self.severity = severity  # "high", "medium", "low"
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Kiểm tra rule
        
        Returns:
            (matched: bool, details: dict)
        """
        raise NotImplementedError


class ClipboardPasteToExternalAppRule(BehavioralRule):
    """
    Rule 1: Copy dữ liệu → Paste vào Web Browser (AI / Web App)
    Phát hiện: Copy dữ liệu nội bộ rồi dán vào web (AI, form web, cloud)
    
    Hybrid Rule: Pseudo Rule (context/behavior) + YARA Rule (content signature)
    Pipeline:
    1. Check Context (is_external_sink) - browser + web/chat/mail
    2. Check Sensitive Content (is_sensitive_text) - sensitivity, entropy, IOC, YARA, text_len
    3. Check Behavior (snapshot_linked, content_type)
    4. Decision: Violation if all conditions met
    """
    
    def __init__(self):
        super().__init__(
            name="Clipboard_Paste_To_External_App",
            description="Paste dữ liệu nhạy cảm vào ứng dụng bên ngoài (GPT, Discord, Zalo, etc.)",
            severity="high"
        )
        
        # Load config từ config_provider (ưu tiên config_sync từ server, fallback to local)
        config_provider = get_config_provider()
        self.browser_apps = config_provider.get_browser_apps()
        self.messaging_apps = config_provider.get_messaging_apps()
        self.sensitive_domains = config_provider.get_sensitive_domains()
        self.sensitive_title_keywords = config_provider.get_sensitive_title_keywords()
        
        logger.info(
            f"ClipboardPasteToExternalAppRule initialized with config: "
            f"browser_apps={len(self.browser_apps)}, "
            f"messaging_apps={len(self.messaging_apps)}, "
            f"sensitive_domains={len(self.sensitive_domains)}, "
            f"sensitive_title_keywords={len(self.sensitive_title_keywords)}"
        )
    
    def _is_external_sink(self, event: Dict[str, Any]) -> bool:
        """
        Check if destination is external sink (browser + web/chat/mail)
        
        Returns:
            True if paste to external web/chat/mail via browser
        """
        clipboard = event.get('clipboard', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_clipboard = raw_original.get('clipboard', {}) or {}
        
        # Get dest_window_title, dest_domain, dest_app
        title = (
            clipboard.get('dest_window_title') or
            raw_clipboard.get('dest_window_title') or
            clipboard.get('active_window_title') or
            raw_clipboard.get('active_window_title') or
            event.get('context', {}).get('window_title') or
            ''
        ).lower()
        
        domain = (
            clipboard.get('dest_domain') or
            raw_clipboard.get('dest_domain') or
            ''
        ).lower()
        
        app = (
            clipboard.get('dest_app') or
            raw_clipboard.get('dest_app') or
            event.get('operation', {}).get('tool') or
            event.get('context', {}).get('fg_app') or
            ''
        ).lower()
        
        # Check if app is browser
        is_browser = any(browser in app for browser in self.browser_apps)
        
        # Check if app is messaging app (desktop app)
        is_messaging_app = any(messaging_app in app for messaging_app in self.messaging_apps)
        
        # If messaging app → always external sink (high risk)
        if is_messaging_app:
            logger.debug(f"External sink detected: Messaging app = {app}")
            return True
        
        # If not browser and not messaging app → not external sink
        if not is_browser:
            return False
        
        # Check if destination is sensitive (web/chat/mail)
        is_sensitive_domain = domain in self.sensitive_domains
        is_sensitive_title = any(keyword in title for keyword in self.sensitive_title_keywords)
        
        # If browser + sensitive domain/title → external sink
        if is_sensitive_domain or is_sensitive_title:
            logger.debug(f"External sink detected: Browser + sensitive domain/title. domain={domain}, title={title[:50]}")
            return True
        
        # If browser + has sensitive content (IOC hits, YARA matches) → also external sink
        # This handles cases where user pastes sensitive data to any browser
        ioc_hits = event.get('ioc_hits') or []
        if len(ioc_hits) > 0:
            # Browser + sensitive content → external sink
            logger.debug(f"External sink detected: Browser + sensitive content (IOC hits={len(ioc_hits)})")
            return True
        
        # Default: browser alone is not external sink (unless sensitive domain/title)
        return False
    
    def _is_sensitive_text(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> bool:
        """
        Check if text content is sensitive
        
        IMPORTANT: Only check entropy/text_len if there is actual text content.
        For images without OCR text, only check YARA/IOC/sensitivity label.
        
        Checks:
        - sensitivity label (Sensitive, Highly Sensitive)
        - IOC hits
        - YARA matches (from actual text content or OCR text)
        - entropy >= 4.3 (ONLY if text content exists)
        - text_len >= 500 (ONLY if text content exists)
        
        Returns:
            True if content is sensitive
        """
        # 1. Check sensitivity label
        obj = event.get('object', {}) or {}
        sensitivity = obj.get('sensitivity') or event.get('File_Sensitivity', '')
        if sensitivity in {"Sensitive", "Highly Sensitive", "sensitive", "highly sensitive"}:
            return True
        
        # 2. Check IOC hits
        ioc_hits = event.get('ioc_hits') or []
        if len(ioc_hits) > 0:
            return True
        
        # 3. Check YARA matches (content signature) - this is the most reliable check
        yara_matches = fast_scan_result.get('yara_matches', [])
        if yara_matches:
            return True
        
        # 4. Check if we have actual text content (not just binary/image data)
        # Get text content from multiple sources
        content = event.get('content', {}) or {}
        clipboard = event.get('clipboard', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_clipboard = raw_original.get('clipboard', {}) or {}
        raw_content = raw_original.get('content', {}) or {}
        
        # Check for actual text content
        has_text_content = bool(
            clipboard.get('text_file') or
            raw_clipboard.get('text_file') or
            content.get('sample') or
            raw_content.get('sample') or
            clipboard.get('content') or
            fast_scan_result.get('ocr_text')  # OCR text from image
        )
        
        # If no text content, only check YARA/IOC/sensitivity (already done above)
        # Don't check entropy/text_len for images without OCR text
        if not has_text_content:
            logger.debug("_is_sensitive_text: No text content found, skipping entropy/text_len checks")
            return False
        
        # 5. Check entropy (ONLY if we have text content)
        metrics = event.get('metrics', {}) or {}
        entropy = metrics.get('entropy') or 0
        if entropy >= 4.3:
            return True
        
        # 6. Check text length (ONLY if we have text content)
        text_len = (
            clipboard.get('content_len') or
            raw_clipboard.get('content_len') or
            clipboard.get('text_len') or
            raw_clipboard.get('text_len') or
            len(fast_scan_result.get('ocr_text', '')) or  # OCR text length
            0
        )
        if text_len >= 500:
            return True
        
        return False
    
    def _is_outside_working_hours(self, event: Dict[str, Any]) -> bool:
        """
        Check if event occurs outside working hours (8:00 - 18:00)
        
        Returns:
            True if outside working hours, False otherwise
        """
        try:
            # Get timestamp from event
            ts_str = event.get('ts') or event.get('timestamp', '')
            if not ts_str:
                return False
            
            # Parse timestamp (ISO format or Unix timestamp)
            if isinstance(ts_str, (int, float)):
                dt = datetime.fromtimestamp(ts_str)
            else:
                # Try ISO format
                dt = datetime.fromisoformat(str(ts_str).replace('Z', '+00:00'))
            
            # Get hour
            event_hour = dt.hour
            
            # Working hours: 8:00 - 18:00 (8 AM - 6 PM)
            # Outside working hours: < 8 or >= 18
            is_outside = event_hour < 8 or event_hour >= 18
            
            return is_outside
        except Exception as e:
            logger.debug(f"Error checking working hours: {e}")
            return False
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Check clipboard paste to external app - Hybrid Rule
        
        Pipeline:
        1. Check operation.op_type = "clipboard_paste"
        2. Check clipboard.content_type = "Text"
        3. Check clipboard.snapshot_linked = True (copy từ file)
        4. Check is_sensitive_text() - sensitivity, IOC, YARA, entropy, text_len
        5. Check is_external_sink() - browser + web/chat/mail
        6. Check outside_working_hours (optional - tăng risk)
        
        Returns:
            (matched: bool, details: dict)
        """
        # 1. Check operation.op_type = "clipboard_paste" (REQUIRED)
        operation = event.get('operation', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_op = raw_original.get('operation', {}) or {}
        
        op_type = (
            raw_op.get('op_type') or
            operation.get('op_type') or
            event.get('type') or
            ''
        ).lower()
        
        if op_type != 'clipboard_paste' and 'paste' not in op_type:
            logger.debug(f"ClipboardPasteToExternalAppRule: op_type check failed. op_type={op_type}")
            return False, {}
        
        # 2. Check clipboard.content_type
        # NOTE:
        #   - For normal text paste:      content_type == "Text"
        #   - For image paste + OCR text: content_type may be "Image"/"Bitmap" but
        #     fast_scan_result will contain YARA matches if OCR extracted sensitive text.
        #   - For FileList with images:    content_type == "FileList" with file_list containing image files
        clipboard = event.get('clipboard', {}) or {}
        raw_clipboard = raw_original.get('clipboard', {}) or {}
        
        content_type = (
            clipboard.get('content_type') or
            raw_clipboard.get('content_type') or
            ''
        )
        
        # Check for FileList with image files
        file_list = (
            clipboard.get('file_list') or
            raw_clipboard.get('file_list') or
            []
        )
        
        # Check if FileList contains image files
        is_filelist_with_images = False
        if content_type == 'FileList' and file_list:
            image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp']
            for file_path_str in file_list:
                if file_path_str:
                    file_path_obj = Path(str(file_path_str))
                    if file_path_obj.suffix.lower() in image_extensions:
                        is_filelist_with_images = True
                        break
        
        # Allow:
        #   - content_type == "Text"
        #   - OR content_type == "FileList" with image files (will be OCR'd)
        #   - OR image-like types IF we already have strong sensitive evidence (OCR + YARA/IOC)
        is_text_type = (content_type == 'Text')
        is_filelist_type = (content_type == 'FileList' and is_filelist_with_images)
        
        # 3. Check clipboard.snapshot_linked = True (copy từ file) (OPTIONAL)
        # NOTE (per Noteupdate.txt pseudo-rule): snapshot_linked should be True.
        # In practice, some agents may omit this field. We allow snapshot_linked=None ONLY when
        # there is strong sensitive evidence (YARA/IOC/sensitivity label) to avoid false positives.
        snapshot_linked = (
            clipboard.get('snapshot_linked') or
            raw_clipboard.get('snapshot_linked')
        )
        
        # Determine whether we have strong evidence of sensitive content without relying on heuristics
        obj = event.get('object', {}) or {}
        sensitivity = obj.get('sensitivity') or event.get('File_Sensitivity', '')
        ioc_hits = event.get('ioc_hits') or []
        yara_matches = fast_scan_result.get('yara_matches', []) or []
        has_strong_sensitive_evidence = bool(
            yara_matches or
            ioc_hits or
            sensitivity in {"Sensitive", "Highly Sensitive", "sensitive", "highly sensitive"}
        )

        # Allow content_type:
        #   - "Text" (normal text paste)
        #   - "FileList" with image files (will be OCR'd, YARA will match if sensitive)
        #   - Image types ("Image", "Bitmap", etc.) IF we have strong evidence (OCR + YARA/IOC)
        content_type_lower = str(content_type).lower()
        is_image_type = any(t in content_type_lower for t in ["image", "bitmap", "png", "jpg", "jpeg"])
        
        if not is_text_type and not is_filelist_type:
            if not (is_image_type and has_strong_sensitive_evidence):
                logger.debug(
                    "ClipboardPasteToExternalAppRule: content_type check failed. "
                    f"content_type={content_type}, is_text_type={is_text_type}, "
                    f"is_filelist_type={is_filelist_type}, is_image_type={is_image_type}, "
                    f"has_strong_evidence={has_strong_sensitive_evidence}"
                )
                return False, {}

        # Enforce snapshot_linked policy
        if snapshot_linked is False:
            logger.debug("ClipboardPasteToExternalAppRule: snapshot_linked=False (required=true) -> skip")
            return False, {}

        if snapshot_linked is None and not has_strong_sensitive_evidence:
            logger.debug("ClipboardPasteToExternalAppRule: snapshot_linked missing and no strong evidence -> skip")
            return False, {}
        
        # 4. Check is_sensitive_text() - Hybrid: Pseudo Rule + YARA Rule
        # For FileList with images: if paste to external sink (messaging app), consider it sensitive even without YARA
        is_external = self._is_external_sink(event)
        
        # Special case: FileList with images paste to messaging app is always risky (even without OCR text)
        if is_filelist_type and is_external:
            # Check if destination is messaging app (high risk)
            dest_app_check = (
                clipboard.get('dest_app') or
                raw_clipboard.get('dest_app') or
                operation.get('tool') or
                event.get('context', {}).get('fg_app') or
                ''
            ).lower()
            
            messaging_apps = ['zalo.exe', 'discord.exe', 'telegram.exe', 'whatsapp.exe', 'teams.exe', 'slack.exe']
            is_messaging = any(app in dest_app_check for app in messaging_apps)
            
            if is_messaging:
                # FileList (image) paste to messaging app → always risky, even without YARA match
                logger.warning(
                    f"ClipboardPasteToExternalAppRule: FileList with images paste to messaging app ({dest_app_check}) "
                    f"- considered sensitive even without YARA match"
                )
                # Skip is_sensitive_text check for this case, proceed to external sink check
            else:
                # For other external sinks (browser), still need YARA/IOC evidence
                if not self._is_sensitive_text(event, fast_scan_result):
                    logger.debug(f"ClipboardPasteToExternalAppRule: is_sensitive_text check failed")
                    return False, {}
        else:
            # Normal case: need sensitive text evidence
            if not self._is_sensitive_text(event, fast_scan_result):
                logger.debug(f"ClipboardPasteToExternalAppRule: is_sensitive_text check failed")
                return False, {}
        
        # 5. Check is_external_sink() - browser + web/chat/mail
        if not is_external:
            logger.debug(f"ClipboardPasteToExternalAppRule: is_external_sink check failed")
            return False, {}
        
        # 6. Check outside_working_hours (optional - tăng risk)
        is_outside_working_hours = self._is_outside_working_hours(event)
        
        # All checks passed - this is a violation (data leak behavior)
        # Get details for logging
        yara_matches = yara_matches
        
        title = (
            clipboard.get('dest_window_title') or
            raw_clipboard.get('dest_window_title') or
            clipboard.get('active_window_title') or
            raw_clipboard.get('active_window_title') or
            event.get('context', {}).get('window_title') or
            ''
        ).lower()
        
        domain = (
            clipboard.get('dest_domain') or
            raw_clipboard.get('dest_domain') or
            ''
        ).lower()
        
        app = (
            clipboard.get('dest_app') or
            raw_clipboard.get('dest_app') or
            operation.get('tool') or
            event.get('context', {}).get('fg_app') or
            ''
        ).lower()
        
        # Get sensitivity details
        obj = event.get('object', {}) or {}
        sensitivity = obj.get('sensitivity') or event.get('File_Sensitivity', '')
        ioc_hits = event.get('ioc_hits') or []
        metrics = event.get('metrics', {}) or {}
        entropy = metrics.get('entropy') or 0
        text_len = clipboard.get('content_len') or raw_clipboard.get('content_len') or 0
        
        # Build reason with all details
        reason_parts = [
            f"Paste sensitive data to external sink",
            f"dest={title[:50] or domain or app}",
            f"op_type={op_type}",
            f"snapshot_linked={snapshot_linked}"
        ]
        
        sensitivity_reasons = []
        if sensitivity in {"Sensitive", "Highly Sensitive"}:
            sensitivity_reasons.append(f"sensitivity={sensitivity}")
        if len(ioc_hits) > 0:
            sensitivity_reasons.append(f"ioc_hits={len(ioc_hits)}")
        if yara_matches:
            sensitivity_reasons.append(f"yara_rules={len(yara_matches)}")
        if entropy >= 4.3:
            sensitivity_reasons.append(f"entropy={entropy:.2f}")
        if text_len >= 500:
            sensitivity_reasons.append(f"text_len={text_len}")
        
        if sensitivity_reasons:
            reason_parts.append("(" + ", ".join(sensitivity_reasons) + ")")
        
        if is_outside_working_hours:
            reason_parts.append("(Outside working hours)")
        
        reason = " | ".join(reason_parts)
        
        logger.warning(
            f"ClipboardPasteToExternalAppRule VIOLATION DETECTED: "
            f"dest={title[:50] or domain or app}, "
            f"yara={len(yara_matches)}, sensitivity={sensitivity}, "
            f"ioc={len(ioc_hits)}, entropy={entropy:.2f}, text_len={text_len}"
        )
        
        return True, {
            'rule_name': self.name,
            'severity': self.severity,
            'window_title': title,
            'dest_domain': domain,
            'dest_app': app,
            'op_type': op_type,
            'snapshot_linked': snapshot_linked,
            'content_type': content_type,
            'sensitivity': sensitivity,
            'ioc_hits_count': len(ioc_hits),
            'entropy': entropy,
            'text_len': text_len,
            'outside_working_hours': is_outside_working_hours,
            'yara_matches': yara_matches,
            'reason': reason
        }


class USBDataExfiltrationRule(BehavioralRule):
    """
    Rule 2: Copy dữ liệu ra USB/Removable device
    Phát hiện: Copy file nhạy cảm ra USB, external drive
    """
    
    def __init__(self):
        super().__init__(
            name="USB_Data_Exfiltration",
            description="Copy dữ liệu nhạy cảm ra USB/Removable device",
            severity="high"
        )
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check USB copy"""
        # Load config từ config provider (unified interface)
        config_provider = get_config_provider()
        removable_drives = config_provider.get_removable_drives()
        
        # Read from both event and raw_original (per Noteupdate.txt event samples)
        raw_original = event.get('raw_original', {}) or {}
        raw_obj = raw_original.get('object', {}) or {}
        operation = event.get('operation', {}) or {}
        raw_operation = raw_original.get('operation', {}) or {}
        
        obj = event.get('object', {}) or {}
        dest_volume_type = (
            operation.get('dest_volume_type') or
            raw_operation.get('dest_volume_type') or
            obj.get('dest_volume_type') or
            raw_obj.get('dest_volume_type') or
            obj.get('volume_type') or
            raw_obj.get('volume_type') or
            event.get('Dest_Volume_Type') or
            ''
        )
        
        dest_path = (
            obj.get('dst_path') or
            raw_obj.get('dst_path') or
            obj.get('path') or
            raw_obj.get('path') or
            event.get('dst_path') or
            event.get('path') or
            event.get('file_path') or
            event.get('Dest_Path') or
            ''
        ).lower()
        
        # Check nếu là removable/USB (per Noteupdate.txt: object.drive = E:\...)
        obj_drive = (
            obj.get('drive') or
            raw_obj.get('drive') or
            ''
        ).lower()

        op_type = str(operation.get('op_type') or raw_operation.get('op_type') or event.get('type') or '').lower()
        semantic_hint = str(
            operation.get('dlp_semantic_hint') or raw_operation.get('dlp_semantic_hint') or ''
        ).lower()
        semantic_action = str(
            operation.get('semantic_action') or raw_operation.get('semantic_action') or ''
        ).lower()
        
        is_removable = (
            dest_volume_type and 'removable' in str(dest_volume_type).lower()
        ) or any(
            drive in dest_path or drive in obj_drive for drive in removable_drives
        )
        
        if not is_removable:
            return False, {}
        is_transfer = (
            'external' in op_type
            or 'copy_to_removable' in semantic_action
            or 'external_transfer' in semantic_hint
        )
        if semantic_hint == 'local' and not is_transfer:
            return False, {}
        if not is_transfer and event.get('type') not in {'file_created', 'file_moved', 'file_renamed'}:
            return False, {}
        
        # Check có YARA match hoặc file sensitivity (per Noteupdate.txt: object.sensitivity = "confidential")
        yara_matches = fast_scan_result.get('yara_matches', [])
        file_sensitivity = (
            obj.get('sensitivity') or
            raw_obj.get('sensitivity') or
            event.get('File_Sensitivity') or
            ''
        ).lower()
        file_name = (
            obj.get('name')
            or raw_obj.get('name')
            or dest_path
            or event.get('file_path')
            or ''
        )
        file_ext = Path(str(file_name)).suffix.lower()
        is_archive = file_ext in {'.zip', '.7z', '.rar'}
        archive_scanned = bool(fast_scan_result.get('archive_scanned'))
        archive_sensitive_hits = fast_scan_result.get('archive_sensitive_hits') or []
        archive_encrypted = bool(fast_scan_result.get('is_encrypted_zip'))

        if is_archive and archive_scanned and not archive_encrypted and not yara_matches and not archive_sensitive_hits:
            if 'confidential' not in file_sensitivity and 'highly' not in file_sensitivity:
                return False, {
                    'rule_name': self.name,
                    'severity': 'low',
                    'dest_volume_type': dest_volume_type,
                    'dest_path': dest_path,
                    'file_sensitivity': file_sensitivity,
                    'archive_scanned': True,
                    'archive_entries': fast_scan_result.get('archive_entries'),
                    'archive_scanned_files': fast_scan_result.get('archive_scanned_files'),
                    'reason': "ZIP copied to USB but scanned archive content had no sensitive hits"
                }
         
        if yara_matches or 'sensitive' in file_sensitivity or 'confidential' in file_sensitivity:
            return True, {
                'rule_name': self.name,
                'severity': (
                    self.severity
                    if not (is_archive and archive_scanned and not archive_encrypted and not archive_sensitive_hits)
                    else 'medium'
                ),
                'dest_volume_type': dest_volume_type,
                'dest_path': dest_path,
                'yara_matches': yara_matches,
                'file_sensitivity': file_sensitivity,
                'archive_scanned': archive_scanned,
                'archive_entries': fast_scan_result.get('archive_entries'),
                'archive_scanned_files': fast_scan_result.get('archive_scanned_files'),
                'archive_sensitive_hits': archive_sensitive_hits,
                'reason': f"Copy dữ liệu nhạy cảm ra USB/Removable: {dest_path}"
            }
        
        return False, {}


class NetworkUploadRule(BehavioralRule):
    """
    Rule 3: SMB/FTP/TCP/UDP Upload
    Phát hiện: Upload file qua network protocols
    """
    
    def __init__(self):
        super().__init__(
            name="Network_Upload",
            description="Upload dữ liệu qua SMB/FTP/TCP/UDP",
            severity="high"
        )
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Implement đúng Rule 3 — Network Upload trong Noteupdate.txt
        
        Phải thỏa 3 cụm điều kiện:
        3.1 Upload operation
        3.2 External destination
        3.3 Sensitive file/content
        """
        raw_original = event.get("raw_original", {}) or {}
        operation = event.get("operation", {}) or {}
        raw_op = raw_original.get("operation", {}) or {}
        network = event.get("network", {}) or raw_original.get("network", {}) or {}
        
        evt_type = str(event.get("type", "") or "").lower()
        op_type = str(
            raw_op.get("op_type")
            or operation.get("op_type")
            or evt_type
        ).lower()
        
        # -------- 3.1 Upload operation --------
        upload_types = {
            "network_flow",
            "network_flow_summary",
            "http_request",
            "http_upload",
            "file_upload",
            "browser_upload",
            "network_upload",
            "cloud_exfiltration",
            "data_exfiltration",
            "corr_suspected_upload",
        }
        method = str(network.get("method") or "").upper()
        content_type = str(network.get("content_type") or "").lower()
        metrics = event.get("metrics", {}) or {}
        bytes_out = (
            network.get("bytes_out_total")
            or network.get("bytes_sent_total")
            or metrics.get("bytes_out")
            or 0
        )
        
        is_upload_type = evt_type in upload_types
        is_upload_op = any(k in op_type for k in ["upload", "post", "put", "send", "exfil"])
        is_upload_http = method in {"POST", "PUT", "PATCH"} or "multipart/form-data" in content_type
        is_large_bytes = isinstance(bytes_out, (int, float)) and bytes_out >= 100 * 1024  # 100KB
        
        cond_upload = is_upload_type or is_upload_op or is_upload_http or is_large_bytes
        if not cond_upload:
            return False, {}
        
        # -------- 3.2 External destination --------
        # Load config từ config provider (unified interface)
        config_provider = get_config_provider()
        
        ctx = event.get("context", {}) or {}
        actor = event.get("actor", {}) or {}
        process_name = str(
            actor.get("process")
            or operation.get("tool")
            or ctx.get("fg_process")
            or ""
        ).lower()
        app = str(
            ctx.get("fg_app")
            or operation.get("tool")
            or actor.get("process")
            or ""
        ).lower()
        window_title = str(ctx.get("window_title") or "").lower()
        dest_domain = str(network.get("dest_domain") or "").lower()
        dest_ip = str(network.get("dest_ip") or "").lower()
        
        # Browser / desktop upload apps / CLI tools - Load từ config
        browser_apps = config_provider.get_network_browser_apps()
        desktop_upload_apps = config_provider.get_desktop_upload_apps()
        cli_tools = config_provider.get_cli_tools()
        
        is_browser = any(b in app for b in browser_apps)
        is_desktop_upload = any(d in app for d in desktop_upload_apps)
        is_cli_upload = any(t in process_name for t in cli_tools)
        
        sensitive_domains = config_provider.get_network_sensitive_domains()
        is_external_domain = bool(dest_domain) and (
            dest_domain in sensitive_domains or "." in dest_domain
        )
        
        cond_external = (
            is_browser
            or is_desktop_upload
            or is_cli_upload
            or is_external_domain
            or bool(dest_ip)
        )
        if not cond_external:
            return False, {}
        
        # -------- 3.3 Sensitive file/content --------
        obj = event.get("object", {}) or {}
        file_path = str(obj.get("path") or event.get("file_path") or "").lower()
        sensitivity = str(obj.get("sensitivity") or event.get("File_Sensitivity") or "").lower()
        yara_matches = fast_scan_result.get("yara_matches", []) or []
        ioc_hits = event.get("ioc_hits") or []
        debug = event.get("debug", {}) or {}
        evidence = debug.get("evidence", {}) or {}
        has_recent_staging = bool(evidence.get("recent_staging"))
        
        sensitive_exts = {
            ".xlsx",
            ".xls",
            ".csv",
            ".docx",
            ".doc",
            ".pdf",
            ".sql",
            ".zip",
            ".7z",
            ".env",
        }
        ext = ""
        if file_path:
            ext = Path(file_path).suffix.lower()
        
        is_sensitive_label = any(k in sensitivity for k in ["sensitive", "confidential", "highly"])
        is_high_label = any(k in sensitivity for k in ["confidential", "highly"])
        is_sensitive_ext = ext in sensitive_exts
        is_corr_source = evt_type in {
            # corr_suspected_upload đã bị skip ở worker process_event() — không có mặt ở đây
            "cloud_exfiltration",
            "http_upload",
            "data_exfiltration",
        }
        
        cond_sensitive = (
            is_sensitive_label
            or yara_matches
            or ioc_hits
            or is_sensitive_ext
            or has_recent_staging
            or is_corr_source
        )
        if not cond_sensitive:
            return False, {}

        yara_count = len(yara_matches)
        evidence_level = "low"
        if ioc_hits or is_high_label or yara_count >= 3 or has_recent_staging or is_corr_source:
            evidence_level = "high"
        elif (
            (is_sensitive_label and (yara_count >= 1 or is_sensitive_ext))
            or (yara_count >= 2 and is_sensitive_ext)
        ):
            evidence_level = "medium"

        severity = {
            "high": "high",
            "medium": "medium",
            "low": "low",
        }.get(evidence_level, "low")
        
        # -------- Build details --------
        reason_parts = [
            "Network upload of sensitive data",
            f"type={evt_type}",
            f"op_type={op_type}",
            f"dest_domain={dest_domain or dest_ip}",
            f"process={process_name or app}",
        ]
        if bytes_out:
            reason_parts.append(f"bytes_out={int(bytes_out)}")
        if is_sensitive_label:
            reason_parts.append(f"sensitivity={sensitivity}")
        if yara_matches:
            reason_parts.append(f"yara_rules={len(yara_matches)}")
        if ioc_hits:
            reason_parts.append(f"ioc_hits={len(ioc_hits)}")
        if has_recent_staging:
            reason_parts.append("recent_staging=True")
        reason_parts.append(f"evidence={evidence_level}")
        
        reason = " | ".join(reason_parts)
        
        logger.warning(
            f"NetworkUploadRule VIOLATION DETECTED: "
            f"dest={dest_domain or dest_ip}, process={process_name or app}, "
            f"bytes_out={bytes_out}, sensitivity={sensitivity}, yara={yara_count}, "
            f"ioc={len(ioc_hits)}, evidence={evidence_level}, severity={severity}"
        )
        
        return True, {
            "rule_name": self.name,
            "severity": severity,
            "dest_domain": dest_domain,
            "dest_ip": dest_ip,
            "dest_app": app,
            "process": process_name,
            "bytes_out": int(bytes_out) if isinstance(bytes_out, (int, float)) else bytes_out,
            "file_path": file_path,
            "sensitivity": sensitivity,
            "yara_matches": yara_matches,
            "ioc_hits_count": len(ioc_hits),
            "evidence_level": evidence_level,
            "recent_staging": has_recent_staging,
            "reason": reason,
        }


class BulkFileCopyRule(BehavioralRule):
    """
    Rule 4: Data Volume Spike - Copy hàng loạt file
    Phát hiện: Copy nhiều file trong thời gian ngắn
    """
    
    def __init__(self):
        super().__init__(
            name="Bulk_File_Copy",
            description="Copy hàng loạt file (Data Volume Spike)",
            severity="medium"
        )
        self.file_count_threshold = 50  # Số file trong cửa sổ thời gian
        self.preferred_window_sec = 10
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check bulk file copy"""
        raw_original = event.get('raw_original', {}) or {}
        raw_metrics = raw_original.get('metrics', {}) or {}
        raw_obj = raw_original.get('object', {}) or {}

        metrics = event.get('metrics', {}) or {}
        # Prefer explicit 10s counters if sensor provides them; fallback to legacy File_Count.
        file_count = (
            metrics.get('file_count_10s')
            or raw_metrics.get('file_count_10s')
            or event.get('File_Count_10s')
            or metrics.get('file_count')
            or raw_metrics.get('file_count')
            or event.get('File_Count')
            or 0
        )

        if file_count >= self.file_count_threshold:
            obj = event.get('object', {}) or {}
            dest_volume_type = (
                obj.get('dest_volume_type')
                or obj.get('volume_type')
                or raw_obj.get('dest_volume_type')
                or raw_obj.get('volume_type')
                or event.get('Dest_Volume_Type', '')
            )

            is_external = (
                'removable' in str(dest_volume_type).lower()
                or 'network' in str(dest_volume_type).lower()
            )

            if is_external:
                return True, {
                    'rule_name': self.name,
                    'severity': self.severity,
                    'file_count': file_count,
                    'window_sec': self.preferred_window_sec,
                    'dest_volume_type': dest_volume_type,
                    'reason': f"Copy {file_count} files ra thiết bị ngoài trong ~{self.preferred_window_sec}s"
                }

        return False, {}


class EncryptedArchiveRule(BehavioralRule):
    """
    Rule 5: Tạo encrypted archive (password-protected)
    Phát hiện: Tạo file nén có mật khẩu
    """
    
    def __init__(self):
        super().__init__(
            name="Encrypted_Archive",
            description="Tạo file nén có mật khẩu",
            severity="high"
        )
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check encrypted archive"""
        raw_original = event.get('raw_original', {}) or {}
        raw_flags = raw_original.get('flags', {}) or {}
        raw_obj = raw_original.get('object', {}) or {}

        flags = event.get('flags', {}) or {}
        password_protected = (
            flags.get('password_protected')
            or raw_flags.get('password_protected')
            or event.get('Password_Flag')
        )

        if password_protected:
            obj = event.get('object', {}) or {}
            dest_volume_type = (
                obj.get('dest_volume_type')
                or obj.get('volume_type')
                or raw_obj.get('dest_volume_type')
                or raw_obj.get('volume_type')
                or event.get('Dest_Volume_Type', '')
            )
            dest_path = (
                obj.get('dst_path') or raw_obj.get('dst_path')
                or event.get('dst_path') or event.get('Dest_Path') or ''
            ).lower()

            is_external = (
                'removable' in str(dest_volume_type).lower()
                or 'network' in str(dest_volume_type).lower()
                or any(d in dest_path for d in ['e:', 'f:', 'g:', 'h:', 'i:', 'j:'])
            )

            if is_external:
                return True, {
                    'rule_name': self.name,
                    'severity': self.severity,
                    'dest_volume_type': dest_volume_type,
                    'dest_path': dest_path,
                    'reason': "Tạo file nén có mật khẩu và copy ra thiết bị ngoài"
                }

        return False, {}


class ExtensionChangeRule(BehavioralRule):
    """
    Rule 6: Đổi extension file (có thể để né tránh detection)
    Phát hiện: Rename file từ .xlsx → .txt, .docx → .encrypted, etc.
    """
    
    def __init__(self):
        super().__init__(
            name="Extension_Change",
            description="Đổi extension file (có thể né tránh detection)",
            severity="medium"
        )
        # Sensitive extensions
        self.sensitive_exts = ['.xlsx', '.xls', '.docx', '.doc', '.pdf', '.csv']
        # Suspicious new extensions
        self.suspicious_exts = ['.txt', '.encrypted', '.bak', '.tmp', '.old']
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check extension change (per Noteupdate.txt Kịch bản 6)"""
        # Check event type (per Noteupdate.txt: operation.op_type = "file_rename")
        event_type = event.get('type', '').lower()
        operation = event.get('operation', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_op = raw_original.get('operation', {}) or {}
        
        op_type = (
            raw_op.get('op_type') or
            operation.get('op_type') or
            event_type or
            ''
        ).lower()
        
        if 'rename' not in op_type and 'move' not in op_type:
            if event.get('Event_Type') not in ['Rename', 'Move']:
                return False, {}
        
        # Read from both event and raw_original (per Noteupdate.txt: object.old_ext, object.new_ext)
        obj = event.get('object', {}) or {}
        raw_obj = raw_original.get('object', {}) or {}
        
        old_ext = (
            obj.get('old_ext') or
            raw_obj.get('old_ext') or
            event.get('old_ext') or
            event.get('Old_Extension') or
            ''
        ).lower()
        
        new_ext = (
            obj.get('new_ext') or
            raw_obj.get('new_ext') or
            event.get('new_ext') or
            event.get('New_Extension') or
            ''
        ).lower()
        
        # Check nếu từ sensitive ext → suspicious ext (per Noteupdate.txt: salary.xlsx → salary.txt)
        if old_ext in self.sensitive_exts and new_ext in self.suspicious_exts:
            return True, {
                'rule_name': self.name,
                'severity': self.severity,
                'old_ext': old_ext,
                'new_ext': new_ext,
                'reason': f"Đổi extension từ {old_ext} sang {new_ext} (có thể né tránh detection)"
            }
        
        # Also check if old_ext != new_ext (any extension change is suspicious)
        if old_ext and new_ext and old_ext != new_ext:
            if old_ext in self.sensitive_exts:
                return True, {
                    'rule_name': self.name,
                    'severity': self.severity,
                    'old_ext': old_ext,
                    'new_ext': new_ext,
                    'reason': f"Đổi extension từ {old_ext} sang {new_ext} (có thể né tránh detection)"
                }
        
        return False, {}


class HighFrequencyClipboardRule(BehavioralRule):
    """
    Rule 7: Clipboard copy/paste tần suất cao
    Phát hiện: Copy/Paste nhiều lần trong thời gian ngắn
    """
    
    def __init__(self):
        super().__init__(
            name="High_Frequency_Clipboard",
            description="Clipboard copy/paste tần suất cao",
            severity="medium"
        )
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check high frequency clipboard"""
        clipboard = event.get('clipboard', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_clipboard = raw_original.get('clipboard', {}) or {}

        copy_frequency = clipboard.get('copy_frequency') or raw_clipboard.get('copy_frequency', '')
        paste_frequency = clipboard.get('paste_frequency') or raw_clipboard.get('paste_frequency', '')

        # Numeric values (per_minute float) — preferred over string parsing
        copy_frequency_value = (
            clipboard.get('copy_frequency_value')
            or raw_clipboard.get('copy_frequency_value')
        )
        paste_frequency_value = (
            clipboard.get('paste_frequency_value')
            or raw_clipboard.get('paste_frequency_value')
        )

        # 1. Check numeric values first (fast path)
        if isinstance(copy_frequency_value, (int, float)) and copy_frequency_value > 10:
            return True, {
                'rule_name': self.name,
                'severity': self.severity,
                'copy_frequency': copy_frequency,
                'copy_frequency_value': copy_frequency_value,
                'reason': f"Copy tần suất cao: {copy_frequency_value:.1f}/min"
            }
        if isinstance(paste_frequency_value, (int, float)) and paste_frequency_value > 10:
            return True, {
                'rule_name': self.name,
                'severity': self.severity,
                'paste_frequency': paste_frequency,
                'paste_frequency_value': paste_frequency_value,
                'reason': f"Paste tần suất cao: {paste_frequency_value:.1f}/min"
            }

        # 2. Fallback: parse string format e.g. "20.00/min" or "12/30s"
        try:
            if copy_frequency:
                copy_rate = float(re.search(r'[\d.]+', str(copy_frequency)).group())
                if copy_rate > 10:
                    return True, {
                        'rule_name': self.name,
                        'severity': self.severity,
                        'copy_frequency': copy_frequency,
                        'reason': f"Copy tần suất cao: {copy_frequency}"
                    }
            if paste_frequency:
                paste_rate = float(re.search(r'[\d.]+', str(paste_frequency)).group())
                if paste_rate > 10:
                    return True, {
                        'rule_name': self.name,
                        'severity': self.severity,
                        'paste_frequency': paste_frequency,
                        'reason': f"Paste tần suất cao: {paste_frequency}"
                    }
        except Exception:
            pass

        return False, {}


class BulkPasteRule(BehavioralRule):
    """
    Rule 8: Bulk paste event
    Phát hiện: Paste khối lượng lớn dữ liệu
    """
    
    def __init__(self):
        super().__init__(
            name="Bulk_Paste",
            description="Paste khối lượng lớn dữ liệu",
            severity="high"
        )
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check bulk paste"""
        clipboard = event.get('clipboard', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_clipboard = raw_original.get('clipboard', {}) or {}
        
        bulk_paste = clipboard.get('bulk_paste_event') or raw_clipboard.get('bulk_paste_event', False)
        content_len = clipboard.get('content_len') or raw_clipboard.get('content_len', 0)
        
        if bulk_paste or (content_len and content_len > 10000):  # > 10KB
            # Check có YARA match
            yara_matches = fast_scan_result.get('yara_matches', [])
            if yara_matches:
                return True, {
                    'rule_name': self.name,
                    'severity': self.severity,
                    'content_len': content_len,
                    'yara_matches': yara_matches,
                    'reason': f"Paste khối lượng lớn dữ liệu nhạy cảm ({content_len} chars)"
                }
        
        return False, {}


class CloudSyncRule(BehavioralRule):
    """
    Rule 9: Cloud Sync Copy/Move
    Phát hiện: Copy/Move file vào thư mục cloud sync (OneDrive, Dropbox)
    """
    def __init__(self):
        super().__init__(
            name="Cloud_Sync",
            description="Copy/Move file vào thư mục cloud sync",
            severity="medium"
        )
    
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check cloud sync (per Noteupdate.txt Kịch bản 6)"""
        # Check operation.op_type (per Noteupdate.txt: file_copy, file_rename)
        event_type = event.get('type', '').lower()
        operation = event.get('operation', {}) or {}
        raw_original = event.get('raw_original', {}) or {}
        raw_op = raw_original.get('operation', {}) or {}
        
        op_type = (
            raw_op.get('op_type') or
            operation.get('op_type') or
            event_type or
            ''
        ).lower()
        
        if 'move' not in op_type and 'rename' not in op_type and 'copy' not in op_type:
            # Check event['Event_Type'] as well
            if event.get('Event_Type') not in ['Move', 'Rename', 'Copy']:
                return False, {}
        
        obj = event.get('object', {}) or {}
        raw_obj = raw_original.get('object', {}) or {}

        dest_path = (
            obj.get('dst_path')
            or raw_obj.get('dst_path')
            or event.get('dst_path')
            or event.get('Dest_Path')
            or ''
        ).lower()

        _CLOUD_HINTS = ['onedrive', 'dropbox', 'google drive', 'googledrive', 'iclouddrive', '\\box\\', '/box/']
        if any(h in dest_path for h in _CLOUD_HINTS):
            # Check yara or sensitivity
            yara_matches = fast_scan_result.get('yara_matches', [])
            sensitivity = (
                obj.get('sensitivity') or
                raw_obj.get('sensitivity') or
                event.get('File_Sensitivity') or
                ''
            )
            if yara_matches or sensitivity in ["Sensitive", "Highly Sensitive", "sensitive", "highly sensitive", "confidential"]:
                return True, {
                    'rule_name': self.name,
                    'severity': "high",  # Tăng lên high nếu có content nhạy cảm
                    'dest_path': dest_path,
                    'yara_matches': yara_matches,
                    'reason': f"Copy/Move dữ liệu nhạy cảm lên Cloud Sync: {dest_path}"
                }
            return True, {
                'rule_name': self.name,
                'severity': self.severity,
                'dest_path': dest_path,
                'reason': f"Copy/Move file lên Cloud Sync: {dest_path}"
            }
        return False, {}

class ProcessAnomalyRule(BehavioralRule):
    """
    Rule 10: Process Anomaly
    Phát hiện: proc_start có ioc_hits chứa archive_staging, download tool, encoded command
    """
    def __init__(self):
        super().__init__(
            name="Process_Anomaly",
            description="Phát hiện process bất thường qua ioc_hits",
            severity="high"
        )

    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Check process anomaly (per Noteupdate.txt Rule 10)"""
        event_type = event.get('type', '').lower()
        if event_type not in ['proc_start', 'process_created']:
            return False, {}

        raw_original = event.get('raw_original', {}) or {}
        ioc_hits = event.get('ioc_hits') or raw_original.get('ioc_hits') or []

        # High-risk tags expected in ioc_hits (from cmdline IOC patterns)
        high_risk_ioc_tags = {
            'archive_staging', 'native_download_tool', 'bitsadmin_download',
            'cloud_exfiltration_tool', 'encoded_command', 'certutil_abuse',
            'email_exfiltration', 'credential_keyword',
        }

        # High-risk tags that appear in the top-level tags[] list
        # (set by _tags_for_name_and_path in process_sensor)
        high_risk_process_tags = {
            'file_transfer_tool', 'archive_tool', 'screen_capture_tool',
        }

        matched_ioc = [
            ioc.get('tag', '') for ioc in ioc_hits
            if any(t in str(ioc.get('tag', '')).lower() for t in high_risk_ioc_tags)
        ]

        tags_list = event.get('tags') or raw_original.get('tags') or []
        matched_proc_tags = [
            t for t in tags_list
            if any(hr in str(t).lower() for hr in high_risk_process_tags)
        ]

        all_matched = list(dict.fromkeys(matched_ioc + matched_proc_tags))

        if not all_matched:
            return False, {}

        actor = event.get('actor', {}) or {}
        raw_actor = raw_original.get('actor', {}) or {}
        proc = event.get('process', {}) or {}
        proc_name = (
            actor.get('process')
            or raw_actor.get('process')
            or proc.get('name')
            or ''
        )
        cmdline = (
            actor.get('cmdline')
            or raw_actor.get('cmdline')
            or proc.get('cmdline')
            or ''
        )

        return True, {
            'rule_name': self.name,
            'severity': self.severity,
            'matched_tags': all_matched,
            'process': proc_name,
            'cmdline': cmdline,
            'reason': f"Process bất thường ({proc_name}): {', '.join(all_matched)}"
        }

class PrintJobRule(BehavioralRule):
    """
    Rule 11: Print Job
    Phát hiện: In dữ liệu nhạy cảm ra máy in ảo (Virtual PDF)
    """
    def __init__(self):
        super().__init__(
            name="Print_Job",
            description="In tài liệu nhạy cảm",
            severity="medium"
        )
        
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        event_type = event.get('type', '').lower()
        if event_type != 'print_job':
            return False, {}
            
        print_info = event.get('print', {}) or {}
        printer_type = print_info.get('printer_type', '').lower()
        
        if printer_type == 'virtual' or 'pdf' in printer_type:
            severity = "high"
            reason = "In ra máy in ảo (Virtual PDF)"
        else:
            severity = "medium"
            reason = "In tài liệu"
            
        return True, {
            'rule_name': self.name,
            'severity': severity,
            'printer_type': printer_type,
            'reason': reason
        }

class CorrelatedEventRule(BehavioralRule):
    """
    Rule 12: Correlated Event từ L1
    Phát hiện: Agent gửi lên các event bắt đầu bằng corr_ (ví dụ: corr_exfil_usb_suspected)
    """
    def __init__(self):
        super().__init__(
            name="Correlated_Event",
            description="Cảnh báo tổng hợp từ Agent L1",
            severity="high"
        )
        
    def check(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        event_type = event.get('type', '').lower()
        
        if event_type.startswith('corr_'):
            return True, {
                'rule_name': self.name,
                'severity': self.severity,
                'event_type': event_type,
                'reason': f"Phát hiện chuỗi hành vi nguy hiểm từ L1: {event_type}"
            }
            
        tags = event.get('tags') or []
        for tag in tags:
            if str(tag).lower().startswith('corr_'):
                return True, {
                    'rule_name': self.name,
                    'severity': self.severity,
                    'event_type': event_type,
                    'tag': tag,
                    'reason': f"Phát hiện chuỗi hành vi nguy hiểm từ L1 qua tag: {tag}"
                }
                
        return False, {}


class BehavioralRulesEngine:
    """Engine chạy các behavioral rules"""
    
    def __init__(self):
        self.rules: List[BehavioralRule] = []
        self._load_rules()
        logger.info(f"Loaded {len(self.rules)} behavioral rules")
    
    def _load_rules(self):
        """Load tất cả behavioral rules"""
        self.rules = [
            ClipboardPasteToExternalAppRule(),  # Rule 1: Priority cao nhất
            USBDataExfiltrationRule(),
            BulkFileCopyRule(),
            EncryptedArchiveRule(),
            ExtensionChangeRule(),
            HighFrequencyClipboardRule(),
            BulkPasteRule(),
            NetworkUploadRule(),  # Cần network sensor
            CloudSyncRule(),
            ProcessAnomalyRule(),
            PrintJobRule(),
            CorrelatedEventRule(),
        ]
    
    def check_all(self, event: Dict[str, Any], fast_scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Chạy tất cả rules và trả về các matches
        
        Returns:
            List of matched rules với details
        """
        matches = []
        
        for rule in self.rules:
            try:
                matched, details = rule.check(event, fast_scan_result)
                if matched:
                    matches.append({
                        'rule': rule.name,
                        'description': rule.description,
                        'severity': rule.severity,
                        **details
                    })
                    logger.warning(f"Behavioral Rule Matched: {rule.name} - {details.get('reason', '')}")
            except Exception as e:
                logger.error(f"Error checking rule {rule.name}: {e}")
        
        return matches
    
    def get_highest_severity_match(self, matches: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Lấy match có severity cao nhất"""
        if not matches:
            return None
        
        severity_order = {'high': 3, 'medium': 2, 'low': 1}
        return max(matches, key=lambda m: severity_order.get(m.get('severity', 'low'), 0))
