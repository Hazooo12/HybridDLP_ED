"""
Action Executor - Thực thi hành động: Block/Alert/Log
"""
import requests
import threading
import json
import os
import time
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from loguru import logger

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig
from core.windows_notification import WindowsNotification

# Import sender from agent_sender
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agent"))
from agent_sender import sender


class ActionExecutor:
    """Thực thi hành động: Block/Alert/Log"""
    
    def __init__(self):
        self.server_url = WorkerConfig.SERVER_URL
        self.api_key = WorkerConfig.SERVER_API_KEY
        self.device_id = WorkerConfig.DEVICE_ID
        self.timeout = WorkerConfig.SERVER_TIMEOUT
        self.windows_alert_min_score = float(getattr(WorkerConfig, "WINDOWS_ALERT_MIN_SCORE", 7.0))
        self.notification = WindowsNotification()
        # BUG FIX: Lock để tránh race condition khi nhiều thread cùng write alerts.json
        self._dashboard_lock = threading.Lock()
        # UEBA-only alerts are grouped into short sessions to avoid popup/tag spam.
        # Rule-based/YARA/NLP alerts bypass this gate.
        self._ueba_sessions = {}
        self.ueba_session_reset_sec = max(
            1,
            int(getattr(WorkerConfig, "UEBA_SESSION_RESET_SEC", 600)),
        )
        
        # Dashboard alerts.json path
        # In Docker: /app/logs/alerts.json (shared volume)
        # Local: dashboard/logs/alerts.json (relative to project root)
        if os.name != "nt" and Path("/app/logs").exists():
            self.dashboard_log_path = Path("/app/logs/alerts.json")
            logger.info(f"[PID={os.getpid()}] Dashboard log path (Docker): {self.dashboard_log_path}")
        else:
            # Local development - find dashboard directory
            base_dir = Path(__file__).parent.parent.parent
            dashboard_log_dir = base_dir / "dashboard" / "logs"
            dashboard_log_dir.mkdir(parents=True, exist_ok=True)
            self.dashboard_log_path = dashboard_log_dir / "alerts.json"
            logger.info(f"[PID={os.getpid()}] Dashboard log path (Local): {self.dashboard_log_path}")
        
        # Ensure parent directory exists
        self.dashboard_log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"[PID={os.getpid()}] Dashboard log directory exists: {self.dashboard_log_path.parent.exists()}")
        logger.info(
            f"[PID={os.getpid()}] UEBA session reset window: "
            f"{self.ueba_session_reset_sec}s"
        )

    def _extract_yara_matches(
        self,
        details: Dict[str, Any],
        report: Optional[Dict[str, Any]] = None,
    ) -> list:
        """Return YARA match dictionaries from the richest available source."""
        candidates = []
        if report:
            candidates.append((report.get("_detection") or {}).get("yara_matches"))
        candidates.extend([
            details.get("yara_matches"),
            (details.get("content") or {}).get("yara_matches"),
        ])

        for value in candidates:
            if isinstance(value, list):
                return value
        return []

    def _rule_names(self, yara_matches: list, limit: int = 3) -> list:
        names = []
        for match in yara_matches or []:
            if isinstance(match, dict):
                name = match.get("rule") or match.get("name")
            else:
                name = str(match)
            if name and name not in names:
                names.append(str(name))
            if len(names) >= limit:
                break
        return names

    def _extract_nlp_analysis(
        self,
        details: Dict[str, Any],
        report: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return NLP evidence from risk details/report if ML/NLP participated."""
        report = report or {}
        candidates = [
            details.get("nlp_analysis"),
            (details.get("content") or {}).get("nlp_analysis"),
            (report.get("_detection") or {}).get("nlp_analysis"),
        ]
        for value in candidates:
            if isinstance(value, dict) and value:
                return value
        return {}

    def _format_nlp_evidence(self, nlp: Dict[str, Any], factor_limit: int = 3) -> str:
        if not nlp:
            return ""

        parts = []
        doc_type = nlp.get("document_type")
        confidence = nlp.get("document_confidence")
        if doc_type:
            try:
                parts.append(f"loai tai lieu={doc_type} ({float(confidence) * 100:.0f}%)")
            except Exception:
                parts.append(f"loai tai lieu={doc_type}")

        risk_score = nlp.get("risk_score")
        risk_level = nlp.get("risk_level")
        if risk_score is not None:
            try:
                risk_text = f"NLP risk={float(risk_score):.1f}/10"
            except Exception:
                risk_text = f"NLP risk={risk_score}/10"
            if risk_level:
                risk_text += f" {risk_level}"
            parts.append(risk_text)

        entities = nlp.get("entity_summary") or nlp.get("nlp_entities") or {}
        if isinstance(entities, dict) and entities:
            entity_text = ", ".join(
                f"{k}:{v}" for k, v in list(entities.items())[:5] if v
            )
            if entity_text:
                parts.append(f"entities={entity_text}")

        factors = nlp.get("risk_factors") or []
        if isinstance(factors, list) and factors:
            parts.append("yeu to=" + "; ".join(str(f) for f in factors[:factor_limit]))

        return " | ".join(parts)

    def _format_ueba_evidence(self, context: Dict[str, Any]) -> str:
        is_anomaly = bool(context.get("ml_is_anomaly"))
        score = context.get("ml_anomaly_score")
        details = context.get("ml_anomaly_details") or {}
        if not is_anomaly and not score and not details:
            return ""

        parts = ["hanh vi bat thuong"]
        if score is not None:
            try:
                parts.append(f"UEBA score={float(score):.1f}/10")
            except Exception:
                parts.append(f"UEBA score={score}/10")

        if isinstance(details, dict) and details.get("model_score") is not None:
            try:
                parts.append(f"IsolationForest={float(details.get('model_score')):.1f}/10")
            except Exception:
                parts.append(f"IsolationForest={details.get('model_score')}/10")

        reasons = []
        if isinstance(details, dict):
            reasons.extend(details.get("profile_reasons") or [])
            reasons.extend(details.get("baseline_reasons") or [])
        reasons.extend(context.get("ml_profile_reasons") or [])
        reasons.extend(context.get("ml_baseline_reasons") or [])
        reasons = [str(r) for r in reasons if r and str(r) != "baseline_warmup"]
        if reasons:
            parts.append("ly do=" + ", ".join(dict.fromkeys(reasons[:5])))

        return " | ".join(parts)

    def _json_safe(self, value: Any) -> Any:
        """Convert ML/runtime objects (numpy arrays, Paths, etc.) into JSON-safe values."""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, dict):
            return {str(k): self._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._json_safe(v) for v in value]
        if hasattr(value, "tolist"):
            try:
                return self._json_safe(value.tolist())
            except Exception:
                pass
        if hasattr(value, "item"):
            try:
                return self._json_safe(value.item())
            except Exception:
                pass
        return str(value)

    def _has_rule_or_content_evidence(
        self,
        details: Dict[str, Any],
        context: Dict[str, Any],
        report: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """True when a non-UEBA detector has evidence; these alerts must not be gated."""
        if self._extract_yara_matches(details, report):
            return True
        if self._extract_nlp_analysis(details, report):
            return True
        if details.get("cache_override") or details.get("force_max_risk"):
            return True
        if context.get("cached_malicious_score") or context.get("force_max_risk"):
            return True

        behavioral = details.get("behavioral") or context.get("behavioral_details") or {}
        if isinstance(behavioral, dict) and (
            behavioral.get("behavioral_rule_matched")
            or behavioral.get("rule")
            or behavioral.get("all_behavioral_matches")
        ):
            return True

        ev = context.get("_event_data") or {}
        if isinstance(ev, dict):
            if ev.get("ioc_hits"):
                return True
            obj = ev.get("object") or {}
            labels = [
                ev.get("File_Sensitivity"),
                ev.get("sensitivity"),
                obj.get("sensitivity") if isinstance(obj, dict) else None,
            ]
            sensitive_labels = {"sensitive", "highly sensitive", "confidential", "secret"}
            if any(str(label or "").strip().lower() in sensitive_labels for label in labels):
                return True

        # Do not use report["File_Sensitivity"] here: ReportGenerator may mark it
        # Sensitive solely because UEBA boosted the risk score.
        return False

    def _ueba_session_key(self, context: Dict[str, Any]) -> str:
        user = str(context.get("user") or "unknown").strip().lower()
        action_type = str(context.get("action_type") or "unknown").strip().lower()
        process_name = str(context.get("process_name") or "").strip().lower()
        return f"{user}|{action_type}|{process_name}"

    def _apply_ueba_session_gate(
        self,
        details: Dict[str, Any],
        context: Dict[str, Any],
        report: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Return True when this event should show a UEBA popup.

        Only gates UEBA-only alerts. Rule/YARA/NLP/sensitivity evidence bypasses it.
        """
        context.pop("_ueba_session_continued", None)
        context.pop("_ueba_session_expires_at", None)
        context.pop("_ueba_session_suppress_popup", None)

        if not context.get("ml_is_anomaly"):
            return True

        now = time.time()
        key = self._ueba_session_key(context)
        session = self._ueba_sessions.get(key) or {}
        expires_at = float(session.get("expires_at") or 0.0)
        has_non_ueba_evidence = self._has_rule_or_content_evidence(details, context, report)

        if now < expires_at:
            context["_ueba_session_continued"] = True
            context["_ueba_session_expires_at"] = expires_at
            context["_ueba_session_suppress_popup"] = not has_non_ueba_evidence
            logger.info(
                f"UEBA-only alert kept in existing session: key={key}, "
                f"expires_in={expires_at - now:.0f}s, "
                f"rule_or_content_evidence={has_non_ueba_evidence}"
            )
            return has_non_ueba_evidence

        if has_non_ueba_evidence:
            return True

        new_expires_at = now + self.ueba_session_reset_sec
        self._ueba_sessions[key] = {
            "first_seen": now,
            "expires_at": new_expires_at,
            "last_score": context.get("ml_anomaly_score"),
        }
        context["_ueba_session_continued"] = False
        context["_ueba_session_expires_at"] = new_expires_at
        context["_ueba_session_suppress_popup"] = False
        logger.info(
            f"UEBA-only alert opened new session: key={key}, "
            f"reset_window={self.ueba_session_reset_sec}s"
        )
        return True

    def _describe_action(
        self,
        context: Dict[str, Any],
        report: Optional[Dict[str, Any]] = None,
    ) -> str:
        report = report or {}
        action_type = str(context.get("action_type") or report.get("Operation_Type") or "").lower()
        destination = str(report.get("Dest_Path") or context.get("destination") or "").strip()
        process_name = str(report.get("Process_Name") or context.get("process_name") or "").strip()

        if "clipboard" in action_type or "paste" in action_type:
            target = destination or context.get("window_title") or context.get("active_window") or process_name
            return f"Dán dữ liệu nhạy cảm vào {target}" if target else "Dán dữ liệu nhạy cảm ra ngoài"
        if "browser_upload" in action_type or "upload" in action_type:
            return f"Tải file nhạy cảm lên {destination}" if destination else "Tải file nhạy cảm lên web/cloud"
        if "usb" in action_type or "removable" in destination.lower():
            return f"Sao chép file nhạy cảm ra thiết bị ngoài: {destination}" if destination else "Sao chép file nhạy cảm ra USB/ổ ngoài"
        if "screenshot" in action_type:
            return "Chụp màn hình có nội dung nhạy cảm"
        if "print" in action_type:
            return "In hoặc xuất tài liệu có nội dung nhạy cảm"
        return report.get("Operation_Type") or context.get("action_type") or "Thao tác với dữ liệu nhạy cảm"

    def _build_violation_reason(
        self,
        violation_type: str,
        details: Dict[str, Any],
        context: Dict[str, Any],
        report: Optional[Dict[str, Any]],
        yara_matches: list,
    ) -> str:
        report = report or {}
        reasons = []

        if details.get("cache_override") or context.get("cached_malicious_score"):
            reasons.append("File trùng hash với tài liệu đã được hệ thống xác nhận là nhạy cảm")

        force_reason = details.get("force_max_risk_reason")
        if force_reason:
            reasons.append(f"Dữ liệu rời khỏi vùng nhạy cảm: {force_reason}")

        behavioral = details.get("behavioral") or context.get("behavioral_details") or {}
        behavioral_reason = behavioral.get("behavioral_reason") or behavioral.get("reason")
        behavioral_rule = behavioral.get("behavioral_rule_matched") or behavioral.get("rule")
        if behavioral_reason:
            if behavioral_rule:
                reasons.append(f"Khớp hành vi {behavioral_rule}: {behavioral_reason}")
            else:
                reasons.append(str(behavioral_reason))

        ueba_evidence = self._format_ueba_evidence(context)
        if ueba_evidence:
            reasons.append(f"UEBA/Isolation Forest phat hien hanh vi bat thuong: {ueba_evidence}")

        rule_names = self._rule_names(yara_matches)
        if rule_names:
            reasons.append(f"Nội dung file khớp rule phát hiện: {', '.join(rule_names)}")

        nlp_evidence = self._format_nlp_evidence(
            self._extract_nlp_analysis(details, report),
            factor_limit=2,
        )
        if nlp_evidence:
            reasons.append(f"ML/NLP phat hien ngu canh nhay cam: {nlp_evidence}")

        sensitivity = str(report.get("File_Sensitivity") or "").strip()
        if sensitivity and sensitivity.lower() != "normal":
            reasons.append(f"Phân loại dữ liệu: {sensitivity}")

        if reasons:
            return "; ".join(reasons[:3])
        return violation_type

    def _build_user_guidance(
        self,
        details: Dict[str, Any],
        context: Dict[str, Any],
        report: Optional[Dict[str, Any]],
    ) -> str:
        report = report or {}
        action_type = str(context.get("action_type") or "").lower()
        destination = str(report.get("Dest_Path") or context.get("destination") or "").lower()

        if details.get("cache_override") or context.get("cached_malicious_score"):
            return "File này đã nằm trong danh sách nhạy cảm; không gửi, sao chép, đổi tên hoặc thử upload lại bằng kênh khác."
        if "clipboard" in action_type or "paste" in action_type:
            return "Không dán dữ liệu nội bộ vào web, chat, AI hoặc ứng dụng ngoài; hãy dùng kênh được công ty phê duyệt."
        if "browser_upload" in action_type or "upload" in action_type or any(k in destination for k in ("drive", "dropbox", "onedrive", "http")):
            return "Không upload tài liệu nhạy cảm lên cloud/web cá nhân; cần chia sẻ thì xin phê duyệt và dùng kho nội bộ."
        if "usb" in action_type or "removable" in destination:
            return "Không chép tài liệu nhạy cảm ra USB/ổ ngoài; hãy lưu trong vùng được cấp quyền hoặc yêu cầu phê duyệt bảo mật."
        if "screenshot" in action_type:
            return "Không chụp hoặc gửi ảnh màn hình chứa dữ liệu nhạy cảm; hãy che/mã hóa thông tin trước khi chia sẻ."
        return "Dừng thao tác và liên hệ quản trị viên nếu cần xử lý hợp lệ; lặp lại hành vi có thể bị escalated theo chính sách."

    def _build_notification_details(
        self,
        file_path: Path,
        risk_score: float,
        violation_type: str,
        details: Dict[str, Any],
        context: Dict[str, Any],
        report: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        report = report or {}
        yara_matches = self._extract_yara_matches(details, report)
        nlp_analysis = self._extract_nlp_analysis(details, report)
        ml_evidence = self._format_nlp_evidence(nlp_analysis)
        ueba_evidence = self._format_ueba_evidence(context)
        is_clipboard = str(file_path) == "clipboard://clipboard_content" if file_path else False
        file_name = report.get("File_Name") or (
            file_path.name if hasattr(file_path, "name") and not is_clipboard else "Clipboard"
        )
        file_path_text = report.get("File_Path") or (
            str(file_path) if file_path and not is_clipboard else None
        )

        return {
            "risk_score": risk_score,
            "window_title": context.get("window_title") or context.get("active_window") or "",
            "yara_matches": yara_matches,
            "nlp_analysis": nlp_analysis,
            "ml_evidence": ml_evidence,
            "ueba_evidence": ueba_evidence,
            "action_type": context.get("action_type", ""),
            "action_description": self._describe_action(context, report),
            "violation_reason": self._build_violation_reason(
                violation_type, details, context, report, yara_matches
            ),
            "user_guidance": self._build_user_guidance(details, context, report),
            "file_name": file_name,
            "file_path": file_path_text,
            "destination": report.get("Dest_Path") or context.get("destination") or "",
            "process_name": report.get("Process_Name") or context.get("process_name") or "",
            "file_sensitivity": report.get("File_Sensitivity") or "",
        }
    
    def execute(self, action: str, file_path: Path, 
               risk_score: float, details: Dict[str, Any],
               event_context: Dict[str, Any],
               report: Optional[Dict[str, Any]] = None) -> bool:
        """
        Thực thi hành động
        
        Args:
            action: 'block', 'alert', hoặc 'log'
            file_path: Đường dẫn file
            risk_score: Risk score
            details: Chi tiết từ risk scoring
            event_context: Context của event
            report: Report fields (REPORT FIELDS format)
        
        Returns:
            True nếu thành công
        """
        event_id = event_context.get('event_id', 'unknown')
        event_type = event_context.get('action_type', 'unknown')
        pid = os.getpid()
        
        logger.info(
            f"[PID={pid}] Executing action: "
            f"action={action.upper()}, event_id={event_id}, "
            f"type={event_type}, risk_score={risk_score:.1f}"
        )
        
        try:
            if action == 'block':
                return self._block_action(file_path, risk_score, details, event_context, report)
            elif action == 'alert':
                return self._alert_action(file_path, risk_score, details, event_context, report)
            elif action == 'log':
                return self._log_action(file_path, risk_score, details, event_context, report)
            else:
                logger.warning(f"[PID={pid}] Unknown action: {action}")
                return False
        except Exception as e:
            logger.error(f"[PID={pid}] Error executing action {action}: {e}", exc_info=True)
            return False
    
    def _block_action(self, file_path: Path, risk_score: float,
                     details: Dict[str, Any], context: Dict[str, Any],
                     report: Optional[Dict[str, Any]] = None) -> bool:
        """Block hành động (xóa file, kill process, etc.)"""
        file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
        event_id = context.get('event_id', 'unknown')
        pid = os.getpid()
        
        logger.warning(
            f"[PID={pid}] BLOCK triggered: "
            f"event_id={event_id}, file={file_name}, score={risk_score:.1f}"
        )
        
        # Hiển thị thông báo block
        try:
            violation_type = self._determine_violation_type(details, context, report)
            # Lấy yara_matches từ nhiều nguồn có thể
            yara_matches = (
                details.get('content', {}).get('yara_matches', []) or
                details.get('yara_matches', []) or
                []
            )
            notification_details = {
                'risk_score': risk_score,
                'window_title': context.get('window_title') or context.get('active_window') or '',
                'yara_matches': yara_matches,
                'action_type': context.get('action_type', ''),
                'file_path': str(file_path) if file_path and str(file_path) != 'clipboard://clipboard_content' else None
            }
            notification_details = self._build_notification_details(
                file_path, risk_score, violation_type, details, context, report
            )
            self.notification.show_violation_alert(
                violation_type=f"Bị chặn: {violation_type}",
                details=notification_details
            )
        except Exception as e:
            logger.error(f"Error showing block notification: {e}")
        
        try:
            # Block clipboard paste if applicable
            is_clipboard = str(file_path) == 'clipboard://clipboard_content' if file_path else False
            
            if is_clipboard:
                # For clipboard, we can't prevent paste that already happened
                # But we can log and alert (already done above)
                # Note: Real-time blocking would require agent-level integration
                logger.warning(f"BLOCKED clipboard paste to sensitive app: {context.get('window_title', 'unknown')}")
            else:
                # For file operations, could implement:
                # - Kill copy process (if PID available)
                # - Delete copied file (if path available)
                logger.warning(f"BLOCKED file operation: {file_path}")
            
            # Send alert to server với report fields
            self._send_to_server('block', file_path, risk_score, details, context, report)
            
            # Save to dashboard log
            self._save_to_dashboard_log('blocked', file_path, risk_score, details, context, report)
            
            return True
        except Exception as e:
            logger.error(f"Block action error: {e}")
            return False
    
    def _alert_action(self, file_path: Path, risk_score: float,
                     details: Dict[str, Any], context: Dict[str, Any],
                     report: Optional[Dict[str, Any]] = None) -> bool:
        """Gửi cảnh báo và hiển thị thông báo trên Windows"""
        file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
        event_id = context.get('event_id', 'unknown')
        pid = os.getpid()
        
        logger.warning(
            f"[PID={pid}] ALERT triggered: "
            f"event_id={event_id}, file={file_name}, score={risk_score:.1f}"
        )
        
        try:
            # Xác định loại vi phạm
            violation_type = self._determine_violation_type(details, context, report)
            
            # Build notification details
            # Lấy yara_matches từ nhiều nguồn có thể
            yara_matches = (
                details.get('content', {}).get('yara_matches', []) or
                details.get('yara_matches', []) or
                []
            )
            
            notification_details = {
                'risk_score': risk_score,
                'window_title': context.get('window_title') or context.get('active_window') or '',
                'yara_matches': yara_matches,
                'action_type': context.get('action_type', ''),
                'file_path': str(file_path) if file_path and str(file_path) != 'clipboard://clipboard_content' else None
            }
            
            # Hiển thị popup Windows chỉ với mức rủi ro cao để tránh spam.
            notification_details = self._build_notification_details(
                file_path, risk_score, violation_type, details, context, report
            )
            should_show_ueba_popup = self._apply_ueba_session_gate(details, context, report)
            if float(risk_score) >= self.windows_alert_min_score and should_show_ueba_popup:
                self.notification.show_violation_alert(
                    violation_type=violation_type,
                    details=notification_details
                )
            elif not should_show_ueba_popup:
                logger.info(
                    f"[PID={pid}] Skip Windows popup for continued UEBA-only session "
                    f"(reset={self.ueba_session_reset_sec}s)"
                )
            else:
                logger.info(
                    f"[PID={pid}] Skip Windows popup (score={risk_score:.1f} < "
                    f"threshold={self.windows_alert_min_score:.1f})"
                )
            
            outbound_action = 'log' if context.get("_ueba_session_suppress_popup") else 'alert'
            dashboard_action = 'allowed' if context.get("_ueba_session_suppress_popup") else 'alerted'

            # Send alert/log to server với report fields
            self._send_to_server(outbound_action, file_path, risk_score, details, context, report)
            
            # Save to dashboard log
            self._save_to_dashboard_log(dashboard_action, file_path, risk_score, details, context, report)
            
            return True
        except Exception as e:
            logger.error(f"Alert action error: {e}")
            return False
    
    def _determine_violation_type(self, 
                                  details: Dict[str, Any],
                                  context: Dict[str, Any],
                                  report: Optional[Dict[str, Any]] = None) -> str:
        """Xác định loại vi phạm"""
        # Check clipboard paste
        if context.get('is_clipboard_paste') and context.get('is_sensitive_app'):
            return "Paste Dữ Liệu Nhạy Cảm Vào Ứng Dụng Bên Ngoài"
        
        # Check YARA matches
        yara_matches = details.get('content', {}).get('yara_matches', [])
        if yara_matches:
            rules = [m.get('rule', '').lower() for m in yara_matches]
            if any('id' in r or 'cmnd' in r or 'cccd' in r for r in rules):
                return "Phát Hiện Thông Tin CMND/CCCD"
            elif any('credit' in r or 'card' in r for r in rules):
                return "Phát Hiện Thông Tin Thẻ Tín Dụng"
            elif any('bank' in r for r in rules):
                return "Phát Hiện Thông Tin Tài Khoản Ngân Hàng"
            elif any('api' in r or 'key' in r for r in rules):
                return "Phát Hiện API Key/Secret"
            else:
                return "Phát Hiện Dữ Liệu Nhạy Cảm"
        
        # Check file operations
        action_type = context.get('action_type', '').lower()
        if 'usb' in action_type or 'removable' in str(context.get('destination', '')).lower():
            return "Copy Dữ Liệu Ra USB"
        elif 'clipboard' in action_type:
            return "Copy Dữ Liệu Nhạy Cảm"
        
        return "Vi Phạm Chính Sách Bảo Mật"
    
    def _determine_violation_type(self,
                                  details: Dict[str, Any],
                                  context: Dict[str, Any],
                                  report: Optional[Dict[str, Any]] = None) -> str:
        """Determine a user-facing violation type for the popup."""
        action_type = str(context.get('action_type', '')).lower()
        nlp_analysis = self._extract_nlp_analysis(details, report)
        has_yara = bool(self._extract_yara_matches(details, report))

        if details.get("cache_override") or context.get("cached_malicious_score"):
            return "File đã biết là dữ liệu nhạy cảm"

        if context.get("ml_is_anomaly") and not has_yara and not nlp_analysis:
            return "UEBA/Isolation Forest phat hien hanh vi bat thuong"

        if nlp_analysis and not has_yara:
            return "ML/NLP phat hien ngu canh du lieu nhay cam"

        if (
            context.get('is_clipboard_paste')
            or 'clipboard' in action_type
            or 'paste' in action_type
        ):
            return "Paste dữ liệu nhạy cảm ra ứng dụng bên ngoài"

        yara_matches = self._extract_yara_matches(details, report)
        if yara_matches:
            rules = [
                str(m.get('rule', '') if isinstance(m, dict) else m).lower()
                for m in yara_matches
            ]
            if any('id' in r or 'cmnd' in r or 'cccd' in r for r in rules):
                return "Phát hiện thông tin CMND/CCCD"
            if any('credit' in r or 'card' in r for r in rules):
                return "Phát hiện thông tin thẻ tín dụng"
            if any('bank' in r for r in rules):
                return "Phát hiện thông tin tài khoản ngân hàng"
            if any('api' in r or 'key' in r for r in rules):
                return "Phát hiện API key/secret"
            return "Phát hiện dữ liệu nhạy cảm"

        destination = str(context.get('destination', '')).lower()
        if 'usb' in action_type or 'removable' in destination:
            return "Copy dữ liệu nhạy cảm ra USB/thiết bị ngoài"
        if 'browser_upload' in action_type or 'upload' in action_type:
            return "Upload dữ liệu nhạy cảm lên web/cloud"

        return "Vi phạm chính sách bảo mật dữ liệu"

    def _log_action(self, file_path: Path, risk_score: float,
                   details: Dict[str, Any], context: Dict[str, Any],
                   report: Optional[Dict[str, Any]] = None) -> bool:
        """Chỉ log"""
        file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
        logger.info(f"LOG: {file_name} (score: {risk_score})")
        
        try:
            # Send log to server với report fields
            self._send_to_server('log', file_path, risk_score, details, context, report)
            
            # Save to dashboard log (save all LOG actions to dashboard)
            # Always save to dashboard for visibility, even low risk events
            self._save_to_dashboard_log('allowed', file_path, risk_score, details, context, report)
            
            return True
        except Exception as e:
            logger.error(f"Log action error: {e}")
            return False
    
    def _send_to_server(self, action: str, file_path: Path,
                       risk_score: float, details: Dict[str, Any],
                       context: Dict[str, Any],
                       report: Optional[Dict[str, Any]] = None) -> bool:
        """Gửi kết quả về server với report fields"""
        if not self.server_url or self.server_url == "https://dlp-server.example.com":
            logger.debug("Server URL not configured, skipping send")
            return True  # Return True để không block flow
        
        try:
            # Build payload với report fields
            file_name = file_path.name if hasattr(file_path, 'name') and str(file_path) != 'clipboard://clipboard_content' else str(file_path)
            payload = {
                'device_id': self.device_id,
                'action': action,
                'file_path': str(file_path),
                'file_name': file_name,
                'risk_score': risk_score,
                'details': details,
                'context': context,
                'timestamp': context.get('time', ''),
                # Include report fields nếu có
                'report': report or {}
            }
            
            headers = {
                'Authorization': f'Bearer {self.api_key}' if self.api_key else '',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.server_url}/api/events",
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                logger.debug(f"Sent {action} to server successfully")
                return True
            else:
                logger.warning(f"Server returned {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            logger.warning("Cannot connect to server, event logged locally only")
            return False
        except requests.exceptions.Timeout:
            logger.warning("Server timeout, event logged locally only")
            return False
        except Exception as e:
            logger.error(f"Error sending to server: {e}")
            return False
    
    def _save_to_dashboard_log(self, action: str, file_path: Path,
                               risk_score: float, details: Dict[str, Any],
                               context: Dict[str, Any],
                               report: Optional[Dict[str, Any]] = None) -> bool:
        """
        Save alert to dashboard alerts.json file
        
        Args:
            action: 'allowed' or 'alerted' (legacy: may still include 'blocked')
            file_path: File path or clipboard placeholder
            risk_score: Risk score
            details: Detection details
            context: Event context
            report: Report fields
        
        Returns:
            True if saved successfully
        """
        try:
            # Resolve filename/path from richest source first (event payload),
            # then fallback to file_path argument.
            ev = context.get("_event_data", {}) or {}
            ev_obj = ev.get("object", {}) if isinstance(ev, dict) else {}
            event_file_name = ""
            event_file_path = ""
            if isinstance(ev_obj, dict):
                event_file_name = str(ev_obj.get("name") or "").strip()
                event_file_path = str(
                    ev_obj.get("path")
                    or ev_obj.get("dst_path")
                    or ev_obj.get("src_path")
                    or ""
                ).strip()
            resolved_file_name = event_file_name or (
                file_path.name if hasattr(file_path, "name") else ""
            )
            resolved_file_path = event_file_path or str(file_path or "")
            file_path_raw = str(file_path or "")
            is_clipboard_placeholder = file_path_raw.lower().startswith("clipboard:")

            # Extract keywords from YARA matches
            yara_matches = (
                details.get('content', {}).get('yara_matches', []) or
                details.get('yara_matches', []) or
                []
            )
            keywords = [match.get('rule', '') for match in yara_matches if match.get('rule')]
            
            # If no YARA matches but has behavioral rule, use that
            if not keywords and details.get('behavioral', {}).get('behavioral_rule_matched'):
                keywords = [details['behavioral']['behavioral_rule_matched']]

            if context.get("ml_is_anomaly"):
                ml_keywords = [
                    "UEBA_Anomaly_Session_Continued"
                    if context.get("_ueba_session_continued")
                    else "UEBA_IsolationForest_Anomaly"
                ]
                ml_details = context.get("ml_anomaly_details") or {}
                if isinstance(ml_details, dict) and not context.get("_ueba_session_continued"):
                    ml_keywords.extend(str(r) for r in (ml_details.get("profile_reasons") or [])[:3])
                    ml_keywords.extend(str(r) for r in (ml_details.get("baseline_reasons") or [])[:3])
                keywords = list(dict.fromkeys(ml_keywords + keywords))
            
            # Get timestamp - ensure ISO8601 format
            timestamp = context.get('time') or context.get('timestamp') or datetime.now().isoformat()
            # Ensure timestamp is in ISO8601 format (with timezone if possible)
            if isinstance(timestamp, str):
                # If already ISO8601, use as is
                if 'T' in timestamp and ('+' in timestamp or 'Z' in timestamp or timestamp.endswith('+00:00')):
                    pass  # Already ISO8601
                else:
                    # Try to parse and reformat
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.isoformat()
                    except:
                        # Fallback to current time
                        timestamp = datetime.now(timezone.utc).isoformat()
            else:
                timestamp = datetime.now(timezone.utc).isoformat()
            
            # Build alert entry
            alert_entry = {
                'type': 'alert',
                'source': 'worker',
                'severity': 'high' if risk_score >= 7 else 'medium' if risk_score >= 4 else 'low',
                'timestamp': timestamp,
                'ts': datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp() if 'T' in timestamp else time.time(),
                'risk_score': round(float(risk_score), 2),
                'action': action,
                'file_path': resolved_file_path if resolved_file_path and not is_clipboard_placeholder else 'Clipboard Content',
                'file_name': resolved_file_name if resolved_file_name and not is_clipboard_placeholder else 'Clipboard',
                'keywords': keywords,
                'window_title': context.get('window_title') or context.get('active_window') or '',
                'process_name': context.get('process_name') or '',
                'user': context.get('user') or 'unknown',
                'source': context.get('source') or 'unknown',
                'ml_is_anomaly': bool(context.get('ml_is_anomaly')),
                'ml_anomaly_score': context.get('ml_anomaly_score'),
                'ml_anomaly_details': self._json_safe(context.get('ml_anomaly_details') or {}),
                'ueba_session_continued': bool(context.get('_ueba_session_continued')),
                'ueba_session_expires_at': context.get('_ueba_session_expires_at'),
                'is_clipboard': is_clipboard_placeholder
            }
            alert_entry = self._json_safe(alert_entry)
            
            # Load existing alerts
            alerts = []
            # BUG FIX: Lock để tránh race condition read-then-write khi multi-thread
            with self._dashboard_lock:
                if self.dashboard_log_path.exists():
                    try:
                        with open(self.dashboard_log_path, 'r', encoding='utf-8') as f:
                            alerts = json.load(f)
                            if not isinstance(alerts, list):
                                alerts = []
                    except (json.JSONDecodeError, IOError) as e:
                        logger.warning(f"Error reading dashboard log: {e}, creating new file")
                        alerts = []

                # Append new alert
                alerts.append(alert_entry)

                # Keep only last 1000 alerts to prevent file from growing too large
                if len(alerts) > 1000:
                    alerts = alerts[-1000:]

                # Write back to file
                with open(self.dashboard_log_path, 'w', encoding='utf-8') as f:
                    json.dump(alerts, f, indent=2, ensure_ascii=False)
            
            # Send alert to dashboard
            sender.send(alert_entry)
            
            pid = os.getpid()
            logger.info(
                f"[PID={pid}] Saved alert to dashboard: "
                f"action={action}, score={risk_score}, "
                f"keywords={keywords}, path={self.dashboard_log_path}, "
                f"total_alerts={len(alerts)}"
            )
            return True
            
        except Exception as e:
            pid = os.getpid()
            logger.error(
                f"[PID={pid}] Error saving to dashboard log: {e} | "
                f"Path: {self.dashboard_log_path} | "
                f"Path exists: {self.dashboard_log_path.exists()} | "
                f"Parent exists: {self.dashboard_log_path.parent.exists()}"
            )
            return False
