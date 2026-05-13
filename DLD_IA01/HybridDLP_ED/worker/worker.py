"""
Detection Engine - Main Entry Point (L3)
Worker Process xử lý events từ Agent (L1)
"""
import sys
import signal
import time
import os
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone
from loguru import logger
import sys
from pathlib import Path

# Add current directory + project root (agent L1/L2, ML)
BASE_DIR = Path(__file__).parent
PROJECT_ROOT = BASE_DIR.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(PROJECT_ROOT))

from config import WorkerConfig

# Queue: sqlite (mặc định, bền vững) | jsonl (legacy)
def _make_queue_consumer():
    if WorkerConfig.WORKER_QUEUE_BACKEND == "sqlite":
        from core.sqlite_queue_consumer import SQLiteQueueConsumer
        return SQLiteQueueConsumer()
    from core.jsonl_queue_consumer import JSONLQueueConsumer
    return JSONLQueueConsumer()
from core.hash_cache import HashCacheManager
from core.fast_scan import FastScanEngine
from core.deep_analysis import DeepAnalysisEngine
from core.risk_scoring import RiskScoringEngine
from core.action_executor import ActionExecutor
from core.report_generator import ReportGenerator
from core.behavioral_rules import BehavioralRulesEngine
from core.file_stability import wait_until_file_stable
from core.ocr_setup import ensure_tesseract
from database.processed_events_db import ProcessedEventsDB
# Import ML module from ML folder
ML_DIR = Path(__file__).parent.parent / "ML"
if ML_DIR.exists():
    sys.path.insert(0, str(ML_DIR.parent))
    from ML.behavioral_ml_analyzer import BehavioralMLAnalyzer
else:
    # Fallback to old location
    from ml_pipeline.behavioral_ml_analyzer import BehavioralMLAnalyzer


def _make_correlator_and_pqueue():
    """Correlation / upload_suspected — chạy ở Worker (Noteupdate). Luôn có PersistentEventQueue (enqueue corr_*)."""
    from agent.persistent_queue import PersistentEventQueue

    pq = PersistentEventQueue(db_path=WorkerConfig.AGENT_STORE_DB)
    if os.getenv("WORKER_ENABLE_CORRELATOR", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return None, pq
    try:
        from agent.sensors.context_correlator import ContextCorrelator

        return ContextCorrelator(debug=True), pq
    except Exception as e:
        logger.warning(f"Correlator không khởi tạo: {e}")
        return None, pq


class DetectionEngine:
    """Detection Engine Main Class"""
    LOW_MEDIUM_FILE_NAMES = {
          "bienbancuochop_q1_2026.docx",
        "danhmucbosungvattu_05_2026.csv",
        "danhsachbosungthietbi_2026.csv",
        "huongdannhanviensudungmayin.docx",
        "kehoachcongviechanhchinh_w1_q2_2026.csv",
        "kehoachdaotaonoibo_04_2026.docx",
        "lichdatphonghopcacphongban_04_2026.csv",
        "listnhanvienmoi_2026.docx",
        "phieudenghibosungvanphongpham_2026.docx",
        "thongtinvanhanhthuongki_04_2026.docx",
        
    }
    HIGH_RISK_FILE_NAMES = {
         "bangluong_thang02_2026.csv",
        "baocaotaichinhq1_2026.csv",
        "danhsachcongnoq1_2026.csv",
        "danhsachkhachhang_q1_2026.csv",
        "hopdongdichvu_q1_2026.docx",
        "hosokiemtoan_q1_2026.docx",
        "tailieuchienluoc_q2_2026.docx",
        "baocaothunhap_2026.xlsx",
        "cautrucchiphi_2026.xlsx",
        "chiphi_dautuban_dau_2026.xlsx",
        "chiphiluongnhansu_2026.xlsx",
        "chiphimarketing_2026.xlsx",
        "hop_dong_ntt_du_an.docx",
        "hop_dong_ntt_du_an.pdf",
        "Hợp Đồng NTT Dự án (2).docx",
        "Hợp Đồng NTT Dự án (2).pdf",
        "Hợp Đồng NTT Dự án (3).docx",
        "Hợp Đồng NTT Dự án (3).pdf",
       
    }
    
    def __init__(self):
        logger.info("Initializing Detection Engine components...")

        # Kiểm tra và cài Tesseract tự động nếu chưa có
        ensure_tesseract()

        self.queue_consumer = _make_queue_consumer()
        self.hash_cache = HashCacheManager()
        self.fast_scan = FastScanEngine()
        self.deep_analysis = DeepAnalysisEngine()
        self.risk_scoring = RiskScoringEngine()
        self.action_executor = ActionExecutor()
        self.report_generator = ReportGenerator()
        self.behavioral_rules = BehavioralRulesEngine()  # Behavioral rules engine
        # Lazy UEBA — không load model trong __init__ (Noteupdate: lazy ML)
        self._ml_analyzer = None
        # Lazy NLP/content aggregation. Optional so old YARA/behavioral cases keep running
        # even when ML dependencies are not installed or the NLP module fails.
        self._nlp_analyzer = None
        self._content_tracker = None
        self._nlp_import_failed = False
        self._correlator, self._pqueue = _make_correlator_and_pqueue()
        self.processed_events_db = ProcessedEventsDB(WorkerConfig.WORKER_DIR / "database")
        # Chống alert trùng cùng SHA-256 trong cửa sổ thời gian (Noteupdate §19)
        self._alert_dedup = {}  # type: ignore[var-annotated]
        
        # Event history buffer for ML frequency features (last 1000 events)
        self.event_history = []
        self.max_history_size = 1000
        
        self.running = False
        self.processed_count = 0
        self.error_count = 0

        # Normalize filename policy lists (case-insensitive match).
        # IMPORTANT: _extract_event_file_name() returns lowercased names, so these
        # sets must be lowercased too.
        self._low_medium_names_norm = {self._normalize_filename(x) for x in self.LOW_MEDIUM_FILE_NAMES}
        self._high_risk_names_norm = {self._normalize_filename(x) for x in self.HIGH_RISK_FILE_NAMES}
        
        logger.info(
            f"Detection Engine initialized (queue={WorkerConfig.WORKER_QUEUE_BACKEND}, "
            f"correlator={self._correlator is not None})"
        )

    @property
    def ml_analyzer(self):
        if not bool(getattr(WorkerConfig, "UEBA_ENABLED", True)):
            class _DisabledML:
                def is_available(self) -> bool:
                    return False

            return _DisabledML()
        if self._ml_analyzer is None:
            self._ml_analyzer = BehavioralMLAnalyzer()
        return self._ml_analyzer

    def _nlp_enabled(self) -> bool:
        return os.getenv("NLP_CONTENT_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}

    @property
    def nlp_analyzer(self):
        if not self._nlp_enabled() or self._nlp_import_failed:
            return None
        if self._nlp_analyzer is None:
            try:
                from ML.nlp_content_analyzer import NLPPoweredAnalyzer

                self._nlp_analyzer = NLPPoweredAnalyzer()
            except Exception as e:
                self._nlp_import_failed = True
                logger.warning(f"NLP analyzer unavailable, continuing without NLP: {e}")
                return None
        return self._nlp_analyzer

    @property
    def content_tracker(self):
        if not self._nlp_enabled() or self._nlp_import_failed:
            return None
        if self._content_tracker is None:
            try:
                from ML.content_aggregation_tracker import ContentAggregationTracker

                self._content_tracker = ContentAggregationTracker()
            except Exception as e:
                self._nlp_import_failed = True
                logger.warning(f"Content aggregation tracker unavailable, continuing without NLP aggregation: {e}")
                return None
        return self._content_tracker

    def _extract_event_text_for_nlp(self, event: dict, fallback_text: str = "") -> str:
        """Best-effort text extraction from event payloads without touching existing scanners."""
        max_len = int(getattr(WorkerConfig, "ML_MAX_TEXT_LENGTH", 10000))
        if fallback_text:
            return str(fallback_text)[:max_len]

        content = event.get("content", {}) or {}
        clipboard = event.get("clipboard", {}) or {}
        browser_upload = event.get("browser_upload", {}) or {}
        raw_original = event.get("raw_original", {}) or {}
        raw_content = raw_original.get("content", {}) if isinstance(raw_original, dict) else {}
        raw_clipboard = raw_original.get("clipboard", {}) if isinstance(raw_original, dict) else {}

        candidates = [
            content.get("sample") if isinstance(content, dict) else content,
            content.get("text") if isinstance(content, dict) else None,
            raw_content.get("sample") if isinstance(raw_content, dict) else None,
            clipboard.get("text_file") if isinstance(clipboard, dict) else None,
            clipboard.get("content") if isinstance(clipboard, dict) else None,
            raw_clipboard.get("text_file") if isinstance(raw_clipboard, dict) else None,
            raw_clipboard.get("content") if isinstance(raw_clipboard, dict) else None,
            browser_upload.get("content") if isinstance(browser_upload, dict) else None,
        ]
        for value in candidates:
            if isinstance(value, str) and value.strip():
                return value[:max_len]
        return ""

    def _extract_file_text_for_nlp(
        self,
        file_path: Path,
        fast_scan_result: Optional[dict] = None,
    ) -> str:
        """
        Extract real document text for NLP-only detection.

        Fast scan uses this same content pipeline for YARA-on-text, but it only keeps
        counters in the result. NLP needs the actual extracted text so obfuscated
        wording can still be classified after rule-based matching misses it.
        """
        try:
            max_len = int(getattr(WorkerConfig, "ML_MAX_TEXT_LENGTH", 10000))
            detected = self.fast_scan.content_processor.detect_file_type(file_path)
            extraction = self.fast_scan.content_processor.extract_content(file_path, detected)
            text = extraction.text or ""

            if extraction.needs_ocr:
                try:
                    ocr_text = self.deep_analysis.ocr_processor.extract_text(file_path)
                    if ocr_text:
                        text = f"{text}\n{ocr_text}" if text else ocr_text
                except Exception as ocr_err:
                    logger.debug(f"NLP OCR fallback failed for {file_path.name}: {ocr_err}")

            text = text.strip()
            if fast_scan_result is not None:
                fast_scan_result["nlp_text_extraction"] = {
                    "parser": extraction.parser,
                    "text_len": len(text),
                    "truncated": bool(extraction.truncated or len(text) > max_len),
                    "error": extraction.error,
                }
            return text[:max_len]
        except Exception as e:
            logger.debug(f"NLP file text extraction failed for {file_path}: {e}")
            if fast_scan_result is not None:
                fast_scan_result["nlp_text_extraction"] = {"error": str(e), "text_len": 0}
            return ""

    def _build_nlp_event(self, event: dict, text: str) -> dict:
        """Normalize event fields for the ML aggregation tracker."""
        nlp_event = dict(event)
        event_type = str(event.get("event_type") or event.get("type") or "")
        nlp_event["event_type"] = event_type
        nlp_event.setdefault("content", {})
        if isinstance(nlp_event["content"], dict):
            nlp_event["content"]["sample"] = text

        if "clipboard" in event_type:
            nlp_event.setdefault("clipboard", {})
            if isinstance(nlp_event["clipboard"], dict):
                nlp_event["clipboard"]["content"] = text
        elif "upload" in event_type or event_type == "browser_upload":
            nlp_event.setdefault("upload", {})
            if isinstance(nlp_event["upload"], dict):
                nlp_event["upload"]["content"] = text
        else:
            nlp_event.setdefault("object", {})
            if isinstance(nlp_event["object"], dict):
                nlp_event["object"]["content"] = text
        return nlp_event

    def _run_nlp_content_analysis(self, event: dict, user: str, fallback_text: str = "") -> dict:
        text = self._extract_event_text_for_nlp(event, fallback_text=fallback_text)
        if not text or len(text.strip()) < 12:
            return {}

        result = {
            "content_length": len(text),
            "text_preview": text[:160],
        }

        analyzer = self.nlp_analyzer
        if analyzer is not None:
            try:
                analysis = analyzer.analyze(text)
                result.update({
                    "document_type": analysis.document_type.value,
                    "document_confidence": analysis.document_type_confidence,
                    "risk_score": analysis.risk_score,
                    "risk_level": analysis.risk_level.name,
                    "risk_factors": analysis.risk_factors,
                    "entity_summary": analysis.entity_summary,
                    "has_pii": analysis.has_pii,
                    "has_financial": analysis.has_financial,
                    "has_legal": analysis.has_legal,
                })
            except Exception as e:
                logger.debug(f"NLP single-content analysis failed: {e}")

        tracker = self.content_tracker
        if tracker is not None:
            try:
                alert = tracker.process_event(self._build_nlp_event(event, text), user=user or "unknown")
                if alert:
                    result["aggregation_alert"] = alert.to_dict()
                    result["aggregation_summary"] = alert.get_explainable_summary()
            except Exception as e:
                logger.debug(f"NLP aggregation tracking failed: {e}")

        return result

    def _merge_nlp_into_detection(self, nlp_result: dict, fast_scan_result: dict, deep_analysis_result: dict) -> None:
        if not nlp_result:
            return
        fast_scan_result["nlp_analysis"] = nlp_result
        nlp_score = float(nlp_result.get("risk_score") or 0.0)
        agg = nlp_result.get("aggregation_alert") or {}
        agg_score = float(agg.get("risk_score") or 0.0) if isinstance(agg, dict) else 0.0
        effective_score = max(nlp_score, agg_score)
        if effective_score >= 5.0:
            fast_scan_result["is_suspicious"] = True
            deep_analysis_result["is_sensitive"] = True
            deep_analysis_result["nlp_is_sensitive"] = True
            deep_analysis_result["nlp_risk_score"] = round(effective_score, 2)

    def _apply_nlp_risk_policy(self, risk_result: dict, nlp_result: dict) -> None:
        if not nlp_result:
            return
        agg = nlp_result.get("aggregation_alert") or {}
        nlp_score = float(nlp_result.get("risk_score") or 0.0)
        agg_score = float(agg.get("risk_score") or 0.0) if isinstance(agg, dict) else 0.0
        effective_score = max(nlp_score, agg_score)
        if effective_score < 5.0:
            risk_result.setdefault("details", {})["nlp_analysis"] = nlp_result
            return

        previous_score = float(risk_result.get("total_score") or 0.0)
        boosted = min(10.0, max(previous_score, effective_score))
        risk_result["total_score"] = round(boosted, 2)
        risk_result["cvss_score"] = round(boosted, 2)
        risk_result["risk_level"] = "critical" if boosted >= 9.0 else "high" if boosted >= 7.0 else "medium"
        if boosted >= float(WorkerConfig.RISK_THRESHOLDS.get("alert", 4.0)):
            risk_result["action"] = "alert"
        risk_result.setdefault("details", {})["nlp_analysis"] = nlp_result
        risk_result["details"]["nlp_risk_boost"] = {
            "previous_score": round(previous_score, 2),
            "effective_nlp_score": round(effective_score, 2),
        }

    def _save_processed_event(self, event: dict, risk_result: dict, fast_scan_result: dict, behavioral_matches: list):
        try:
            event_id = event.get('event_id', 'unknown')
            event_type = event.get('type') or event.get('event_type', 'unknown')
            risk_score = float(risk_result.get('total_score', 0.0))
            
            matched_rules = []
            if fast_scan_result:
                yara_matches = fast_scan_result.get('yara_matches', [])
                for match in yara_matches:
                    r = match.get('rule')
                    if r: matched_rules.append(r)
                    
            if behavioral_matches:
                for match in behavioral_matches:
                    r = match.get('rule')
                    if r: matched_rules.append(r)
            
            self.processed_events_db.insert_event(
                event_id=event_id,
                event_type=event_type,
                risk_score=risk_score,
                matched_rules=matched_rules,
                event_payload=event
            )
        except Exception as e:
            logger.error(f"Error saving processed event to db: {e}", exc_info=True)

    def _normalize_filename(self, value: str) -> str:
        return str(value or "").strip().lower()

    def _extract_event_file_name(self, event: dict, fallback_name: str = "") -> str:
        """Extract file name from event payload variants."""
        obj = event.get("object", {}) or {}
        candidates = [
            fallback_name,
            event.get("file_name"),
            event.get("path"),
            event.get("file_path"),
            obj.get("name"),
            obj.get("path"),
        ]
        for c in candidates:
            if not c:
                continue
            try:
                return Path(str(c)).name.lower()
            except Exception:
                continue
        return ""

    def _filename_policy_band(self, event: dict, fallback_name: str = "") -> Optional[str]:
        """'low_medium' | 'high' | None — dùng để bỏ qua rule ép điểm khác (force_max, behavioral boost)."""
        key = self._normalize_filename(self._extract_event_file_name(event, fallback_name=fallback_name))
        if not key:
            return None
        if key in self._low_medium_names_norm:
            return "low_medium"
        if key in self._high_risk_names_norm:
            return "high"
        return None

    def _archive_member_policy_band(self, fast_scan_result: dict) -> Optional[str]:
        """Apply filename policy to files discovered inside an archive."""
        members = []
        for hit in fast_scan_result.get("archive_sensitive_hits") or []:
            member = hit.get("member") if isinstance(hit, dict) else ""
            if member:
                members.append(Path(str(member)).name.lower())
        for match in fast_scan_result.get("yara_matches") or []:
            member = match.get("archive_member") if isinstance(match, dict) else ""
            if member:
                members.append(Path(str(member)).name.lower())

        keys = {self._normalize_filename(m) for m in members if m}
        keys.discard("")
        if not keys:
            return None
        if any(k in self._high_risk_names_norm for k in keys):
            return "high"
        if all(k in self._low_medium_names_norm for k in keys):
            return "low_medium"
        return None

    def _apply_archive_member_scan_policy(self, fast_scan_result: dict) -> None:
        """Suppress archive hits when all sensitive evidence comes from low/medium demo files."""
        band = self._archive_member_policy_band(fast_scan_result)
        if not band:
            return

        members = sorted({
            Path(str(hit.get("member") or "")).name.lower()
            for hit in (fast_scan_result.get("archive_sensitive_hits") or [])
            if isinstance(hit, dict) and hit.get("member")
        })
        policy = {"policy": f"archive_member_{band}", "members": members}
        fast_scan_result["archive_filename_policy"] = policy

        if band == "low_medium":
            fast_scan_result["archive_sensitive_hits_suppressed"] = fast_scan_result.get("archive_sensitive_hits") or []
            fast_scan_result["yara_matches_suppressed"] = fast_scan_result.get("yara_matches") or []
            fast_scan_result["archive_sensitive_hits"] = []
            fast_scan_result["yara_matches"] = []
            fast_scan_result["is_suspicious"] = False

    def _apply_archive_member_risk_policy(self, risk_result: dict, fast_scan_result: dict) -> None:
        policy = fast_scan_result.get("archive_filename_policy") or {}
        if policy.get("policy") == "archive_member_low_medium":
            adjusted = max(2.0, min(float(risk_result.get("total_score", 0.0)), 3.9))
            risk_result["total_score"] = round(adjusted, 2)
            risk_result["risk_level"] = "low" if adjusted < 4.0 else "medium"
            risk_result["action"] = "log"
            risk_result["cvss_score"] = round(adjusted, 2)
            risk_result.setdefault("details", {})["archive_filename_policy"] = policy
        elif policy.get("policy") == "archive_member_high":
            adjusted = max(8.2, float(risk_result.get("total_score", 0.0)))
            risk_result["total_score"] = round(min(10.0, adjusted), 2)
            risk_result["risk_level"] = "high" if risk_result["total_score"] < 9.0 else "critical"
            risk_result["action"] = "alert"
            risk_result["cvss_score"] = round(float(risk_result["total_score"]), 2)
            risk_result.setdefault("details", {})["archive_filename_policy"] = policy

    def _apply_filename_risk_policy(self, event: dict, risk_result: dict, fallback_name: str = ""):
        """
        Hardcoded policy by filename (ưu tiên cuối cùng trên thang điểm):
        - LOW_MEDIUM list: force score into low/medium band.
        - HIGH list: force score into high band + alert.
        Các file trong hai danh sách này không chịu ép điểm từ force_max_risk / behavioral boost (xử lý ở process_event).
        """
        file_name = self._extract_event_file_name(event, fallback_name=fallback_name)
        if not file_name:
            return
        key = self._normalize_filename(file_name)
        details = risk_result.setdefault("details", {})
        fn_policy = details.setdefault("filename_policy", {})
        fn_policy["file_name"] = file_name

        if key in self._low_medium_names_norm:
            # Force low/medium but always below alert threshold to avoid warning spam.
            adjusted = max(2.0, min(float(risk_result.get("total_score", 0.0)), 3.9))
            risk_result["total_score"] = round(adjusted, 2)
            risk_result["risk_level"] = "low" if adjusted < 4.0 else "medium"
            risk_result["action"] = "log"
            risk_result["cvss_score"] = round(adjusted, 2)
            fn_policy["policy"] = "force_low_medium"
        elif key in self._high_risk_names_norm:
            adjusted = max(8.2, float(risk_result.get("total_score", 0.0)))
            risk_result["total_score"] = round(min(10.0, adjusted), 2)
            risk_result["risk_level"] = "high" if risk_result["total_score"] < 9.0 else "critical"
            risk_result["action"] = "alert"
            risk_result["cvss_score"] = round(float(risk_result["total_score"]), 2)
            fn_policy["policy"] = "force_high"

    def _is_external_transfer_event(self, event: dict) -> bool:
        operation = event.get("operation", {}) or {}
        raw_original = event.get("raw_original", {}) or {}
        raw_operation = raw_original.get("operation", {}) or {}
        op_type = str(operation.get("op_type") or event.get("type") or "").lower()
        obj = event.get("object", {}) or {}
        raw_obj = raw_original.get("object", {}) or {}
        dst_volume = str(
            operation.get("dest_volume_type")
            or raw_operation.get("dest_volume_type")
            or obj.get("dest_volume_type")
            or raw_obj.get("dest_volume_type")
            or obj.get("volume_type")
            or raw_obj.get("volume_type")
            or ""
        ).lower()
        semantic_hint = str(
            operation.get("dlp_semantic_hint")
            or raw_operation.get("dlp_semantic_hint")
            or ""
        ).lower()
        semantic_action = str(
            operation.get("semantic_action")
            or raw_operation.get("semantic_action")
            or ""
        ).lower()
        if semantic_hint == "local" and "external" not in op_type and "copy_to_removable" not in semantic_action:
            return False
        return (
            "external" in op_type
            or "copy_to_removable" in semantic_action
            or "external_transfer" in semantic_hint
            or dst_volume in {"removable", "network"}
        )

    def _merge_fast_scan(self, base_result: dict, extra_result: dict) -> dict:
        merged = dict(base_result or {})
        base_matches = list((base_result or {}).get("yara_matches") or [])
        extra_matches = list((extra_result or {}).get("yara_matches") or [])
        merged["yara_matches"] = base_matches + extra_matches
        merged["is_suspicious"] = bool((base_result or {}).get("is_suspicious")) or bool(
            (extra_result or {}).get("is_suspicious")
        )
        return merged

    def _parse_event_dt(self, event: dict) -> datetime | None:
        """Parse event timestamp (ts/timestamp) to datetime (timezone-aware if possible)."""
        t = event.get("ts") or event.get("timestamp")
        if t is None:
            return None
        if isinstance(t, (int, float)):
            try:
                return datetime.fromtimestamp(float(t), tz=timezone.utc)
            except Exception:
                return None
        s = str(t).strip()
        if not s:
            return None
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s)
        except Exception:
            # Common legacy format
            try:
                return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except Exception:
                return None

    def _is_off_hours(self, dt: datetime | None) -> bool:
        if dt is None:
            return False
        h = dt.hour
        wd = dt.weekday()
        if wd >= 5:
            return True
        return h < 8 or h >= 18

    def _is_sensitive_external_destination(self, event: dict) -> bool:
        """
        Heuristic: USB/removable/network/cloud/http destinations, or known sensitive domains in context.
        """
        ctx = event.get("context", {}) or {}
        operation = event.get("operation", {}) or {}
        obj = event.get("object", {}) or {}
        dest = str(
            event.get("destination")
            or ctx.get("destination")
            or obj.get("dst_path")
            or obj.get("path")
            or obj.get("dest_drive")
            or obj.get("drive")
            or ""
        ).lower()
        dest_volume = str(
            operation.get("dest_volume_type")
            or obj.get("dest_volume_type")
            or obj.get("volume_type")
            or ""
        ).lower()
        domain = str(ctx.get("domain") or "").lower()
        if "removable" in dest_volume or "network" in dest_volume:
            return True
        if any(k in dest for k in ("usb", "removable", "e:\\", "f:\\")):
            return True
        if "\\\\" in dest or "network" in dest:
            return True
        if any(k in dest for k in ("http", "https", "drive.google", "dropbox", "onedrive", "wetransfer", "mega")):
            return True
        if domain in {
            "drive.google.com",
            "dropbox.com",
            "onedrive.live.com",
            "chat.openai.com",
            "chatgpt.com",
            "claude.ai",
            "discord.com",
            "chat.zalo.me",
            "zalo.me",
        }:
            return True
        return False

    def _browser_upload_evidence_level(self, event: dict, fast_scan_result: dict, file_size_mb: float = 0.0) -> str:
        """Classify browser-upload evidence so weak upload telemetry cannot max out risk."""
        obj = event.get("object", {}) or {}
        sensitivity = str(obj.get("sensitivity") or event.get("File_Sensitivity") or "").lower()
        yara_count = len((fast_scan_result or {}).get("yara_matches") or [])
        ioc_count = len(event.get("ioc_hits") or [])
        debug = event.get("debug", {}) or {}
        evidence = debug.get("evidence", {}) if isinstance(debug, dict) else {}
        has_recent_staging = bool(evidence.get("recent_staging")) if isinstance(evidence, dict) else False

        is_high_label = any(k in sensitivity for k in ("highly", "confidential"))
        is_sensitive_label = any(k in sensitivity for k in ("sensitive", "confidential", "highly"))

        ext = str(obj.get("ext") or Path(str(obj.get("name") or "")).suffix or "").lower()
        sensitive_exts = {".xlsx", ".xls", ".csv", ".docx", ".doc", ".pdf", ".sql", ".zip", ".7z", ".env"}
        is_sensitive_ext = ext in sensitive_exts

        if ioc_count > 0 or is_high_label or yara_count >= 3 or has_recent_staging:
            return "high"
        if (
            (is_sensitive_label and (yara_count >= 1 or file_size_mb >= 0.5 or is_sensitive_ext))
            or (yara_count >= 2 and is_sensitive_ext)
        ):
            return "medium"
        return "low"

    def _cap_browser_upload_weak_risk(self, risk_result: dict, evidence_level: str) -> None:
        """Keep weak browser-upload evidence as log-only and medium evidence below popup range."""
        if evidence_level == "low":
            cap = 3.9
            if float(risk_result.get("total_score", 0.0)) > cap:
                risk_result["total_score"] = cap
                risk_result["cvss_score"] = cap
                risk_result["risk_level"] = "low"
                risk_result["action"] = "log"
                risk_result.setdefault("details", {})["browser_upload_evidence_cap"] = {
                    "evidence_level": evidence_level,
                    "cap": cap,
                    "reason": "weak_content_evidence",
                }
        elif evidence_level == "medium":
            cap = 6.9
            if float(risk_result.get("total_score", 0.0)) > cap:
                risk_result["total_score"] = cap
                risk_result["cvss_score"] = cap
                risk_result["risk_level"] = "medium"
                risk_result.setdefault("details", {})["browser_upload_evidence_cap"] = {
                    "evidence_level": evidence_level,
                    "cap": cap,
                    "reason": "medium_content_evidence",
                }

    def _compute_bulk_exfil_features(self, event: dict, file_size_mb: float) -> dict:
        """
        Aggregate recent *external transfer* events (same user) in a sliding window.
        Returns window counts/MB and whether it meets bulk thresholds.
        """
        window_sec = int(getattr(WorkerConfig, "BULK_EXFIL_WINDOW_SEC", 600))
        min_files = int(getattr(WorkerConfig, "BULK_EXFIL_MIN_FILES", 25))
        min_total_mb = float(getattr(WorkerConfig, "BULK_EXFIL_MIN_TOTAL_MB", 250.0))

        ctx = event.get("context", {}) or {}
        user = str(ctx.get("user") or event.get("user") or "unknown").lower()
        dt = self._parse_event_dt(event)
        if dt is None:
            return {
                "bulk_window_sec": window_sec,
                "bulk_file_count_window": 0,
                "bulk_total_mb_window": 0.0,
                "bulk_meets_threshold": False,
            }

        cutoff = dt.timestamp() - float(window_sec)
        files = 0
        total_mb = 0.0

        # Count current event (if it is an external transfer)
        if self._is_external_transfer_event(event) and self._is_sensitive_external_destination(event):
            files += 1
            total_mb += float(file_size_mb or 0.0)

        # Count recent history
        for ev in reversed(self.event_history[-500:]):  # bounded scan
            try:
                ev_ctx = ev.get("context", {}) or {}
                ev_user = str(ev_ctx.get("user") or ev.get("user") or "unknown").lower()
                if ev_user != user:
                    continue
                ev_dt = self._parse_event_dt(ev)
                if ev_dt is None:
                    continue
                if ev_dt.timestamp() < cutoff:
                    break
                if not self._is_external_transfer_event(ev):
                    continue
                if not self._is_sensitive_external_destination(ev):
                    continue
                # size bytes
                size_b = (
                    ev.get("size")
                    or (ev.get("object", {}) or {}).get("size_bytes")
                    or 0
                )
                mb = float(size_b) / (1024.0 * 1024.0) if size_b else 0.0
                files += 1
                total_mb += mb
            except Exception:
                continue

        meets = (files >= min_files) or (total_mb >= min_total_mb)
        return {
            "bulk_window_sec": window_sec,
            "bulk_file_count_window": int(files),
            "bulk_total_mb_window": round(float(total_mb), 2),
            "bulk_meets_threshold": bool(meets),
        }
    
    def process_event(self, event: dict) -> bool:
        """
        Xử lý 1 event từ Agent.
        
        Event schema từ Agent:
        - File events: có path
        - Clipboard events: có content.sample hoặc clipboard.text_file
        - Other events: heartbeat, usb_mounted, etc.
        """
        # Correlation (upload_suspected, corr_*) — đẩy thêm event vào queue SQLite
        if self._correlator is not None:
            try:
                ev_clean = {k: v for k, v in event.items() if k != "_queue_id"}
                for ce in self._correlator.on_event(ev_clean) or []:
                    self._pqueue.enqueue(ce)
            except Exception:
                pass

        event_id = event.get('event_id', 'unknown')
        event_type = event.get('type') or event.get('event_type', 'unknown')
        pid = os.getpid()
        
        # Skip heartbeat events - không cần quét
        if event_type and event_type.lower() == 'heartbeat':
            logger.debug(f"[PID={pid}] Skipping heartbeat event: event_id={event_id}")
            return True
        
        logger.info(
            f"[PID={pid}] Processing event: "
            f"event_id={event_id}, type={event_type}"
        )
        
        try:
            # ==== 0. Chuẩn hoá schema sự kiện ====
            # Map event từ agent schema sang detection engine schema
            # Check both 'type' and 'event_type' for compatibility
            event_type = event.get('type') or event.get('event_type', '')
            source = event.get('source', '')
            operation = event.get('operation', {}) or {}
            op_type = operation.get('op_type', '').lower()
            
            # Double check heartbeat after normalization
            if event_type and event_type.lower() == 'heartbeat':
                logger.debug(f"[PID={pid}] Skipping heartbeat event after normalization: event_id={event_id}")
                return True
            
            # ==== Xử lý Screenshot Events ====
            # Phải kiểm tra TRƯỚC clipboard để screenshot không bị thuợc vào clipboard branch
            is_screenshot_event = event_type.lower() == "screenshot"
            if is_screenshot_event:
                return self._process_screenshot_event(event)

            # ==== Bỏ qua corr_* Events ====
            # Các event corr_* do ContextCorrelator sinh ra; không cần xử lý thêm ở detection engine.
            if event_type.startswith('corr_'):
                logger.debug(f"[PID={pid}] Skipping corr_ event: event_id={event_id}, type={event_type}")
                return True

            # ==== Xử lý Browser Upload Events ====
            # Phải check TRƯỚC clipboard vì browser_upload có thể có field 'clipboard' trong một số trường hợp.
            if event_type == 'browser_upload':
                return self._process_browser_upload_event(event)

            file_path_str = (
                event.get('path') or
                event.get('file_path') or
                event.get('object', {}).get('path') or
                ''
            )
            is_file_event = (
                str(source).lower() in {'file', 'endpoint'}
                or str(event_type).lower().startswith('file_')
                or str(op_type).lower().startswith('file_')
                or self._is_external_transfer_event(event)
            )
            is_special_event = (
                event_type in ['usb_connected', 'usb_mounted', 'usb_unmounted', 'volume_mounted', 'process_created', 'proc_start', 'proc_end', 'print_job']
                or event_type in [
                    'http_upload',
                    'file_upload',
                    'network_upload',
                    'network_flow',
                    'network_flow_summary',
                    'http_request',
                    'cloud_exfiltration',
                    'data_exfiltration',
                ]
            )
            if event_type in ['usb_connected', 'usb_mounted', 'usb_unmounted', 'volume_mounted']:
                return self._process_special_event(event)
            if is_special_event and not is_file_event:
                return self._process_special_event(event)

            # ==== Xử lý Clipboard Events ====
            # Check nếu là clipboard event (clipboard_paste, clipboard_text, etc.)
            # Also check clipboard field exists
            has_clipboard_field = 'clipboard' in event and event.get('clipboard')
            is_clipboard_event = (
                'clipboard' in event_type.lower() or
                'clipboard' in source.lower() or
                'clipboard' in op_type or
                (has_clipboard_field and not is_file_event and not is_special_event)
            )
            
            # Log for debugging
            if is_clipboard_event:
                logger.debug(f"Detected clipboard event: type={event_type}, source={source}, op_type={op_type}, has_clipboard_field={has_clipboard_field}")
            
            if is_clipboard_event:
                return self._process_clipboard_event(event)
            
            # ==== Xử lý File Events ====
            # Lấy file path từ nhiều nguồn có thể
            if not file_path_str:
                if is_special_event:
                    return self._process_special_event(event)
                
                # Những event còn lại thực sự không có file (heartbeat, etc.)
                logger.debug(f"Skipping non-file event: {event_type}")
                return True
            
            file_path = Path(file_path_str)
            
            if not file_path.exists():
                logger.debug(f"File not found (may be deleted): {file_path}")
                return False
            
            # Check file size limit
            try:
                obj_meta = event.get('object', {}) or {}
                size_bytes = (
                    event.get('size')
                    or event.get('size_bytes')
                    or obj_meta.get('size_bytes')
                    or obj_meta.get('size')
                )
                if size_bytes is None:
                    size_bytes = file_path.stat().st_size
                file_size_mb = size_bytes / (1024 * 1024)
                if file_size_mb > WorkerConfig.MAX_FILE_SIZE_MB:
                    logger.debug(f"Skipping large file: {file_path.name} ({file_size_mb:.2f}MB)")
                    return False
            except Exception as e:
                logger.warning(f"Error checking file size: {e}")
                return False
            
            # Debounce: chờ file ổn định (size/mtime) trước khi hash (Noteupdate §17)
            if getattr(WorkerConfig, "HASH_STABILITY_ENABLED", True):
                if not wait_until_file_stable(
                    file_path,
                    interval_sec=float(getattr(WorkerConfig, "FILE_STABILITY_INTERVAL_SEC", 0.15)),
                    max_wait_sec=float(getattr(WorkerConfig, "FILE_STABILITY_MAX_WAIT_SEC", 3.0)),
                ):
                    logger.debug(f"File not stable in time, will retry: {file_path}")
                    return False
            
            # 1. Check Panic Mode
            panic_mode = self.queue_consumer.check_panic_mode()
            # Nếu hệ thống upstream báo panic_mode thì OR thêm
            if event.get('system', {}).get('panic_mode', False):
                panic_mode = True
            
            # 2. Hash Cache Check
            file_hash = self.hash_cache.calculate_hash(file_path)
            if not file_hash:
                logger.warning(f"Failed to calculate hash for {file_path}")
                return False
            
            cached_result = self.hash_cache.get_cached_result(file_hash)
            cached_malicious_score = None
            if cached_result:
                scan_result = cached_result.get('scan_result', '')
                if scan_result == 'safe':
                    if self._is_external_transfer_event(event):
                        logger.info(
                            f"File cached as safe but external transfer requires policy analysis: "
                            f"{file_path.name}"
                        )
                    else:
                        logger.debug(f"File cached as safe: {file_path.name}")
                        self.processed_count += 1
                        return True
                elif scan_result == 'malicious':
                    cached_malicious_score = float(cached_result.get('risk_score', 10.0))
                    logger.info(f"File cached as malicious: {file_path.name}, keeping cached risk score: {cached_malicious_score}")
            # Tên file trong whitelist demo: không ép điểm từ force_max / behavioral (xem _apply_filename_risk_policy).
            fn_band = self._filename_policy_band(event, file_path.name)

            # 2.5 Fuzzy hash (ssdeep): đã lưu safe trước đó với nội dung gần giống → bỏ qua quét lại (SHA có thể khác).
            ssdeep_sig = ""
            if getattr(WorkerConfig, "SSDEEP_ENABLED", True):
                ssdeep_sig = self.hash_cache.calculate_ssdeep(file_path)
                if ssdeep_sig:
                    fuzzy_safe = self.hash_cache.find_fuzzy_safe_match(ssdeep_sig, int(size_bytes))
                    if fuzzy_safe:
                        if self._is_external_transfer_event(event):
                            logger.info(
                                f"SSDEEP fuzzy safe hit but external transfer requires policy analysis: "
                                f"{file_path.name} match_score={fuzzy_safe.get('ssdeep_matched_score')}"
                            )
                        else:
                            logger.info(
                                f"SSDEEP fuzzy cache hit (safe): {file_path.name} "
                                f"match_score={fuzzy_safe.get('ssdeep_matched_score')}"
                            )
                            self.processed_count += 1
                            return True
            
            # 3. Fast Scan (file content)
            # Nếu là external transfer + file >= FORCE_SCAN_MIN_KB → bắt buộc bóc nội dung tại tầng fast scan
            FORCE_SCAN_MIN_KB = 50
            force_extract = (
                not panic_mode
                and file_size_mb >= (FORCE_SCAN_MIN_KB / 1024)
                and self._is_external_transfer_event(event)
            )
            if force_extract:
                logger.debug(
                    "External transfer >%dKB – force_extract=True for %s (%.1fKB)",
                    FORCE_SCAN_MIN_KB, file_path.name, file_size_mb * 1024
                )
            fast_scan_result = self.fast_scan.scan_file(file_path, panic_mode, force_extract=force_extract)

            # Nếu có sample text trong event (ví dụ CSV trông như bin) → quét thêm
            if self._is_external_transfer_event(event):
                ev_content = event.get("content", {}) or {}
                sample_text = str(ev_content.get("sample") or "").strip()
                if sample_text:
                    text_scan_result = self.fast_scan.scan_text_content(sample_text, panic_mode)
                    fast_scan_result = self._merge_fast_scan(fast_scan_result, text_scan_result)
                    logger.info(
                        f"External transfer content-enriched scan: sample_len={len(sample_text)}, "
                        f"yara_matches={len(fast_scan_result.get('yara_matches', []))}"
                    )

            if file_path.suffix.lower() in {".zip", ".7z", ".rar"}:
                self._apply_archive_member_scan_policy(fast_scan_result)
             
            yara_matches = fast_scan_result.get('yara_matches', [])

            # 3.5 Bulk exfiltration features (demo: off-hours + many files/large total to USB/sensitive)
            bulk_feats = self._compute_bulk_exfil_features(event, file_size_mb=file_size_mb)
            ev_dt = self._parse_event_dt(event)
            is_off_hours = self._is_off_hours(ev_dt)
            is_sensitive_external = self._is_sensitive_external_destination(event)
            bulk_force_deep = bool(
                getattr(WorkerConfig, "BULK_EXFIL_FORCE_DEEP_ANALYSIS", True)
                and is_off_hours
                and is_sensitive_external
                and bulk_feats.get("bulk_meets_threshold", False)
            )
            if bulk_force_deep:
                logger.warning(
                    "Bulk exfiltration trigger: off_hours=%s sensitive_external=%s files=%s total_mb=%s window_sec=%s",
                    is_off_hours,
                    is_sensitive_external,
                    bulk_feats.get("bulk_file_count_window"),
                    bulk_feats.get("bulk_total_mb_window"),
                    bulk_feats.get("bulk_window_sec"),
                )

            # 4. Decision Point — fast_scan đã xử lý toàn bộ text extraction + YARA.
            #    Decision ở đây chỉ dựa vào kết quả is_suspicious từ fast_scan.
            if fast_scan_result.get('is_suspicious', False) or bulk_force_deep:
                # Nếu YARA phát hiện ngay với high confidence → có thể skip deep analysis
                if yara_matches and not panic_mode and not bulk_force_deep:
                    # Check nếu là high-risk rule (ID, credit card)
                    high_risk_rules = ['id', 'cmnd', 'cccd', 'credit', 'card']
                    is_high_risk = any(
                        any(keyword in match.get('rule', '').lower() for keyword in high_risk_rules)
                        for match in yara_matches
                    )
                    if is_high_risk:
                        deep_analysis_result = {'is_sensitive': True}
                    else:
                        deep_analysis_result = self.deep_analysis.analyze(
                            file_path,
                            fast_scan_result.get('file_type'),
                            panic_mode
                        )
                else:
                    if not panic_mode:
                        deep_analysis_result = self.deep_analysis.analyze(
                            file_path,
                            fast_scan_result.get('file_type'),
                            panic_mode
                        )
                        if bulk_force_deep:
                            deep_analysis_result["bulk_triggered_deep_scan"] = True
                    else:
                        deep_analysis_result = {'is_sensitive': False}
            else:
                deep_analysis_result = {'is_sensitive': False}

            nlp_result = {}
            if fn_band != "low_medium":
                nlp_user = (event.get("context", {}) or {}).get("user") or event.get("user") or "unknown"
                nlp_fallback = self._extract_file_text_for_nlp(file_path, fast_scan_result)
                nlp_result = self._run_nlp_content_analysis(event, user=nlp_user, fallback_text=nlp_fallback)
                self._merge_nlp_into_detection(nlp_result, fast_scan_result, deep_analysis_result)
             
            # 5.5. Behavioral Rules Check (theo Noteupdate.txt)
            # Check các behavioral rules dựa trên điều kiện từ event fields
            behavioral_matches = self.behavioral_rules.check_all(event, fast_scan_result)
            
            # Nếu có behavioral rule match, tăng risk score
            behavioral_risk_boost = 0
            behavioral_details = {}
            if behavioral_matches and fn_band != "low_medium":
                highest_match = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest_match:
                    # Tăng risk score dựa trên severity
                    severity_boost = WorkerConfig.BEHAVIORAL_RISK_BOOST
                    behavioral_risk_boost = severity_boost.get(highest_match.get('severity', 'low'), 0)
                    behavioral_details = {
                        'behavioral_rule_matched': highest_match.get('rule'),
                        'behavioral_reason': highest_match.get('reason', ''),
                        'behavioral_severity': highest_match.get('severity'),
                        'all_behavioral_matches': behavioral_matches
                    }
                    logger.warning(
                        f"Behavioral Rule Matched: {highest_match.get('rule')} - "
                        f"{highest_match.get('reason', '')} (+{behavioral_risk_boost} risk boost)"
                    )
            
            # 5.6. UEBA ML Anomaly Detection
            ml_anomaly_result = {'anomaly_score': 0.0, 'is_anomaly': False}
            if self.ml_analyzer.is_available():
                try:
                    # Use recent event history for frequency features
                    recent_history = self.event_history[-100:] if len(self.event_history) > 100 else self.event_history
                    ml_anomaly_result = self.ml_analyzer.predict(event, event_history=recent_history)
                    
                    if ml_anomaly_result.get('is_anomaly', False):
                        anomaly_score = ml_anomaly_result.get('anomaly_score', 0.0)
                        reasons = (
                            (ml_anomaly_result.get("profile_reasons") or [])
                            + (ml_anomaly_result.get("baseline_reasons") or [])
                        )
                        logger.warning(
                            f"UEBA Anomaly Detected: score={anomaly_score:.2f} "
                            f"(raw={ml_anomaly_result.get('raw_score', 0):.3f}) "
                            f"reasons={reasons}"
                        )
                except Exception as e:
                    logger.error(f"Error in ML anomaly detection: {e}")
            # Bridge UEBA output into deep_analysis payload for scoring engines that
            # still read anomaly info from deep_analysis.
            try:
                ml_score_0_10 = float(ml_anomaly_result.get('anomaly_score') or 0.0)
                deep_analysis_result['ml_anomaly_score'] = ml_score_0_10
                deep_analysis_result['ml_is_anomaly'] = bool(ml_anomaly_result.get('is_anomaly', False))
                # ResearchBasedRiskScoringEngine expects anomaly_score roughly in [-1, 1].
                deep_analysis_result['anomaly_score'] = max(-1.0, min(1.0, (ml_score_0_10 / 5.0) - 1.0))
            except Exception:
                pass
            
            # 6. Risk Scoring
            # Chuẩn hoá context cho RiskScoringEngine
            # Lấy context từ event
            ctx = event.get('context', {}) or {}
            
            # action_type: ưu tiên event_type từ agent, fallback type
            action_type = operation.get('op_type') or event.get('event_type') or event.get('type', 'file_copy')
            
            # destination: từ correlation events hoặc context
            destination = event.get('destination', '')
            if not destination and ctx:
                # Có thể có thông tin destination trong context
                destination = ctx.get('destination', '')
            if not destination:
                obj = event.get('object', {}) or {}
                destination = (
                    obj.get('dst_path')
                    or obj.get('path')
                    or obj.get('dest_drive')
                    or obj.get('drive')
                    or ''
                )
            
            # user: từ context
            user = ctx.get('user') or event.get('user', 'unknown')
            
            # Detect exfiltration from sensitive folders (config-based)
            obj = event.get('object', {}) or {}
            src_path = str(obj.get('path') or file_path_str or '').lower()
            dst_path = str(
                obj.get('dst_path') or
                event.get('dst_path') or
                event.get('Dest_Path') or
                ''
            ).lower()
            sensitive_folders = WorkerConfig.SENSITIVE_EXFIL_FOLDERS
            is_sensitive_folder_src = any(
                src_path.startswith(folder) for folder in sensitive_folders
            ) if src_path else False
            is_same_folder = bool(dst_path) and any(
                dst_path.startswith(folder) for folder in sensitive_folders
            )
            is_sensitive_folder_exfil = is_sensitive_folder_src and (not is_same_folder)
            # Danh sách tên low/medium demo: không áp dụng force_max (ép lên max) — chỉ tin band filename + CVSS sau cùng.
            force_max = is_sensitive_folder_exfil and fn_band != "low_medium"
            
            event_context = {
                'action_type': action_type,
                'destination': destination,
                'user': user,
                'time': event.get('ts') or event.get('timestamp', ''),
                'location': str(file_path.parent),
                'file_size_mb': file_size_mb,
                # Bulk exfiltration window features (used by CVSS-DLP EM volume & demo explainability)
                'bulk_window_sec': bulk_feats.get("bulk_window_sec"),
                'bulk_file_count_window': bulk_feats.get("bulk_file_count_window"),
                'bulk_total_mb_window': bulk_feats.get("bulk_total_mb_window"),
                'bulk_meets_threshold': bulk_feats.get("bulk_meets_threshold"),
                'is_off_hours': is_off_hours,
                'is_sensitive_external_destination': is_sensitive_external,
                # Bổ sung context nâng cao
                'process_name': ctx.get('process_name'),
                'active_window': ctx.get('active_window'),
                'event_id': event.get('event_id'),
                'source': event.get('source', 'unknown'),
                'severity': event.get('severity'),
                'extension': event.get('ext') or file_path.suffix,
                # Behavioral rules context
                'behavioral_risk_boost': behavioral_risk_boost,
                'behavioral_details': behavioral_details,
                # UEBA ML anomaly detection
                'ml_anomaly_score': ml_anomaly_result.get('anomaly_score', 0.0),
                'ml_is_anomaly': ml_anomaly_result.get('is_anomaly', False),
                # Hard policy: any exfil from sensitive folders must be max score + alert (trừ file trong whitelist tên low/medium)
                'force_max_risk': force_max,
                'force_max_risk_reason': (
                    f"Sensitive folder exfiltration from {src_path} to {dst_path}"
                    if force_max else ''
                ),
                '_event_data': event
            }
            if cached_malicious_score is not None:
                event_context['cached_malicious_score'] = cached_malicious_score
            
            risk_result = self.risk_scoring.calculate_score(
                fast_scan_result,
                deep_analysis_result,
                event_context
            )

            # Apply cached malicious score if it was previously detected as malicious
            if cached_malicious_score is not None:
                if risk_result['total_score'] < cached_malicious_score:
                    risk_result['total_score'] = cached_malicious_score
                    if "cvss_score" in risk_result:
                        risk_result["cvss_score"] = round(min(10.0, cached_malicious_score), 2)
                    risk_result.setdefault('details', {})['cache_override'] = f"Retained previous malicious score: {cached_malicious_score}"
                    logger.warning(f"Overriding calculated risk score with cached malicious score: {cached_malicious_score}")
                    if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert']:
                        risk_result['action'] = 'alert'

            # Apply behavioral risk boost
            if behavioral_risk_boost > 0 and fn_band != "low_medium":
                risk_result['total_score'] = min(10.0, risk_result['total_score'] + behavioral_risk_boost)
                if "cvss_score" in risk_result:
                    risk_result["cvss_score"] = round(min(10.0, risk_result["total_score"]), 2)
                risk_result['details']['behavioral'] = behavioral_details
                # Nếu behavioral rule match + high severity → force alert/block
                highest_match = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest_match and highest_match.get('severity') == 'high':
                    # Alert-only system: never force block
                    if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert']:
                        risk_result['action'] = 'alert'

            self._apply_filename_risk_policy(event, risk_result, fallback_name=file_path.name)
            self._apply_archive_member_risk_policy(risk_result, fast_scan_result)
            if fn_band != "low_medium":
                self._apply_nlp_risk_policy(risk_result, nlp_result)
            if (
                file_path.suffix.lower() == ".zip"
                and fast_scan_result.get("archive_scanned")
                and not fast_scan_result.get("is_encrypted_zip")
                and not fast_scan_result.get("archive_sensitive_hits")
                and not fast_scan_result.get("yara_matches")
                and fn_band != "high"
            ):
                cap = 4.9
                if float(risk_result.get("total_score", 0.0)) > cap:
                    risk_result["total_score"] = cap
                    risk_result["cvss_score"] = cap
                    risk_result["risk_level"] = "medium"
                    risk_result["action"] = "log"
                    risk_result.setdefault("details", {})["archive_clean_cap"] = {
                        "cap": cap,
                        "archive_entries": fast_scan_result.get("archive_entries"),
                        "archive_scanned_files": fast_scan_result.get("archive_scanned_files"),
                        "reason": "zip_scanned_no_sensitive_hits",
                    }
             
            # 7. Generate Report Fields
            report = self.report_generator.generate_report(
                event,
                fast_scan_result,
                deep_analysis_result,
                risk_result,
                file_path
            )
            
            # 8. Action Executor (với report fields); dedup alert: SHA hoặc ssdeep (nội dung gần giống, SHA khác nhau)
            action = risk_result['action']
            now_ts = time.time()
            dedup_sec = float(getattr(WorkerConfig, "ALERT_DEDUP_SEC", 600))
            suppress_alert = False
            dedup_key = file_hash
            if getattr(WorkerConfig, "ALERT_DEDUP_USE_SSDEEP", True) and ssdeep_sig:
                dedup_key = f"ssdeep:{ssdeep_sig}"
            if action == "alert" and dedup_key and dedup_sec > 0 and cached_malicious_score is None:
                last_alert = self._alert_dedup.get(dedup_key)
                if last_alert is not None and (now_ts - last_alert) < dedup_sec:
                    suppress_alert = True
                    logger.warning(
                        f"Alert dedup: same key within {dedup_sec}s — executed LOG instead of ALERT "
                        f"(no Windows toast; dashboard action=allowed). key={str(dedup_key)[:48]}… "
                        f"Disable dedup: ALERT_DEDUP_SEC=0"
                    )
            exec_action = "log" if suppress_alert else action
            if action == "alert" and not suppress_alert and cached_malicious_score is None:
                self._alert_dedup[dedup_key] = now_ts
            elif action == "alert" and cached_malicious_score is not None:
                logger.info(
                    f"Known malicious hash alert bypassed dedup so Windows popup is still shown: "
                    f"{file_path.name}, cached_score={cached_malicious_score:.1f}"
                )
            self.action_executor.execute(
                exec_action,
                file_path,
                risk_result['total_score'],
                risk_result['details'],
                event_context,
                report  # Pass report fields
            )
            
            # 9. Update Cache
            scan_result = 'malicious' if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert'] else 'safe'
            if not ssdeep_sig and getattr(WorkerConfig, "SSDEEP_ENABLED", True):
                ssdeep_sig = self.hash_cache.calculate_ssdeep(file_path)
            self.hash_cache.save_result(
                file_hash,
                str(file_path),
                file_path.stat().st_size,
                scan_result,
                risk_result['total_score'],
                action,
                ssdeep_sig=ssdeep_sig,
            )
            try:
                self._pqueue.insert_scan_result(
                    event_ref=str(event.get("event_id") or ""),
                    file_hash=file_hash,
                    risk_score=float(risk_result["total_score"]),
                    scan_summary=scan_result,
                    payload={"action": action, "path": str(file_path)},
                )
            except Exception:
                pass
            
            # Update Event History for ML
            self.event_history.append(event.copy())
            if len(self.event_history) > self.max_history_size:
                self.event_history.pop(0)  # Remove oldest event
            
            self._save_processed_event(event, risk_result, fast_scan_result, behavioral_matches)
            
            self.processed_count += 1
            
            logger.info(
                f"Processed: {file_path.name} | "
                f"Score: {risk_result['total_score']:.1f} | "
                f"Executed: {exec_action.upper()}"
                + (f" (policy={action.upper()}, dedup)" if suppress_alert else "")
                + f" | Sensitivity: {report.get('File_Sensitivity', 'Unknown')}"
            )
            
            return True
            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing event: {e}", exc_info=True)
            return False

    # ------------------------------------------------------------------ #
    #  BROWSER UPLOAD PIPELINE                                            #
    # ------------------------------------------------------------------ #
    def _process_browser_upload_event(self, event: dict) -> bool:
        """
        Xử lý browser_upload event với full DLP pipeline.

        Luồng xử lý khi CÓ file local (object.path tồn tại):
          1. Hash cache check — nếu đã safe → skip
          2. File stability debounce
          3a. Ảnh (PNG/JPG/…) → OCR → scan_text_content (như screenshot)
          3b. File khác       → scan_file + deep_analysis (như file event)
          4. Behavioral rules
          5. ML/UEBA anomaly detection
          6. Risk scoring (tích hợp network upload context)
          7. Apply filename policy
          8. Action executor + report + cache update

        Khi KHÔNG có file local:
          → Metadata-based scoring dựa trên: extension sensitivity,
            destination domain, upload confidence_score, behavioral rules.
        """
        try:
            event_id  = event.get('event_id', 'unknown')
            pid       = os.getpid()
            logger.info(f"[PID={pid}] Processing browser_upload event: event_id={event_id}")

            # --- Trích xuất metadata từ event ---
            bu          = event.get('browser_upload', {}) or {}
            obj         = event.get('object', {}) or {}
            net         = event.get('network', {}) or {}
            ctx         = event.get('context', {}) or {}

            filename        = str(bu.get('filename') or obj.get('name') or '')
            dest_domain     = str(bu.get('destination') or net.get('dest_domain') or '')
            tab_url         = str(bu.get('tab_url') or net.get('dest_url') or '')
            trigger         = str(bu.get('trigger') or 'unknown')
            browser         = str(bu.get('browser') or 'unknown')
            confidence_raw  = bu.get('confidence_score', 0.80)
            upload_confidence = float(confidence_raw) if confidence_raw is not None else 0.80
            size_bytes_raw  = obj.get('size') or net.get('bytes_sent_total') or bu.get('size') or 0
            size_bytes      = int(size_bytes_raw) if size_bytes_raw else 0
            file_size_mb    = size_bytes / (1024 * 1024) if size_bytes else 0.0

            # Lấy extension — ưu tiên obj.ext rồi mới suy từ filename
            ext = str(obj.get('ext') or '').lower()
            if not ext and filename:
                try:
                    ext = Path(filename).suffix.lower()
                except Exception:
                    ext = ''

            # Resolve local path: object.path → browser_upload.local_path
            file_path_str = str(obj.get('path') or bu.get('local_path') or '')
            file_path: Optional[Path] = None
            if file_path_str:
                try:
                    p = Path(file_path_str)
                    file_path = p if p.exists() else None
                except Exception:
                    file_path = None

            # BUG FIX: init tất cả variables trước các if/else blocks để tránh NameError
            file_hash: str = ''
            ssdeep_sig: str = ''
            fn_band: Optional[str] = None
            cached_malicious_score = None
            actual_size: int = size_bytes  # fallback từ network metadata

            panic_mode = self.queue_consumer.check_panic_mode()
            if event.get('system', {}).get('panic_mode', False):
                panic_mode = True

            # ===================================================
            # PATH A: File tồn tại — full content scan pipeline
            # ===================================================
            if file_path is not None:
                # --- Kiểm tra kích thước ---
                try:
                    actual_size = file_path.stat().st_size
                    file_size_mb = actual_size / (1024 * 1024)
                    if file_size_mb > WorkerConfig.MAX_FILE_SIZE_MB:
                        logger.debug(
                            f"[PID={pid}] browser_upload: file too large, skip content scan: "
                            f"{file_path.name} ({file_size_mb:.2f}MB)"
                        )
                        file_path = None  # Fall through to PATH B
                except Exception as _e:
                    logger.warning(f"[PID={pid}] browser_upload: stat failed: {_e}")
                    file_path = None

            if file_path is not None:
                # Filename policy band (trước hash cache để tránh bypass whitelist)
                fn_band = self._filename_policy_band(event, file_path.name)
                # Đặt fn_band fallback theo filename nếu file_path còn tồn tại

                # --- File stability debounce ---
                if getattr(WorkerConfig, 'HASH_STABILITY_ENABLED', True):
                    if not wait_until_file_stable(
                        file_path,
                        interval_sec=float(getattr(WorkerConfig, 'FILE_STABILITY_INTERVAL_SEC', 0.15)),
                        max_wait_sec=float(getattr(WorkerConfig, 'FILE_STABILITY_MAX_WAIT_SEC', 3.0)),
                    ):
                        logger.debug(f"[PID={pid}] browser_upload: file not stable, retry later: {file_path}")
                        return False

                # --- Hash cache check ---
                file_hash = self.hash_cache.calculate_hash(file_path)
                cached_malicious_score = None
                if not file_hash:
                    logger.warning(f"[PID={pid}] browser_upload: hash failed: {file_path}")
                    file_path = None  # Fallback to PATH B
                else:
                    cached = self.hash_cache.get_cached_result(file_hash)
                    if cached:
                        scan_result = cached.get('scan_result', '')
                        if scan_result == 'safe':
                            logger.debug(f"[PID={pid}] browser_upload: cached safe: {file_path.name}")
                            self.processed_count += 1
                            return True
                        elif scan_result == 'malicious':
                            cached_malicious_score = float(cached.get('risk_score', 10.0))
                            logger.info(f"[PID={pid}] browser_upload: cached malicious: {file_path.name}, keeping cached risk score: {cached_malicious_score}")

                    # ssdeep fuzzy cache
                    ssdeep_sig = ''
                    if getattr(WorkerConfig, 'SSDEEP_ENABLED', True):
                        ssdeep_sig = self.hash_cache.calculate_ssdeep(file_path)
                        if ssdeep_sig:
                            fuzzy = self.hash_cache.find_fuzzy_safe_match(ssdeep_sig, actual_size)
                            if fuzzy:
                                logger.info(
                                    f"[PID={pid}] browser_upload SSDEEP fuzzy cache hit (safe): "
                                    f"{file_path.name} score={fuzzy.get('ssdeep_matched_score')}"
                                )
                                self.processed_count += 1
                                return True

            # Re-check nếu file_path bị nulled sau các bước trên
            if file_path is not None:
                # ---- Phân nhánh theo loại file ----
                _image_exts = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.heic', '.heif'}
                is_image = ext in _image_exts

                if is_image:
                    # ---- 3a. Ảnh → OCR → scan_text_content ----
                    ocr_text = ''
                    if not panic_mode:
                        logger.info(f"[PID={pid}] browser_upload: OCR on image: {file_path.name}")
                        try:
                            extracted = self.deep_analysis.ocr_processor.extract_text(file_path)
                            if extracted:
                                ocr_text = extracted.strip()
                                logger.info(
                                    f"[PID={pid}] browser_upload OCR: {len(ocr_text)} chars "
                                    f"from {file_path.name}: {ocr_text[:80]!r}"
                                )
                        except Exception as _ocr_err:
                            logger.warning(f"[PID={pid}] browser_upload OCR error: {_ocr_err}")

                    fast_scan_result = (
                        self.fast_scan.scan_text_content(ocr_text, panic_mode)
                        if ocr_text else
                        {'yara_matches': [], 'is_suspicious': False}
                    )
                    deep_analysis_result = {
                        'is_sensitive': bool(fast_scan_result.get('yara_matches')),
                        'ocr_text': ocr_text or None,
                    }
                else:
                    # ---- 3b. File khác → scan_file + deep_analysis ----
                    fast_scan_result = self.fast_scan.scan_file(file_path, panic_mode)

                    yara_matches = fast_scan_result.get('yara_matches', [])
                    if fast_scan_result.get('is_suspicious', False) and not panic_mode:
                        high_risk_rules = ['id', 'cmnd', 'cccd', 'credit', 'card']
                        is_high_risk = any(
                            any(kw in m.get('rule', '').lower() for kw in high_risk_rules)
                            for m in yara_matches
                        )
                        if is_high_risk:
                            deep_analysis_result = {'is_sensitive': True}
                        else:
                            deep_analysis_result = self.deep_analysis.analyze(
                                file_path, fast_scan_result.get('file_type'), panic_mode
                            )
                    else:
                        deep_analysis_result = {'is_sensitive': False}

                    # Nếu có text sample từ event → scan thêm (bổ sung YARA hits)
                    ev_content = event.get('content', {}) or {}
                    sample_text = str(ev_content.get('sample') or '').strip()
                    if sample_text:
                        text_scan = self.fast_scan.scan_text_content(sample_text, panic_mode)
                        fast_scan_result = self._merge_fast_scan(fast_scan_result, text_scan)
            else:
                # ===================================================
                # PATH B: Không có file — metadata-based scan only
                # ===================================================
                # fn_band, file_hash, ssdeep_sig đã được init ở trên
                if fn_band is None:
                    fn_band = self._filename_policy_band(event, filename)
                ocr_text = ''
                is_image = ext in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.heic', '.heif'}

                # Scan filename / extension với YARA (heuristic)
                scan_target = filename or dest_domain
                fast_scan_result = (
                    self.fast_scan.scan_text_content(scan_target, panic_mode)
                    if scan_target else
                    {'yara_matches': [], 'is_suspicious': False}
                )
                deep_analysis_result = {'is_sensitive': False}
                logger.info(
                    f"[PID={pid}] browser_upload: no local file — metadata-only scan "
                    f"filename={filename!r} dest={dest_domain!r}"
                )

            yara_matches = fast_scan_result.get('yara_matches', [])
            nlp_result = {}
            if fn_band != 'low_medium':
                nlp_fallback = str(locals().get('ocr_text') or locals().get('sample_text') or '')
                if file_path is not None and not nlp_fallback.strip():
                    nlp_fallback = self._extract_file_text_for_nlp(file_path, fast_scan_result)
                nlp_user = ctx.get('user') or event.get('actor', {}).get('user', 'unknown')
                nlp_result = self._run_nlp_content_analysis(event, user=nlp_user, fallback_text=nlp_fallback)
                self._merge_nlp_into_detection(nlp_result, fast_scan_result, deep_analysis_result)

            upload_evidence_level = self._browser_upload_evidence_level(
                event, fast_scan_result, file_size_mb=file_size_mb
            )

            # ---- 4. Behavioral Rules ----
            behavioral_matches   = self.behavioral_rules.check_all(event, fast_scan_result)
            behavioral_risk_boost = 0
            behavioral_details   = {}
            if behavioral_matches and fn_band != 'low_medium':
                highest = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest:
                    behavioral_risk_boost = WorkerConfig.BEHAVIORAL_RISK_BOOST.get(
                        highest.get('severity', 'low'), 0
                    )
                    if highest.get('rule') == 'Network_Upload':
                        if upload_evidence_level == 'low':
                            behavioral_risk_boost = 0
                        elif upload_evidence_level == 'medium':
                            behavioral_risk_boost = min(float(behavioral_risk_boost), 1.2)
                    behavioral_details = {
                        'behavioral_rule_matched': highest.get('rule'),
                        'behavioral_reason':       highest.get('reason', ''),
                        'behavioral_severity':     highest.get('severity'),
                        'upload_evidence_level':   upload_evidence_level,
                        'all_behavioral_matches':  behavioral_matches,
                    }
                    logger.warning(
                        f"Behavioral Rule Matched (BrowserUpload): {highest.get('rule')} "
                        f"- {highest.get('reason', '')} (+{behavioral_risk_boost})"
                    )

            # ---- 5. ML / UEBA ----
            ml_anomaly_result = {'anomaly_score': 0.0, 'is_anomaly': False}
            if self.ml_analyzer.is_available():
                try:
                    recent = self.event_history[-100:] if len(self.event_history) > 100 else self.event_history
                    ml_anomaly_result = self.ml_analyzer.predict(event, event_history=recent)
                    if ml_anomaly_result.get('is_anomaly', False):
                        logger.warning(
                            f"[PID={pid}] UEBA Anomaly (BrowserUpload): "
                            f"score={ml_anomaly_result.get('anomaly_score', 0):.2f}"
                        )
                except Exception as _ml_err:
                    logger.error(f"[PID={pid}] ML error (browser_upload): {_ml_err}")
            try:
                _ml_s = float(ml_anomaly_result.get('anomaly_score') or 0.0)
                deep_analysis_result['ml_anomaly_score'] = _ml_s
                deep_analysis_result['ml_is_anomaly']    = bool(ml_anomaly_result.get('is_anomaly', False))
                deep_analysis_result['anomaly_score']    = max(-1.0, min(1.0, (_ml_s / 5.0) - 1.0))
            except Exception:
                pass

            # ---- 6. Risk Scoring ----
            # Nhận diện sensitive domain để tăng risk tương tự _is_sensitive_external_destination
            is_sensitive_dest = self._is_sensitive_external_destination(event) or bool(dest_domain)

            event_context = {
                'action_type':                'browser_upload',
                'destination':                dest_domain or tab_url,
                'user':                       ctx.get('user') or event.get('actor', {}).get('user', 'unknown'),
                'time':                       event.get('ts') or event.get('timestamp', ''),
                'location':                   str(file_path.parent) if file_path else 'browser',
                'file_size_mb':               file_size_mb,
                'process_name':               ctx.get('fg_app') or browser,
                'active_window':              ctx.get('window_title', ''),
                'domain':                     dest_domain,
                'event_id':                   event_id,
                'source':                     event.get('source', 'browser_upload_sensor'),
                'severity':                   event.get('severity'),
                'extension':                  ext,
                # Upload-specific context
                'upload_trigger':             trigger,
                'upload_browser':             browser,
                'upload_confidence':          upload_confidence,
                'upload_evidence_level':      upload_evidence_level,
                'is_sensitive_external_destination': is_sensitive_dest,
                # Behavioral / ML
                'behavioral_risk_boost':      behavioral_risk_boost,
                'behavioral_details':         behavioral_details,
                'ml_anomaly_score':           ml_anomaly_result.get('anomaly_score', 0.0),
                'ml_is_anomaly':              ml_anomaly_result.get('is_anomaly', False),
                '_event_data':                event,
            }

            risk_result = self.risk_scoring.calculate_score(
                fast_scan_result, deep_analysis_result, event_context
            )

            # Apply cached malicious score if it was previously detected as malicious
            if cached_malicious_score is not None:
                if risk_result['total_score'] < cached_malicious_score:
                    risk_result['total_score'] = cached_malicious_score
                    if "cvss_score" in risk_result:
                        risk_result["cvss_score"] = round(min(10.0, cached_malicious_score), 2)
                    risk_result.setdefault('details', {})['cache_override'] = f"Retained previous malicious score: {cached_malicious_score}"
                    logger.warning(f"Overriding calculated risk score with cached malicious score: {cached_malicious_score}")
                    if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert']:
                        risk_result['action'] = 'alert'

            # Boost từ upload confidence cao (>= 0.85 = browser extension rất chắc là upload nhạy cảm)
            if upload_confidence >= 0.85 and fn_band != 'low_medium' and upload_evidence_level != 'low':
                conf_boost = round((upload_confidence - 0.85) * 20, 2)  # max +3.0
                risk_result['total_score'] = min(10.0, risk_result['total_score'] + conf_boost)
                if 'cvss_score' in risk_result:
                    risk_result['cvss_score'] = round(min(10.0, risk_result['total_score']), 2)
                risk_result.setdefault('details', {})['upload_confidence_boost'] = conf_boost

            # Apply behavioral boost
            if behavioral_risk_boost > 0 and fn_band != 'low_medium':
                risk_result['total_score'] = min(10.0, risk_result['total_score'] + behavioral_risk_boost)
                if 'cvss_score' in risk_result:
                    risk_result['cvss_score'] = round(min(10.0, risk_result['total_score']), 2)
                risk_result['details']['behavioral'] = behavioral_details
                highest = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest and highest.get('severity') == 'high':
                    if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert']:
                        risk_result['action'] = 'alert'

            self._apply_filename_risk_policy(event, risk_result, fallback_name=filename)
            if fn_band != 'high':
                self._cap_browser_upload_weak_risk(risk_result, upload_evidence_level)
            if fn_band != 'low_medium':
                self._apply_nlp_risk_policy(risk_result, nlp_result)

            # ---- 7. Report & Action (với alert dedup tránh spam) ----
            dummy_path = Path(file_path) if file_path else Path(f"browser_upload://{filename or dest_domain}")
            report = self.report_generator.generate_report(
                event, fast_scan_result, deep_analysis_result, risk_result, dummy_path
            )

            action = risk_result['action']

            # BUG FIX: Alert dedup cho browser_upload — cùng file/domain trong ALERT_DEDUP_SEC → downgrade sang log
            now_ts = time.time()
            dedup_sec = float(getattr(WorkerConfig, 'ALERT_DEDUP_SEC', 600))
            suppress_alert = False
            if file_hash:
                dedup_key_bu = file_hash
            else:
                dedup_key_bu = f"browser_upload:{filename}:{dest_domain}"
            if action == 'alert' and dedup_key_bu and dedup_sec > 0 and cached_malicious_score is None:
                _last_bu = self._alert_dedup.get(dedup_key_bu)
                if _last_bu is not None and (now_ts - _last_bu) < dedup_sec:
                    suppress_alert = True
                    logger.warning(
                        f"[PID={pid}] BrowserUpload alert dedup: same key within {dedup_sec}s → log "
                        f"key={str(dedup_key_bu)[:48]}…"
                    )
            exec_action_bu = 'log' if suppress_alert else action
            if action == 'alert' and not suppress_alert and cached_malicious_score is None:
                self._alert_dedup[dedup_key_bu] = now_ts
            elif action == 'alert' and cached_malicious_score is not None:
                logger.info(
                    f"[PID={pid}] browser_upload known malicious hash bypassed dedup so Windows popup is still shown: "
                    f"{filename!r}, cached_score={cached_malicious_score:.1f}"
                )

            logger.info(
                f"[PID={pid}] BrowserUpload scan complete: event_id={event_id} "
                f"file={filename!r} dest={dest_domain!r} "
                f"score={risk_result['total_score']:.1f} action={exec_action_bu.upper()} "
                f"yara={len(yara_matches)} has_file={file_path is not None}"
                + (f" (policy={action.upper()}, dedup)" if suppress_alert else "")
            )

            self.action_executor.execute(
                exec_action_bu, dummy_path,
                risk_result['total_score'], risk_result['details'],
                event_context, report
            )

            # ---- 8. Cache update (chỉ khi có file) ----
            if file_path is not None and file_hash:
                scan_result_label = (
                    'malicious' if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert']
                    else 'safe'
                )
                if not ssdeep_sig and getattr(WorkerConfig, 'SSDEEP_ENABLED', True):
                    ssdeep_sig = self.hash_cache.calculate_ssdeep(file_path)
                self.hash_cache.save_result(
                    file_hash, str(file_path), file_path.stat().st_size,
                    scan_result_label, risk_result['total_score'], action,
                    ssdeep_sig=ssdeep_sig,
                )
                try:
                    self._pqueue.insert_scan_result(
                        event_ref=str(event_id),
                        file_hash=file_hash,
                        risk_score=float(risk_result['total_score']),
                        scan_summary=scan_result_label,
                        payload={'action': action, 'path': str(file_path)},
                    )
                except Exception:
                    pass

            self.event_history.append(event.copy())
            if len(self.event_history) > self.max_history_size:
                self.event_history.pop(0)

            self._save_processed_event(event, risk_result, fast_scan_result, behavioral_matches)
            self.processed_count += 1
            return True

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing browser_upload event: {e}", exc_info=True)
            return False

    def _process_clipboard_event(self, event: dict) -> bool:
        """
        Xử lý clipboard event (paste, copy)
        
        Logic:
        1. Lấy text content từ content.sample hoặc clipboard.text_file
        2. Scan text với YARA rules
        3. Nếu hit YARA + window_title (gpt, discord, zalo) + clipboard_paste → alert/block
        """
        try:
            # Log event structure for debugging
            logger.debug(f"Clipboard event structure: type={event.get('type')}, source={event.get('source')}, has_clipboard={bool(event.get('clipboard'))}, has_content={bool(event.get('content'))}")
            
            content = event.get('content', {}) or {}
            clipboard = event.get('clipboard', {}) or {}
            raw_original = event.get('raw_original', {}) or {}
            
            raw_clipboard = raw_original.get('clipboard', {}) or {}
            raw_content = raw_original.get('content', {}) or {}
            
            # Try multiple sources for text content
            text_content = (
                clipboard.get('text_file') or      # Primary: clipboard.text_file
                raw_clipboard.get('text_file') or  # From raw_original
                content.get('sample') or            # content.sample
                raw_content.get('sample') or        # raw_original.content.sample
                clipboard.get('content') or         # clipboard.content (if string)
                ''
            )
            
            # If text_content is still empty, check if it's an image that needs OCR
            fast_scan_result = None
            if not text_content or not text_content.strip():
                # Check if clipboard contains image (content_type = Image, FileList, or similar)
                content_type = (
                    clipboard.get('content_type') or
                    raw_clipboard.get('content_type') or
                    ''
                ).lower()
                
                # Check for FileList with image files (per event sample: content_type="FileList", file_list=["path/to/image.png"])
                file_list = (
                    clipboard.get('file_list') or
                    raw_clipboard.get('file_list') or
                    []
                )
                
                image_file_path = None
                
                # Case 1: content_type = "FileList" with image files
                if content_type == 'filelist' and file_list:
                    image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp'}
                    extracted_texts = []
                    aggregated_yara_matches = []
                    
                    # Giới hạn tối đa 10 file đầu tiên
                    max_files = 10
                    processed_count = 0
                    
                    for file_path_str in file_list:
                        if processed_count >= max_files:
                            logger.info(f"Reached max limit of {max_files} files for bulk scanning.")
                            break
                        if not file_path_str:
                            continue
                            
                        p = Path(str(file_path_str))
                        if not p.exists():
                            continue
                            
                        processed_count += 1
                        ext = p.suffix.lower()
                        
                        if ext in image_extensions:
                            logger.info(f"Processing image file in FileList for OCR: {p.name}")
                            try:
                                ocr_text = self.deep_analysis.ocr_processor.extract_text(p)
                                if ocr_text and ocr_text.strip():
                                    extracted_texts.append(ocr_text.strip())
                            except Exception as e:
                                logger.warning(f"OCR error for {p.name}: {e}")
                        else:
                            # Non-image file, scan using fast_scan.scan_file
                            logger.info(f"Processing document file in FileList: {p.name}")
                            try:
                                fs_res = self.fast_scan.scan_file(p, panic_mode=self.queue_consumer.check_panic_mode())
                                if fs_res and fs_res.get('yara_matches'):
                                    aggregated_yara_matches.extend(fs_res.get('yara_matches'))
                            except Exception as e:
                                logger.warning(f"File scan error for {p.name}: {e}")
                                
                    if extracted_texts:
                        text_content = "\n---\n".join(extracted_texts)
                        logger.info(f"OCR extracted {len(text_content)} total chars from FileList images.")
                    
                    if aggregated_yara_matches:
                        fast_scan_result = {
                            'yara_matches': aggregated_yara_matches,
                            'is_suspicious': len(aggregated_yara_matches) > 0
                        }
                
                # Case 2: content_type = "Image" or similar with direct image_file path
                elif not image_file_path and ('image' in content_type or not content_type):
                    image_file_path = (
                        clipboard.get('image_file') or
                        raw_clipboard.get('image_file') or
                        clipboard.get('file_path') or
                        raw_clipboard.get('file_path') or
                        None
                    )
                    if image_file_path:
                        image_file_path = Path(image_file_path)
                
                    # If we found an image file, perform OCR
                    if image_file_path:
                        if image_file_path.exists():
                            logger.info(f"Processing image file for OCR: {image_file_path}")
                            # Extract OCR text from image
                            ocr_text = self.deep_analysis.ocr_processor.extract_text(image_file_path)
                            if ocr_text and ocr_text.strip():
                                logger.info(f"OCR extracted {len(ocr_text)} characters from image: {ocr_text[:100]}...")
                                # Use OCR text as text_content for scanning
                                text_content = ocr_text
                            else:
                                logger.debug(f"No text extracted from image via OCR: {image_file_path}")
                                # No text in image - but still process for behavioral rules (paste to Zalo is risky)
                                # Don't return True here - let it continue to check behavioral rules
                                text_content = ""  # Empty but continue processing
                        else:
                            logger.warning(f"Image file path does not exist: {image_file_path}")
                            # File doesn't exist - skip OCR but continue for behavioral rules
                            text_content = ""
                
                # If still no text content and not FileList/Image, skip
                if not text_content and content_type not in ['filelist', 'image', 'bitmap', '']:
                    logger.warning(
                        f"Clipboard event has no text content and is not FileList/Image. "
                        f"content_type={content_type}, "
                        f"Available fields: clipboard.keys()={list(clipboard.keys()) if clipboard else []}"
                    )
                    # Still continue for behavioral rules check (FileList paste to Zalo is risky even without OCR)
                    if content_type != 'filelist':
                        return True
            
            # Log processing info
            if text_content:
                logger.info(f"Processing clipboard event: {len(text_content)} characters")
                logger.debug(f"Clipboard text sample: {text_content[:200]}")
            else:
                # Check if this is FileList with images (OCR may have failed or no text in image)
                content_type_check = (
                    clipboard.get('content_type') or
                    raw_clipboard.get('content_type') or
                    ''
                ).lower()
                file_list_check = clipboard.get('file_list') or raw_clipboard.get('file_list') or []
                if content_type_check == 'filelist' and file_list_check:
                    logger.info(f"Processing clipboard FileList event (may contain images): {len(file_list_check)} file(s)")
                else:
                    logger.info(f"Processing clipboard event with no text content (content_type={content_type_check})")
            
            # 1. Check Panic Mode
            panic_mode = self.queue_consumer.check_panic_mode()
            if event.get('system', {}).get('panic_mode', False):
                panic_mode = True
            
            if fast_scan_result is None:
                fast_scan_result = {'yara_matches': [], 'is_suspicious': False}
                
            # 2. Fast Scan text content with YARA (even if empty, for FileList we still check behavioral rules)
            logger.debug("Starting YARA scan on clipboard content...")
            if text_content:
                text_scan_res = self.fast_scan.scan_text_content(text_content, panic_mode)
                fast_scan_result = self._merge_fast_scan(fast_scan_result, text_scan_res)
            
            # Log YARA scan results
            yara_matches = fast_scan_result.get('yara_matches', [])
            if yara_matches:
                logger.info(f"YARA matches found: {len(yara_matches)} rules matched")
                for match in yara_matches:
                    logger.info(f"  - Rule: {match.get('rule')}, Tags: {match.get('tags')}")
            else:
                logger.debug("No YARA matches in clipboard content")
            
            # 3. Deep Analysis (nếu có YARA match và không panic mode)
            deep_analysis_result = {'is_sensitive': False}
            if fast_scan_result.get('is_suspicious', False) and not panic_mode:
                # Có thể thêm ML classification cho text nếu cần
                deep_analysis_result = {'is_sensitive': True}

            nlp_user = (event.get('context', {}) or {}).get('user') or event.get('actor', {}).get('user', 'unknown')
            nlp_result = self._run_nlp_content_analysis(event, user=nlp_user, fallback_text=text_content)
            self._merge_nlp_into_detection(nlp_result, fast_scan_result, deep_analysis_result)
            
            # 3.5. Behavioral Rules Check (theo Noteupdate.txt)
            # Check behavioral rules cho clipboard events
            behavioral_matches = self.behavioral_rules.check_all(event, fast_scan_result)
            
            # Nếu có behavioral rule match, tăng risk score
            behavioral_risk_boost = 0
            behavioral_details = {}
            if behavioral_matches:
                highest_match = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest_match:
                    # Tăng risk score dựa trên severity
                    severity_boost = WorkerConfig.BEHAVIORAL_RISK_BOOST
                    behavioral_risk_boost = severity_boost.get(highest_match.get('severity', 'low'), 0)
                    behavioral_details = {
                        'behavioral_rule_matched': highest_match.get('rule'),
                        'behavioral_reason': highest_match.get('reason', ''),
                        'behavioral_severity': highest_match.get('severity'),
                        'all_behavioral_matches': behavioral_matches
                    }
                    logger.warning(
                        f"Behavioral Rule Matched (Clipboard): {highest_match.get('rule')} - "
                        f"{highest_match.get('reason', '')} (+{behavioral_risk_boost} risk boost)"
                    )
            
            # 3.6. UEBA ML Anomaly Detection cho clipboard (context-based & transformation cases)
            ml_anomaly_result = {'anomaly_score': 0.0, 'is_anomaly': False}
            if self.ml_analyzer.is_available():
                try:
                    recent_history = self.event_history[-150:] if len(self.event_history) > 150 else self.event_history
                    ml_anomaly_result = self.ml_analyzer.predict(event, event_history=recent_history)
                    if ml_anomaly_result.get('is_anomaly', False):
                        anomaly_score = ml_anomaly_result.get('anomaly_score', 0.0)
                        reasons = (
                            (ml_anomaly_result.get("profile_reasons") or [])
                            + (ml_anomaly_result.get("baseline_reasons") or [])
                        )
                        logger.warning(
                            f"UEBA Anomaly Detected (Clipboard): score={anomaly_score:.2f} "
                            f"reasons={reasons}"
                        )
                except Exception as e:
                    logger.error(f"Error in ML anomaly detection (clipboard): {e}")
            try:
                ml_score_0_10 = float(ml_anomaly_result.get('anomaly_score') or 0.0)
                deep_analysis_result['ml_anomaly_score'] = ml_score_0_10
                deep_analysis_result['ml_is_anomaly'] = bool(ml_anomaly_result.get('is_anomaly', False))
                deep_analysis_result['anomaly_score'] = max(-1.0, min(1.0, (ml_score_0_10 / 5.0) - 1.0))
            except Exception:
                pass

            # 4. Risk Scoring với context đặc biệt cho clipboard
            # BUG FIX: Không redeclare raw_clipboard (đã khai báo ở line ~1265) để tránh variable shadowing
            ctx = event.get('context', {}) or {}
            raw_ctx = raw_original.get('context', {}) or {}
            operation = event.get('operation', {}) or {}
            
            window_title = (
                ctx.get('window_title') or                    
                raw_ctx.get('window_title') or                
                clipboard.get('active_window_title') or
                raw_clipboard.get('active_window_title') or    
                raw_clipboard.get('active_window_context') or 
                ''
            ).lower()
            
            # Check sensitive apps
            sensitive_apps = ['gpt', 'chatgpt', 'discord', 'zalo', 'telegram', 'whatsapp', 'messenger']
            is_sensitive_app = any(app in window_title for app in sensitive_apps)
            
            # Check clipboard_paste
            op_type = operation.get('op_type', '').lower()
            is_clipboard_paste = 'paste' in op_type or 'clipboard_paste' in event.get('type', '').lower()
            
            # Get domain from clipboard data
            domain = (
                clipboard.get('dest_domain') or
                raw_clipboard.get('dest_domain') or
                ''
            ).lower()
            
            event_context = {
                'action_type': operation.get('op_type') or event.get('type', 'clipboard'),
                'destination': '',  # Clipboard không có destination
                'user': ctx.get('user') or event.get('actor', {}).get('user', 'unknown'),
                'time': event.get('ts') or event.get('timestamp', ''),
                'location': 'clipboard',  # Clipboard location
                'file_size_mb': 0,
                'process_name': ctx.get('fg_app') or operation.get('tool'),
                'active_window': window_title,
                'window_title': window_title,
                'domain': domain,  # Domain for context scoring
                'event_id': event.get('event_id'),
                'source': event.get('source', 'clipboard'),
                'severity': event.get('severity'),
                'extension': '',
                'is_clipboard_paste': is_clipboard_paste,
                'is_sensitive_app': is_sensitive_app,
                'text_content': text_content[:100],  # Sample for logging
                # Behavioral rules context
                'behavioral_risk_boost': behavioral_risk_boost,
                'behavioral_details': behavioral_details,
                'ml_anomaly_score': ml_anomaly_result.get('anomaly_score', 0.0),
                'ml_is_anomaly': ml_anomaly_result.get('is_anomaly', False),
                # Event data for risk scoring (IOC hits, etc.)
                '_event_data': event
            }
            
            risk_result = self.risk_scoring.calculate_score(
                fast_scan_result,
                deep_analysis_result,
                event_context
            )
            
            # Apply behavioral risk boost
            if behavioral_risk_boost > 0:
                risk_result['total_score'] = min(10.0, risk_result['total_score'] + behavioral_risk_boost)
                if "cvss_score" in risk_result:
                    risk_result["cvss_score"] = round(min(10.0, risk_result["total_score"]), 2)
                risk_result['details']['behavioral'] = behavioral_details
                # Nếu behavioral rule match + high severity → force alert/block
                highest_match = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest_match and highest_match.get('severity') == 'high':
                    # Alert-only system: never force block
                    if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert']:
                        risk_result['action'] = 'alert'

            self._apply_filename_risk_policy(event, risk_result)
            self._apply_nlp_risk_policy(risk_result, nlp_result)

            # Demo-friendly clipboard policy:
            # Pasting normal text to ChatGPT/Discord/Zalo/etc. should be allowed.
            # Only alert when the clipboard content itself has strong sensitive evidence.
            obj = event.get('object', {}) or {}
            sensitivity_label = str(
                obj.get('sensitivity')
                or event.get('File_Sensitivity')
                or ''
            ).strip().lower()
            has_sensitive_label = sensitivity_label in {
                'sensitive',
                'highly sensitive',
                'confidential',
                'secret',
            }
            has_clipboard_sensitive_evidence = bool(
                yara_matches
                or event.get('ioc_hits')
                or has_sensitive_label
                or deep_analysis_result.get('is_sensitive')
            )
            if is_clipboard_paste and not has_clipboard_sensitive_evidence:
                previous_score = float(risk_result.get('total_score') or 0.0)
                capped_score = min(previous_score, 3.9)
                risk_result['total_score'] = round(capped_score, 2)
                risk_result['cvss_score'] = round(capped_score, 2)
                risk_result['risk_level'] = 'low'
                risk_result['action'] = 'log'
                risk_result.setdefault('details', {})['clipboard_non_sensitive_allowed'] = {
                    'previous_score': round(previous_score, 2),
                    'cap': 3.9,
                    'reason': 'clipboard_paste_without_sensitive_content_evidence',
                }
                logger.info(
                    f"[PID={pid}] Clipboard paste allowed as non-sensitive: "
                    f"event_id={event.get('event_id', 'unknown')}, "
                    f"previous_score={previous_score:.1f}, capped_score={capped_score:.1f}, "
                    f"window_title={window_title[:50]}"
                )
            elif is_clipboard_paste and yara_matches:
                highly_sensitive_keywords = ('id', 'cmnd', 'cccd', 'credit', 'card', 'api', 'key', 'secret')
                min_score = float(getattr(WorkerConfig, 'CLIPBOARD_YARA_MIN_ALERT_SCORE', 7.2))
                if any(
                    any(
                        keyword in str(match.get('rule', '') if isinstance(match, dict) else match).lower()
                        for keyword in highly_sensitive_keywords
                    )
                    for match in yara_matches
                ):
                    min_score = float(getattr(WorkerConfig, 'CLIPBOARD_HIGHLY_SENSITIVE_MIN_ALERT_SCORE', 8.4))
                if float(risk_result.get('total_score') or 0.0) < min_score:
                    risk_result['total_score'] = round(min_score, 2)
                    risk_result['cvss_score'] = round(min_score, 2)
                    risk_result['risk_level'] = 'high'
                    risk_result['action'] = 'alert'
                    risk_result.setdefault('details', {})['clipboard_yara_min_score_applied'] = {
                        'min_score': round(min_score, 2),
                        'yara_matches': len(yara_matches),
                    }
            
            # 5. Generate Report Fields
            # Tạo dummy file_path cho report (vì clipboard không có file)
            dummy_path = Path("clipboard://clipboard_content")
            report = self.report_generator.generate_report(
                event,
                fast_scan_result,
                deep_analysis_result,
                risk_result,
                dummy_path
            )
            
            # 6. Action Executor
            action = risk_result['action']
            event_id = event.get('event_id', 'unknown')
            pid = os.getpid()
            
            logger.info(
                f"[PID={pid}] Clipboard processing complete: "
                f"event_id={event_id}, action={action.upper()}, "
                f"score={risk_result['total_score']:.1f}, "
                f"yara_matches={len(yara_matches)}, "
                f"behavioral_matches={len(behavioral_matches)}, "
                f"window_title={window_title[:50]}"
            )
            
            self.action_executor.execute(
                action,
                dummy_path,
                risk_result['total_score'],
                risk_result['details'],
                event_context,
                report
            )
            
            self._save_processed_event(event, risk_result, fast_scan_result, behavioral_matches)

            # BUG FIX: Clipboard events cũng cần vào event_history để ML/UEBA có context
            self.event_history.append(event.copy())
            if len(self.event_history) > self.max_history_size:
                self.event_history.pop(0)

            self.processed_count += 1

            logger.info(
                f"[PID={pid}] Processed Clipboard: "
                f"event_id={event_id}, {len(text_content)} chars | "
                f"Score: {risk_result['total_score']:.1f} | "
                f"Action: {action.upper()} | "
                f"App: {window_title[:30]} | "
                f"YARA: {len(fast_scan_result.get('yara_matches', []))}"
            )

            return True
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing clipboard event: {e}", exc_info=True)
            return False
    
    def _process_screenshot_event(self, event: dict) -> bool:
        """
        Xử lý screenshot event từ clipboard_sensor:
        1. OCR ảnh chụp màn hình
        2. YARA scan trên text vừa OCR
        3. Risk Scoring & Action
        4. Dọn file ảnh sau scan (nếu được cấu hình)
        """
        try:
            event_id = event.get('event_id', 'unknown')
            pid = os.getpid()
            logger.info(f"[PID={pid}] Processing screenshot event: event_id={event_id}")

            raw_original = event.get('raw_original') or {}
            file_path_str = (
                event.get('file_path') or
                (event.get('screenshot') or {}).get('file_path') or
                (event.get('object') or {}).get('path') or
                raw_original.get('file_path') or
                (raw_original.get('screenshot') or {}).get('file_path') or
                ''
            )
            if not file_path_str:
                logger.warning(f"[PID={pid}] Screenshot event has no file_path: event_id={event_id}")
                return True

            file_path = Path(file_path_str)
            if not file_path.exists():
                logger.warning(f"[PID={pid}] Screenshot file not found: {file_path}")
                return True

            # Check file size
            size_bytes = file_path.stat().st_size
            file_size_mb = size_bytes / (1024 * 1024)
            if file_size_mb > WorkerConfig.OCR_MAX_FILE_SIZE_MB:
                logger.debug(f"[PID={pid}] Screenshot too large for OCR: {file_size_mb:.2f}MB")
                return True

            panic_mode = self.queue_consumer.check_panic_mode()

            # 1. OCR: trích xuất text từ ảnh
            ocr_text = ""
            if not panic_mode:
                logger.info(f"[PID={pid}] Running OCR on screenshot: {file_path.name}")
                extracted = self.deep_analysis.ocr_processor.extract_text(file_path)
                if extracted:
                    ocr_text = extracted.strip()
                    logger.info(
                        f"[PID={pid}] OCR extracted {len(ocr_text)} chars "
                        f"from screenshot: {ocr_text[:100]!r}"
                    )
                else:
                    logger.debug(f"[PID={pid}] OCR returned no text for {file_path.name}")

            # 2. YARA scan trên text vừa OCR
            if ocr_text:
                fast_scan_result = self.fast_scan.scan_text_content(ocr_text, panic_mode)
            else:
                fast_scan_result = {'yara_matches': [], 'is_suspicious': False}

            yara_matches = fast_scan_result.get('yara_matches', [])
            if yara_matches:
                logger.warning(
                    f"[PID={pid}] Screenshot YARA matches ({len(yara_matches)}): "
                    + ", ".join(m.get('rule', '?') for m in yara_matches)
                )

            # 3. Deep analysis hint
            deep_analysis_result = {
                'is_sensitive': bool(yara_matches),
                'ocr_text': ocr_text or None,
            }
            nlp_user = (event.get('context', {}) or {}).get('user') or event.get('actor', {}).get('user', 'unknown')
            nlp_result = self._run_nlp_content_analysis(event, user=nlp_user, fallback_text=ocr_text)
            self._merge_nlp_into_detection(nlp_result, fast_scan_result, deep_analysis_result)

            # Behavioral rules
            behavioral_matches = self.behavioral_rules.check_all(event, fast_scan_result)
            behavioral_risk_boost = 0
            behavioral_details = {}
            if behavioral_matches:
                highest_match = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest_match:
                    severity_boost = WorkerConfig.BEHAVIORAL_RISK_BOOST
                    behavioral_risk_boost = severity_boost.get(highest_match.get('severity', 'low'), 0)
                    behavioral_details = {
                        'behavioral_rule_matched': highest_match.get('rule'),
                        'behavioral_reason': highest_match.get('reason', ''),
                        'behavioral_severity': highest_match.get('severity'),
                    }

            # UEBA
            ml_anomaly_result = {'anomaly_score': 0.0, 'is_anomaly': False}
            if self.ml_analyzer.is_available():
                try:
                    ml_anomaly_result = self.ml_analyzer.predict(
                        event, event_history=self.event_history[-100:]
                    )
                except Exception as _e:
                    logger.debug(f"ML anomaly error (screenshot): {_e}")
            try:
                ml_score_0_10 = float(ml_anomaly_result.get('anomaly_score') or 0.0)
                deep_analysis_result['ml_anomaly_score'] = ml_score_0_10
                deep_analysis_result['ml_is_anomaly'] = bool(ml_anomaly_result.get('is_anomaly', False))
                deep_analysis_result['anomaly_score'] = max(-1.0, min(1.0, (ml_score_0_10 / 5.0) - 1.0))
            except Exception:
                pass

            # 4. Risk Scoring
            ctx = event.get('context', {}) or {}
            screenshot_meta = event.get('screenshot', {}) or {}
            source_hint = screenshot_meta.get('source', 'screenshot')
            event_context = {
                'action_type': 'screenshot',
                'destination': '',
                'user': ctx.get('user') or event.get('actor', {}).get('user', 'unknown'),
                'time': event.get('ts') or event.get('timestamp', ''),
                'location': str(file_path.parent),
                'file_size_mb': file_size_mb,
                'process_name': ctx.get('fg_app') or (event.get('operation') or {}).get('tool', ''),
                'active_window': ctx.get('window_title', ''),
                'source': source_hint,
                'event_id': event_id,
                'severity': event.get('severity'),
                'extension': '.png',
                'behavioral_risk_boost': behavioral_risk_boost,
                'behavioral_details': behavioral_details,
                'ml_anomaly_score': ml_anomaly_result.get('anomaly_score', 0.0),
                'ml_is_anomaly': ml_anomaly_result.get('is_anomaly', False),
                'text_content': ocr_text[:100] if ocr_text else '',
                '_event_data': event,
            }

            risk_result = self.risk_scoring.calculate_score(
                fast_scan_result, deep_analysis_result, event_context
            )

            if behavioral_risk_boost > 0:
                risk_result['total_score'] = min(10.0, risk_result['total_score'] + behavioral_risk_boost)
                if 'cvss_score' in risk_result:
                    risk_result['cvss_score'] = round(min(10.0, risk_result['total_score']), 2)
                risk_result['details']['behavioral'] = behavioral_details
            self._apply_nlp_risk_policy(risk_result, nlp_result)

            # Screenshot YARA minimum score enforcement
            # Yêu cầu TỐI THIỂU 2 rule match để tránh spam alert (1 rule đơn lẻ bỏ qua)
            if len(yara_matches) >= 2:
                _highly_sensitive_rules = {
                    'credit', 'card', 'vietnam_id', 'cccd', 'cmnd', 'id_single',
                    'api_key', 'bank_account', 'screenshot_confidential'
                }
                _is_highly_sensitive = any(
                    any(kw in m.get('rule', '').lower() for kw in _highly_sensitive_rules)
                    for m in yara_matches
                )
                _min_score = (
                    WorkerConfig.SCREENSHOT_YARA_HIGHLY_SENSITIVE_MIN_SCORE
                    if _is_highly_sensitive
                    else WorkerConfig.SCREENSHOT_YARA_MIN_SCORE
                )
                if risk_result['total_score'] < _min_score:
                    logger.info(
                        f"[PID={pid}] Screenshot score boosted: "
                        f"{risk_result['total_score']:.1f} → {_min_score} "
                        f"({'highly_sensitive' if _is_highly_sensitive else 'standard'} YARA match, "
                        f"{len(yara_matches)} rules)"
                    )
                    risk_result['total_score'] = _min_score
                    risk_result['action'] = 'alert'
                    if 'cvss_score' in risk_result:
                        risk_result['cvss_score'] = round(_min_score, 2)

            # 5. Report & Action
            dummy_path = Path(f"screenshot://{file_path.name}")
            report = self.report_generator.generate_report(
                event, fast_scan_result, deep_analysis_result, risk_result, dummy_path
            )

            action = risk_result['action']
            self.action_executor.execute(
                action, file_path, risk_result['total_score'],
                risk_result['details'], event_context, report
            )

            self._save_processed_event(event, risk_result, fast_scan_result, behavioral_matches)

            self.processed_count += 1

            logger.info(
                f"[PID={pid}] Processed Screenshot: {file_path.name} | "
                f"OCR chars={len(ocr_text)} | "
                f"Score={risk_result['total_score']:.1f} | "
                f"Action={action.upper()} | "
                f"YARA={len(yara_matches)}"
            )

            # 6. Dọn file ảnh sau khi scan
            if getattr(WorkerConfig, 'SCREENSHOT_CLEANUP_AFTER_SCAN', True):
                try:
                    file_path.unlink()
                    logger.debug(f"[PID={pid}] Deleted screenshot file: {file_path}")
                except FileNotFoundError:
                    pass  # Already deleted
                except Exception as _del_err:
                    logger.warning(f"[PID={pid}] Failed to delete screenshot: {_del_err}")

            self.event_history.append(event.copy())
            if len(self.event_history) > self.max_history_size:
                self.event_history.pop(0)

            return True

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing screenshot event: {e}", exc_info=True)
            return False

    def _process_special_event(self, event: dict) -> bool:
        """
        Xử lý các event đặc biệt không có file path:
        proc_start, proc_end, usb_connected/mounted/unmounted, print_job,
        và các network events (http_upload, network_flow, v.v.)
        Lưu ý: corr_* events đã bị skip sớm tại process_event(), không vào đây.
        """
        try:
            event_id = event.get('event_id', 'unknown')
            event_type = event.get('type') or event.get('event_type', 'unknown')
            pid = os.getpid()
            
            logger.info(f"[PID={pid}] Processing special event: event_id={event_id}, type={event_type}")
            
            # Dummy scan results (no file)
            fast_scan_result = {'yara_matches': [], 'is_suspicious': False}
            deep_analysis_result = {'is_sensitive': False}
            
            # 1. Behavioral Rules Check
            behavioral_matches = self.behavioral_rules.check_all(event, fast_scan_result)
            
            behavioral_risk_boost = 0
            behavioral_details = {}
            if behavioral_matches:
                highest_match = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest_match:
                    severity_boost = WorkerConfig.BEHAVIORAL_RISK_BOOST
                    behavioral_risk_boost = severity_boost.get(highest_match.get('severity', 'low'), 0)
                    behavioral_details = {
                        'behavioral_rule_matched': highest_match.get('rule'),
                        'behavioral_reason': highest_match.get('reason', ''),
                        'behavioral_severity': highest_match.get('severity'),
                        'all_behavioral_matches': behavioral_matches
                    }
                    logger.warning(
                        f"Behavioral Rule Matched (Special Event): {highest_match.get('rule')} - "
                        f"{highest_match.get('reason', '')} (+{behavioral_risk_boost} risk boost)"
                    )
            
            # 1.5. UEBA ML Anomaly Detection
            ml_anomaly_result = {'anomaly_score': 0.0, 'is_anomaly': False}
            if self.ml_analyzer.is_available():
                try:
                    recent_history = self.event_history[-100:] if len(self.event_history) > 100 else self.event_history
                    ml_anomaly_result = self.ml_analyzer.predict(event, event_history=recent_history)
                    
                    if ml_anomaly_result.get('is_anomaly', False):
                        anomaly_score = ml_anomaly_result.get('anomaly_score', 0.0)
                        logger.warning(
                            f"UEBA Anomaly Detected (Special Event): score={anomaly_score:.2f}"
                        )
                except Exception as e:
                    logger.error(f"Error in ML anomaly detection (special event): {e}")
            try:
                ml_score_0_10 = float(ml_anomaly_result.get('anomaly_score') or 0.0)
                deep_analysis_result['ml_anomaly_score'] = ml_score_0_10
                deep_analysis_result['ml_is_anomaly'] = bool(ml_anomaly_result.get('is_anomaly', False))
                deep_analysis_result['anomaly_score'] = max(-1.0, min(1.0, (ml_score_0_10 / 5.0) - 1.0))
            except Exception:
                pass
            
            # 2. Risk Scoring
            ctx = event.get('context', {}) or {}
            operation = event.get('operation', {}) or {}
            
            event_context = {
                'action_type': operation.get('op_type') or event_type,
                'destination': event.get('object', {}).get('dst_path') or '',
                'user': ctx.get('user') or event.get('actor', {}).get('user', 'unknown'),
                'time': event.get('ts') or event.get('timestamp', ''),
                'location': 'special_event',
                'file_size_mb': 0,
                'process_name': ctx.get('fg_app') or event.get('process', {}).get('name') or operation.get('tool') or '',
                'active_window': ctx.get('window_title') or '',
                'domain': '',
                'event_id': event_id,
                'source': event.get('source', 'unknown'),
                'severity': event.get('severity'),
                'behavioral_risk_boost': behavioral_risk_boost,
                'behavioral_details': behavioral_details,
                'ml_anomaly_score': ml_anomaly_result.get('anomaly_score', 0.0),
                'ml_is_anomaly': ml_anomaly_result.get('is_anomaly', False),
                '_event_data': event
            }
            
            risk_result = self.risk_scoring.calculate_score(
                fast_scan_result,
                deep_analysis_result,
                event_context
            )
            
            # Apply behavioral risk boost
            if behavioral_risk_boost > 0:
                risk_result['total_score'] = min(10.0, risk_result['total_score'] + behavioral_risk_boost)
                if "cvss_score" in risk_result:
                    risk_result["cvss_score"] = round(min(10.0, risk_result["total_score"]), 2)
                risk_result['details']['behavioral'] = behavioral_details
                
                highest_match = self.behavioral_rules.get_highest_severity_match(behavioral_matches)
                if highest_match and highest_match.get('severity') == 'high':
                    if risk_result['total_score'] >= WorkerConfig.RISK_THRESHOLDS['alert']:
                        risk_result['action'] = 'alert'
                        
            # Dedup alert theo event_id để tránh double-alert khi cùng event bị process nhiều lần
            if risk_result.get('action') == 'alert':
                _dedup_key = f"special_alert:{event_id}"
                _now_ts = time.time()
                _last_alert = self._alert_dedup.get(_dedup_key)
                if _last_alert is not None and (_now_ts - _last_alert) < 30.0:
                    logger.warning(
                        f"[PID={pid}] Dedup special alert suppressed (within 30s): event_id={event_id}, type={event_type}"
                    )
                    risk_result['action'] = 'log'
                else:
                    self._alert_dedup[_dedup_key] = _now_ts

            self._apply_filename_risk_policy(event, risk_result)
            
            # 3. Generate Report Fields
            dummy_path = Path(f"special_event://{event_type}")
            report = self.report_generator.generate_report(
                event,
                fast_scan_result,
                deep_analysis_result,
                risk_result,
                dummy_path
            )
            
            # 4. Action Executor
            action = risk_result['action']
            
            self.action_executor.execute(
                action,
                dummy_path,
                risk_result['total_score'],
                risk_result['details'],
                event_context,
                report
            )
            
            # Update Event History for ML
            self.event_history.append(event.copy())
            if len(self.event_history) > self.max_history_size:
                self.event_history.pop(0)  # Remove oldest event
            
            self._save_processed_event(event, risk_result, fast_scan_result, behavioral_matches)
            
            self.processed_count += 1
            
            logger.info(
                f"[PID={pid}] Processed Special Event: "
                f"event_id={event_id}, type={event_type} | "
                f"Score: {risk_result['total_score']:.1f} | "
                f"Action: {action.upper()}"
            )
            
            return True
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing special event: {e}", exc_info=True)
            return False

    def run(self):
        """Main loop"""
        self.running = True
        logger.info("=" * 60)
        logger.info("Detection Engine running...")
        logger.info("=" * 60)
        
        # Cleanup cache on startup
        try:
            self.hash_cache.cleanup_old_entries()
        except Exception as e:
            logger.warning(f"Error cleaning cache: {e}")
        
        # Print stats
        cache_stats = self.hash_cache.get_cache_stats()
        logger.info(f"Cache stats: {cache_stats}")
        
        last_stats_time = time.time()
        
        while self.running:
            try:
                # Get event from queue
                event = self.queue_consumer.get_event(timeout=1)
                
                if event:
                    # Log event being processed
                    event_id = event.get('event_id', 'unknown')
                    event_type = event.get('type') or event.get('event_type', 'unknown')
                    logger.info(
                        f"[PID={os.getpid()}] Received event: "
                        f"event_id={event_id}, type={event_type}, "
                        f"source={event.get('source', 'unknown')}"
                    )
                    qid = event.get("_queue_id")
                    try:
                        self.process_event(event)
                    except Exception as proc_err:
                        self.error_count += 1
                        logger.error(f"process_event failed: {proc_err}", exc_info=True)
                        if hasattr(self.queue_consumer, "fail") and qid is not None:
                            try:
                                self.queue_consumer.fail(qid, str(proc_err))
                            except Exception:
                                pass
                        time.sleep(0.2)
                        continue
                    if hasattr(self.queue_consumer, "ack") and qid is not None:
                        try:
                            self.queue_consumer.ack(qid)
                        except Exception as e:
                            logger.warning(f"ack queue id={qid} failed: {e}")
                else:
                    # get_event đã chờ timeout; sleep ngắn tránh busy-spin nếu backend khác
                    time.sleep(0.02)
                
                # Print stats every 60 seconds
                if time.time() - last_stats_time > 60:
                    queue_stats = self.queue_consumer.get_stats()
                    logger.info(
                        f"Stats: Processed={self.processed_count}, "
                        f"Errors={self.error_count}, "
                        f"Queue={queue_stats['queue_size']}, "
                        f"PanicMode={queue_stats['panic_mode']}"
                    )
                    last_stats_time = time.time()
                    
            except KeyboardInterrupt:
                logger.info("Shutdown requested")
                break
            except Exception as e:
                self.error_count += 1
                logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(1)  # Wait before retry
        
        logger.info("Detection Engine stopped")
        logger.info(f"Final stats: Processed={self.processed_count}, Errors={self.error_count}")
    
    def stop(self):
        """Stop detection engine"""
        self.running = False


def setup_logging():
    """Setup logging"""
    WorkerConfig.ensure_directories()
    
    # Remove default handler
    logger.remove()
    
    # Add file handler
    logger.add(
        WorkerConfig.LOG_FILE,
        rotation=WorkerConfig.LOG_ROTATION,
        retention=WorkerConfig.LOG_RETENTION,
        level=WorkerConfig.LOG_LEVEL,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}"
    )
    
    # Add console handler
    logger.add(
        sys.stderr,
        level=WorkerConfig.LOG_LEVEL,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    )


def signal_handler(sig, frame):
    """Handle shutdown signals"""
    logger.info("Shutdown signal received")
    sys.exit(0)


def main():
    """Main entry point"""
    setup_logging()
    
    logger.info("=" * 60)
    logger.info("Detection Engine Starting...")
    logger.info("=" * 60)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    engine: Optional["DetectionEngine"] = None
    try:
        engine = DetectionEngine()
        engine.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        raise
    finally:
        if engine is not None:
            qc = getattr(engine, "queue_consumer", None)
            if qc is not None and hasattr(qc, "flush_state"):
                try:
                    qc.flush_state()
                except Exception:
                    pass
        logger.info("Detection Engine stopped")


if __name__ == "__main__":
    main()
