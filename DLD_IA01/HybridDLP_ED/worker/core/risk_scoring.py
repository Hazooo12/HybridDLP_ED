"""
Risk Scoring Engine - Tính toán Risk Score tổng hợp
"""
import re
import math
from datetime import datetime
from typing import Dict, Any, Optional
from loguru import logger
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def _clamp_0_10(v: float) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return 0.0
    return min(10.0, max(0.0, x))


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def normalize_anomaly_score(raw_value: Any) -> float:
    """
    Normalize anomaly signal to [0,10] using configurable policy.
    """
    x = _safe_float(raw_value, 0.0)
    method = (WorkerConfig.ML_ANOMALY_NORM_METHOD or "percentile").lower()
    if method == "minmax":
        lo = WorkerConfig.ML_ANOMALY_MIN
        hi = WorkerConfig.ML_ANOMALY_MAX
    else:
        lo = WorkerConfig.ML_ANOMALY_P5
        hi = WorkerConfig.ML_ANOMALY_P95
    if hi <= lo:
        lo, hi = -1.0, 1.0
    xc = min(max(x, lo), hi)
    return _clamp_0_10(10.0 * (xc - lo) / (hi - lo))


def total_score_to_cvss10(total_score: float) -> float:
    """Điểm tổng đã là thang 0–10 (đồng nhất CVSS Base)."""
    try:
        s = float(total_score)
    except (TypeError, ValueError):
        return 0.0
    return round(min(10.0, max(0.0, s)), 1)


def classify_risk_level(total_score: float) -> str:
    """
    Ánh xạ điểm tổng 0–10 theo CVSS v3 Severity:
    None (0), Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9), Critical (9.0–10.0).
    """
    try:
        s = float(total_score)
    except (TypeError, ValueError):
        return "none"
    s = _clamp_0_10(s)
    if s <= 0.0:
        return "none"
    if s < 4.0:
        return "low"
    if s < 7.0:
        return "medium"
    if s < 9.0:
        return "high"
    return "critical"


class RiskScoringEngine:
    """Tính toán Risk Score"""
    
    def __init__(self):
        self.weights = WorkerConfig.RISK_WEIGHTS
        self.thresholds = WorkerConfig.RISK_THRESHOLDS
        self.method = WorkerConfig.RISK_SCORING_METHOD
        self.research_engine = ResearchBasedRiskScoringEngine() if self.method == 'research_based' else None
        self.nist_engine = NISTBasedRiskScoringEngine() if self.method == 'nist_based' else None
        self._debug = getattr(WorkerConfig, "DEBUG", False)
        logger.info(
            "Risk policy loaded: method=%s, composite=%s, alert_threshold=%s (thang 0–10)",
            self.method,
            WorkerConfig.RISK_COMPOSITE_MODEL,
            self.thresholds.get("alert"),
        )
    
    def _dbg(self, *args) -> None:
        if self._debug:
            try:
                print("[RiskScoringEngine]", *args)
            except Exception:
                pass
    
    def calculate_score(self, 
                       fast_scan_result: Dict[str, Any],
                       deep_analysis_result: Dict[str, Any],
                       event_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tính Risk Score tổng hợp
        
        Args:
            fast_scan_result: Kết quả từ Fast Scan
            deep_analysis_result: Kết quả từ Deep Analysis
            event_context: Context (user, time, location, action) - may contain event data
        
        Returns:
            {
                'total_score': 75.5,
                'content_score': 50,
                'behavior_score': 20,
                'context_score': 10,
                'action': 'block',  # block, alert, log
                'details': {...}
            }
        """
        # Hard-coded rule override: Screenshot/Browser paste >= 10 times
        # Event data nằm trong _event_data (worker.py _process_special_event line 1510)
        event_data = event_context.get("_event_data", {})
        debug_info = event_data.get("debug", {})
        hardcoded_rule = debug_info.get("hardcoded_rule", False)
        hardcoded_risk = debug_info.get("hardcoded_risk_score")
        
        if hardcoded_rule and hardcoded_risk is not None:
            hardcoded_score = float(hardcoded_risk)
            self._dbg(f"[HardCode Rule Override] Risk score forced to {hardcoded_score}")
            evidence = debug_info.get("evidence", {})
            return {
                'total_score': round(hardcoded_score, 2),
                'cvss_score': round(hardcoded_score, 1),
                'content_score': 0,
                'behavior_score': 0,
                'context_score': 0,
                'action': 'alert',
                'risk_level': 'critical',
                'details': {
                    'hardcoded_rule': True,
                    'rule_description': evidence.get("rule_description", ""),
                    'screenshot_count': evidence.get("screenshot_count", 0),
                    'browser_paste_count': evidence.get("browser_paste_count", 0),
                    'user': evidence.get("user", "unknown"),
                },
                'method': 'hardcoded_override',
            }
        
        # CVSS-inspired DLP (Noteupdate.txt)
        if str(self.method).lower() == 'cvss_dlp':
            from core.cvss_dlp_orchestrator import CVSSDLPScoringEngine

            if getattr(self, '_cvss_dlp_engine', None) is None:
                self._cvss_dlp_engine = CVSSDLPScoringEngine()
            return self._cvss_dlp_engine.calculate_score(
                fast_scan_result,
                deep_analysis_result,
                event_context,
            )

        # Use research-based method if configured
        if self.method == 'research_based' and self.research_engine:
            return self.research_engine.calculate_score(
                fast_scan_result,
                deep_analysis_result,
                event_context
            )
        
        # Use NIST-based method if configured
        if self.method == 'nist_based' and self.nist_engine:
            return self.nist_engine.calculate_score(
                fast_scan_result,
                deep_analysis_result,
                event_context
            )
        
        # Otherwise use traditional method
        scores = {
            'content_score': 0,
            'behavior_score': 0,
            'context_score': 0
        }
        
        details = {}
        
        # Get event data from context if available (for IOC hits)
        event_data = event_context.get('_event_data', {})
        
        # 1) Content Score = Impact proxy (Sc in [0,10])
        content_score = self._calculate_content_score(
            fast_scan_result, 
            deep_analysis_result,
            event_data
        )
        scores['content_score'] = _clamp_0_10(content_score)
        details['content'] = {
            'yara_matches': len(fast_scan_result.get('yara_matches', [])),
            'encrypted_zip': fast_scan_result.get('is_encrypted_zip', False),
            'ml_sensitive': deep_analysis_result.get('is_sensitive', False)
        }
        
        # 2) Behavior Score (Sb): blend action risk + anomaly
        # Sb = min(10, S_action + beta * S_anomaly)
        behavior_base = self._calculate_behavior_score(event_context)
        ml_anomaly = _safe_float(event_context.get("ml_anomaly_score"), 0.0)
        if ml_anomaly <= 1.0 and _safe_float(deep_analysis_result.get("anomaly_score"), 0.0) != 0.0:
            # Backward compat path for raw anomaly signals.
            ml_anomaly = normalize_anomaly_score(deep_analysis_result.get("anomaly_score"))
        blend = WorkerConfig.ML_ANOMALY_BEHAVIOR_BLEND
        behavior_score = _clamp_0_10(behavior_base + ml_anomaly * blend)
        scores['behavior_score'] = behavior_score
        details['behavior'] = {
            'action_type': event_context.get('action_type', 'unknown'),
            'destination': event_context.get('destination', 'unknown'),
            'behavior_base': round(behavior_base, 2),
            'ml_anomaly_score': round(ml_anomaly, 2),
            'ml_anomaly_behavior_blend': blend,
        }
        
        # 3) Context Score (Sx in [0,10])
        context_score = self._calculate_context_score(event_context)
        scores['context_score'] = _clamp_0_10(context_score)
        details['context'] = {
            'user': event_context.get('user', 'unknown'),
            'time': event_context.get('time', 'unknown'),
            'location': event_context.get('location', 'unknown')
        }
        
        # 4) Composite model: weighted sum OR NIST-like multiplicative
        model = (WorkerConfig.RISK_COMPOSITE_MODEL or "nist_multiplicative").lower()
        if model == "weighted_sum":
            total_score = (
                scores['content_score'] * self.weights['content'] +
                scores['behavior_score'] * self.weights['behavior'] +
                scores['context_score'] * self.weights['context']
            )
            details["composite_model"] = {
                "name": "weighted_sum",
                "weights": {
                    "content": self.weights.get("content", 0.0),
                    "behavior": self.weights.get("behavior", 0.0),
                    "context": self.weights.get("context", 0.0),
                },
            }
        else:
            alpha = WorkerConfig.RISK_LIKELIHOOD_ALPHA
            impact = scores["content_score"]
            likelihood = _clamp_0_10(alpha * scores["behavior_score"] + (1.0 - alpha) * scores["context_score"])
            total_score = (impact * likelihood) / 10.0
            details["composite_model"] = {
                "name": "nist_multiplicative",
                "likelihood_alpha": alpha,
                "impact": round(impact, 2),
                "likelihood": round(likelihood, 2),
                "formula": "risk=(impact*likelihood)/10",
            }
        
        # Quyết định hành động
        total_score = _clamp_0_10(total_score)
        
        # UEBA Anomaly Assurance:
        ml_is_anomaly = event_context.get("ml_is_anomaly", False)
        ml_anomaly_score = _safe_float(event_context.get("ml_anomaly_score", 0.0))
        boost_threshold = getattr(WorkerConfig, "ML_ANOMALY_BOOST_THRESHOLD", 7.0)
        
        if ml_is_anomaly and ml_anomaly_score >= boost_threshold:
            alert_threshold = self.thresholds.get("alert", 4.0)
            if total_score < alert_threshold:
                boosted = min(10.0, max(alert_threshold, ml_anomaly_score * 0.9))
                logger.warning(
                    f"Traditional Score Boost: UEBA Anomaly ({ml_anomaly_score:.2f}) vượt ngưỡng {boost_threshold}. "
                    f"Tự động boost final risk từ {total_score:.2f} lên {boosted:.2f} để cảnh báo (Alert) lên Dashboard."
                )
                total_score = boosted
                details['ueba_force_alert'] = True
                
        action = self._determine_action(total_score)
        risk_level = classify_risk_level(total_score)
        
        return {
            'total_score': round(total_score, 2),
            'cvss_score': total_score_to_cvss10(total_score),
            **scores,
            'action': action,
            'risk_level': risk_level,
            'details': details,
            'method': 'traditional',
        }
    
    def _calculate_content_score(self, 
                                 fast_scan: Dict[str, Any],
                                 deep_analysis: Dict[str, Any],
                                 event_data: Dict[str, Any] = None) -> float:
        """Tính Content Score"""
        score = 0
        event_data = event_data or {}
        
        # YARA matches
        yara_matches = fast_scan.get('yara_matches', [])
        if yara_matches:
            # Mỗi match cộng điểm
            for match in yara_matches:
                rule_name = match.get('rule', '').lower()
                if 'id' in rule_name or 'cmnd' in rule_name or 'cccd' in rule_name:
                    score += 50  # ID card = high risk
                elif 'credit' in rule_name or 'card' in rule_name:
                    score += 40  # Credit card = high risk
                elif 'email' in rule_name:
                    score += 20  # Email pattern
                elif 'api' in rule_name or 'key' in rule_name:
                    score += 35  # API key = high risk
                else:
                    score += 30  # Other patterns
        
        # IOC hits (from agent) - even if YARA didn't match
        ioc_hits = event_data.get('ioc_hits', [])
        if ioc_hits:
            for ioc in ioc_hits:
                tag = ioc.get('tag', '').lower()
                if 'email' in tag:
                    score += 25  # Email detected by agent
                elif 'id' in tag or 'cmnd' in tag or 'cccd' in tag:
                    score += 50  # ID detected by agent
                elif 'credit' in tag or 'card' in tag:
                    score += 40  # Credit card detected by agent
                elif 'phone' in tag:
                    score += 15  # Phone number detected
                else:
                    score += 20  # Other IOC hits
        
        # Encrypted ZIP
        if fast_scan.get('is_encrypted_zip', False):
            score += 30  # Cannot read = high risk
        
        # ML classification
        ml_result = deep_analysis.get('ml_result')
        if ml_result and ml_result.get('is_sensitive', False):
            confidence = ml_result.get('confidence', 0)
            score += int(confidence * 30)  # Max 30 points
        
        # OCR detected sensitive pattern
        ocr_text = deep_analysis.get('ocr_text', '')
        if ocr_text:
            # Check for ID patterns in OCR text (9-12 digits)
            if re.search(r'\b\d{9,12}\b', ocr_text):
                score += 40
            # Check for credit card patterns
            if re.search(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', ocr_text):
                score += 35
        
        return min(score / 10.0, 10.0)
    
    def _calculate_behavior_score(self, context: Dict[str, Any]) -> float:
        """Tính Behavior Score"""
        score = 0
        action_type = str(context.get('action_type', '')).lower()
        destination = str(context.get('destination', '')).lower()
        window_title = str(context.get('window_title', '')).lower()
        domain = str(context.get('domain', '')).lower()
        process_name = str(context.get('process_name', '')).lower()
        
        # Sensitive title keywords (Full List)
        sensitive_title_keywords = [
            "chatgpt", "claude", "gemini", "bard", "perplexity", "poe ai", "copilot",
            "gmail", "google mail", "outlook", "outlook mail", "yahoo mail", "proton mail",
            "google drive", "dropbox", "onedrive", "mega", "box", "icloud",
            "slack", "teams", "discord", "telegram", "whatsapp", "messenger", "line", "signal",
            "zalo",
            "facebook", "instagram", "twitter", "linkedin", "tiktok", "reddit", "threads",
            "pastebin", "github gist", "gitlab", "bitbucket", "replit",
            "wetransfer", "sendspace", "mediafire"
        ]
        
        # Sensitive domains (Full List)
        sensitive_domains = {
            "chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com", "bard.google.com",
            "perplexity.ai", "poe.com", "copilot.microsoft.com", "phind.com", "you.com",
            "mail.google.com", "gmail.com", "outlook.office.com", "outlook.live.com",
            "mail.yahoo.com", "mail.proton.me", "protonmail.com", "zoho.com", "yandex.com",
            "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com",
            "mega.nz", "box.com", "icloud.com", "pcloud.com", "sync.com",
            "wetransfer.com", "transfer.sh", "file.io", "sendgb.com", "wormhole.app",
            "sendspace.com", "mediafire.com", "zippyshare.com",
            "web.whatsapp.com", "discord.com", "teams.microsoft.com", "slack.com",
            "messenger.com", "facebook.com/messages", "telegram.org", "web.telegram.org",
            "line.me", "signal.org",
            "zalo.me", "chat.zalo.me",
            "facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com",
            "linkedin.com", "reddit.com", "threads.net",
            "gist.github.com", "pastebin.com", "hastebin.com", "gitlab.com",
            "bitbucket.org", "replit.com"
        }
        
        # Messaging / Desktop Apps
        messaging_apps = {
            "teams.exe", "slack.exe", "discord.exe", "telegram.exe", "whatsapp.exe",
            "line.exe", "signal.exe", "skype.exe", "zalo.exe"
        }
        
        # Clipboard paste vào sensitive apps (HIGH RISK)
        is_clipboard_paste = context.get('is_clipboard_paste', False)
        is_sensitive_app = context.get('is_sensitive_app', False)
        
        # Check if messaging app (desktop app) - highest risk
        is_messaging_app = any(app in process_name for app in messaging_apps)
        
        # Check if sensitive domain
        is_sensitive_domain = domain in sensitive_domains
        
        # Check if sensitive title
        is_sensitive_title = any(keyword in window_title for keyword in sensitive_title_keywords)
        sensitive_web_behavior_weight = float(
            getattr(WorkerConfig, "SENSITIVE_WEB_BEHAVIOR_WEIGHT", 1.0)
        )
        
        if is_clipboard_paste and (is_messaging_app or is_sensitive_app or is_sensitive_domain or is_sensitive_title):
            # Clipboard paste vào GPT/Discord/Zalo/Messaging App → rất nguy hiểm
            if is_messaging_app:
                score += 60  # Very high risk (desktop app)
                logger.warning(f"VERY HIGH RISK: Clipboard paste to messaging app: {process_name}")
            else:
                score += 50 * sensitive_web_behavior_weight  # Reduced weight for sensitive web pages
                logger.warning(f"HIGH RISK: Clipboard paste to sensitive app: {window_title} or domain: {domain}")
        
        # Clipboard paste (general)
        elif is_clipboard_paste:
            score += 20
        
        # Clipboard copy
        elif action_type == 'clipboard' or 'clipboard' in action_type:
            score += 15
        
        # Copy to USB
        if 'usb' in destination or 'removable' in destination or 'f:' in destination or 'e:' in destination:
            score += 20
        
        # Copy to network/cloud
        if 'network' in destination or 'cloud' in destination or 'onedrive' in destination or 'dropbox' in destination:
            score += 10
        
        # Screenshot/Print
        if 'screenshot' in action_type or 'print' in action_type:
            score += 10
        
        # Off-hours activity (simplified check)
        time_str = str(context.get('time', ''))
        # TODO: Implement proper time parsing
        # if is_off_hours(time_str):
        #     score += 10
        
        return min(score / 10.0, 10.0)
    
    def _calculate_context_score(self, context: Dict[str, Any]) -> float:
        """Tính Context Score"""
        score = 0
        window_title = str(context.get('window_title', '')).lower()
        domain = str(context.get('domain', '')).lower()
        process_name = str(context.get('process_name', '')).lower()
        
        # Sensitive title keywords (Full List)
        sensitive_title_keywords = [
            # AI tools
            "chatgpt", "claude", "gemini", "bard", "perplexity", "poe ai", "copilot",
            # Email
            "gmail", "google mail", "outlook", "outlook mail", "yahoo mail", "proton mail",
            # Cloud
            "google drive", "dropbox", "onedrive", "mega", "box", "icloud",
            # Messaging / Chat
            "slack", "teams", "discord", "telegram", "whatsapp", "messenger", "line", "signal",
            # Vietnam chat apps
            "zalo",
            # Social media
            "facebook", "instagram", "twitter", "linkedin", "tiktok", "reddit", "threads",
            # Code sharing
            "pastebin", "github gist", "gitlab", "bitbucket", "replit",
            # File sharing
            "wetransfer", "sendspace", "mediafire"
        ]
        
        # Sensitive domains (Full List)
        sensitive_domains = {
            # AI / LLM Tools
            "chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com", "bard.google.com",
            "perplexity.ai", "poe.com", "copilot.microsoft.com", "phind.com", "you.com",
            # Email Services
            "mail.google.com", "gmail.com", "outlook.office.com", "outlook.live.com",
            "mail.yahoo.com", "mail.proton.me", "protonmail.com", "zoho.com", "yandex.com",
            # Cloud Storage
            "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com",
            "mega.nz", "box.com", "icloud.com", "pcloud.com", "sync.com",
            # Temporary File Transfer
            "wetransfer.com", "transfer.sh", "file.io", "sendgb.com", "wormhole.app",
            "sendspace.com", "mediafire.com", "zippyshare.com",
            # Messaging / Chat
            "web.whatsapp.com", "discord.com", "teams.microsoft.com", "slack.com",
            "messenger.com", "facebook.com/messages", "telegram.org", "web.telegram.org",
            "line.me", "signal.org",
            # Vietnam Popular Messaging
            "zalo.me", "chat.zalo.me",
            # Social Media
            "facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com",
            "linkedin.com", "reddit.com", "threads.net",
            # Code Sharing / Paste
            "gist.github.com", "pastebin.com", "hastebin.com", "gitlab.com",
            "bitbucket.org", "replit.com"
        }
        
        # Messaging / Desktop Apps
        messaging_apps = {
            "teams.exe", "slack.exe", "discord.exe", "telegram.exe", "whatsapp.exe",
            "line.exe", "signal.exe", "skype.exe", "zalo.exe"
        }
        
        # Check sensitive window title
        sensitive_title_points = float(
            getattr(WorkerConfig, "SENSITIVE_WEB_CONTEXT_TITLE_POINTS", 25.0)
        )
        if any(keyword in window_title for keyword in sensitive_title_keywords):
            score += sensitive_title_points
        
        # Check sensitive domain
        sensitive_domain_points = float(
            getattr(WorkerConfig, "SENSITIVE_WEB_CONTEXT_DOMAIN_POINTS", 25.0)
        )
        if domain in sensitive_domains:
            score += sensitive_domain_points
        
        # Check messaging app (desktop app)
        if any(app in process_name for app in messaging_apps):
            score += 30  # Very high context risk (desktop app = more direct)
        
        # File location (sensitive folder)
        location = str(context.get('location', '')).lower()
        sensitive_folders = ['contract', 'financial', 'hr', 'confidential', 'secret', 'private']
        if any(folder in location for folder in sensitive_folders):
            score += 10
        
        # File size (large files = more data)
        file_size_mb = context.get('file_size_mb', 0)
        if file_size_mb > 10:
            score += 5
        elif file_size_mb > 50:
            score += 10
        
        # User context (có thể thêm check user role)
        user = str(context.get('user', '')).lower()
        # TODO: Check if user is in sensitive role
        
        return min(score / 10.0, 10.0)
    
    def _determine_action(self, total_score: float) -> str:
        """Quyết định hành động dựa trên score"""
        # Alert-only mode: never return 'block'
        if total_score >= self.thresholds['alert']:
            return 'alert'
        else:
            return 'log'


class ResearchBasedRiskScoringEngine:
    """
    Research-Based Risk Scoring Engine
    Based on: "A Multi-Factor Risk Assessment Framework for Insider Threat Detection"
    
    Formula: Total Risk Score = w₁×A + w₂×B + w₃×C + w₄×T + w₅×F
    Where:
    - A–F ∈ [0,10]
    """
    
    def __init__(self):
        self.weights = WorkerConfig.RESEARCH_RISK_WEIGHTS
        self.thresholds = WorkerConfig.RISK_THRESHOLDS
        self.user_baselines = {}  # Store user baselines for deviation calculation
    
    def calculate_score(self,
                       fast_scan_result: Dict[str, Any],
                       deep_analysis_result: Dict[str, Any],
                       event_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate Composite Multi-Factor Risk Score
        
        Args:
            fast_scan_result: Results from Fast Scan
            deep_analysis_result: Results from Deep Analysis
            event_context: Event context with user, time, location, etc.
        
        Returns:
            {
                'total_score': 75.5,
                'anomaly_score': 60,
                'behavioral_deviation_score': 70,
                'content_sensitivity_score': 80,
                'temparol_risk_score': 3,
                'frequency_risk_score': 4,
                'action': 'alert',
                'details': {...}
            }
        """
        scores = {}
        details = {}
        
        event_data = event_context.get('_event_data', {})
        user = event_context.get('user', 'unknown')
        
        # 1. Anomaly Score (A) - 25%
        anomaly_score = self._calculate_anomaly_score(
            fast_scan_result,
            deep_analysis_result,
            event_data
        )
        scores['anomaly_score'] = anomaly_score
        details['anomaly'] = {
            'yara_matches': len(fast_scan_result.get('yara_matches', [])),
            'ioc_hits': len(event_data.get('ioc_hits', [])),
            'ml_sensitive': deep_analysis_result.get('is_sensitive', False)
        }
        
        # 2. Behavioral Deviation Score (B) - 25%
        behavioral_deviation_score = self._calculate_behavioral_deviation_score(
            event_context,
            user
        )
        scores['behavioral_deviation_score'] = behavioral_deviation_score
        details['behavioral_deviation'] = {
            'action_type': event_context.get('action_type', 'unknown'),
            'deviation_from_baseline': event_context.get('deviation_from_baseline', {})
        }
        
        # 3. Content Sensitivity Score (C) - 30%
        content_sensitivity_score = self._calculate_content_sensitivity_score(
            fast_scan_result,
            deep_analysis_result,
            event_data
        )
        scores['content_sensitivity_score'] = content_sensitivity_score
        details['content_sensitivity'] = {
            'yara_matches': len(fast_scan_result.get('yara_matches', [])),
            'ioc_hits': len(event_data.get('ioc_hits', [])),
            'encrypted_zip': fast_scan_result.get('is_encrypted_zip', False)
        }
        
        # 4. Temparol Risk Score (T) - 10%
        temparol_risk_score = self._calculate_temparol_risk_score(event_context)
        scores['temparol_risk_score'] = temparol_risk_score
        details['temparol'] = {
            'time': event_context.get('time', 'unknown'),
            'is_off_hours': event_context.get('is_off_hours', False),
            'is_weekend': event_context.get('is_weekend', False)
        }
        
        # 5. Frequency Risk Score (F) - 10%
        frequency_risk_score = self._calculate_frequency_risk_score(event_context)
        scores['frequency_risk_score'] = frequency_risk_score
        details['frequency'] = {
            'clipboard_pastes_last_1h': event_context.get('clipboard_pastes_last_1h', 0),
            'file_copies_to_usb_last_24h': event_context.get('file_copies_to_usb_last_24h', 0)
        }
        
        # Calculate total composite score
        total_score = (
            scores['anomaly_score'] * self.weights['anomaly'] +
            scores['behavioral_deviation_score'] * self.weights['behavioral_deviation'] +
            scores['content_sensitivity_score'] * self.weights['content_sensitivity'] +
            scores['temparol_risk_score'] * self.weights['temparol'] +
            scores['frequency_risk_score'] * self.weights['frequency']
        )
        
        # Determine action
        action = self._determine_action(total_score)
        risk_level = classify_risk_level(total_score)
        
        return {
            'total_score': round(total_score, 2),
            'cvss_score': total_score_to_cvss10(total_score),
            **scores,
            'action': action,
            'risk_level': risk_level,
            'details': details,
            'method': 'research_based'
        }
    
    def _calculate_anomaly_score(self,
                                 fast_scan: Dict[str, Any],
                                 deep_analysis: Dict[str, Any],
                                 event_data: Dict[str, Any]) -> float:
        """
        Calculate Anomaly Score (A)
        A = min(100, (anomaly_score_from_ml × 100) + anomaly_boost)
        """
        score = 0
        
        # ML Anomaly Score (if available from Isolation Forest or similar)
        ml_anomaly = deep_analysis.get("ml_anomaly_score")
        if ml_anomaly is None:
            ml_anomaly = deep_analysis.get("anomaly_score")
            score += normalize_anomaly_score(ml_anomaly)
        else:
            score += _clamp_0_10(ml_anomaly)
        
        # Anomaly Boost from indicators
        anomaly_boost = 0
        
        # YARA matches boost
        yara_matches = fast_scan.get('yara_matches', [])
        anomaly_boost += len(yara_matches) * 10
        
        # IOC hits boost
        ioc_hits = event_data.get('ioc_hits', [])
        anomaly_boost += len(ioc_hits) * 15
        
        # Encrypted ZIP boost
        if fast_scan.get('is_encrypted_zip', False):
            anomaly_boost += 20
        
        # ML classification boost
        ml_result = deep_analysis.get('ml_result')
        if ml_result and ml_result.get('is_sensitive', False):
            anomaly_boost += 25
        
        score += anomaly_boost
        
        return min(score, 100) / 10.0
    
    def _calculate_behavioral_deviation_score(self,
                                            context: Dict[str, Any],
                                            user: str) -> float:
        """
        Calculate Behavioral Deviation Score (B)
        B = min(100, 50 + (deviation_z_score × 20))
        """
        # Get baseline for user (if available)
        baseline = self.user_baselines.get(user, {})
        if not baseline:
            # No baseline available, return neutral score (0–10)
            return 5.0
        
        # Get current metrics from context
        current_metrics = {
            'file_accesses_last_1h': context.get('file_accesses_last_1h', 0),
            'usb_connects_last_24h': context.get('usb_connects_last_24h', 0),
            'clipboard_pastes_last_10m': context.get('clipboard_pastes_last_10m', 0),
            'external_urls_visited_last_24h': context.get('external_urls_visited_last_24h', 0)
        }
        
        # Calculate Z-scores for each metric
        max_z_score = 0
        for metric_name, current_value in current_metrics.items():
            baseline_mean = baseline.get(f'{metric_name}_mean', 0)
            baseline_std = baseline.get(f'{metric_name}_std', 1)
            
            if baseline_std > 0:
                z_score = (current_value - baseline_mean) / baseline_std
                max_z_score = max(max_z_score, abs(z_score))
        
        # Convert Z-score to risk score
        # Z-score > 2.5 is considered high deviation (p < 0.01)
        if max_z_score > 2.5:
            deviation_score = 50 + (max_z_score * 20)
        elif max_z_score > 1.5:
            deviation_score = 50 + (max_z_score * 15)
        else:
            deviation_score = 50 + (max_z_score * 10)
        
        return min(max(deviation_score, 0), 100) / 10.0
    
    def _calculate_content_sensitivity_score(self,
                                            fast_scan: Dict[str, Any],
                                            deep_analysis: Dict[str, Any],
                                            event_data: Dict[str, Any]) -> float:
        """
        Calculate Content Sensitivity Score (C)
        C = min(100, Σ(sensitivity_weights × match_count) + ml_boost + ocr_boost)
        """
        score = 0
        
        # Sensitivity weights (based on research)
        sensitivity_weights = {
            'id': 40, 'cmnd': 40, 'cccd': 40,
            'credit': 35, 'card': 35,
            'api': 30, 'key': 30,
            'email': 20,
            'phone': 15,
            'other': 25
        }
        
        # YARA matches
        yara_matches = fast_scan.get('yara_matches', [])
        for match in yara_matches:
            rule_name = match.get('rule', '').lower()
            if 'id' in rule_name or 'cmnd' in rule_name or 'cccd' in rule_name:
                score += sensitivity_weights['id']
            elif 'credit' in rule_name or 'card' in rule_name:
                score += sensitivity_weights['credit']
            elif 'api' in rule_name or 'key' in rule_name:
                score += sensitivity_weights['api']
            elif 'email' in rule_name:
                score += sensitivity_weights['email']
            elif 'phone' in rule_name:
                score += sensitivity_weights['phone']
            else:
                score += sensitivity_weights['other']
        
        # IOC hits
        ioc_hits = event_data.get('ioc_hits', [])
        for ioc in ioc_hits:
            tag = ioc.get('tag', '').lower()
            if 'id' in tag or 'cmnd' in tag or 'cccd' in tag:
                score += sensitivity_weights['id']
            elif 'credit' in tag or 'card' in tag:
                score += sensitivity_weights['credit']
            elif 'email' in tag:
                score += sensitivity_weights['email']
            elif 'phone' in tag:
                score += sensitivity_weights['phone']
            else:
                score += sensitivity_weights['other']
        
        # ML Boost
        ml_result = deep_analysis.get('ml_result')
        if ml_result and ml_result.get('is_sensitive', False):
            score += 30
            confidence = ml_result.get('confidence', 0)
            score += int(confidence * 20)
        
        # OCR Boost
        ocr_text = deep_analysis.get('ocr_text', '')
        if ocr_text:
            if re.search(r'\b\d{9,12}\b', ocr_text):
                score += 35
            if re.search(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', ocr_text):
                score += 30
        
        return min(score, 100) / 10.0
    
    def _calculate_temparol_risk_score(self, context: Dict[str, Any]) -> float:
        """
        Calculate Temparol Risk Score (T)
        T = temparol_base_score + off_hours_penalty + weekend_penalty
        """
        score = 0
        time_str = str(context.get('time', ''))
        
        # Parse timestamp
        is_off_hours = False
        is_weekend = False
        
        try:
            if time_str:
                # Try to parse ISO format or common formats
                if 'T' in time_str:
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                else:
                    # Try other formats
                    dt = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                
                hour = dt.hour
                day_of_week = dt.weekday()  # 0=Monday, 6=Sunday
                
                # Off hours: 18:00-08:00
                is_off_hours = hour < 8 or hour >= 18
                # Weekend: Saturday (5) or Sunday (6)
                is_weekend = day_of_week >= 5
        except Exception:
            # If parsing fails, check context flags
            is_off_hours = context.get('is_off_hours', False)
            is_weekend = context.get('is_weekend', False)
        
        # Calculate temparol score
        if is_off_hours and is_weekend:
            score = 45
        elif is_off_hours:
            score = 30
        elif is_weekend:
            score = 20
        else:
            score = 0
        
        return min(score, 100) / 10.0
    
    def _calculate_frequency_risk_score(self, context: Dict[str, Any]) -> float:
        """
        Calculate Frequency Risk Score (F)
        F = min(100, frequency_base_score × frequency_multiplier)
        """
        score = 0
        
        # Frequency base scores
        clipboard_pastes_1h = context.get('clipboard_pastes_last_1h', 0)
        file_copies_usb_24h = context.get('file_copies_to_usb_last_24h', 0)
        external_urls_24h = context.get('external_urls_visited_last_24h', 0)
        
        # Clipboard paste to external (1h)
        if clipboard_pastes_1h > 0:
            base_score = 20
            multiplier = self._get_frequency_multiplier(clipboard_pastes_1h)
            score += base_score * multiplier
        
        # File copy to USB (24h)
        if file_copies_usb_24h > 0:
            base_score = 25
            multiplier = self._get_frequency_multiplier(file_copies_usb_24h)
            score += base_score * multiplier
        
        # External URL visits (24h) - lower weight
        if external_urls_24h > 0:
            base_score = 15
            multiplier = self._get_frequency_multiplier(external_urls_24h)
            score += base_score * multiplier
        
        return min(score, 100) / 10.0
    
    def _get_frequency_multiplier(self, count: int) -> float:
        """Get frequency multiplier based on count"""
        if count <= 2:
            return 1.0
        elif count <= 5:
            return 1.5
        elif count <= 10:
            return 2.0
        else:
            return 2.5
    
    def _determine_action(self, total_score: float) -> str:
        """Determine action based on total score"""
        if total_score >= self.thresholds['alert']:
            return 'alert'
        else:
            return 'log'
    
    def update_user_baseline(self, user: str, metrics: Dict[str, float]):
        """
        Update user baseline for behavioral deviation calculation
        
        Args:
            user: User identifier
            metrics: Dictionary with metric_name_mean and metric_name_std
                    e.g., {'file_accesses_last_1h_mean': 5.0, 'file_accesses_last_1h_std': 2.0}
        """
        self.user_baselines[user] = metrics


class NISTBasedRiskScoringEngine:
    """
    NIST SP 800-30 Based Risk Scoring Engine
    
    R = L × I
    - L: Likelihood (1–5), calculated as weighted sum of channel, behavior, protection, frequency
    - I: Impact (1–4), based on data sensitivity (Public, Internal, Confidential, Secret)
    
    Final Risk Score = (L × I / (L_max × I_max)) × 10
    """
    
    def __init__(self):
        self.likelihood_weights = WorkerConfig.NIST_LIKELIHOOD_WEIGHTS
        self.max_values = WorkerConfig.NIST_MAX_VALUES
        self.thresholds = WorkerConfig.RISK_THRESHOLDS
    
    def calculate_score(
        self,
        fast_scan_result: Dict[str, Any],
        deep_analysis_result: Dict[str, Any],
        event_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Tính Risk Score theo NIST SP 800-30."""
        details: Dict[str, Any] = {}
        event_data = event_context.get("_event_data", {})
        
        # 1) Impact (I) – độ nhạy cảm dữ liệu
        impact = self._calculate_impact(fast_scan_result, deep_analysis_result, event_data, event_context)
        details["impact"] = {
            "value": round(impact, 2),
            "classification": self._get_classification_label(impact),
        }
        
        # 2) Likelihood (L) – khả năng xảy ra thất thoát
        destination_score = self._get_destination_score(event_context)
        user_behavior_score = self._get_user_behavior_score(event_context)
        file_protection_score = self._get_file_protection_score(event_context, fast_scan_result)
        frequency_score = self._get_frequency_score(event_context)
        
        # UEBA ML Anomaly Score (0-10) -> likelihood boost
        ml_anomaly_score = _safe_float(event_context.get("ml_anomaly_score"), 0.0)
        if ml_anomaly_score <= 1.0 and _safe_float(deep_analysis_result.get("anomaly_score"), 0.0) != 0.0:
            ml_anomaly_score = normalize_anomaly_score(deep_analysis_result.get("anomaly_score"))
        ml_is_anomaly = event_context.get("ml_is_anomaly", False)
        ml_likelihood_boost = 0.0
        if ml_is_anomaly and ml_anomaly_score > 0:
            boost_threshold = WorkerConfig.ML_ANOMALY_BOOST_THRESHOLD
            if ml_anomaly_score >= boost_threshold:
                span = max(10.0 - boost_threshold, 0.01)
                ml_likelihood_boost = min(2.0, (ml_anomaly_score - boost_threshold) / span * 2.0)
            else:
                ml_likelihood_boost = 0.0
        
        details["likelihood_components"] = {
            "destination": destination_score,
            "user_behavior": user_behavior_score,
            "file_protection": file_protection_score,
            "frequency": frequency_score,
            "ml_anomaly_boost": round(ml_likelihood_boost, 2),
        }
        
        weighted_sum = (
            destination_score * self.likelihood_weights["destination"]
            + user_behavior_score * self.likelihood_weights["user_behavior"]
            + file_protection_score * self.likelihood_weights["file_protection"]
            + frequency_score * self.likelihood_weights["frequency"]
        ) + ml_likelihood_boost  # Add ML boost directly
        sum_weights = sum(self.likelihood_weights.values())
        likelihood = weighted_sum / sum_weights if sum_weights > 0 else 0.0
        likelihood = min(likelihood, self.max_values["likelihood_max"])
        
        details["likelihood"] = round(likelihood, 2)
        
        # 3) Raw risk và chuẩn hoá về 0–10
        risk_raw = likelihood * impact
        total_score = 0.0
        denom = self.max_values["likelihood_max"] * self.max_values["impact_max"]
        if denom > 0:
            total_score = (risk_raw / denom) * 10.0
        
        # 4) Hard override: exfil từ sensitive folder → max score
        force_max = bool(event_context.get("force_max_risk", False))
        if force_max:
            total_score = 10.0
            action = "alert"
            details["force_max_risk"] = True
            details["force_max_risk_reason"] = event_context.get("force_max_risk_reason", "")
        else:
            # Quyết định action (alert/log)
            action = self._determine_action(total_score)
        
        risk_level = classify_risk_level(total_score)
        
        return {
            "total_score": round(total_score, 2),
            "cvss_score": total_score_to_cvss10(total_score),
            "likelihood": round(likelihood, 2),
            "impact": round(impact, 2),
            "risk_raw": round(risk_raw, 2),
            "action": action,
            "risk_level": risk_level,
            "details": details,
            "method": "nist_based",
        }
    
    # ---------------- Impact (I) ----------------
    def _calculate_impact(
        self,
        fast_scan: Dict[str, Any],
        deep_analysis: Dict[str, Any],
        event_data: Dict[str, Any],
        event_context: Dict[str, Any],
    ) -> float:
        """
        Impact I ∈ {1,2,3,4}:
        1 = Public, 2 = Internal, 3 = Confidential, 4 = Secret/Top Secret
        Lấy max của tất cả indicators.
        """
        scores = []
        
        # YARA rules → sensitivity
        yara_matches = fast_scan.get("yara_matches", [])
        for m in yara_matches:
            rule = (m.get("rule") or "").lower()
            if any(k in rule for k in ["id", "cmnd", "cccd"]):
                scores.append(4.0)
            elif "credit" in rule or "card" in rule:
                scores.append(4.0)
            elif "api" in rule or "key" in rule:
                scores.append(4.0)
            elif "email" in rule:
                scores.append(3.0)
            elif "phone" in rule:
                scores.append(3.0)
            else:
                scores.append(2.0)
        
        # IOC hits từ agent
        for ioc in event_data.get("ioc_hits", []):
            tag = (ioc.get("tag") or "").lower()
            if any(k in tag for k in ["id", "cmnd", "cccd"]):
                scores.append(4.0)
            elif "credit" in tag or "card" in tag:
                scores.append(4.0)
            elif "email" in tag:
                scores.append(3.0)
            elif "phone" in tag:
                scores.append(3.0)
            else:
                scores.append(2.0)
        
        # ML classification
        ml_result = deep_analysis.get("ml_result") or {}
        if ml_result.get("is_sensitive"):
            conf = float(ml_result.get("confidence") or 0.0)
            if conf >= 0.8:
                scores.append(4.0)
            elif conf >= 0.6:
                scores.append(3.0)
            else:
                scores.append(2.0)
        
        # Encrypted ZIP → treat as high impact
        if fast_scan.get("is_encrypted_zip"):
            scores.append(4.0)
        
        # OCR patterns
        ocr_text = deep_analysis.get("ocr_text") or ""
        if ocr_text:
            if re.search(r"\b\d{9,12}\b", ocr_text):
                scores.append(4.0)
            if re.search(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", ocr_text):
                scores.append(4.0)
        
        # Nếu không có indicator nào → dựa trên location
        if not scores:
            location = str(event_context.get("location", "")).lower()
            sensitive_folders = ["contract", "financial", "hr", "confidential", "secret", "private"]
            if any(k in location for k in sensitive_folders):
                scores.append(3.0)
            else:
                scores.append(1.0)
        
        return max(scores) if scores else 1.0
    
    def _get_classification_label(self, impact: float) -> str:
        if impact >= 4.0:
            return "Secret/Top Secret"
        if impact >= 3.0:
            return "Confidential"
        if impact >= 2.0:
            return "Internal"
        return "Public"
    
    # ---------------- Likelihood (L) ----------------
    def _get_destination_score(self, context: Dict[str, Any]) -> float:
        """
        Destination channel score cj (1–5):
        - USB, external app (ChatGPT, Zalo, Discord): 5
        - Cloud Storage: 4
        - Email / Network share: 3
        - Local only: 1–2
        """
        destination = str(context.get("destination", "")).lower()
        action_type = str(context.get("action_type", "")).lower()
        domain = str(context.get("domain", "")).lower()
        process_name = str(context.get("process_name", "")).lower()
        
        # USB
        if any(x in destination for x in ["usb", "removable", "f:", "e:"]):
            return 5.0
        
        # External apps (LLM / messaging)
        external_domains = {
            "chat.openai.com",
            "chatgpt.com",
            "claude.ai",
            "discord.com",
            "slack.com",
            "teams.microsoft.com",
            "zalo.me",
            "chat.zalo.me",
        }
        messaging_apps = {"teams.exe", "slack.exe", "discord.exe", "zalo.exe"}
        if domain in external_domains or any(app in process_name for app in messaging_apps):
            return 5.0
        
        # Cloud storage
        cloud_domains = {
            "drive.google.com",
            "dropbox.com",
            "onedrive.live.com",
            "mega.nz",
            "box.com",
        }
        if any(x in destination for x in ["cloud", "onedrive", "dropbox"]):
            return 4.0
        if domain in cloud_domains:
            return 4.0
        
        # Email
        email_domains = {
            "mail.google.com",
            "gmail.com",
            "outlook.office.com",
            "outlook.live.com",
        }
        if "email" in action_type or "mail" in destination or domain in email_domains:
            return 3.0
        
        # Network share
        if "network" in destination:
            return 3.0
        
        # Local default
        return 2.0 if "copy" in action_type else 1.0
    
    def _get_user_behavior_score(self, context: Dict[str, Any]) -> float:
        """
        User behavior score cj (1–5):
        - Off-hours + bulk: 5
        - Off-hours only: 4
        - Bulk only: 3
        - Weekend: 2
        - Normal: 1
        """
        time_str = str(context.get("time", ""))
        file_count = int(context.get("file_count", 0) or 0)
        clipboard_pastes_1h = int(context.get("clipboard_pastes_last_1h", 0) or 0)
        
        is_off_hours = False
        is_weekend = False
        
        try:
            if time_str:
                if "T" in time_str:
                    dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                else:
                    dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                h = dt.hour
                d = dt.weekday()
                is_off_hours = h < 8 or h >= 18
                is_weekend = d >= 5
        except Exception:
            is_off_hours = bool(context.get("is_off_hours", False))
            is_weekend = bool(context.get("is_weekend", False))
        
        is_bulk = file_count > 10 or clipboard_pastes_1h > 5
        
        if is_off_hours and is_bulk:
            return 5.0
        if is_off_hours:
            return 4.0
        if is_bulk:
            return 3.0
        if is_weekend:
            return 2.0
        return 1.0
    
    def _get_file_protection_score(self, context: Dict[str, Any], fast_scan: Dict[str, Any]) -> float:
        """
        File protection score cj (1–5):
        - Obfuscation / encrypted ZIP: 5
        - No protection (plaintext sensitive data): 4
        - Encrypted / protected: 2
        - Safe / public: 1
        """
        # Encrypted archive
        if fast_scan.get("is_encrypted_zip"):
            return 5.0
        
        ext = str(context.get("extension", "") or "").lower()
        suspicious_exts = {".bak", ".tmp", ".old", ".backup"}
        if ext in suspicious_exts:
            return 5.0
        
        # Password protected
        if context.get("password_protected"):
            return 2.0
        
        # Default: assume no protection for potential sensitive data
        return 4.0
    
    def _get_frequency_score(self, context: Dict[str, Any]) -> float:
        """
        Frequency score cj (1–5) dựa trên max của:
        - clipboard_pastes_last_1h
        - file_copies_to_usb_last_24h
        """
        clipboard_pastes_1h = int(context.get("clipboard_pastes_last_1h", 0) or 0)
        usb_copies_24h = int(context.get("file_copies_to_usb_last_24h", 0) or 0)
        external_urls_24h = int(context.get("external_urls_visited_last_24h", 0) or 0)
        
        m = max(clipboard_pastes_1h, usb_copies_24h, external_urls_24h)
        if m > 10:
            return 5.0
        if m >= 6:
            return 4.0
        if m >= 3:
            return 3.0
        if m >= 1:
            return 2.0
        return 1.0
    
    def _determine_action(self, total_score: float) -> str:
        """Quyết định action dựa trên Risk Score 0–10."""
        if total_score >= self.thresholds["alert"]:
            return "alert"
        return "log"
