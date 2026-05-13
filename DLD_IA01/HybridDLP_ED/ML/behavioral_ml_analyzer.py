"""
Behavioral ML Analyzer - Real-time UEBA anomaly detection.

Hybrid scoring:
- IsolationForest model score (0-10)
- Profile/context deviation score (0-10)
- Low-and-slow accumulator (0-10 contribution cap)
"""
import logging
import math
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from .feature_extractor import EventFeatureExtractor

logger = logging.getLogger(__name__)


def _clamp_0_10(v: float) -> float:
    return max(0.0, min(10.0, float(v)))


# Debug logging control
_DEBUG_ML = os.getenv("DEBUG_ML", "0").strip().lower() in {"1", "true", "yes", "on", "debug"}
def _ml_debug(*args, **kwargs):
    if _DEBUG_ML:
        logger.debug(*args, **kwargs)


def _normalize_anomaly_raw(raw_score: float, worker_cfg) -> float:
    """Normalize model raw score to unified anomaly scale [0,10]."""
    method = str(getattr(worker_cfg, "ML_ANOMALY_NORM_METHOD", "percentile") or "percentile").lower()
    if method == "minmax":
        lo = float(getattr(worker_cfg, "ML_ANOMALY_MIN", -1.0))
        hi = float(getattr(worker_cfg, "ML_ANOMALY_MAX", 1.0))
    else:
        lo = float(getattr(worker_cfg, "ML_ANOMALY_P5", -0.6))
        hi = float(getattr(worker_cfg, "ML_ANOMALY_P95", 0.6))
    if hi <= lo:
        lo, hi = -1.0, 1.0
    x = min(max(float(raw_score), lo), hi)
    return _clamp_0_10((x - lo) / (hi - lo) * 10.0)


class BehavioralMLAnalyzer:
    def __init__(self, model_path: Optional[Path] = None):
        if model_path is None:
            model_path = Path(__file__).parent.parent / "worker" / "ml_models" / "ueba_iso_forest.pkl"
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = []
        self.feature_extractor = EventFeatureExtractor()
        self.is_loaded = False
        self._accumulator: Dict[str, Dict[str, float]] = {}
        # Baseline per-user (persist across worker restarts).
        # Stored as lightweight JSON (atomic replace) under worker/logs/ for easy inspection.
        try:
            base = Path(__file__).parent.parent / "worker" / "logs" / "ueba"
            base.mkdir(parents=True, exist_ok=True)
        except Exception:
            base = Path(__file__).parent
        self._profile_path = Path(os.getenv("UEBA_PROFILE_PATH", str(base / "ueba_user_baselines.json")))
        self._profiles: Dict[str, Dict[str, Any]] = {}
        self._profile_dirty = 0
        self._profile_last_save_ts = 0.0
        self._profile_save_every = max(1, int(os.getenv("UEBA_PROFILE_SAVE_EVERY", "25")))
        self._profile_save_min_sec = max(0.2, float(os.getenv("UEBA_PROFILE_SAVE_MIN_SEC", "2.0")))
        self._profile_decay_hours = max(1.0, float(os.getenv("UEBA_PROFILE_DECAY_HOURS", "168")))  # 7d default
        self._profile_min_events = max(10, int(os.getenv("UEBA_PROFILE_MIN_EVENTS", "35")))
        self._load_profiles()
        if not self.model_path.exists():
            logger.warning(f"UEBA model not found at {self.model_path}. Anomaly detection disabled.")

    def _load_profiles(self) -> None:
        try:
            if not self._profile_path.exists():
                return
            raw = self._profile_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict) and isinstance(data.get("profiles"), dict):
                self._profiles = data["profiles"]
        except Exception as e:
            logger.warning(f"UEBA baseline load failed: {e}")

    def _save_profiles(self, force: bool = False) -> None:
        try:
            now = datetime.now().timestamp()
            if not force:
                if self._profile_dirty <= 0:
                    return
                if self._profile_dirty < self._profile_save_every and (now - self._profile_last_save_ts) < self._profile_save_min_sec:
                    return
            payload = {
                "version": 1,
                "saved_ts": now,
                "profiles": self._profiles,
            }
            tmp = self._profile_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self._profile_path)
            self._profile_dirty = 0
            self._profile_last_save_ts = now
        except Exception as e:
            logger.debug(f"UEBA baseline save failed: {e}")

    def load_model(self) -> bool:
        try:
            model_data = joblib.load(self.model_path)
            if isinstance(model_data, dict):
                self.model = model_data.get("model")
                self.scaler = model_data.get("scaler")
                self.feature_names = model_data.get("feature_names", []) or []
            else:
                self.model = model_data
                self.scaler = None
                self.feature_names = []
            self.is_loaded = self.model is not None
            if self.is_loaded:
                logger.info(f"UEBA model loaded from {self.model_path}")
            return self.is_loaded
        except Exception as e:
            logger.error(f"Failed to load UEBA model: {e}")
            self.is_loaded = False
            return False

    def _parse_ts(self, event: Dict[str, Any]) -> datetime:
        ts = event.get("ts") or event.get("timestamp")
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(float(ts))
        s = str(ts or "").replace("Z", "+00:00")
        if s:
            try:
                return datetime.fromisoformat(s)
            except Exception:
                pass
        return datetime.now()

    def _extract_user(self, event: Dict[str, Any]) -> str:
        ctx = event.get("context", {}) or {}
        actor = event.get("actor", {}) or {}
        return str(
            ctx.get("user")
            or actor.get("user")
            or event.get("user")
            or "unknown"
        ).strip().lower()

    def _model_input_features(self, raw_features: np.ndarray) -> np.ndarray:
        """
        Backward compatibility for models trained on older feature sets.
        - If model has saved feature_names, map by name.
        - Else fallback to raw features.
        """
        if not self.feature_names:
            return raw_features
        names_now = self.feature_extractor.get_feature_names()
        idx_map = {name: i for i, name in enumerate(names_now)}
        out = np.zeros((len(self.feature_names),), dtype=np.float32)
        for i, fname in enumerate(self.feature_names):
            j = idx_map.get(fname)
            if j is not None and j < len(raw_features):
                out[i] = raw_features[j]
        return out

    def _event_signals(self, event: Dict[str, Any]) -> Dict[str, float]:
        ctx = event.get("context", {}) or {}
        operation = event.get("operation", {}) or {}
        obj = event.get("object", {}) or {}
        clipboard = event.get("clipboard", {}) or {}
        network = event.get("network", {}) or {}
        raw_original = event.get("raw_original", {}) or {}
        raw_clipboard = raw_original.get("clipboard", {}) if isinstance(raw_original, dict) else {}
        raw_ctx = raw_original.get("context", {}) if isinstance(raw_original, dict) else {}
        e_type = str(event.get("type") or event.get("event_type") or "").lower()
        op_type = str(operation.get("op_type") or "").lower()
        dst = str(obj.get("dst_path") or event.get("dst_path") or "").lower()
        app = str(
            clipboard.get("dest_app")
            or raw_clipboard.get("dest_app")
            or ctx.get("fg_app")
            or ctx.get("process_name")
            or operation.get("tool")
            or ""
        ).lower()
        domain = str(
            clipboard.get("dest_domain")
            or raw_clipboard.get("dest_domain")
            or network.get("dest_domain")
            or ctx.get("dest_domain")
            or ctx.get("domain")
            or raw_ctx.get("dest_domain")
            or raw_ctx.get("domain")
            or ""
        ).lower()
        window_title = str(
            clipboard.get("dest_window_title")
            or raw_clipboard.get("dest_window_title")
            or clipboard.get("active_window_title")
            or raw_clipboard.get("active_window_title")
            or ctx.get("window_title")
            or raw_ctx.get("window_title")
            or ""
        ).lower()
        file_path = str(obj.get("path") or "").lower()

        is_clipboard = 1.0 if "clipboard" in e_type or "paste" in op_type else 0.0
        external_markers = (
            "drive.google", "gemini.google", "bard.google", "chatgpt", "chat.openai",
            "openai.com", "dropbox", "onedrive", "wetransfer", "mega", "telegram",
            "discord", "zalo",
        )
        is_external = 1.0 if any(x in dst for x in ("usb", "removable", "onedrive", "dropbox")) or any(
            x in domain or x in window_title for x in external_markers
        ) else 0.0
        is_archive = 1.0 if any(x in file_path for x in (".zip", ".rar", ".7z")) else 0.0
        is_rename_like = 1.0 if any(x in e_type for x in ("rename", "modified")) and any(
            x in file_path for x in (".tmp", ".dat", ".bin")
        ) else 0.0
        app_risky = 1.0 if any(
            x in app or x in window_title or x in domain
            for x in ("chrome", "edge", "discord", "telegram", "zalo", "chatgpt", "gemini", "openai")
        ) else 0.0
        file_size = float(event.get("size") or obj.get("size") or obj.get("size_bytes") or 0.0)
        
        is_file_op = 1.0 if any(x in e_type for x in ("file_", "upload", "usb_copy")) else 0.0
        
        clip_content = clipboard.get("content", "")
        clip_len = (
            clipboard.get("content_len")
            or clipboard.get("text_len")
            or raw_clipboard.get("content_len")
            or raw_clipboard.get("text_len")
            or obj.get("text_len")
            or len(str(clip_content))
        )
        actual_size = file_size if file_size > 0 else clip_len
        try:
            from worker.config import WorkerConfig
            small_fragment_max = int(getattr(WorkerConfig, "UEBA_SMALL_FRAGMENT_MAX_BYTES", 2048))
        except Exception:
            small_fragment_max = 2048
        is_small_fragment = 1.0 if (
            (is_clipboard > 0.0 or is_file_op > 0.0)
            and 0 < float(actual_size) <= max(1, small_fragment_max)
        ) else 0.0

        return {
            "is_clipboard": is_clipboard,
            "is_external": is_external,
            "is_archive": is_archive,
            "is_rename_like": is_rename_like,
            "app_risky": app_risky,
            "file_size_mb": file_size / (1024.0 * 1024.0),
            "is_small_fragment": is_small_fragment,
        }

    def _get_user_profile(self, user: str) -> Dict[str, Any]:
        p = self._profiles.get(user)
        if not isinstance(p, dict):
            p = {
                "n": 0,
                "last_ts": 0.0,
                # Exponential moving averages (EMA) of key habits.
                "ema_off_hours": 0.0,
                "ema_external": 0.0,
                "ema_clipboard": 0.0,
                "ema_risky_app": 0.0,
                # Optional hour histogram (0-23) for explainability.
                "hour_hist": [0] * 24,
            }
            self._profiles[user] = p
        return p

    def _ema_alpha(self, elapsed_hours: float) -> float:
        # Convert elapsed time to EMA alpha using a decay horizon.
        # alpha ~ 1-exp(-dt/T). Clamp for stability.
        T = float(self._profile_decay_hours)
        if T <= 0:
            return 0.2
        a = 1.0 - math.exp(-max(0.0, elapsed_hours) / T)
        return max(0.005, min(0.35, a))

    def _update_user_profile(self, user: str, ts: datetime, signal: Dict[str, float]) -> Dict[str, Any]:
        p = self._get_user_profile(user)
        last_ts = float(p.get("last_ts") or 0.0)
        now_ts = float(ts.timestamp())
        elapsed_h = 0.0 if last_ts <= 0 else max(0.0, (now_ts - last_ts) / 3600.0)
        alpha = self._ema_alpha(elapsed_h)

        is_off = 1.0 if (ts.hour < 8 or ts.hour >= 18) else 0.0
        p["ema_off_hours"] = (1 - alpha) * float(p.get("ema_off_hours", 0.0)) + alpha * is_off
        p["ema_external"] = (1 - alpha) * float(p.get("ema_external", 0.0)) + alpha * float(signal.get("is_external", 0.0))
        p["ema_clipboard"] = (1 - alpha) * float(p.get("ema_clipboard", 0.0)) + alpha * float(signal.get("is_clipboard", 0.0))
        p["ema_risky_app"] = (1 - alpha) * float(p.get("ema_risky_app", 0.0)) + alpha * float(signal.get("app_risky", 0.0))

        try:
            hh = p.get("hour_hist")
            if isinstance(hh, list) and len(hh) == 24:
                hh[ts.hour] = int(hh[ts.hour] or 0) + 1
        except Exception:
            pass

        p["n"] = int(p.get("n") or 0) + 1
        p["last_ts"] = now_ts
        self._profile_dirty += 1
        self._save_profiles(force=False)
        return p

    def _baseline_drift_score(self, ts: datetime, signal: Dict[str, float], profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score how far the current event deviates from the user's long-term baseline.
        Output is [0..10] and a list of reasons for defendability.
        """
        n = int(profile.get("n") or 0)
        if n < self._profile_min_events:
            _ml_debug(f"[BaselineDrift] User profile warmup: n={n} < {self._profile_min_events}")
            return {"score": 0.0, "reasons": ["baseline_warmup"], "n": n}

        off_b = float(profile.get("ema_off_hours") or 0.0)
        ext_b = float(profile.get("ema_external") or 0.0)
        clip_b = float(profile.get("ema_clipboard") or 0.0)
        risky_b = float(profile.get("ema_risky_app") or 0.0)

        is_off = 1.0 if (ts.hour < 8 or ts.hour >= 18) else 0.0
        is_ext = float(signal.get("is_external") or 0.0)
        is_clip = float(signal.get("is_clipboard") or 0.0)
        is_risky = float(signal.get("app_risky") or 0.0)

        score = 0.0
        reasons: List[str] = []

        # Off-hours: only strong when user rarely works off-hours.
        if is_off > 0 and off_b < 0.10:
            score += 2.4
            reasons.append(f"off_hours_vs_baseline(p={off_b:.2f})")
        elif is_off > 0 and off_b < 0.25:
            score += 1.2
            reasons.append(f"off_hours_elevated(p={off_b:.2f})")

        # External channel (USB/cloud/messaging domain signals): strong when baseline is low.
        if is_ext > 0 and ext_b < 0.05:
            score += 3.2
            reasons.append(f"external_channel_first_time(p={ext_b:.2f})")
        elif is_ext > 0 and ext_b < 0.15:
            score += 1.6
            reasons.append(f"external_channel_rare(p={ext_b:.2f})")

        # Clipboard paste: spike is handled by short-term profile; here we detect baseline drift.
        if is_clip > 0 and clip_b < 0.05:
            score += 1.2
            reasons.append(f"clipboard_unusual(p={clip_b:.2f})")

        # Risky app usage: when baseline risky-app is low.
        if is_risky > 0 and risky_b < 0.10:
            score += 1.3
            reasons.append(f"risky_app_unusual(p={risky_b:.2f})")

        # Sequence synergy: off-hours + external + risky app is strong.
        if is_off > 0 and is_ext > 0 and is_risky > 0:
            score += 1.4
            reasons.append("sequence_offhours_external_riskyapp")
        elif is_off > 0 and is_ext > 0:
            score += 0.8
            reasons.append("sequence_offhours_external")

        _ml_debug(
            f"[BaselineDrift] n={n}, is_off={is_off:.0f}, is_ext={is_ext:.0f}, "
            f"is_clip={is_clip:.0f}, is_risky={is_risky:.0f}, "
            f"baseline_offs={off_b:.3f}, ext={ext_b:.3f}, clip={clip_b:.3f}, risky={risky_b:.3f}, "
            f"score={score:.2f}, reasons={reasons}"
        )

        return {"score": _clamp_0_10(score), "reasons": reasons, "n": n}

    def _profile_deviation(self, event: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        now = self._parse_ts(event)
        user = self._extract_user(event)
        user_hist = [e for e in history if self._extract_user(e) == user]
        try:
            from worker.config import WorkerConfig
            clipboard_window_sec = int(getattr(WorkerConfig, "UEBA_CLIPBOARD_SPIKE_WINDOW_SEC", 120))
            fragment_window_sec = int(getattr(WorkerConfig, "UEBA_FRAGMENT_WINDOW_SEC", 120))
            external_window_sec = int(getattr(WorkerConfig, "UEBA_EXTERNAL_SPIKE_WINDOW_SEC", 120))
            clipboard_elevated_count = int(getattr(WorkerConfig, "UEBA_CLIPBOARD_ELEVATED_COUNT", 12))
            clipboard_spike_count = int(getattr(WorkerConfig, "UEBA_CLIPBOARD_SPIKE_COUNT", 20))
            fragment_suspicious_count = int(getattr(WorkerConfig, "UEBA_FRAGMENT_SUSPICIOUS_COUNT", 8))
            fragment_exfil_count = int(getattr(WorkerConfig, "UEBA_FRAGMENT_EXFIL_COUNT", 10))
            external_elevated_count = int(getattr(WorkerConfig, "UEBA_EXTERNAL_ELEVATED_COUNT", 3))
            external_spike_count = int(getattr(WorkerConfig, "UEBA_EXTERNAL_SPIKE_COUNT", 6))
        except Exception:
            clipboard_window_sec = 120
            fragment_window_sec = 120
            external_window_sec = 120
            clipboard_elevated_count = 12
            clipboard_spike_count = 20
            fragment_suspicious_count = 8
            fragment_exfil_count = 10
            external_elevated_count = 3
            external_spike_count = 6
        clipboard_window_sec = max(1, clipboard_window_sec)
        fragment_window_sec = max(1, fragment_window_sec)
        external_window_sec = max(1, external_window_sec)
        clipboard_elevated_count = max(1, clipboard_elevated_count)
        clipboard_spike_count = max(clipboard_elevated_count, clipboard_spike_count)
        fragment_suspicious_count = max(1, fragment_suspicious_count)
        fragment_exfil_count = max(fragment_suspicious_count, fragment_exfil_count)
        external_elevated_count = max(1, external_elevated_count)
        external_spike_count = max(external_elevated_count, external_spike_count)

        recent_clipboard = []
        recent_fragments = []
        recent_external = []
        for e in user_hist:
            dt = self._parse_ts(e)
            delta = (now - dt).total_seconds()
            if 0 <= delta <= clipboard_window_sec:
                recent_clipboard.append(e)
            if 0 <= delta <= fragment_window_sec:
                recent_fragments.append(e)
            if 0 <= delta <= external_window_sec:
                recent_external.append(e)

        off_hours_hist = 0
        for e in user_hist[-200:]:
            h = self._parse_ts(e).hour
            if h < 8 or h >= 18:
                off_hours_hist += 1
        off_hours_ratio = (off_hours_hist / max(1, len(user_hist[-200:]))) if user_hist else 0.0
        is_off_hours = 1.0 if (now.hour < 8 or now.hour >= 18) else 0.0

        signal = self._event_signals(event)
        clipboard_count = sum(
            1 for e in recent_clipboard if self._event_signals(e)["is_clipboard"] > 0
        )
        ext_count_window = sum(
            1 for e in recent_external if self._event_signals(e)["is_external"] > 0
        )
        ext_baseline = sum(
            1 for e in user_hist[-200:] if self._event_signals(e)["is_external"] > 0
        ) / max(1, min(200, len(user_hist)))

        deviation = 0.0
        reasons: List[str] = []

        # Case 1 guard: off-hours alone should only raise slightly.
        if is_off_hours and off_hours_ratio < 0.08:
            deviation += 1.0
            reasons.append("off_hours_deviation")

        if clipboard_count >= clipboard_spike_count:
            deviation += 1.2
            reasons.append(f"clipboard_spike_{clipboard_window_sec}s")
        elif clipboard_count >= clipboard_elevated_count:
            deviation += 0.6
            reasons.append(f"clipboard_elevated_{clipboard_window_sec}s")
            
        # Fragmented Exfiltration Check
        small_clip_ext_window = sum(
            1 for e in recent_fragments
            if self._event_signals(e).get("is_small_fragment", 0.0) > 0 
            and (self._event_signals(e)["is_external"] > 0 or self._event_signals(e)["app_risky"] > 0)
        )

        if small_clip_ext_window >= fragment_exfil_count:
            deviation += 2.5
            reasons.append(f"fragmented_exfiltration_{fragment_window_sec}s({small_clip_ext_window})")
        elif small_clip_ext_window >= fragment_suspicious_count:
            deviation += 1.0
            reasons.append(f"suspicious_fragments_{fragment_window_sec}s({small_clip_ext_window})")

        if ext_count_window >= external_spike_count:
            deviation += 2.2
            reasons.append(f"external_channel_spike_{external_window_sec}s")
        elif ext_count_window >= external_elevated_count:
            deviation += 1.0
            reasons.append(f"external_channel_elevated_{external_window_sec}s")

        if ext_baseline < 0.05 and signal["is_external"] > 0:
            deviation += 1.2
            reasons.append("channel_baseline_drift")

        if signal["app_risky"] > 0 and signal["is_clipboard"] > 0 and small_clip_ext_window < 2:
            deviation += 1.0
            reasons.append("risky_app_clipboard_sequence")

        if signal["is_archive"] > 0 or signal["is_rename_like"] > 0:
            deviation += 0.9
            reasons.append("transformation_signal")

        # Debug logging
        _ml_debug(
            f"[ProfileDeviation] User={user}, is_off={is_off_hours:.0f}, "
            f"off_ratio={off_hours_ratio:.3f}, clip_10m={clipboard_count}, "
            f"ext_window={ext_count_window}, ext_base={ext_baseline:.3f}, "
            f"small_clip_ext={small_clip_ext_window}, signal={signal}, "
            f"deviation={deviation:.2f}, reasons={reasons}"
        )

        return {
            "score": _clamp_0_10(deviation),
            "reasons": reasons,
            "off_hours_ratio": round(off_hours_ratio, 3),
            "clipboard_10m": clipboard_count,
            "external_1h": ext_count_window,
        }

    def _update_accumulator(self, user: str, ts: datetime, profile_score: float, signal: Dict[str, float]) -> float:
        state = self._accumulator.get(user, {"value": 0.0, "ts": ts.timestamp()})
        elapsed_h = max(0.0, (ts.timestamp() - float(state["ts"])) / 3600.0)
        decay = math.exp(-elapsed_h / 6.0)  # ~6h half-life-like decay
        value = float(state["value"]) * decay

        incremental = 0.0
        if signal["is_external"] > 0:
            incremental += 0.45
        if signal["is_archive"] > 0 or signal["is_rename_like"] > 0:
            incremental += 0.35
            
        # Fragmented Exfiltration accelerates accumulation significantly
        if signal.get("is_small_fragment", 0.0) > 0 and (signal["is_external"] > 0 or signal["app_risky"] > 0):
            incremental += 1.2
            
        if profile_score >= 2.0:
            incremental += min(0.6, profile_score / 10.0)

        value = min(6.0, value + incremental)  # Cap tại 6.0 để cho phép fragmented exfil tích lũy đủ để trigger alert (previous cap: 3.0)

        self._accumulator[user] = {"value": value, "ts": ts.timestamp()}
        
        _ml_debug(
            f"[Accumulator] User={user}, elapsed_h={elapsed_h:.2f}, decay={decay:.3f}, "
            f"old_value={float(state['value']):.3f}, incremental={incremental:.3f}, "
            f"new_value={value:.3f}"
        )
        
        return value

    def predict(self, event: Dict[str, Any], event_history: Optional[list] = None) -> Dict[str, Any]:
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        if not self.is_loaded or self.model is None:
            _ml_debug("ML: Model not loaded, returning 0.0")
            return {"anomaly_score": 0.0, "is_anomaly": False, "features": None, "error": "Model not loaded"}

        try:
            history = event_history or []
            user = self._extract_user(event)
            ts = self._parse_ts(event)
            event_type = str(event.get("type") or event.get("event_type") or "").lower()
            
            _ml_debug(f"[ML DEBUG] === New Event ===")
            _ml_debug(f"[ML DEBUG] User: {user}, Type: {event_type}, Time: {ts}")

            if history:
                self.feature_extractor.event_history = history
                _ml_debug(f"[ML DEBUG] History size: {len(history)} events")

            raw_features = self.feature_extractor.extract(event)
            model_features = self._model_input_features(raw_features)
            model_features_2d = model_features.reshape(1, -1)
            if self.scaler is not None:
                model_features_2d = self.scaler.transform(model_features_2d)

            raw_score = float(self.model.decision_function(model_features_2d)[0])
            try:
                from worker.config import WorkerConfig
            except Exception:
                WorkerConfig = None

            if WorkerConfig is not None:
                model_score = _normalize_anomaly_raw(raw_score, WorkerConfig)
                threshold = float(getattr(WorkerConfig, "ML_ANOMALY_THRESHOLD", 7.0))
                boost_factor = float(getattr(WorkerConfig, "ML_ANOMALY_RISK_BOOST_FACTOR", 1.0))
            else:
                model_score = _clamp_0_10((raw_score + 1.0) * 5.0)
                threshold = 7.0
                boost_factor = 1.0

            _ml_debug(f"[ML DEBUG] Raw score: {raw_score:.4f} -> Model score: {model_score:.2f}, Threshold: {threshold:.2f}")

            profile = self._profile_deviation(event, history)
            signal = self._event_signals(event)
            user_profile = self._update_user_profile(user, ts, signal)
            baseline = self._baseline_drift_score(ts, signal, user_profile)
            accum = self._update_accumulator(user, ts, float(profile["score"]), signal)

            anomaly_score = _clamp_0_10(
                model_score * 0.65
                + float(profile["score"]) * 0.25
                + float(baseline["score"]) * 0.10
                + accum * max(0.0, min(1.0, boost_factor))
            )
            is_anomaly = anomaly_score >= threshold

            # Detailed breakdown logging
            _ml_debug(f"[ML DEBUG] Score Breakdown:")
            _ml_debug(f"  - Model Score:     {model_score:.3f} x 0.65 = {model_score * 0.65:.3f}")
            _ml_debug(f"  - Profile Score:  {profile['score']:.3f} x 0.25 = {float(profile['score']) * 0.25:.3f}")
            _ml_debug(f"  - Baseline Score: {baseline['score']:.3f} x 0.10 = {float(baseline['score']) * 0.10:.3f}")
            _ml_debug(f"  - Slow Burn:      {accum:.3f} x {boost_factor:.2f} = {accum * boost_factor:.3f}")
            _ml_debug(f"  - TOTAL: {anomaly_score:.3f}, Is Anomaly: {is_anomaly}")
            _ml_debug(f"[ML DEBUG] Profile reasons: {profile['reasons']}")
            _ml_debug(f"[ML DEBUG] Baseline reasons: {baseline['reasons']}")
            _ml_debug(f"[ML DEBUG] Signal flags: {signal}")

            return {
                "anomaly_score": float(anomaly_score),
                "is_anomaly": bool(is_anomaly),
                "features": raw_features,
                "raw_score": raw_score,
                "model_score": round(model_score, 3),
                "profile_score": round(float(profile["score"]), 3),
                "baseline_score": round(float(baseline["score"]), 3),
                "slow_burn_score": round(accum, 3),
                "profile_reasons": profile["reasons"],
                "baseline_reasons": baseline["reasons"],
                "baseline_n": int(baseline.get("n") or 0),
            }
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return {"anomaly_score": 0.0, "is_anomaly": False, "features": None, "error": str(e)}

    def is_available(self) -> bool:
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        return self.is_loaded and self.model is not None
    
    def analyze_combined_content(self, combined_text: str) -> Dict[str, Any]:
        """
        Phân tích combined content từ nhiều fragments.
        
        ĐÂY LÀ TÍNH NĂNG ML để cover case "attacker chia nhỏ dữ liệu để né YARA".
        Khi các fragments được gom lại, ML sẽ phân tích:
        1. Entity extraction (CCCD, phone, email, bank account...)
        2. Semantic classification (contract, personal_info, financial...)
        3. Sensitive content detection
        
        Args:
            combined_text: Text đã gom từ nhiều fragments
            
        Returns:
            Dict chứa:
            - entities: Dict[str, int] - count của mỗi loại entity
            - semantic_categories: Dict[str, float] - semantic scores
            - is_sensitive: bool - True nếu phát hiện sensitive content
            - risk_level: str - 'low', 'medium', 'high', 'critical'
        """
        try:
            # 1. Entity extraction sử dụng MLContentAnalyzer
            entities = {}
            try:
                from .content_fingerprint import MLContentAnalyzer
                ml_analyzer = MLContentAnalyzer()
                analysis = ml_analyzer.analyze_content(combined_text)
                
                if analysis:
                    # Trích xuất entities từ ML analysis
                    for entity_type, count in analysis.items():
                        if isinstance(entity_type, str) and entity_type.startswith('_'):
                            continue
                        if isinstance(count, (int, float)) and count > 0:
                            entities[entity_type] = int(count)
            except Exception as e:
                logger.debug(f"[MLAnalyzer] Entity extraction failed: {e}")
            
            # 2. Regex-based entity extraction cho structured data
            # CCCD/CMND (9 hoặc 12 số)
            import re
            cccd_pattern = r'\b\d{9}\b|\b\d{12}\b'
            cccd_matches = re.findall(cccd_pattern, combined_text)
            if cccd_matches:
                entities['cccd'] = max(entities.get('cccd', 0), len(cccd_matches))
            
            # Phone numbers (10-11 số, bắt đầu bằng 0)
            phone_pattern = r'\b0\d{9,10}\b'
            phone_matches = re.findall(phone_pattern, combined_text)
            if phone_matches:
                entities['phone'] = max(entities.get('phone', 0), len(set(phone_matches)))
            
            # Email
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            email_matches = re.findall(email_pattern, combined_text, re.IGNORECASE)
            if email_matches:
                entities['email'] = max(entities.get('email', 0), len(set(email_matches)))
            
            # Bank account (số có 10-14 chữ số)
            bank_pattern = r'\b\d{10,14}\b'
            bank_matches = re.findall(bank_pattern, combined_text)
            if bank_matches:
                entities['bank_account'] = max(entities.get('bank_account', 0), len(bank_matches))
            
            # 3. Semantic classification
            semantic_categories = {}
            text_lower = combined_text.lower()
            
            # Contract/legal keywords
            contract_keywords = ['hợp đồng', 'hđtt', 'bên a', 'bên b', 'điều khoản', 
                               'thỏa thuận', 'cam kết', 'quyền và nghĩa vụ']
            contract_score = sum(1 for kw in contract_keywords if kw in text_lower) / len(contract_keywords)
            if contract_score > 0:
                semantic_categories['contract'] = contract_score
            
            # Personal info keywords
            personal_keywords = ['họ tên', 'ngày sinh', 'nơi sinh', 'địa chỉ', 'cmnd', 'cccd',
                               'passport', 'sinh viên', 'nhân viên']
            personal_score = sum(1 for kw in personal_keywords if kw in text_lower) / len(personal_keywords)
            if personal_score > 0:
                semantic_categories['personal_info'] = personal_score
            
            # Financial keywords
            financial_keywords = ['tiền', 'vnd', 'đồng', 'thanh toán', 'chuyển khoản', 
                                'tài khoản', 'lương', 'thu nhập']
            financial_score = sum(1 for kw in financial_keywords if kw in text_lower) / len(financial_keywords)
            if financial_score > 0:
                semantic_categories['financial'] = financial_score
            
            # 4. Sensitive content detection
            sensitive_keywords = {
                'critical': ['mật khẩu', 'password', 'secret', 'key', 'api_key', 'token'],
                'high': ['cccd', 'cmnd', 'số chứng minh', 'credit card', 'bank account'],
                'medium': ['email', 'phone', 'sđt', 'điện thoại']
            }
            
            is_sensitive = False
            sensitivity_level = 'none'
            
            for level in ['critical', 'high', 'medium']:
                if any(kw in text_lower for kw in sensitive_keywords[level]):
                    is_sensitive = True
                    sensitivity_level = level
                    break
            
            # 5. Risk assessment
            entity_count = sum(entities.values())
            risk_score = 0.0
            
            # Risk từ entities
            if entities.get('cccd', 0) > 0 or entities.get('cmnd', 0) > 0:
                risk_score += 3.0
            if entities.get('bank_account', 0) > 0:
                risk_score += 2.0
            if entities.get('phone', 0) > 2:
                risk_score += 1.5
            if entities.get('email', 0) > 3:
                risk_score += 1.0
            
            # Risk từ semantic categories
            risk_score += semantic_categories.get('contract', 0) * 2.0
            risk_score += semantic_categories.get('personal_info', 0) * 2.0
            risk_score += semantic_categories.get('financial', 0) * 1.5
            
            # Risk từ sensitive content
            if sensitivity_level == 'critical':
                risk_score += 3.0
            elif sensitivity_level == 'high':
                risk_score += 2.0
            elif sensitivity_level == 'medium':
                risk_score += 1.0
            
            # Determine risk level
            risk_level = 'low'
            if risk_score >= 8.0:
                risk_level = 'critical'
            elif risk_score >= 5.0:
                risk_level = 'high'
            elif risk_score >= 3.0:
                risk_level = 'medium'
            
            result = {
                'entities': entities,
                'entity_count': entity_count,
                'semantic_categories': semantic_categories,
                'is_sensitive': is_sensitive,
                'sensitivity_level': sensitivity_level,
                'risk_score': min(10.0, risk_score),
                'risk_level': risk_level,
                'content_length': len(combined_text),
                'fragment_combined': True
            }
            
            logger.debug(
                f"[MLAnalyzer] Combined content analysis: "
                f"entities={entities}, risk_level={risk_level}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"[MLAnalyzer] Error analyzing combined content: {e}")
            return {
                'entities': {},
                'entity_count': 0,
                'semantic_categories': {},
                'is_sensitive': False,
                'sensitivity_level': 'none',
                'risk_score': 0.0,
                'risk_level': 'low',
                'content_length': 0,
                'error': str(e)
            }
