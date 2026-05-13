"""
L2-style correlation: clipboard text (copy) → file on removable volume within a time window.

Phase 1: plain-text files only (.txt, .csv, .json, …). Matching: exact SHA-256 (same rules as
clipboard_sensor strip + utf-8), substring of captured snippet, then difflib similarity.

Controlled by env:
  CLIPBOARD_USB_ENABLED — default on (1/true/yes/on)
  CLIPBOARD_USB_WINDOW_SEC — default 120
  CLIPBOARD_USB_FILE_READ_MAX — max bytes read from destination file (default 2 MiB)
  CLIPBOARD_USB_SIMILARITY_THRESHOLD — default 0.85 for "similarity" tier
  CLIPBOARD_USB_SIMILARITY_LOOSE — default 0.70 when clipboard sensitivity is high
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from difflib import SequenceMatcher
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
from collections import deque as deque_cls


def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "").strip() or default)
    except Exception:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except Exception:
        return default


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


# Same strip semantics as clipboard_sensor._make_snapshot_from_text (before hash).
def _strip_like_clipboard_sensor(s: str) -> str:
    return (s or "").strip()


PHASE1_TEXT_EXTS = {
    ".txt",
    ".csv",
    ".log",
    ".json",
    ".xml",
    ".ini",
    ".env",
    ".md",
    ".tsv",
    ".yaml",
    ".yml",
}


def _ext_from_path(path: str) -> str:
    p = (path or "").strip().lower()
    if "." not in p:
        return ""
    return "." + p.rsplit(".", 1)[-1]


def _read_file_text(path: str, max_bytes: int, retries: int = 3) -> Optional[str]:
    delay = 0.12
    for attempt in range(retries):
        try:
            with open(path, "rb") as f:
                raw = f.read(max_bytes)
            if raw.startswith(b"\xff\xfe"):
                text = raw.decode("utf-16-le", errors="replace")
            elif raw.startswith(b"\xfe\xff"):
                text = raw.decode("utf-16-be", errors="replace")
            else:
                text = raw.decode("utf-8", errors="replace")
            return text
        except OSError:
            if attempt + 1 < retries:
                time.sleep(delay)
                delay *= 1.5
            return None
    return None


def _sensitivity_tier(s: str) -> int:
    sl = (s or "").lower()
    if "highly" in sl:
        return 2
    if "sensitive" in sl:
        return 1
    return 0


class ClipboardUsbMatcher:
    """
    Keeps recent clipboard text copies and, on file create/modify on Removable volumes,
    tries to correlate content with on-disk file text.
    """

    def __init__(
        self,
        *,
        clip_window_sec: Optional[float] = None,
        dedupe_window_sec: float = 30.0,
        dedupe_fn: Optional[Callable[[str, float], bool]] = None,
    ) -> None:
        self.clip_window_sec = clip_window_sec if clip_window_sec is not None else _env_float("CLIPBOARD_USB_WINDOW_SEC", 120.0)
        self._file_read_max = _env_int("CLIPBOARD_USB_FILE_READ_MAX", 2 * 1024 * 1024)
        self._sim_hi = _env_float("CLIPBOARD_USB_SIMILARITY_THRESHOLD", 0.85)
        self._sim_lo = _env_float("CLIPBOARD_USB_SIMILARITY_LOOSE", 0.70)
        self._enabled = _env_bool("CLIPBOARD_USB_ENABLED", True)
        self._dedupe_window_sec = float(dedupe_window_sec)
        self._dedupe_fn = dedupe_fn

        self._entries: Deque[Dict[str, Any]] = deque_cls()
        self._max_entries = 256
        self._recent_keys: Deque[Tuple[float, str]] = deque_cls()

    def _trim(self, now: float) -> None:
        cutoff = now - self.clip_window_sec
        while self._entries:
            ts = float(self._entries[0].get("_ts_unix", 0.0) or 0.0)
            if ts >= cutoff:
                break
            self._entries.popleft()

    def _dedupe_ok(self, key: str, now: float) -> bool:
        if self._dedupe_fn is not None:
            return bool(self._dedupe_fn(key, now))
        cutoff = now - self._dedupe_window_sec
        while self._recent_keys and self._recent_keys[0][0] < cutoff:
            self._recent_keys.popleft()
        for _, k in self._recent_keys:
            if k == key:
                return False
        self._recent_keys.append((now, key))
        return True

    def record_clipboard_copy(self, evt: Dict[str, Any], now_unix: float) -> None:
        if not self._enabled:
            return
        self._trim(now_unix)

        etype = str(evt.get("type") or "").lower()
        if etype not in ("clipboard_copy", "clipboard_text"):
            return

        ctype = str(
            evt.get("content_type")
            or (evt.get("clipboard") or {}).get("content_type")
            or ""
        ).lower()
        if ctype != "text":
            return

        clip = evt.get("clipboard") if isinstance(evt.get("clipboard"), dict) else {}
        content_hash = clip.get("content_hash") or evt.get("content_hash")
        if not content_hash:
            return

        text_plain = clip.get("text_file") or clip.get("content")
        if text_plain is not None:
            text_plain = str(text_plain)
        content_len = clip.get("content_len") or clip.get("text_len") or (len(text_plain) if text_plain else 0)
        try:
            content_len = int(content_len)
        except Exception:
            content_len = len(text_plain or "")

        ctx = evt.get("context") if isinstance(evt.get("context"), dict) else {}
        actor = evt.get("actor") if isinstance(evt.get("actor"), dict) else {}
        user = actor.get("user") or ctx.get("user")

        sensitivity = str(clip.get("sensitivity") or (evt.get("object") or {}).get("sensitivity") or "")

        entry = {
            "_ts_unix": now_unix,
            "clipboard_id": str(clip.get("clipboard_id") or uuid.uuid4()),
            "content_hash": str(content_hash),
            "content_len": content_len,
            "text_plain": text_plain,
            "user": str(user) if user else None,
            "sensitivity": sensitivity,
            "source_app": str(clip.get("source_app") or clip.get("source_process") or ""),
            "ioc_hits_count": len(evt.get("ioc_hits") or []) if isinstance(evt.get("ioc_hits"), list) else 0,
            "event_id": evt.get("event_id"),
        }
        self._entries.append(entry)
        while len(self._entries) > self._max_entries:
            self._entries.popleft()

    def correlate_file_on_removable(
        self,
        evt: Dict[str, Any],
        now_unix: float,
        *,
        path: str,
        volume_type: str,
        etype: str,
        op_type: str,
        build_actor: Callable[[Dict[str, Any]], Dict[str, Any]],
        build_context: Callable[[Dict[str, Any]], Dict[str, Any]],
        iso_from_ts: Callable[[float], str],
        sev_fn: Callable[[str], Any],
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not self._enabled:
            return out
        self._trim(now_unix)

        vt = (volume_type or "").lower()
        if "removable" not in vt:
            return out

        ext = _ext_from_path(path)
        if ext not in PHASE1_TEXT_EXTS:
            return out

        file_text = _read_file_text(path, self._file_read_max)
        if file_text is None:
            return out

        stripped_file = _strip_like_clipboard_sensor(file_text)
        if not stripped_file:
            return out
        file_hash = _sha256_text(stripped_file)

        ctx_evt = evt.get("context") if isinstance(evt.get("context"), dict) else {}
        actor_evt = evt.get("actor") if isinstance(evt.get("actor"), dict) else {}
        file_user = actor_evt.get("user") or ctx_evt.get("user")

        obj = evt.get("object") if isinstance(evt.get("object"), dict) else {}
        file_sensitivity = str(obj.get("sensitivity") or evt.get("File_Sensitivity") or "")

        best: Optional[Tuple[float, float, Dict[str, Any]]] = None  # (confidence, ts_e, corr_raw)

        for ent in reversed(list(self._entries)):
            ts_e = float(ent.get("_ts_unix", 0.0) or 0.0)
            if now_unix - ts_e > self.clip_window_sec:
                continue

            eu = ent.get("user")
            if eu and file_user and str(eu).lower() != str(file_user).lower():
                continue

            clip_hash = str(ent.get("content_hash") or "")
            snippet = ent.get("text_plain")
            snippet = str(snippet) if snippet else ""
            clip_sens = str(ent.get("sensitivity") or "")
            tier = _sensitivity_tier(clip_sens)

            match_kind: Optional[str] = None
            confidence: float = 0.0
            extra: Dict[str, Any] = {}

            if clip_hash and file_hash == clip_hash:
                match_kind = "exact_hash"
                confidence = 0.95
            elif snippet and len(snippet) >= 8 and snippet in stripped_file:
                match_kind = "substring"
                confidence = 0.90
                extra["snippet_len"] = len(snippet)
            elif snippet and len(snippet) >= 24:
                window = stripped_file[: max(len(snippet) * 4, 4000)]
                ratio = SequenceMatcher(a=snippet, b=window).ratio()
                extra["similarity_ratio"] = round(ratio, 4)
                thresh = self._sim_lo if tier >= 1 or ent.get("ioc_hits_count", 0) > 0 else self._sim_hi
                if ratio >= self._sim_hi:
                    match_kind = "similarity"
                    confidence = 0.75
                elif ratio >= thresh and tier >= 2:
                    match_kind = "similarity"
                    confidence = 0.65

            if not match_kind:
                continue

            dedupe_key = f"clipusb:{path}:{ent.get('clipboard_id')}:{match_kind}"
            if not self._dedupe_ok(dedupe_key, now_unix):
                continue

            sev = "info"
            if match_kind == "exact_hash" and tier >= 1:
                sev = "high"
            elif match_kind == "exact_hash":
                sev = "warn"
            elif match_kind == "substring" and tier >= 1:
                sev = "high"
            elif match_kind == "substring":
                sev = "warn"
            elif tier >= 2:
                sev = "warn"
            else:
                sev = "info"

            proc_name = str(actor_evt.get("process") or ctx_evt.get("fg_process") or ctx_evt.get("fg_app") or "")

            corr_raw = {
                "type": "clipboard_text_written_to_usb",
                "source": "correlator",
                "severity": sev_fn(sev),
                "ts": iso_from_ts(now_unix),
                "tags": ["clipboard_usb", "usb", "clipboard", "exfil_chain"],
                "actor": build_actor(evt),
                "context": build_context(evt),
                "operation": {
                    "op_type": "clipboard_text_written_to_usb",
                    "tool": proc_name or None,
                    "confidence": confidence,
                    "match_kind": match_kind,
                    "clipboard_id": ent.get("clipboard_id"),
                    "source_clipboard_event_id": ent.get("event_id"),
                    "clipboard_age_sec": round(now_unix - ts_e, 3),
                },
                "object": {
                    "path": path,
                    "dst_path": None,
                    "drive": obj.get("drive") or evt.get("drive"),
                    "volume_type": "Removable",
                    "sensitivity": file_sensitivity or clip_sens or None,
                    "ext": ext,
                },
                "clipboard": {
                    "clipboard_id": ent.get("clipboard_id"),
                    "content_hash": clip_hash,
                    "content_len": ent.get("content_len"),
                    "sensitivity": clip_sens or None,
                    "source_app": ent.get("source_app") or None,
                },
                "debug": {
                    "evidence": {
                        "source_file_event_type": etype,
                        "source_file_op_type": op_type,
                        "file_sha256_after_strip": file_hash,
                        "match_kind": match_kind,
                        "confidence": confidence,
                        **extra,
                    }
                },
            }
            cand = (confidence, ts_e, corr_raw)
            if best is None or cand[0] > best[0] or (cand[0] == best[0] and cand[1] > best[1]):
                best = cand

        if best:
            out.append(best[2])
        return out
