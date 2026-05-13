from __future__ import annotations

import time
import os
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from agent.event_schema import normalize_event
from agent.sensors.clipboard_usb_matcher import ClipboardUsbMatcher

__all__ = ["ContextCorrelator"]

ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}

BROWSER_PROCS = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
}

TRANSFER_PROCS = {
    "code.exe",
    "slack.exe",
    "teams.exe",
    "discord.exe",
    "telegram.exe",
    "outlook.exe",
    "onedrive.exe",
    "dropbox.exe",
    "whatsapp.exe",
    "zalo.exe",
    "signal.exe",
    "skype.exe",
    "filezilla.exe",
    "winscp.exe",
    "curl.exe",
    "powershell.exe",
    "pwsh.exe",
    "python.exe",
    "pythonw.exe",
    "wget.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "scp.exe",
    "sftp.exe",
    "ftp.exe",
    "rclone.exe",
    "cmd.exe",
}

UPLOAD_DOMAIN_HINTS = {
    "google",
    "googleusercontent",
    "drive.google",
    "docs.google",
    "dropbox",
    "onedrive",
    "sharepoint",
    "mega",
    "discord",
    "slack",
    "telegram",
    "teams",
    "gmail",
    "outlook",
    "chatgpt",
    "openai",
    "oaistatic",
    "claude",
    "anthropic",
    "gemini",
    "bard",
    "copilot",
    "perplexity",
    "box",
    "icloud",
    "pastebin",
    "github",
    "gitlab",
    "bitbucket",
    "facebook",
    "messenger",
    "zalo",
    "whatsapp",
    "signal",
    "line",
    "linkedin",
    "reddit",
    "tiktok",
    "x.com",
    "twitter",
    "wetransfer",
    "mediafire",
    "sendspace",
}

GPT_HINTS = {"chatgpt", "openai", "oaistatic"}

SENSITIVE_TITLE_HINTS = [
    "chatgpt",
    "openai",
    "claude",
    "gemini",
    "bard",
    "copilot",
    "perplexity",
    "gmail",
    "google mail",
    "outlook",
    "yahoo mail",
    "proton mail",
    "google drive",
    "dropbox",
    "onedrive",
    "mega",
    "box",
    "icloud",
    "slack",
    "teams",
    "discord",
    "telegram",
    "whatsapp",
    "messenger",
    "line",
    "signal",
    "zalo",
    "facebook",
    "instagram",
    "twitter",
    "x.com",
    "linkedin",
    "reddit",
    "tiktok",
    "pastebin",
    "github gist",
    "gitlab",
    "bitbucket",
    "replit",
    "wetransfer",
    "sendspace",
    "mediafire",
]


def _iso_from_ts(ts: Any) -> str:
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    if isinstance(ts, str) and ts.strip():
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
        except Exception:
            pass
    return datetime.now(timezone.utc).isoformat()


def _sev(level: str) -> int:
    lv = str(level or "").strip().lower()
    if lv in {"none", "null", ""}:
        return 0
    if lv in {"critical", "crit"}:
        return 90
    if lv in {"high", "error"}:
        return 70
    if lv in {"warn", "warning", "medium"}:
        return 50
    if lv in {"low", "info"}:
        return 30
    return 50


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default


def _get_nested(evt: Dict[str, Any], path: str, default=None):
    cur: Any = evt
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
    return cur if cur is not None else default


def _evt_ts_unix(evt: Dict[str, Any], fallback: float) -> float:
    ts = evt.get("ts")
    if isinstance(ts, (int, float)):
        return float(ts)

    if isinstance(ts, str) and ts.strip():
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return fallback

    return fallback


def _evt_path(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "object.path", None)
        or evt.get("path")
        or evt.get("File_Path")
        or ""
    )


def _evt_dst_path(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "object.dst_path", None)
        or evt.get("dst_path")
        or evt.get("Dest_Path")
        or ""
    )


def _evt_ext(evt: Dict[str, Any]) -> str:
    ext = (
        _get_nested(evt, "object.ext", None)
        or evt.get("ext")
        or evt.get("File_Extension")
        or ""
    )
    ext = str(ext or "")
    if ext:
        return ext.lower()

    path = _evt_path(evt) or _evt_dst_path(evt)
    if "." in path:
        return "." + path.rsplit(".", 1)[-1].lower()
    return ""


def _evt_size(evt: Dict[str, Any]) -> Any:
    return (
        _get_nested(evt, "object.size", None)
        or evt.get("size")
        or evt.get("file_size")
        or evt.get("File_Size")
        or None
    )


def _evt_drive(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "object.drive", None)
        or evt.get("drive")
        or _get_nested(evt, "usb.drive", None)
        or ""
    )


def _evt_context(evt: Dict[str, Any]) -> Dict[str, Any]:
    ctx = evt.get("context") or {}
    return ctx if isinstance(ctx, dict) else {}


def _evt_actor_user(evt: Dict[str, Any]) -> Optional[str]:
    u = _get_nested(evt, "actor.user", None)
    if u:
        return str(u)

    ctx = evt.get("context") or {}
    if isinstance(ctx, dict) and ctx.get("user"):
        return str(ctx.get("user"))

    proc = evt.get("process") or {}
    if isinstance(proc, dict) and proc.get("username"):
        return str(proc.get("username"))

    if evt.get("username"):
        return str(evt.get("username"))

    return None


def _evt_actor_pid(evt: Dict[str, Any]) -> Optional[int]:
    pid = (
        _get_nested(evt, "actor.pid", None)
        or _get_nested(evt, "process.pid", None)
        or _get_nested(evt, "context.fg_pid", None)
    )
    try:
        return int(pid) if pid is not None else None
    except Exception:
        return None


def _evt_process(evt: Dict[str, Any]) -> Dict[str, Any]:
    proc = evt.get("process") or {}
    return proc if isinstance(proc, dict) else {}


def _evt_actor_process_name(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "actor.process", None)
        or _get_nested(evt, "process.name", None)
        or _get_nested(evt, "context.fg_process", None)
        or _get_nested(evt, "context.fg_app", None)
        or ""
    ).lower()


def _evt_actor_cmdline(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "actor.cmdline", None)
        or _get_nested(evt, "process.cmdline", None)
        or _get_nested(evt, "context.fg_cmdline", None)
        or ""
    )


def _evt_window_title(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "clipboard.dest_window_title", None)
        or _get_nested(evt, "clipboard.active_window_title", None)
        or _get_nested(evt, "context.window_title", None)
        or ""
    ).lower()


def _evt_dest_domain(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "network.resolved_domain", None)
        or _get_nested(evt, "network.dest_domain", None)
        or _get_nested(evt, "context.resolved_domain", None)
        or _get_nested(evt, "clipboard.dest_domain", None)
        or _get_nested(evt, "context.dest_domain", None)
        or _get_nested(evt, "context.domain", None)
        or _get_nested(evt, "context.fg_domain", None)
        or _get_nested(evt, "debug.evidence.dest_domain", None)
        or ""
    ).lower()


def _evt_dest_url(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "network.dest_url", None)
        or _get_nested(evt, "context.fg_url_hint", None)
        or _get_nested(evt, "debug.evidence.dest_url", None)
        or ""
    ).lower()


def _evt_dest_ip(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "network.dest_ip", None)
        or _get_nested(evt, "context.dest_ip", None)
        or _get_nested(evt, "debug.evidence.dest_ip", None)
        or ""
    )


def _evt_bytes_sent(evt: Dict[str, Any]) -> int:
    return _safe_int(
        _get_nested(evt, "network.bytes_sent_total", None)
        or _get_nested(evt, "network.bytes_out_total", None)
        or _get_nested(evt, "metrics.bytes_out", None)
        or evt.get("bytes_out")
        or _get_nested(evt, "debug.evidence.bytes_sent_total", None)
        or _get_nested(evt, "debug.evidence.flow_sent_bytes", None)
        or _get_nested(evt, "debug.evidence.flow_bytes_out", None)
        or 0,
        default=0,
    )


def _evt_clipboard_len(evt: Dict[str, Any]) -> int:
    return _safe_int(
        evt.get("len")
        or _get_nested(evt, "clipboard.content_len", None)
        or _get_nested(evt, "clipboard.text_len", None)
        or 0,
        default=0,
    )


def _evt_clipboard_type(evt: Dict[str, Any]) -> str:
    return str(
        evt.get("content_type")
        or _get_nested(evt, "clipboard.content_type", None)
        or ""
    ).lower()


def _evt_clipboard_snapshot_linked(evt: Dict[str, Any]) -> bool:
    v = _get_nested(evt, "clipboard.snapshot_linked", None)
    if isinstance(v, bool):
        return v
    return bool(
        _get_nested(evt, "clipboard.copy_ts", None)
        and _get_nested(evt, "clipboard.content_hash", None)
    )


def _evt_clipboard_source_app(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "clipboard.source_app", None)
        or _get_nested(evt, "clipboard.source_process", None)
        or ""
    ).lower()


def _evt_clipboard_dest_app(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "clipboard.dest_app", None)
        or _get_nested(evt, "clipboard.dest_process", None)
        or ""
    ).lower()


def _evt_clipboard_preview(evt: Dict[str, Any]) -> Optional[str]:
    return (
        evt.get("preview")
        or _get_nested(evt, "content.sample", None)
        or _get_nested(evt, "clipboard.text_file", None)
        or _get_nested(evt, "clipboard.content", None)
    )


def _evt_clipboard_sensitivity(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "object.sensitivity", None)
        or evt.get("File_Sensitivity")
        or ""
    ).lower()


def _evt_file_sensitivity(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "object.sensitivity", None)
        or evt.get("File_Sensitivity")
        or ""
    ).lower()


def _evt_yara_hits(evt: Dict[str, Any]) -> List[Any]:
    v = _get_nested(evt, "fast_scan_result.yara_matches", None)
    if isinstance(v, list):
        return v
    v2 = _get_nested(evt, "debug.evidence.yara_matches", None)
    if isinstance(v2, list):
        return v2
    return []


def _evt_ioc_hits(evt: Dict[str, Any]) -> List[Any]:
    v = evt.get("ioc_hits")
    if isinstance(v, list):
        return v
    return []


def _evt_dest_volume_type(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "object.dest_volume_type", None)
        or _get_nested(evt, "object.volume_type", None)
        or evt.get("Dest_Volume_Type")
        or ""
    ).lower()


def _evt_op_type(evt: Dict[str, Any]) -> str:
    return str(_get_nested(evt, "operation.op_type", "") or "").lower()


def _evt_type(evt: Dict[str, Any]) -> str:
    return str(evt.get("type") or "").lower()


def _evt_service_name(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "operation.service_name", None)
        or _get_nested(evt, "context.service_name", None)
        or ""
    ).lower()


def _evt_service_category(evt: Dict[str, Any]) -> str:
    return str(
        _get_nested(evt, "operation.service_category", None)
        or _get_nested(evt, "context.service_category", None)
        or ""
    ).lower()


def _evt_resolved_from(evt: Dict[str, Any]) -> str:
    return str(_get_nested(evt, "context.resolved_from", "") or "").lower()


def _evt_method_inferred_only(evt: Dict[str, Any]) -> Optional[bool]:
    v = _get_nested(evt, "debug.evidence.method_is_inferred_only", None)
    if isinstance(v, bool):
        return v
    return None


def _evt_content_type_inferred_only(evt: Dict[str, Any]) -> Optional[bool]:
    v = _get_nested(evt, "debug.evidence.content_type_is_inferred_only", None)
    if isinstance(v, bool):
        return v
    return None


# Hard-coded: Counter cho screenshot/browser paste để đẩy risk score 9.3
# Set = "1" để chỉ chạy hardcoded rule, disable tất cả correlation khác
_HARDCODE_ONLY_MODE = os.getenv("HYBRIDDLP_HARDCODE_ONLY", "1").strip().lower() in {"1", "true", "yes", "on"}

class ContextCorrelator:
    # Hard-coded: Counter cho screenshot/browser paste để đẩy risk score 9.3
    _screenshot_browser_count: int = 0
    _screenshot_browser_user: str = ""
    _screenshot_browser_window_sec: float = 3600.0  # Reset sau 1 giờ
    _screenshot_browser_last_ts: float = 0.0

    def __init__(
        self,
        usb_window_sec: float = 180.0,
        staging_window_sec: float = 300.0,
        clip_window_sec: float = 60.0,
        max_buf: int = 2000,
        dedupe_window_sec: float = 8.0,
        debug: bool = False,
    ):
        self.usb_window_sec = float(usb_window_sec)
        self.staging_window_sec = float(staging_window_sec)
        self.clip_window_sec = float(clip_window_sec)
        self.max_buf = int(max_buf)
        self.dedupe_window_sec = float(dedupe_window_sec)
        self.debug = bool(debug)

        self._usb_recent: Deque[Dict[str, Any]] = deque()
        self._staging_recent: Deque[Dict[str, Any]] = deque()
        self._network_recent: Deque[Dict[str, Any]] = deque()
        self._clipboard_recent: Deque[Dict[str, Any]] = deque()
        self._recent_corr_keys: Deque[Tuple[float, str]] = deque()
        self._clipboard_usb = ClipboardUsbMatcher(dedupe_fn=lambda k, t: self._dedupe_ok(k, t))

        # Counter cho screenshot/browser paste hard-coded rule
        self._scr_browser_count: int = 0
        self._scr_browser_user: str = ""
        self._scr_browser_last_ts: float = 0.0
        self._scr_browser_window_sec: float = 3600.0  # 1 hour window

        _default_noise = (
            "\\windows\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\programdata\\",
            "\\appdata\\",
            "\\system32\\",
            "\\$recycle.bin\\",
            "\\system volume information\\",
            "\\cache\\",
            "\\dawncache\\",
            "\\local storage\\leveldb\\",
            "\\session storage\\",
            "\\webstorage\\",
            "\\antigravity\\",
            "\\code cache\\",
            "\\gpucache\\",
            "\\python\\python312\\",
            "\\python\\python311\\",
            "\\python\\python310\\",
            "\\hybriddlp_ed\\",
            "\\dld_ia01\\",
            "\\programs\\cursor\\",
            "\\.cursor\\",
            "\\.vscode\\",
            "\\.idea\\",
            "\\roaming\\github desktop\\",
            "\\zalo\\local storage\\",
            "\\network\\",
            "\\logs\\",
            "\\indexeddb\\",
            "\\service worker\\",
            "\\localstate\\tabstate\\",
            "\\microsoft visual studio\\",
            "\\.git\\",
            "\\__pycache__\\",
            "\\node_modules\\",
            "\\.pytest_cache\\",
            "\\.venv\\",
            "\\venv\\",
            "\\site-packages\\",
            "\\.mypy_cache\\",
            "\\.ruff_cache\\",
            "\\dist\\",
            "\\build\\",
            "\\.egg-info\\",
        )
        extra = os.getenv("FILE_SENSOR_EXTRA_NOISE_TOKENS", "").strip()
        _extra_toks = tuple(
            x.strip().lower()
            for x in extra.split(";")
            if x.strip()
        )
        self._noise_path_tokens = tuple(
            t.lower().replace("/", "\\") for t in (_default_noise + _extra_toks)
        )
        self._noise_extensions = {
            ".tmp",
            ".temp",
            ".log",
            ".log1",
            ".log2",
            ".mui",
            ".nlp",
            ".dll",
            ".db",
            ".jsonl",
            ".ldb",
            ".sqlite",
            ".journal",
            ".wal",
            ".idx",
            ".pack",
            ".pkl",
            ".bin",
            ".exe",
            ".pyc",
            ".pyo",
            ".pyd",
            ".so",
            ".cache",
            ".lock",
            ".bak",
            ".swp",
            ".swo",
            ".db-wal",
            ".db-journal",
            ".db-shm",
        }
        self._noise_json_path_markers = (
            "\\cache\\",
            "leveldb",
            "code cache",
            "vscode",
            "cursor",
            "appdata",
            "node_modules",
            ".git",
        )

    def _is_noise_event(self, evt: Dict[str, Any]) -> bool:
        path = (_evt_path(evt) or "").lower().replace("/", "\\")
        dst_path = (_evt_dst_path(evt) or "").lower().replace("/", "\\")
        
        for p in [path, dst_path]:
            if not p:
                continue
            
            ext = "." + p.rsplit(".", 1)[-1] if "." in p else ""
            if ext in self._noise_extensions:
                return True
                
            if any(t in p for t in self._noise_path_tokens):
                if ext == ".json":
                    if any(m in p for m in self._noise_json_path_markers):
                        return True
                else:
                    return True
        return False

    def _dbg(self, *args) -> None:
        if self.debug:
            try:
                print("[ContextCorrelator]", *args)
            except Exception:
                pass

    def _now(self) -> float:
        return time.time()

    def _hard_cap(self, dq: Deque) -> None:
        while len(dq) > self.max_buf:
            dq.popleft()

    def _trim(self, dq: Deque, window: float, now: float) -> None:
        cutoff = now - window
        while dq:
            head = dq[0]
            if isinstance(head, dict):
                ts = float(head.get("_ts_unix", 0.0) or 0.0)
            else:
                ts = float(head[0])
            if ts >= cutoff:
                break
            dq.popleft()

    def _dedupe_ok(self, key: str, now_unix: float) -> bool:
        cutoff = now_unix - self.dedupe_window_sec
        while self._recent_corr_keys and self._recent_corr_keys[0][0] < cutoff:
            self._recent_corr_keys.popleft()

        for _, k in self._recent_corr_keys:
            if k == key:
                return False

        self._recent_corr_keys.append((now_unix, key))
        return True

    def _is_sensitive_app_context(self, ctx: Dict[str, Any], evt: Optional[Dict[str, Any]] = None) -> bool:
        title = str(ctx.get("window_title") or "").lower()
        fg_proc = str(ctx.get("fg_process") or "").lower()
        fg_app = str(ctx.get("fg_app") or "").lower()
        fg_url_hint = str(ctx.get("fg_url_hint") or "").lower()

        domain = ""
        if evt:
            domain = _evt_dest_domain(evt)

        if domain and any(h in domain for h in UPLOAD_DOMAIN_HINTS):
            return True
        if fg_url_hint and any(h in fg_url_hint for h in UPLOAD_DOMAIN_HINTS):
            return True
        if fg_proc in BROWSER_PROCS or fg_proc in TRANSFER_PROCS:
            return True
        if fg_app and (fg_app in BROWSER_PROCS or fg_app in TRANSFER_PROCS):
            return True
        if any(h in title for h in SENSITIVE_TITLE_HINTS):
            return True
        return False

    def _is_browser_paste_event(self, evt: Dict[str, Any]) -> bool:
        """Check if event is a clipboard paste into a browser."""
        etype = _evt_type(evt)
        if etype != "clipboard_paste":
            return False
        
        dest_app = _evt_clipboard_dest_app(evt)
        dest_domain = _evt_dest_domain(evt)
        
        # Check dest_app is a browser
        dest_app_lower = dest_app.lower() if dest_app else ""
        if any(browser in dest_app_lower for browser in BROWSER_PROCS):
            return True
        
        # Check dest_domain looks like browser URL (google, chatgpt, etc.)
        if dest_domain:
            browser_domains = {"google", "chatgpt", "claude", "gemini", "bard", "copilot", 
                             "perplexity", "openai", "anthropic", "microsoft", "bing",
                             "facebook", "twitter", "instagram", "linkedin", "reddit",
                             "youtube", "dropbox", "onedrive", "mega", "box"}
            if any(h in dest_domain.lower() for h in browser_domains):
                return True
        
        return False

    def _check_screenshot_browser_count(self, evt: Dict[str, Any], now_unix: float) -> Optional[Dict[str, Any]]:
        """
        Hard-coded rule: Nếu user screenshot hoặc paste vào browser >= 10 lần trong 1 giờ
        → Đẩy risk score lên 9.3 (Critical)
        """
        etype = _evt_type(evt)
        
        # Check if this is a screenshot or browser paste
        is_screenshot = etype == "screenshot"
        is_browser_paste = self._is_browser_paste_event(evt)
        
        if not (is_screenshot or is_browser_paste):
            return None
        
        # Get user
        user = _evt_actor_user(evt) or "unknown"
        
        # Reset counter nếu window đã hết hoặc user khác
        if now_unix - self._scr_browser_last_ts > self._scr_browser_window_sec:
            self._scr_browser_count = 0
            self._scr_browser_user = user
        
        # Reset nếu user khác
        if user != self._scr_browser_user:
            self._scr_browser_count = 0
            self._scr_browser_user = user
        
        # Tăng counter
        self._scr_browser_count += 1
        self._scr_browser_last_ts = now_unix
        
        event_desc = "Screenshot capture" if is_screenshot else "Browser paste"
        self._dbg(f"[HardCode Rule] {event_desc} #{self._scr_browser_count}/10 by {user}")
        
        # Nếu đến lần thứ 10
        if self._scr_browser_count >= 10:
            corr_raw = {
                "type": "corr_screenshot_browser_excessive",
                "source": "correlator",
                "severity": _sev("critical"),
                "ts": _iso_from_ts(now_unix),
                "tags": ["corr_screenshot_browser", "excessive_activity", "hardcoded_rule"],
                "actor": self._build_actor(evt),
                "context": self._build_context(evt),
                "object": {
                    "path": None,
                    "dst_path": None,
                    "drive": None,
                    "volume_type": None,
                    "sensitivity": "Sensitive",
                },
                "debug": {
                    "evidence": {
                        "hardcoded_rule": True,
                        "rule_description": "Screenshot/Browser paste >= 10 times in 1 hour",
                        "screenshot_count": self._scr_browser_count if is_screenshot else 0,
                        "browser_paste_count": self._scr_browser_count if is_browser_paste else 0,
                        "user": user,
                        "event_type": etype,
                        "window_title": _evt_window_title(evt),
                        "dest_app": _evt_clipboard_dest_app(evt),
                        "dest_domain": _evt_dest_domain(evt),
                    },
                    "hardcoded_risk_score": 9.3,
                    "hardcoded_risk_level": "critical",
                    "rule_trigger": "screenshot_browser_excessive_10times_1hour",
                },
            }
            # Reset counter sau khi trigger
            self._scr_browser_count = 0
            return corr_raw
        
        return None

    def _classify_network_target(self, evt: Dict[str, Any]) -> Dict[str, Any]:
        dest_domain = _evt_dest_domain(evt)
        dest_url = _evt_dest_url(evt)
        title = _evt_window_title(evt)
        proc_name = _evt_actor_process_name(evt)
        service_name = _evt_service_name(evt)
        service_category = _evt_service_category(evt)

        all_text = " ".join([dest_domain, dest_url, title, proc_name, service_name, service_category])

        is_gpt = (
            service_name == "chatgpt"
            or service_category == "ai"
            or any(h in all_text for h in GPT_HINTS)
        )
        is_upload_hint = any(h in all_text for h in UPLOAD_DOMAIN_HINTS)
        is_browser = proc_name in BROWSER_PROCS
        is_transfer = proc_name in TRANSFER_PROCS

        return {
            "is_gpt": is_gpt,
            "is_upload_hint": is_upload_hint,
            "is_browser": is_browser,
            "is_transfer": is_transfer,
            "service_name": service_name or None,
            "service_category": service_category or None,
        }

    def _is_interesting_network_evt(self, evt: Dict[str, Any]) -> bool:
        proc_name = _evt_actor_process_name(evt)
        dest_domain = _evt_dest_domain(evt)
        dest_url = _evt_dest_url(evt)
        bytes_sent = _evt_bytes_sent(evt)
        etype = _evt_type(evt)
        op_type = _evt_op_type(evt)
        method = str(_get_nested(evt, "network.method", "") or "").upper()
        title = _evt_window_title(evt)
        service_name = _evt_service_name(evt)
        service_category = _evt_service_category(evt)

        interesting_proc = proc_name in BROWSER_PROCS or proc_name in TRANSFER_PROCS
        interesting_dest = any(h in dest_domain for h in UPLOAD_DOMAIN_HINTS) or any(
            h in dest_url for h in UPLOAD_DOMAIN_HINTS
        )
        interesting_title = any(h in title for h in SENSITIVE_TITLE_HINTS)
        interesting_service = bool(service_name or service_category)

        if etype in {
            "http_upload",
            "cloud_exfiltration",
            "data_exfiltration",
            "network_upload",
            "network_upload_summary",
            "browser_upload",
            "file_upload",
        }:
            return True

        if any(k in op_type for k in ("upload", "send", "post", "put", "exfil", "gpt_upload")):
            return True

        if method in {"POST", "PUT", "PATCH"}:
            return True

        if interesting_proc and bytes_sent >= 32 * 1024:
            return True

        if (interesting_dest or interesting_title or interesting_service) and bytes_sent >= 16 * 1024:
            return True

        return False

    def _recent_clipboard_evidence(self, now_unix: float) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for e in list(self._clipboard_recent)[-5:]:
            ets = float(e.get("_ts_unix", 0.0) or 0.0)
            if now_unix - ets > self.clip_window_sec:
                continue
            out.append(
                {
                    "event_id": e.get("event_id"),
                    "type": e.get("type"),
                    "content_len": e.get("content_len"),
                    "content_type": e.get("content_type"),
                    "source_app": e.get("source_app"),
                    "dest_app": e.get("dest_app"),
                    "dest_domain": e.get("dest_domain"),
                    "window_title": e.get("window_title"),
                    "snapshot_linked": e.get("snapshot_linked"),
                    "sensitivity": e.get("sensitivity"),
                }
            )
        return out

    def _recent_staging_ids(self) -> List[str]:
        ids: List[str] = []
        for e in list(self._staging_recent)[-5:]:
            eid = e.get("event_id")
            if eid:
                ids.append(str(eid))
        return ids

    def _recent_staging_paths(self) -> List[str]:
        paths: List[str] = []
        for e in list(self._staging_recent)[-5:]:
            p = (
                _get_nested(e, "object.path", None)
                or _get_nested(e, "debug.evidence.path", None)
                or _get_nested(e, "debug.evidence.dst_path", None)
            )
            if p:
                paths.append(str(p))
        return paths

    def _recent_staging_primary_path(self) -> Optional[str]:
        paths = self._recent_staging_paths()
        return paths[-1] if paths else None

    def _recent_staging_sensitivity(self) -> Optional[str]:
        seen_sensitive = False
        for e in list(self._staging_recent)[-10:]:
            s = (_get_nested(e, "object.sensitivity", None) or _get_nested(e, "File_Sensitivity", None) or None)
            if not s:
                continue
            s_norm = str(s).strip().lower()
            if "high" in s_norm:
                return "Highly Sensitive"
            if "sens" in s_norm:
                seen_sensitive = True
        return "Sensitive" if seen_sensitive else None

    def _has_file_evidence(self, evt: Dict[str, Any], staging_paths: List[str], clip_evidence: List[Dict[str, Any]]) -> bool:
        if _evt_path(evt) or _evt_dst_path(evt):
            return True
        if staging_paths:
            return True
        for c in clip_evidence:
            if str(c.get("content_type") or "").lower() == "filelist":
                return True
        return False

    def _build_actor(self, evt: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "user": _evt_actor_user(evt),
            "pid": _evt_actor_pid(evt),
            "process": _evt_actor_process_name(evt) or None,
            "cmdline": _evt_actor_cmdline(evt) or None,
        }

    def _build_context(self, evt: Dict[str, Any]) -> Dict[str, Any]:
        ctx = _evt_context(evt)
        return {
            "user": ctx.get("user") or _evt_actor_user(evt),
            "fg_app": ctx.get("fg_app") or ctx.get("fg_process") or _evt_actor_process_name(evt) or None,
            "fg_process": ctx.get("fg_process") or ctx.get("fg_app") or _evt_actor_process_name(evt) or None,
            "fg_pid": ctx.get("fg_pid") or _evt_actor_pid(evt),
            "fg_cmdline": ctx.get("fg_cmdline") or _evt_actor_cmdline(evt) or None,
            "fg_exe_path": ctx.get("fg_exe_path") or _get_nested(evt, "actor.exe", None) or _get_nested(evt, "process.exe", None),
            "fg_hwnd": ctx.get("fg_hwnd"),
            "fg_tid": ctx.get("fg_tid"),
            "window_title": ctx.get("window_title") or _evt_window_title(evt) or None,
            "window_title_lc": ctx.get("window_title_lc") or _evt_window_title(evt) or None,
            "session": ctx.get("session"),
            "process_tags": ctx.get("process_tags") or [],
            "outside_working_hours": ctx.get("outside_working_hours"),
            "fg_domain": ctx.get("fg_domain") or _evt_dest_domain(evt) or None,
            "domain": ctx.get("domain") or _evt_dest_domain(evt) or None,
            "dest_domain": ctx.get("dest_domain") or _evt_dest_domain(evt) or None,
            "resolved_domain": ctx.get("resolved_domain") or _evt_dest_domain(evt) or None,
            "resolved_from": ctx.get("resolved_from") or _evt_resolved_from(evt) or None,
            "dest_ip": ctx.get("dest_ip") or _evt_dest_ip(evt) or None,
            "fg_url_hint": ctx.get("fg_url_hint") or _evt_dest_url(evt) or None,
            "net_snapshot": ctx.get("net_snapshot"),
            "service_name": ctx.get("service_name") or _evt_service_name(evt) or None,
            "service_category": ctx.get("service_category") or _evt_service_category(evt) or None,
        }

    def _build_network_block(self, evt: Dict[str, Any], bytes_sent: Optional[int] = None) -> Dict[str, Any]:
        b = _evt_bytes_sent(evt) if bytes_sent is None else bytes_sent
        return {
            "dest_domain": _evt_dest_domain(evt) or None,
            "resolved_domain": _get_nested(evt, "network.resolved_domain", None) or _evt_dest_domain(evt) or None,
            "dest_url": _evt_dest_url(evt) or None,
            "dest_ip": _evt_dest_ip(evt) or None,
            "dest_host_display": _get_nested(evt, "network.dest_host_display", None),
            "protocol_type": _get_nested(evt, "network.protocol_type", None),
            "dst_port": _get_nested(evt, "network.dst_port", None),
            "method": _get_nested(evt, "network.method", None),
            "content_type": _get_nested(evt, "network.content_type", None),
            "external_dst": _get_nested(evt, "network.external_dst", None),
            "dns_correlated": _get_nested(evt, "network.dns_correlated", None),
            "dns_cache_domain": _get_nested(evt, "network.dns_cache_domain", None),
            "bytes_sent_total": b,
            "bytes_out_total": b,
            "bytes_in_total": _get_nested(evt, "network.bytes_in_total", None),
            "packets_total": _get_nested(evt, "network.packets_total", None),
            "packets_out_total": _get_nested(evt, "network.packets_out_total", None),
            "packets_in_total": _get_nested(evt, "network.packets_in_total", None),
            "session_duration_sec": _get_nested(evt, "network.session_duration_sec", None),
        }

    def _make_corr(
        self,
        corr_raw: Dict[str, Any],
        now_unix: float,
        add_to_staging: bool = False,
    ) -> Dict[str, Any]:
        corr = normalize_event(corr_raw)
        corr["_ts_unix"] = now_unix
        if add_to_staging:
            self._staging_recent.append(corr)
            self._hard_cap(self._staging_recent)
        return corr

    def on_event(self, evt: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        try:
            etype = _evt_type(evt)
            op_type = _evt_op_type(evt)
            source = str(evt.get("source") or "")
            now_unix = _evt_ts_unix(evt, self._now())

            if source == "correlator" or etype.startswith("corr_"):
                return out

            if self._is_noise_event(evt):
                return out

            # HARDCODE ONLY MODE: Skip all other correlations, only process hardcoded rule
            if _HARDCODE_ONLY_MODE:
                # Check screenshot event
                if etype == "screenshot":
                    hardcoded_corr = self._check_screenshot_browser_count(evt, now_unix)
                    if hardcoded_corr:
                        out.append(self._make_corr(hardcoded_corr, now_unix))
                
                # Check browser paste event
                if etype == "clipboard_paste":
                    hardcoded_corr = self._check_screenshot_browser_count(evt, now_unix)
                    if hardcoded_corr:
                        out.append(self._make_corr(hardcoded_corr, now_unix))
                
                return out

            self._trim(self._staging_recent, self.staging_window_sec, now_unix)
            self._trim(self._network_recent, 120.0, now_unix)
            self._trim(self._clipboard_recent, self.clip_window_sec, now_unix)
            self._trim(self._usb_recent, self.usb_window_sec, now_unix)

            if etype == "usb_connected":
                drive = _evt_drive(evt)
                usb_block = evt.get("usb") if isinstance(evt.get("usb"), dict) else {}
                if drive:
                    self._usb_recent.append(
                        {
                            "_ts_unix": now_unix,
                            "drive": drive,
                            "device_id": usb_block.get("device_id") or usb_block.get("Device_ID"),
                            "trust_status": usb_block.get("trust_status") or usb_block.get("Device_Trust_Status"),
                            "event_id": evt.get("event_id"),
                        }
                    )
                self._hard_cap(self._usb_recent)
                return out

            if etype in ("proc_start", "process_created"):
                ioc_hits = _evt_ioc_hits(evt)

                if ioc_hits:
                    proc = _evt_process(evt)
                    proc_name = _evt_actor_process_name(evt) or str(proc.get("name") or "")
                    cmdline = _evt_actor_cmdline(evt) or str(proc.get("cmdline") or "")

                    key = f"proc_staging:{proc_name}:{cmdline[:160]}"
                    if self._dedupe_ok(key, now_unix):
                        corr_raw = {
                            "type": "corr_staging_detected",
                            "source": "correlator",
                            "severity": _sev("warn"),
                            "ts": _iso_from_ts(now_unix),
                            "tags": ["corr_staging", "staging", "proc_ioc"],
                            "actor": self._build_actor(evt),
                            "context": self._build_context(evt),
                            "object": {
                                "path": None,
                                "dst_path": None,
                                "drive": None,
                                "volume_type": None,
                                "sensitivity": "Sensitive",
                            },
                            "debug": {
                                "evidence": {
                                    "pid": _evt_actor_pid(evt),
                                    "proc": proc_name,
                                    "cmdline": cmdline,
                                    "ioc_hits": ioc_hits,
                                    "source_event_type": etype,
                                    "source_op_type": op_type,
                                }
                            },
                        }

                        out.append(self._make_corr(corr_raw, now_unix, add_to_staging=True))
                return out

            if etype in {"file_created", "file_moved", "file_modified", "file_copied", "file_renamed"} or op_type in {
                "file_create",
                "file_move",
                "file_rename",
                "file_copy",
                "file_copy_external",
                "file_move_external",
            }:
                ext = _evt_ext(evt).lower()
                path = _evt_path(evt)
                candidate = _evt_dst_path(evt) or path
                size = _evt_size(evt)
                sensitivity = _evt_file_sensitivity(evt) or None

                staging_like = (
                    ext in ARCHIVE_EXTS
                    or sensitivity is not None
                    or bool(candidate)
                )
                if staging_like and candidate:
                    self._staging_recent.append(
                        {
                            "_ts_unix": now_unix,
                            "event_id": evt.get("event_id"),
                            "object": {
                                "path": path or None,
                                "dst_path": _evt_dst_path(evt) or None,
                                "size": size,
                                "ext": ext or None,
                                "sensitivity": sensitivity,
                            },
                            "debug": {
                                "evidence": {
                                    "path": path or None,
                                    "dst_path": _evt_dst_path(evt) or None,
                                }
                            },
                        }
                    )
                    self._hard_cap(self._staging_recent)

                if ext in ARCHIVE_EXTS and self._staging_recent:
                    key = f"archive:{path}:{ext}"
                    if self._dedupe_ok(key, now_unix):
                        corr_raw = {
                            "type": "corr_archive_staging",
                            "source": "correlator",
                            "severity": _sev("warn"),
                            "ts": _iso_from_ts(now_unix),
                            "tags": ["corr_archive", "archive", "staging"],
                            "actor": self._build_actor(evt),
                            "context": self._build_context(evt),
                            "object": {
                                "path": path or None,
                                "dst_path": _evt_dst_path(evt) or None,
                                "drive": _evt_drive(evt) or None,
                                "volume_type": _evt_dest_volume_type(evt) or None,
                                "size": size,
                                "ext": ext,
                                "sensitivity": sensitivity,
                            },
                            "debug": {
                                "evidence": {
                                    "recent_staging": self._recent_staging_ids(),
                                    "recent_staging_paths": self._recent_staging_paths(),
                                    "source_event_type": etype,
                                    "source_op_type": op_type,
                                }
                            },
                        }
                        out.append(self._make_corr(corr_raw, now_unix))

            if etype in ("clipboard_text", "clipboard_copy", "clipboard_paste"):
                clip_evt = {
                    "_ts_unix": now_unix,
                    "event_id": evt.get("event_id"),
                    "type": etype,
                    "content_len": _evt_clipboard_len(evt),
                    "content_type": _evt_clipboard_type(evt),
                    "source_app": _evt_clipboard_source_app(evt),
                    "dest_app": _evt_clipboard_dest_app(evt),
                    "dest_domain": _evt_dest_domain(evt),
                    "window_title": _get_nested(evt, "clipboard.dest_window_title", None)
                    or _get_nested(evt, "clipboard.active_window_title", None)
                    or _evt_window_title(evt),
                    "snapshot_linked": _evt_clipboard_snapshot_linked(evt),
                    "sensitivity": _evt_clipboard_sensitivity(evt),
                }
                self._clipboard_recent.append(clip_evt)
                self._hard_cap(self._clipboard_recent)
                try:
                    self._clipboard_usb.record_clipboard_copy(evt, now_unix)
                except Exception:
                    pass

            # ===== HARD-CODED RULE: Screenshot/Browser Paste Counter =====
            # Check screenshot event
            if etype == "screenshot":
                hardcoded_corr = self._check_screenshot_browser_count(evt, now_unix)
                if hardcoded_corr:
                    out.append(self._make_corr(hardcoded_corr, now_unix))
            
            # Check browser paste event
            if etype == "clipboard_paste":
                hardcoded_corr = self._check_screenshot_browser_count(evt, now_unix)
                if hardcoded_corr:
                    out.append(self._make_corr(hardcoded_corr, now_unix))
            # ===== END HARD-CODED RULE =====

            if etype in (
                "net_flow_violation",
                "network_flow_summary",
                "network_upload_summary",
                "http_upload",
                "cloud_exfiltration",
                "data_exfiltration",
                "network_upload",
                "browser_upload",
                "file_upload",
            ):
                self._network_recent.append({"_ts_unix": now_unix, "evt": evt})
                self._hard_cap(self._network_recent)

                if self._is_interesting_network_evt(evt):
                    proc_name = _evt_actor_process_name(evt)
                    dest_domain = _evt_dest_domain(evt)
                    dest_url = _evt_dest_url(evt)
                    dest_ip = _evt_dest_ip(evt)
                    bytes_sent = _evt_bytes_sent(evt)
                    clip_evidence = self._recent_clipboard_evidence(now_unix)
                    staging_ids = self._recent_staging_ids()
                    staging_paths = self._recent_staging_paths()
                    staged_path = self._recent_staging_primary_path()
                    context_block = self._build_context(evt)
                    network_block = self._build_network_block(evt, bytes_sent=bytes_sent)
                    target = self._classify_network_target(evt)

                    has_file_evidence = self._has_file_evidence(evt, staging_paths, clip_evidence)
                    if has_file_evidence and not staged_path:
                        staged_path = _evt_path(evt) or _evt_dst_path(evt) or None
                    inferred_only = (
                        _evt_method_inferred_only(evt) is True
                        and _evt_content_type_inferred_only(evt) is True
                    )

                    # Không bắn 2 event trùng nhau nữa.
                    if target["is_gpt"]:
                        corr_type = "corr_gpt_file_upload_suspected" if has_file_evidence else "corr_gpt_data_send_suspected"
                        corr_op_type = corr_type
                        severity = "high" if has_file_evidence else ("warn" if inferred_only else "high")
                        tags = ["corr_upload", "upload", "network", "gpt", "chatgpt"]
                        dedupe_key = f"{corr_type}:{proc_name}:{dest_domain}:{dest_ip}:{bool(has_file_evidence)}"

                        if self._dedupe_ok(dedupe_key, now_unix):
                            corr_raw = {
                                "type": corr_type,
                                "source": "correlator",
                                "severity": _sev(severity),
                                "ts": _iso_from_ts(now_unix),
                                "tags": tags,
                                "actor": self._build_actor(evt),
                                "context": context_block,
                                "operation": {
                                    "op_type": corr_op_type,
                                    "tool": proc_name or context_block.get("fg_app"),
                                    "service_name": target.get("service_name"),
                                    "service_category": target.get("service_category"),
                                },
                                "object": {
                                    "path": staged_path if has_file_evidence else None,
                                    "dst_path": None,
                                    "drive": None,
                                    "volume_type": None,
                                    "dest": dest_domain or dest_url or dest_ip or None,
                                    "bytes": bytes_sent,
                                    "sensitivity": self._recent_staging_sensitivity(),
                                    "cloud_provider": "gpt",
                                },
                                "network": network_block,
                                "debug": {
                                    "evidence": {
                                        "reason": "destination_or_context_matched_gpt",
                                        "process": proc_name,
                                        "dest_ip": dest_ip,
                                        "dest_domain": dest_domain,
                                        "dest_url": dest_url,
                                        "bytes_sent_total": bytes_sent,
                                        "recent_staging": staging_ids,
                                        "recent_staging_paths": staging_paths,
                                        "recent_clipboard": clip_evidence,
                                        "source_event_type": etype,
                                        "source_op_type": op_type,
                                        "window_title": context_block.get("window_title"),
                                        "fg_app": context_block.get("fg_app"),
                                        "fg_process": context_block.get("fg_process"),
                                        "fg_pid": context_block.get("fg_pid"),
                                        "fg_domain": context_block.get("fg_domain"),
                                        "fg_url_hint": context_block.get("fg_url_hint"),
                                        "service_name": target.get("service_name"),
                                        "service_category": target.get("service_category"),
                                        "resolved_from": context_block.get("resolved_from"),
                                        "has_file_evidence": has_file_evidence,
                                        "is_browser_proc": target["is_browser"],
                                        "is_transfer_proc": target["is_transfer"],
                                        "is_gpt_destination": True,
                                        "is_upload_hint_destination": target["is_upload_hint"],
                                        "method_is_inferred_only": _evt_method_inferred_only(evt),
                                        "content_type_is_inferred_only": _evt_content_type_inferred_only(evt),
                                        "threshold_used": _get_nested(evt, "debug.evidence.threshold_used", None),
                                    }
                                },
                            }
                            self._dbg(corr_type, dest_domain, bytes_sent, proc_name, "file_evidence=", has_file_evidence)
                            out.append(self._make_corr(corr_raw, now_unix))

                    else:
                        # Lọc nhiễu: Chỉ phát alert network upload nếu có bằng chứng file HOẶC lượng dữ liệu lớn
                        if has_file_evidence or bytes_sent >= 128 * 1024:
                            severity = "high" if bytes_sent >= 256 * 1024 or staged_path else "warn"
                            key = f"upload:{proc_name}:{dest_domain}:{dest_ip}:{target['is_gpt']}"
    
                            if self._dedupe_ok(key, now_unix):
                                corr_raw = {
                                    "type": "corr_suspected_upload",
                                    "source": "correlator",
                                    "severity": _sev(severity),
                                    "ts": _iso_from_ts(now_unix),
                                "tags": [
                                    "corr_upload",
                                    "upload",
                                    "network",
                                ],
                                "actor": self._build_actor(evt),
                                "context": context_block,
                                "operation": {
                                    "op_type": "corr_suspected_upload",
                                    "tool": proc_name or context_block.get("fg_app"),
                                    "service_name": target.get("service_name"),
                                    "service_category": target.get("service_category"),
                                },
                                "object": {
                                    "path": staged_path,
                                    "dst_path": None,
                                    "drive": None,
                                    "volume_type": None,
                                    "dest": dest_domain or dest_url or dest_ip or None,
                                    "bytes": bytes_sent,
                                    "sensitivity": self._recent_staging_sensitivity() or _evt_file_sensitivity(evt) or None,
                                    "cloud_provider": "cloud" if target["is_upload_hint"] else None,
                                },
                                "network": network_block,
                                "debug": {
                                    "evidence": {
                                        "process": proc_name,
                                        "dest_ip": dest_ip,
                                        "dest_domain": dest_domain,
                                        "dest_url": dest_url,
                                        "bytes_sent_total": bytes_sent,
                                        "recent_staging": staging_ids,
                                        "recent_staging_paths": staging_paths,
                                        "recent_clipboard": clip_evidence,
                                        "source_event_type": etype,
                                        "source_op_type": op_type,
                                        "is_browser_proc": target["is_browser"],
                                        "is_transfer_proc": target["is_transfer"],
                                        "is_gpt_destination": False,
                                        "is_upload_hint_destination": target["is_upload_hint"],
                                        "window_title": context_block.get("window_title"),
                                        "fg_app": context_block.get("fg_app"),
                                        "fg_process": context_block.get("fg_process"),
                                        "fg_pid": context_block.get("fg_pid"),
                                        "fg_domain": context_block.get("fg_domain"),
                                        "fg_url_hint": context_block.get("fg_url_hint"),
                                        "service_name": target.get("service_name"),
                                        "service_category": target.get("service_category"),
                                        "resolved_from": context_block.get("resolved_from"),
                                        "method_is_inferred_only": _evt_method_inferred_only(evt),
                                        "content_type_is_inferred_only": _evt_content_type_inferred_only(evt),
                                        "threshold_used": _get_nested(evt, "debug.evidence.threshold_used", None),
                                        "parent_name": _get_nested(evt, "process.parent_name", None),
                                        "parent_cmdline": _get_nested(evt, "debug.evidence.parent_cmdline", None),
                                    }
                                },
                            }
                            self._dbg("corr_suspected_upload", dest_domain, bytes_sent, proc_name)
                            out.append(self._make_corr(corr_raw, now_unix))

                # Tạm thời tắt corr_network_exfil_suspected theo chiều hướng vô hiệu hoá
                if False and self._staging_recent and not _classify_network_target_is_gpt_safe(evt=self._classify_network_target(evt)):
                    dest_domain = _evt_dest_domain(evt)
                    bytes_sent = _evt_bytes_sent(evt)
                    key = f"net_exfil:{dest_domain}:{bytes_sent // 1024}"
                    if self._dedupe_ok(key, now_unix):
                        corr_raw = {
                            "type": "corr_network_exfil_suspected",
                            "source": "correlator",
                            "severity": _sev("high"),
                            "ts": _iso_from_ts(now_unix),
                            "tags": ["corr_network_exfil", "network", "exfil"],
                            "actor": self._build_actor(evt),
                            "context": self._build_context(evt),
                            "object": {
                                "path": self._recent_staging_primary_path(),
                                "dst_path": None,
                                "drive": None,
                                "volume_type": None,
                                "dest": _evt_dest_domain(evt) or _evt_dest_ip(evt) or None,
                                "bytes": _evt_bytes_sent(evt),
                                "sensitivity": self._recent_staging_sensitivity() or "Sensitive",
                            },
                            "network": self._build_network_block(evt),
                            "debug": {
                                "evidence": {
                                    "recent_staging": self._recent_staging_ids(),
                                    "recent_staging_paths": self._recent_staging_paths(),
                                    "source_event_type": etype,
                                    "source_op_type": op_type,
                                }
                            },
                        }
                        out.append(self._make_corr(corr_raw, now_unix))

            fileish_evt = etype in ("file_created", "file_modified", "file_moved", "file_copied", "file_renamed")
            fileish_op = op_type in (
                "file_create",
                "file_modify",
                "file_move",
                "file_copy",
                "file_rename",
                "file_copy_external",
                "file_move_external",
            )
            if fileish_evt or fileish_op:
                path = _evt_path(evt)
                dst_path = _evt_dst_path(evt)
                candidate = dst_path or path

                if candidate:
                    for rec in list(self._usb_recent):
                        ts_d = float(rec.get("_ts_unix", 0.0) or 0.0)
                        d = str(rec.get("drive") or "")
                        if now_unix - ts_d > self.usb_window_sec:
                            continue

                        if d and candidate.lower().startswith(d.lower()):
                            key = f"usb_exfil:{candidate}:{d}"
                            if self._dedupe_ok(key, now_unix):
                                corr_raw = {
                                    "type": "corr_exfil_usb_suspected",
                                    "source": "correlator",
                                    "severity": _sev("warn"),
                                    "ts": _iso_from_ts(now_unix),
                                    "tags": ["corr_usb_exfil", "usb", "exfil"],
                                    "actor": self._build_actor(evt),
                                    "context": self._build_context(evt),
                                    "object": {
                                        "path": path or None,
                                        "dst_path": dst_path or candidate,
                                        "drive": d,
                                        "volume_type": _evt_dest_volume_type(evt) or "removable",
                                        "sensitivity": _evt_file_sensitivity(evt) or None,
                                    },
                                    "usb": {
                                        "device_id": rec.get("device_id"),
                                        "trust_status": rec.get("trust_status"),
                                        "drive": d,
                                    },
                                    "debug": {
                                        "evidence": {
                                            "drive": d,
                                            "candidate_path": candidate,
                                            "source_event_type": etype,
                                            "source_op_type": op_type,
                                            "usb_event_id": rec.get("event_id"),
                                        }
                                    },
                                }
                                out.append(self._make_corr(corr_raw, now_unix))
                            break

                vt_usb = _evt_dest_volume_type(evt)
                if candidate and vt_usb and "removable" in vt_usb:
                    if etype in (
                        "file_created",
                        "file_modified",
                        "file_moved",
                        "file_copied",
                        "file_renamed",
                    ) or op_type in (
                        "file_create",
                        "file_modify",
                        "file_move",
                        "file_copy",
                        "file_rename",
                        "file_copy_external",
                        "file_move_external",
                    ):
                        try:
                            for cr in self._clipboard_usb.correlate_file_on_removable(
                                evt,
                                now_unix,
                                path=candidate,
                                volume_type=vt_usb,
                                etype=etype,
                                op_type=op_type,
                                build_actor=self._build_actor,
                                build_context=self._build_context,
                                iso_from_ts=_iso_from_ts,
                                sev_fn=_sev,
                            ):
                                out.append(self._make_corr(cr, now_unix))
                        except Exception:
                            pass

            if etype in ("clipboard_text", "clipboard_copy", "clipboard_paste"):
                ctx = _evt_context(evt)
                length = _evt_clipboard_len(evt)
                clip_type = _evt_clipboard_type(evt)
                snapshot_linked = _evt_clipboard_snapshot_linked(evt)
                sensitivity = _evt_clipboard_sensitivity(evt)
                dest_domain = _evt_dest_domain(evt)
                dest_app = _evt_clipboard_dest_app(evt)
                window_title = _evt_window_title(evt)
                ioc_count = len(_evt_ioc_hits(evt))
                yara_count = len(_evt_yara_hits(evt))

                strong_sensitive = (
                    "highly sensitive" in sensitivity
                    or "sensitive" in sensitivity
                    or ioc_count > 0
                    or yara_count > 0
                )

                bulk_or_structured = (
                    length >= 300
                    or clip_type == "filelist"
                    or snapshot_linked
                )

                looks_sensitive = strong_sensitive or bulk_or_structured

                # Toggle: disable corr_clipboard_exfil_suspected via env
                ENABLE_CLIPBOARD_EXFIL_CORR = os.getenv(
                    "HYBRIDDLP_ENABLE_CLIPBOARD_EXFIL_CORR", "1"
                ).strip().lower() in {"1", "true", "yes", "on"}

                if (looks_sensitive and
                    ENABLE_CLIPBOARD_EXFIL_CORR and
                    self._is_sensitive_app_context(ctx, evt)):
                    key = f"clip_exfil:{dest_domain}:{dest_app}:{length}:{snapshot_linked}"
                    if self._dedupe_ok(key, now_unix):
                        corr_raw = {
                            "type": "corr_clipboard_exfil_suspected",
                            "source": "correlator",
                            "severity": _sev("high" if "highly sensitive" in sensitivity or yara_count > 0 else "warn"),
                            "ts": _iso_from_ts(now_unix),
                            "tags": ["corr_clipboard_exfil", "clipboard", "exfil"],
                            "actor": self._build_actor(evt),
                            "context": self._build_context(evt),
                            "object": {
                                "path": None,
                                "dst_path": None,
                                "drive": None,
                                "volume_type": None,
                                "sensitivity": sensitivity or None,
                            },
                            "debug": {
                                "evidence": {
                                    "len": length,
                                    "content_type": clip_type,
                                    "preview": _evt_clipboard_preview(evt),
                                    "source_app": _evt_clipboard_source_app(evt),
                                    "dest_app": dest_app,
                                    "dest_domain": dest_domain,
                                    "window_title": window_title,
                                    "snapshot_linked": snapshot_linked,
                                    "ioc_hits_count": ioc_count,
                                    "yara_matches_count": yara_count,
                                    "source_event_type": etype,
                                    "source_op_type": op_type,
                                }
                            },
                        }
                        out.append(self._make_corr(corr_raw, now_unix))

        except Exception as e:
            self._dbg("on_event error:", repr(e))
            return out

        return out


def _classify_network_target_is_gpt_safe(evt: Dict[str, Any]) -> bool:
    try:
        return bool(evt.get("is_gpt"))
    except Exception:
        return False